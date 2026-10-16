"""Durable custody for Issue 170's one live qualification.

The consumption store is the irreversible boundary.  This module validates a
closed release-install anchor, spends ``live_attempt`` before loading or
calling the owner, and writes one terminal outcome whether the owner passes,
refuses, or crashes.  The independent live-attempt reader then replays that
durable record before this module exposes any completion facts.

The owner implementation remains a late-bound, fixed-source boundary.  Only
after the durable claim, the executor inventories every local Python source
and starts one isolated ``-I -B`` interpreter.  That clean process cannot
inherit the parent's module cache or import finders.  A permanent audit hook
compares every local code object, including direct ``exec_module`` targets,
with the exact inventoried source before execution.  Cached bytecode and
unregistered local code refuse.  The child validates the original owner result
inside its issuing process and returns only the closed projection.  If child
transport ends after owner publication, the parent reconstructs that same
projection from the create-only terminal, completion marker and promotion
receipt, so a durable PASS cannot be downgraded to a contradictory failure.
No caller-supplied callback or loader enters this path.  Its closed contract is:

* ``Issue170QualificationOwnerResult``;
* ``run_issue170_qualification_owner_session(request)``; and
* ``validate_issue170_qualification_owner_result(result, request)`` returning exactly
  ``{"status", "terminal_artifact", "receipt_path"}``.

The validator's projection is data, never authority: receipt bytes, the
append-only store, and ``live_attempt_consumption`` remain the durable proof.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import weakref

from lifecycle_conformance import (
    consumption,
    live_attempt_consumption,
    reference_values as rv,
)
from lifecycle_conformance.values import (
    LifecycleContractError,
    canonical_digest,
    canonical_json,
)
import orch_dork_runtime_package as runtime_package


SCHEMA = "orch-dork/issue170-live-qualification-execution/v1"
OWNER_MODULE = "orch_dork_issue170_qualification_owner"
OWNER_RESULT_TYPE = "Issue170QualificationOwnerResult"
OWNER_RUNNER = "run_issue170_qualification_owner_session"
OWNER_VALIDATOR = "validate_issue170_qualification_owner_result"
OWNER_PROJECTION_FIELDS = frozenset({"status", "terminal_artifact", "receipt_path"})
TERMINAL_ARTIFACT_SCHEMA = "orch-dork/issue170-live-attempt-terminal/v1"
TERMINAL_OUTCOMES = ("SUCCEEDED", "FAILED", "REFUSED", "CRASHED")
_OWNER_TERMINAL_STATUSES = ("PASS", "FAILED", "REFUSED", "CRASHED")
_AUTHORITY = object()
_INPUTS: dict[int, list[object]] = {}
_EXECUTIONS: dict[int, tuple[weakref.ReferenceType[object], int, tuple[object, ...]]] = {}
_OWNER_CHILD_SCHEMA = "orch-dork/issue170-source-owner-child/v1"
_OWNER_INVENTORY_SCHEMA = "orch-dork/issue170-source-owner-inventory/v1"
_OWNER_COMPLETE_SCHEMA = "orch-dork/issue170-qualification-owner-complete/v1"
_OWNER_FAILURE_SCHEMA = "orch-dork/issue170-qualification-owner-terminal/v1"
_OWNER_PUBLICATION_SCHEMA = "orch-dork/issue170-qualification-owner-publication/v1"
_OWNER_RECEIPT_SCHEMA = "orch-dork/promotion-qualification-receipt/v1"
_OWNER_TERMINAL_NAME = ".issue170-qualification-terminal.stage.json"
_OWNER_RECEIPT_NAME = "promotion-qualification-receipt.json"
_OWNER_MARKER_NAME = "issue170-qualification-complete.json"
_OWNER_FAILURE_NAMES = (
    "issue170-qualification-terminal.json",
    *("issue170-qualification-terminal.fallback-" + str(index) + ".json"
      for index in range(1, 5)),
)
# The owner binds its artifacts to the ticket whose "codex/issue-<ticket>-repair"
# branch carries the generation; the same closed rule applies when a durable
# owner terminal is recovered without a live child.  The owner module and
# action_host._bind_owner_ticket carry the same rule, and a test holds the
# three copies equal.
_OWNER_TICKET_ID = re.compile(r"\A[1-9][0-9]{0,8}\Z")


def _owner_repair_branch(ticket_id: int) -> str:
    return "codex/issue-" + str(ticket_id) + "-repair"


_SOURCE_OWNER_RESULTS: dict[
    int, tuple[weakref.ReferenceType[object], int, str, str, str]
] = {}


def _require(condition, reason: str) -> None:
    if condition is not True:
        raise LifecycleContractError("live_qualification_execution:" + reason)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _safe_type_name(value: object) -> str:
    """Describe an exception without trusting a user-defined renderer."""

    kind = type(value)
    module = getattr(kind, "__module__", "unavailable")
    name = getattr(kind, "__qualname__", getattr(kind, "__name__", "unavailable"))
    if type(module) is not str:
        module = "unavailable"
    if type(name) is not str:
        name = "unavailable"
    return module + "." + name


def _unique_json(raw: str, label: str) -> dict:
    """Decode one JSON object without silently accepting duplicate keys."""

    _require(type(raw) is str and 0 < len(raw.encode("utf-8")) <= consumption.MAX_BYTES,
             label + "_extent")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, label + "_duplicate_key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique)
        canonical_json(value)
    except LifecycleContractError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise LifecycleContractError(
            "live_qualification_execution:" + label + "_invalid_json"
        ) from error
    _require(type(value) is dict, label + "_not_object")
    return value


def _frozen_plain(value, label: str) -> dict:
    if type(value) is rv.FrozenValue:
        plain = value.to_plain()
    else:
        plain = value
    _require(type(plain) is dict, label + "_object")
    try:
        frozen = rv.freeze(plain)
    except LifecycleContractError as error:
        raise LifecycleContractError(
            "live_qualification_execution:" + label + "_canonical"
        ) from error
    _require(len(frozen._canonical_text.encode("utf-8")) <= consumption.MAX_BYTES,
             label + "_extent")
    return frozen.to_plain()


def _freeze_terminal_artifact(value, label: str) -> rv.FrozenValue:
    plain = _frozen_plain(value, label)
    schema = plain.get("schema")
    _require(type(schema) is str and 0 < len(schema) <= 256,
             label + "_schema")
    _require(schema != live_attempt_consumption.RECEIPT_SCHEMA,
             label + "_promotion_receipt")
    return rv.freeze(plain)


def _anchor_snapshot(anchor: dict) -> str:
    """Bind the exact mutable ActionHost anchor until its one execution starts."""

    _require(type(anchor) is dict and set(anchor) == {
        "root", "initial_receipt", "latest_receipt", "campaign_receipt_json"
    }, "anchor_shape")
    initial, latest = anchor["initial_receipt"], anchor["latest_receipt"]
    _require(type(initial) is rv.FrozenValue and type(latest) is rv.FrozenValue,
             "anchor_receipt_type")
    campaign = anchor["campaign_receipt_json"]
    _require(type(campaign) is str and 0 < len(campaign.encode("utf-8")) <= consumption.MAX_BYTES,
             "anchor_campaign_json")
    root = anchor["root"]
    _require(isinstance(root, (str, Path)) and bool(str(root))
             and "\x00" not in str(root), "anchor_root")
    return canonical_digest({
        "root": str(root),
        "initial": initial.to_plain(),
        "latest": latest.to_plain(),
        "campaign_receipt_json": campaign,
    })


def _closed_anchor(anchor: dict) -> tuple[Path, rv.FrozenValue, dict]:
    """Re-read a release-install terminal anchor before a live claim exists."""

    _anchor_snapshot(anchor)
    root = Path(anchor["root"])
    latest = anchor["latest_receipt"]
    initial = anchor["initial_receipt"]
    latest_plain = latest.to_plain()
    initial_plain = initial.to_plain()
    _require(type(latest_plain) is dict and type(initial_plain) is dict,
             "anchor_receipt_plain")
    binding = latest_plain.get("binding")
    _require(type(binding) is dict, "anchor_binding")
    # read_store replays the locked MAC chain and refuses any caller-minted
    # FrozenValue.  Keep the equality check local in case its implementation
    # ever changes to return a merely equivalent projection.
    replayed = consumption.read_store(root, latest, expected_binding=binding)
    _require(replayed == latest, "anchor_latest_binding")
    _require(latest_plain.get("phase") == "release_install"
             and latest_plain.get("status") == "SUCCEEDED"
             and latest_plain.get("claim") is not None, "release_install_terminal_required")
    _require(initial_plain.get("schema") == consumption.RECEIPT_SCHEMA
             and initial_plain.get("sequence") == 0
             and initial_plain.get("phase") == "candidate"
             and initial_plain.get("status") == "READY"
             and initial_plain.get("claim") is None
             and initial_plain.get("store") == latest_plain.get("store"),
             "initial_anchor_binding")
    initial_binding = initial_plain.get("binding")
    _require(type(initial_binding) is dict
             and initial_binding.get("pre_runtime") == binding.get("pre_runtime")
             and initial_binding.get("post_runtime") is None
             and initial_binding.get("transition_sha256") is None,
             "initial_binding")
    campaign = anchor["campaign_receipt_json"].encode("utf-8")
    _require(_sha(campaign) == binding.get("campaign_receipt_sha256"),
             "campaign_anchor_binding")
    post = binding.get("post_runtime")
    _require(type(post) is dict and type(post.get("version")) is str
             and type(post.get("package_digest")) is str,
             "post_runtime_binding")
    return root, latest, binding


@dataclass(frozen=True, init=False)
class LiveQualificationInputs:
    """One source-issued, pre-claim request; it is never reusable."""

    anchor: dict
    owner_request: object
    root: Path
    release_latest: rv.FrozenValue
    expected_binding: rv.FrozenValue
    anchor_sha256: str

    def __init__(self, authority, **fields):
        _require(authority is _AUTHORITY, "inputs_factory_required")
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, fields[name])


@dataclass(frozen=True, init=False)
class LiveQualificationExecution:
    """Opaque same-PID custody of one claimed terminal live attempt."""

    inputs: LiveQualificationInputs
    root: Path
    claim: rv.FrozenValue
    latest: rv.FrozenValue
    outcome_bytes: bytes
    validated_report: rv.FrozenValue
    terminal_artifact: rv.FrozenValue
    terminal_original_json: str
    receipt_path: str | None
    receipt_sha256: str | None
    owner_result: object | None
    owner_projection: rv.FrozenValue | None

    def __init__(self, authority, **fields):
        _require(authority is _AUTHORITY, "execution_factory_required")
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, fields[name])


def _inputs_fingerprint(value: LiveQualificationInputs) -> tuple[object, ...]:
    return (
        id(value.anchor),
        id(value.owner_request),
        str(value.root),
        value.release_latest.digest(),
        value.expected_binding.digest(),
        value.anchor_sha256,
    )


def _issue_inputs(value: LiveQualificationInputs) -> LiveQualificationInputs:
    _INPUTS[id(value)] = [
        weakref.ref(value, lambda _: _INPUTS.pop(id(value), None)),
        os.getpid(),
        _inputs_fingerprint(value),
        "PREPARED",
    ]
    return value


def _consume_inputs(value: LiveQualificationInputs) -> None:
    record = _INPUTS.get(id(value))
    _require(type(value) is LiveQualificationInputs and record is not None
             and record[0]() is value and record[1] == os.getpid()
             and record[2] == _inputs_fingerprint(value)
             and record[3] == "PREPARED", "issued_inputs_binding")
    # Consume the in-memory handle before touching the durable store.  A stale
    # store refusal is therefore not an invitation to call the owner later.
    record[3] = "CONSUMED"


def _execution_fingerprint(value: LiveQualificationExecution) -> tuple[object, ...]:
    frozen = (value.claim, value.latest, value.validated_report,
              value.terminal_artifact)
    _require(all(type(item) is rv.FrozenValue for item in frozen),
             "issued_execution_binding")
    _require(type(value.outcome_bytes) is bytes
             and type(value.terminal_original_json) is str,
             "issued_execution_binding")
    _require(value.receipt_path is None or type(value.receipt_path) is str,
             "issued_execution_binding")
    _require(value.receipt_sha256 is None
             or (type(value.receipt_sha256) is str and len(value.receipt_sha256) == 64),
             "issued_execution_binding")
    projection = value.owner_projection
    _require(projection is None or type(projection) is rv.FrozenValue,
             "issued_execution_binding")
    return (
        id(value.inputs), str(value.root), value.claim.digest(), value.latest.digest(),
        _sha(value.outcome_bytes), value.validated_report.digest(),
        value.terminal_artifact.digest(), _sha(value.terminal_original_json.encode("utf-8")),
        value.receipt_path, value.receipt_sha256, id(value.owner_result),
        None if projection is None else projection.digest(),
    )


def _issue_execution(value: LiveQualificationExecution) -> LiveQualificationExecution:
    _EXECUTIONS[id(value)] = (
        weakref.ref(value, lambda _: _EXECUTIONS.pop(id(value), None)),
        os.getpid(),
        _execution_fingerprint(value),
    )
    return value


def _issued_execution(value) -> None:
    record = _EXECUTIONS.get(id(value))
    _require(type(value) is LiveQualificationExecution and record is not None
             and record[0]() is value and record[1] == os.getpid()
             and record[2] == _execution_fingerprint(value),
             "issued_execution_binding")


def _clear_process_authority() -> None:
    _INPUTS.clear()
    _EXECUTIONS.clear()
    _SOURCE_OWNER_RESULTS.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_clear_process_authority)


def _owner_source_path(request: dict) -> Path:
    """Resolve the owner from the exact installed runtime being qualified.

    Stage L installs the candidate before spending the live attempt.  Loading
    the owner from this module's checkout would mix source modules with the
    installed app server and make runtime-relative validation compare two
    different plugin roots.  Verify the installed package as a self-projection
    before any of its Python is inventoried or executed.
    """

    _require(type(request) is dict, "owner_boundary_request")
    root_value = request.get("installed_plugin_root")
    _require(
        type(root_value) is str and bool(root_value) and "\x00" not in root_value,
        "owner_boundary_installed_root",
    )
    root = Path(root_value)
    try:
        resolved = root.resolve(strict=True)
        info = resolved.lstat()
    except (OSError, RuntimeError) as error:
        raise LifecycleContractError(
            "live_qualification_execution:owner_boundary_installed_root"
        ) from error
    _require(
        root.is_absolute()
        and not root.is_symlink()
        and resolved == root
        and stat.S_ISDIR(info.st_mode),
        "owner_boundary_installed_root",
    )
    try:
        projection = runtime_package.validate_projected_runtime_package(
            resolved, resolved
        )
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise LifecycleContractError(
            "live_qualification_execution:owner_boundary_installed_runtime"
        ) from error
    package = projection.get("package") if type(projection) is dict else None
    _require(
        type(projection) is dict
        and projection.get("status") == "PASS"
        and type(package) is dict
        and package.get("version") == request.get("generation")
        and package.get("package_digest")
        == request.get("runtime_package_digest"),
        "owner_boundary_installed_runtime",
    )
    source = resolved / "skills" / "orch-dork" / "scripts" / (
        OWNER_MODULE + ".py"
    )
    try:
        source_info = source.lstat()
        selected = source.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise LifecycleContractError(
            "live_qualification_execution:owner_boundary_source_unavailable"
        ) from error
    _require(
        not source.is_symlink()
        and stat.S_ISREG(source_info.st_mode)
        and selected == source,
        "owner_boundary_source_location",
    )
    return selected


def _read_source_bytes(source: Path, *, unavailable: str, file_label: str,
                       changed_label: str) -> bytes:
    """Read one regular source or evidence file as a stable byte snapshot."""

    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as error:
        raise LifecycleContractError("live_qualification_execution:" + unavailable) from error
    try:
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode)
            and 0 < before.st_size <= consumption.MAX_BYTES,
            file_label,
        )
        raw = os.pread(descriptor, before.st_size + 1, 0)
        after = os.fstat(descriptor)
        named = os.lstat(source)
        _require(
            len(raw) == before.st_size
            and (
                before.st_mode,
                before.st_uid,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) == (
                after.st_mode,
                after.st_uid,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            and (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino),
            changed_label,
        )
        return raw
    finally:
        os.close(descriptor)


def _read_owner_source_bytes(source: Path) -> bytes:
    return _read_source_bytes(
        source,
        unavailable="owner_boundary_source_unavailable",
        file_label="owner_boundary_source_file",
        changed_label="owner_boundary_source_changed",
    )


def _read_owner_collaborator_source_bytes(source: Path) -> bytes:
    return _read_source_bytes(
        source,
        unavailable="owner_boundary_collaborator_unavailable",
        file_label="owner_boundary_collaborator_file",
        changed_label="owner_boundary_collaborator_changed",
    )


def _owner_source_inventory(source: Path) -> tuple[Path, dict]:
    """Bind every local Python source, including direct-loader targets."""

    try:
        root = source.parent.resolve(strict=True)
        expected_owner = source.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise LifecycleContractError(
            "live_qualification_execution:owner_boundary_source_root"
        ) from error
    _require(expected_owner.parent == root, "owner_boundary_source_location")
    entries = {}
    for directory, names, files in os.walk(root):
        directory_path = Path(directory)
        for name in names:
            child = directory_path / name
            _require(not child.is_symlink(), "owner_boundary_source_directory")
        names[:] = sorted(names)
        for name in sorted(files):
            path = directory_path / name
            _require(not path.is_symlink(), "owner_boundary_source_symlink")
            _require(not name.endswith((".pyc", ".pyo")),
                     "owner_boundary_compiled_cache")
            if not name.endswith(".py"):
                continue
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise LifecycleContractError(
                    "live_qualification_execution:owner_boundary_source_lookup"
                ) from error
            _require(root == resolved.parent or root in resolved.parents,
                     "owner_boundary_source_scope")
            raw = (
                _read_owner_source_bytes(resolved)
                if resolved == expected_owner
                else _read_owner_collaborator_source_bytes(resolved)
            )
            relative = resolved.relative_to(root).as_posix()
            entries[relative] = {"sha256": _sha(raw), "bytes": len(raw)}
    owner_relative = expected_owner.relative_to(root).as_posix()
    _require(owner_relative in entries and bool(entries),
             "owner_boundary_source_inventory")
    plain = {
        "schema": _OWNER_INVENTORY_SCHEMA,
        "root": str(root),
        "owner_relative": owner_relative,
        "entries": entries,
    }
    return root, {**plain, "inventory_sha256": canonical_digest(plain)}


def _plain_owner_request(value):
    """Normalize path-like request leaves without invoking custom encoders."""

    if isinstance(value, os.PathLike):
        return str(value)
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) in (list, tuple):
        return [_plain_owner_request(item) for item in value]
    if type(value) is dict:
        _require(all(type(key) is str for key in value),
                 "owner_request_key")
        return {key: _plain_owner_request(item) for key, item in value.items()}
    raise LifecycleContractError(
        "live_qualification_execution:owner_request_not_json"
    )


def _owner_request_plain(request) -> dict:
    plain = _plain_owner_request(request)
    _require(type(plain) is dict, "owner_request_object")
    try:
        encoded = canonical_json(plain)
        decoded = _unique_json(encoded, "owner_request")
    except LifecycleContractError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise LifecycleContractError(
            "live_qualification_execution:owner_request_invalid"
        ) from error
    _require(decoded == plain, "owner_request_roundtrip")
    return plain


_OWNER_CHILD_PROGRAM = r"""
import contextlib
import hashlib
import importlib
import importlib.machinery
import json
import os
from pathlib import Path
import stat
import sys


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    )


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError("duplicate input key")
        result[key] = value
    return result


def stable_read(path):
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1:
            raise RuntimeError("unsafe source")
        raw = os.pread(descriptor, before.st_size + 1, 0)
        after = os.fstat(descriptor)
        named = os.lstat(path)
        if (
            len(raw) != before.st_size
            or (
                before.st_mode,
                before.st_uid,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_mode,
                after.st_uid,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or (named.st_dev, named.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise RuntimeError("changed source")
        return raw
    finally:
        os.close(descriptor)


raw_input = sys.stdin.buffer.read()
payload = json.loads(raw_input.decode("utf-8"), object_pairs_hook=unique)
if raw_input != canonical(payload).encode("utf-8"):
    raise RuntimeError("noncanonical input")
if set(payload) != {"schema", "inventory", "request"}:
    raise RuntimeError("input shape")
if payload["schema"] != "orch-dork/issue170-source-owner-child/v1":
    raise RuntimeError("input schema")
inventory = payload["inventory"]
if (
    type(inventory) is not dict
    or set(inventory)
    != {"schema", "root", "owner_relative", "entries", "inventory_sha256"}
    or inventory["schema"] != "orch-dork/issue170-source-owner-inventory/v1"
):
    raise RuntimeError("inventory shape")
root = Path(inventory["root"])
if not root.is_absolute() or root.is_symlink():
    raise RuntimeError("inventory root")
root = root.resolve(strict=True)
if str(root) != inventory["root"]:
    raise RuntimeError("inventory root identity")
entries = inventory["entries"]
if type(entries) is not dict or not entries:
    raise RuntimeError("inventory entries")


def inventory_core():
    return {
        "schema": inventory["schema"],
        "root": inventory["root"],
        "owner_relative": inventory["owner_relative"],
        "entries": entries,
    }


if hashlib.sha256(canonical(inventory_core()).encode("utf-8")).hexdigest() != inventory["inventory_sha256"]:
    raise RuntimeError("inventory digest")


def current_inventory():
    actual = {}
    for directory, names, files in os.walk(root):
        directory_path = Path(directory)
        for name in names:
            if (directory_path / name).is_symlink():
                raise RuntimeError("source directory symlink")
        names[:] = sorted(names)
        for name in sorted(files):
            path = directory_path / name
            if path.is_symlink() or name.endswith((".pyc", ".pyo")):
                raise RuntimeError("compiled or linked source")
            if not name.endswith(".py"):
                continue
            resolved = path.resolve(strict=True)
            if root != resolved.parent and root not in resolved.parents:
                raise RuntimeError("source scope")
            relative = resolved.relative_to(root).as_posix()
            source_bytes = stable_read(resolved)
            actual[relative] = {
                "sha256": hashlib.sha256(source_bytes).hexdigest(),
                "bytes": len(source_bytes),
            }
    return actual


if current_inventory() != entries:
    raise RuntimeError("source inventory drift")
owner_path = (root / inventory["owner_relative"]).resolve(strict=True)
if root != owner_path.parent and root not in owner_path.parents:
    raise RuntimeError("owner source scope")

_compiler = compile


def source_audit(event, arguments):
    if event != "exec" or not arguments:
        return
    code = arguments[0]
    filename = getattr(code, "co_filename", None)
    if type(filename) is not str:
        return
    try:
        candidate = Path(filename)
        if not candidate.is_absolute():
            return
        candidate = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return
    if root != candidate.parent and root not in candidate.parents:
        return
    relative = candidate.relative_to(root).as_posix()
    expected = entries.get(relative)
    if type(expected) is not dict:
        raise RuntimeError("unregistered local code")
    source_bytes = stable_read(candidate)
    if (
        len(source_bytes) != expected.get("bytes")
        or hashlib.sha256(source_bytes).hexdigest() != expected.get("sha256")
    ):
        raise RuntimeError("local source drift")
    reference = _compiler(
        source_bytes, str(candidate), "exec", dont_inherit=True,
        optimize=sys.flags.optimize,
    )
    if code != reference:
        raise RuntimeError("local code mismatch")


sys.addaudithook(source_audit)


def source_code(loader, fullname):
    path = loader.get_filename(fullname)
    return loader.source_to_code(loader.get_data(path), path)


def refuse_bytecode(loader, fullname):
    raise ImportError("source-only owner import:" + fullname)


importlib.machinery.SourceFileLoader.get_code = source_code
importlib.machinery.SourcelessFileLoader.get_code = refuse_bytecode
sys.dont_write_bytecode = True
sys.path.insert(0, str(root))
with contextlib.redirect_stdout(sys.stderr):
    module = importlib.import_module("orch_dork_issue170_qualification_owner")
    if Path(module.__file__).resolve(strict=True) != owner_path:
        raise RuntimeError("owner origin")
    cached = getattr(module, "__cached__", None)
    if cached and Path(cached).exists():
        raise RuntimeError("owner bytecode")
    result_type = getattr(module, "Issue170QualificationOwnerResult", None)
    runner = getattr(module, "run_issue170_qualification_owner_session", None)
    validator = getattr(module, "validate_issue170_qualification_owner_result", None)
    if (
        type(result_type) is not type
        or not callable(runner)
        or not callable(validator)
        or result_type.__module__ != module.__name__
    ):
        raise RuntimeError("owner shape")
    owner_result = runner(payload["request"])
    projection = validator(owner_result, payload["request"])
    if (
        type(projection) is not dict
        or set(projection) != {"status", "terminal_artifact", "receipt_path"}
        or projection["status"] not in {"PASS", "FAILED", "REFUSED", "CRASHED"}
        or type(projection["terminal_artifact"]) is not dict
        or (
            projection["receipt_path"] is not None
            and type(projection["receipt_path"]) is not str
        )
    ):
        raise RuntimeError("owner projection")
output = {
    "schema": "orch-dork/issue170-source-owner-child/v1",
    "status": "COMPLETE",
    "inventory_sha256": inventory["inventory_sha256"],
    "projection": projection,
}
sys.stdout.write(canonical(output))
"""


def _invoke_source_owner_child(root: Path, inventory: dict,
                               request: dict) -> dict:
    payload = {
        "schema": _OWNER_CHILD_SCHEMA,
        "inventory": inventory,
        "request": request,
    }
    input_bytes = canonical_json(payload).encode("utf-8")
    executable = Path(sys.executable)
    try:
        executable = executable.resolve(strict=True)
        info = executable.lstat()
    except (OSError, RuntimeError) as error:
        raise LifecycleContractError(
            "live_qualification_execution:owner_boundary_python_unavailable"
        ) from error
    _require(
        stat.S_ISREG(info.st_mode) and os.access(executable, os.X_OK),
        "owner_boundary_python_executable",
    )
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        completed = subprocess.run(
            [
                str(executable),
                "-I",
                "-S",
                "-B",
                "-c",
                _OWNER_CHILD_PROGRAM,
            ],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=root,
            env=environment,
            check=False,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LifecycleContractError(
            "live_qualification_execution:owner_boundary_child_unavailable"
        ) from error
    if (
        completed.returncode != 0
        or not completed.stdout
        or len(completed.stdout) > consumption.MAX_BYTES
    ):
        raise LifecycleContractError(
            "live_qualification_execution:owner_boundary_child_failed"
        )
    try:
        text = completed.stdout.decode("utf-8")
    except UnicodeError as error:
        raise LifecycleContractError(
            "live_qualification_execution:owner_boundary_child_output"
        ) from error
    value = _unique_json(text, "owner_child")
    _require(text == canonical_json(value), "owner_boundary_child_canonical")
    _require(
        set(value) == {
            "schema", "status", "inventory_sha256", "projection"
        }
        and value["schema"] == _OWNER_CHILD_SCHEMA
        and value["status"] == "COMPLETE"
        and value["inventory_sha256"] == inventory["inventory_sha256"]
        and type(value["projection"]) is dict,
        "owner_boundary_child_output",
    )
    return value["projection"]


def _owner_artifact_bytes(path: Path) -> bytes:
    raw = _read_source_bytes(
        path,
        unavailable="owner_artifact_unavailable",
        file_label="owner_artifact_file",
        changed_label="owner_artifact_changed",
    )
    try:
        info = path.lstat()
    except OSError as error:
        raise LifecycleContractError(
            "live_qualification_execution:owner_artifact_unavailable"
        ) from error
    _require(
        info.st_uid == os.getuid()
        and not stat.S_IMODE(info.st_mode) & 0o077,
        "owner_artifact_custody",
    )
    return raw


def _parse_owner_artifact(path: Path, schema: str) -> tuple[dict, bytes]:
    raw = _owner_artifact_bytes(path)
    _require(raw.endswith(b"\n"), "owner_artifact_canonical")
    try:
        text = raw[:-1].decode("utf-8")
    except UnicodeError as error:
        raise LifecycleContractError(
            "live_qualification_execution:owner_artifact_utf8"
        ) from error
    value = _unique_json(text, "owner_artifact")
    _require(
        raw == (canonical_json(value) + "\n").encode("utf-8")
        and value.get("schema") == schema,
        "owner_artifact_canonical",
    )
    return value, raw


def _normalized_owner_request(request: dict) -> dict | None:
    fields = {
        "schema", "ticket_id", "repair_branch", "source_commit", "generation",
        "runtime_package_digest", "codex_executable", "workspace",
        "owner_socket", "observer_trust_store", "observer_replay_db",
        "installed_plugin_root", "opencodex_root", "evidence_root",
        "enrollment_registry_root", "root_model", "root_model_provider",
        "worker_model", "worker_effort", "service_name", "controller_id",
        "case_id",
    }
    if type(request) is not dict:
        return None
    schema = request.get("schema")
    if schema == "orch-dork/issue170-qualification-owner-request/v2":
        fields.add("execution_environment")
    elif schema == "orch-dork/issue170-qualification-owner-request/v3":
        fields.add("root_effort")
    elif schema == "orch-dork/issue170-qualification-owner-request/v4":
        # Issue 203: the onboarded reviewer the standards lane runs on.
        fields.update({"root_effort", "reviewer_model", "reviewer_effort"})
    elif schema != "orch-dork/issue170-qualification-owner-request/v1":
        return None
    if set(request) != fields:
        return None
    ticket_id = request.get("ticket_id")
    if (
        type(ticket_id) is not int
        or _OWNER_TICKET_ID.fullmatch(str(ticket_id)) is None
        or request.get("repair_branch") != _owner_repair_branch(ticket_id)
    ):
        return None
    try:
        normalized = dict(request)
        for name in (
            "codex_executable", "workspace", "observer_trust_store",
            "observer_replay_db", "installed_plugin_root", "opencodex_root",
            "evidence_root", "enrollment_registry_root",
        ):
            normalized[name] = str(Path(request[name]).resolve(strict=True))
        socket = Path(request["owner_socket"])
        normalized["owner_socket"] = str(
            socket.parent.resolve(strict=True) / socket.name
        )
        if "execution_environment" in fields:
            binding = request["execution_environment"]
            if (
                type(binding) is not dict
                or set(binding) != {
                    "schema", "environment_id", "exec_server_url", "workspace", "policy_sha256",
                    "code_mode_host_url",
                }
                or any(not isinstance(value, str) for value in binding.values())
                or binding["schema"] != "orch-dork/qualification-execution-environment/v1"
                or binding["environment_id"] != "issue170-worker"
                or binding["workspace"] != normalized["workspace"]
            ):
                return None
            # Preserve every bound byte in the request hash. Recovery validates
            # existing owner publications; it never authorizes this endpoint.
            normalized["execution_environment"] = dict(binding)
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        return None
    return normalized


def _recover_owner_projection(request: dict) -> dict | None:
    """Recover a durable owner terminal if child transport ended ambiguously."""

    normalized = _normalized_owner_request(request)
    if normalized is None:
        return None
    root = Path(normalized["evidence_root"])
    receipt_path = root / _OWNER_RECEIPT_NAME
    terminal_path = root / _OWNER_TERMINAL_NAME
    marker_path = root / _OWNER_MARKER_NAME
    failure_paths = tuple(root / name for name in _OWNER_FAILURE_NAMES)
    if os.path.lexists(receipt_path):
        terminal, terminal_raw = _parse_owner_artifact(
            terminal_path, _OWNER_COMPLETE_SCHEMA
        )
        receipt, receipt_raw = _parse_owner_artifact(
            receipt_path, _OWNER_RECEIPT_SCHEMA
        )
        marker, _marker_raw = _parse_owner_artifact(
            marker_path, _OWNER_PUBLICATION_SCHEMA
        )
        receipt_info = os.lstat(receipt_path)
        expected_receipt = {
            "generation": normalized["generation"],
            "qualification_evidence_sha256": _sha(terminal_raw),
            "repair_branch": normalized["repair_branch"],
            "runtime_package_digest": normalized["runtime_package_digest"],
            "schema": _OWNER_RECEIPT_SCHEMA,
            "source_commit": normalized["source_commit"],
            "status": "PASS",
            "ticket_id": str(normalized["ticket_id"]),
        }
        expected_marker = {
            "schema": _OWNER_PUBLICATION_SCHEMA,
            "status": "PASS",
            "ticket_id": str(normalized["ticket_id"]),
            "repair_branch": normalized["repair_branch"],
            "request_sha256": _sha(canonical_json(normalized).encode("utf-8")),
            "evidence_root": str(root),
            "terminal_evidence_path": str(terminal_path),
            "terminal_evidence_sha256": _sha(terminal_raw),
            "promotion_receipt_path": str(receipt_path),
            "promotion_receipt_sha256": _sha(receipt_raw),
            "promotion_receipt_inode": {
                "device": receipt_info.st_dev,
                "inode": receipt_info.st_ino,
            },
        }
        _require(
            terminal.get("status") == "PASS"
            and terminal.get("ticket_id") == normalized["ticket_id"]
            and terminal.get("repair_branch") == normalized["repair_branch"]
            and terminal.get("source_commit") == normalized["source_commit"]
            and terminal.get("generation") == normalized["generation"]
            and terminal.get("runtime_package_digest")
            == normalized["runtime_package_digest"]
            and receipt == expected_receipt
            and marker == expected_marker
            and not any(os.path.lexists(path) for path in failure_paths),
            "owner_durable_pass_invalid",
        )
        return {
            "status": "PASS",
            "terminal_artifact": terminal,
            "receipt_path": str(receipt_path),
        }
    existing_failures = [path for path in failure_paths if os.path.lexists(path)]
    if not existing_failures:
        return None
    _require(len(existing_failures) == 1, "owner_failure_terminal_ambiguous")
    failure_path = existing_failures[0]
    terminal, _raw = _parse_owner_artifact(
        failure_path, _OWNER_FAILURE_SCHEMA
    )
    _require(
        terminal.get("status") == "FAIL"
        and terminal.get("ticket_id") == normalized["ticket_id"]
        and terminal.get("repair_branch") == normalized["repair_branch"]
        and terminal.get("source_commit") == normalized["source_commit"]
        and terminal.get("generation") == normalized["generation"]
        and terminal.get("runtime_package_digest")
        == normalized["runtime_package_digest"]
        and terminal.get("terminal_evidence_path") == str(failure_path)
        and terminal.get("promotion_receipt_emitted") is False,
        "owner_durable_failure_invalid",
    )
    return {
        "status": "FAILED",
        "terminal_artifact": terminal,
        "receipt_path": None,
    }


@dataclass(frozen=True, eq=False)
class _SourceOwnedOwnerResult:
    __slots__ = (
        "projection",
        "request_sha256",
        "inventory_sha256",
        "__weakref__",
    )

    projection: rv.FrozenValue
    request_sha256: str
    inventory_sha256: str


def _source_owner_result_fingerprint(result: _SourceOwnedOwnerResult) -> str:
    return canonical_digest({
        "projection": result.projection.to_plain(),
        "request_sha256": result.request_sha256,
        "inventory_sha256": result.inventory_sha256,
    })


def _issue_source_owner_result(request: dict, projection: dict,
                               inventory_sha256: str) -> _SourceOwnedOwnerResult:
    frozen = rv.freeze(projection)
    result = _SourceOwnedOwnerResult(
        frozen,
        _sha(canonical_json(request).encode("utf-8")),
        inventory_sha256,
    )
    identity = id(result)
    _SOURCE_OWNER_RESULTS[identity] = (
        weakref.ref(result, lambda _: _SOURCE_OWNER_RESULTS.pop(identity, None)),
        os.getpid(),
        result.request_sha256,
        result.inventory_sha256,
        _source_owner_result_fingerprint(result),
    )
    return result


def _run_source_owned_owner_session(request) -> _SourceOwnedOwnerResult:
    request_plain = _owner_request_plain(request)
    source = _owner_source_path(request_plain)
    root, inventory = _owner_source_inventory(source)
    child_error = None
    try:
        child_projection = _invoke_source_owner_child(
            root, inventory, request_plain
        )
    except LifecycleContractError as error:
        child_error = error
        child_projection = None
    durable = _recover_owner_projection(request_plain)
    if durable is not None:
        projection = durable
    elif child_projection is not None:
        projection = child_projection
    else:
        raise child_error
    _require(
        type(projection) is dict
        and set(projection) == OWNER_PROJECTION_FIELDS,
        "owner_boundary_projection",
    )
    return _issue_source_owner_result(
        request_plain, projection, inventory["inventory_sha256"]
    )


def _validate_source_owned_owner_result(result, request) -> dict:
    request_plain = _owner_request_plain(request)
    _require(
        type(result) is _SourceOwnedOwnerResult,
        "owner_boundary_result_type",
    )
    record = _SOURCE_OWNER_RESULTS.get(id(result))
    _require(
        record is not None
        and record[0]() is result
        and record[1] == os.getpid()
        and record[2] == _sha(canonical_json(request_plain).encode("utf-8"))
        and record[3] == result.inventory_sha256
        and record[4] == _source_owner_result_fingerprint(result),
        "owner_boundary_result_binding",
    )
    durable = _recover_owner_projection(request_plain)
    if durable is not None:
        _require(
            rv.freeze(durable) == result.projection,
            "owner_boundary_durable_result_mutated",
        )
    return result.projection.to_plain()


def _load_source_owned_owner_boundary():
    """Return a fixed proxy whose runner uses one clean source-only process."""

    return (
        _SourceOwnedOwnerResult,
        _run_source_owned_owner_session,
        _validate_source_owned_owner_result,
    )


def _owner_boundary():
    """Resolve the fixed source-owned owner after the durable claim."""

    return _load_source_owned_owner_boundary()


def _owner_projection(result_type, validator, result, request) -> rv.FrozenValue:
    """Validate the exact owner object before using its terminal projection."""

    _require(type(result) is result_type, "owner_result_type")
    value = validator(result, request)
    _require(type(value) is dict and set(value) == OWNER_PROJECTION_FIELDS,
             "owner_result_projection")
    status = value["status"]
    _require(type(status) is str and status in _OWNER_TERMINAL_STATUSES,
             "owner_result_status")
    path = value["receipt_path"]
    _require(path is None or isinstance(path, (str, Path)), "owner_result_receipt_path")
    if path is not None:
        path = str(path)
        _require(bool(path) and "\x00" not in path, "owner_result_receipt_path")
    artifact = _frozen_plain(value["terminal_artifact"], "owner_terminal_artifact")
    return rv.freeze({"status": status, "terminal_artifact": artifact,
                      "receipt_path": path})


def _failure_artifact(reason: str, *, projection: rv.FrozenValue | None = None,
                      error: BaseException | None = None) -> rv.FrozenValue:
    _require(type(reason) is str and bool(reason), "failure_reason")
    body = {
        "schema": TERMINAL_ARTIFACT_SCHEMA,
        "status": "FAILED",
        "reason": reason,
        "owner_projection_sha256": None if projection is None else projection.digest(),
        "error_type": None if error is None else _safe_type_name(error),
    }
    return rv.freeze(body)


def _failure_terminal(projection: rv.FrozenValue) -> tuple[str, rv.FrozenValue]:
    """Use an owner's non-receipt terminal only when it cannot smuggle PASS."""

    value = projection.to_plain()
    status = value["status"]
    _require(status != "PASS", "failure_status")
    artifact = value["terminal_artifact"]
    path = value["receipt_path"]
    if path is None:
        try:
            return status, _freeze_terminal_artifact(artifact, "owner_terminal_artifact")
        except LifecycleContractError:
            pass
    return status, _failure_artifact("owner_nonpass_receipt_or_artifact", projection=projection)


def _read_exact_receipt_bytes(path: str) -> bytes:
    """Retain the same create-only regular file that the reader validated."""

    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LifecycleContractError(
            "live_qualification_execution:receipt_unavailable"
        ) from error
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode), "receipt_not_regular_file")
        _require(before.st_uid in (0, os.getuid()), "receipt_not_owned")
        # The owner creates its private evidence at 0600 while it retains the
        # descriptor.  Group- or world-writable paths cannot be custody
        # evidence, matching the independent reader's public file contract.
        _require(not stat.S_IMODE(before.st_mode) & 0o022, "receipt_writable")
        _require(before.st_nlink == 1, "receipt_shared_name")
        _require(0 < before.st_size <= live_attempt_consumption.MAX_RECEIPT_BYTES,
                 "receipt_extent")
        raw = os.pread(descriptor, before.st_size + 1, 0)
        after = os.fstat(descriptor)
        named = os.lstat(path)
        _require(len(raw) == before.st_size
                 and (before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                 == (after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                 and (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino),
                 "receipt_changed")
        return raw
    finally:
        os.close(descriptor)


def _success_terminal(projection: rv.FrozenValue, binding: dict):
    """Read one PASS receipt before it can enter the successful envelope."""

    value = projection.to_plain()
    _require(value["status"] == "PASS" and value["receipt_path"] is not None,
             "owner_pass_receipt_required")
    path = value["receipt_path"]
    receipt, receipt_sha256 = live_attempt_consumption.read_promotion_receipt(path)
    raw = _read_exact_receipt_bytes(path)
    _require(_sha(raw) == receipt_sha256, "receipt_substituted")
    try:
        original = raw.decode("utf-8")
    except UnicodeError as error:
        raise LifecycleContractError(
            "live_qualification_execution:receipt_invalid_utf8"
        ) from error
    _require(_unique_json(original, "receipt") == receipt, "receipt_substituted")
    artifact = _freeze_terminal_artifact(
        value["terminal_artifact"], "owner_terminal_artifact"
    )
    post = binding["post_runtime"]
    _require(receipt["status"] == "PASS"
             and receipt["generation"] == post["version"]
             and receipt["runtime_package_digest"] == post["package_digest"],
             "receipt_generation_binding")
    return artifact, original, path, receipt_sha256


def _outcome_bytes(claim: rv.FrozenValue, outcome: str, original_json: str,
                   transport_status: str) -> bytes:
    _require(outcome in TERMINAL_OUTCOMES
             and transport_status in {"VALIDATED", "REFUSED"}, "outcome_status")
    body = {
        "schema": consumption.OUTCOME_SCHEMA,
        "phase": "live_attempt",
        "claim_sha256": claim.digest(),
        "outcome": outcome,
        "transport": {
            "schema": consumption.TRANSPORT_SCHEMA,
            "status": transport_status,
            "original_receipt_json": original_json,
        },
    }
    return canonical_json(body).encode("utf-8")


def _terminal_envelope(claim, binding, inputs):
    """Call the fixed owner once and convert every outcome to durable bytes."""

    owner_result = None
    projection = None
    try:
        result_type, runner, validator = _owner_boundary()
        owner_result = runner(inputs.owner_request)
        projection = _owner_projection(
            result_type, validator, owner_result, inputs.owner_request
        )
        if projection.to_plain()["status"] == "PASS":
            artifact, original, path, receipt_sha256 = _success_terminal(projection, binding)
            return (
                "SUCCEEDED", "VALIDATED", artifact, original, path, receipt_sha256,
                owner_result, projection,
            )
        outcome, artifact = _failure_terminal(projection)
        return (
            outcome, "REFUSED", artifact, canonical_json(artifact.to_plain()), None, None,
            owner_result, projection,
        )
    except BaseException as error:
        if owner_result is None:
            outcome, reason = "CRASHED", "owner_exception"
        else:
            outcome, reason = "REFUSED", "owner_result_refused"
        artifact = _failure_artifact(reason, projection=projection, error=error)
        return (
            outcome, "REFUSED", artifact, canonical_json(artifact.to_plain()), None, None,
            owner_result, projection,
        )


def prepare_live_qualification(consumption_anchor: dict, owner_request) -> LiveQualificationInputs:
    """Validate and retain one closed release-install anchor without claiming it."""

    _require(not callable(owner_request), "owner_callback_forbidden")
    root, latest, binding = _closed_anchor(consumption_anchor)
    return _issue_inputs(LiveQualificationInputs(
        _AUTHORITY,
        anchor=consumption_anchor,
        owner_request=owner_request,
        root=root,
        release_latest=latest,
        expected_binding=rv.freeze(binding),
        anchor_sha256=_anchor_snapshot(consumption_anchor),
    ))


def execute_live_qualification(inputs) -> LiveQualificationExecution:
    """Spend and terminalize exactly one live attempt from prepared inputs."""

    _consume_inputs(inputs)
    root, latest, binding = _closed_anchor(inputs.anchor)
    _require(root == inputs.root and latest == inputs.release_latest
             and rv.freeze(binding) == inputs.expected_binding,
             "prepared_anchor_stale")
    # This is the irreversible action and must remain before lazy owner import,
    # host launch, receipt access, or any owner-visible effect.
    claim = consumption.claim_phase(
        root,
        latest,
        phase="live_attempt",
        expected_binding=binding,
    )
    (outcome, transport_status, artifact, original_json, receipt_path,
     receipt_sha256, owner_result, projection) = _terminal_envelope(
        claim, binding, inputs
    )
    outcome_bytes = _outcome_bytes(claim, outcome, original_json, transport_status)
    # One call only.  If the store rejects this final append, the durable claim
    # remains spent and this API deliberately has no recovery/retry route.
    latest_terminal = consumption.record_outcome(
        root,
        claim,
        outcome_receipt=outcome_bytes,
        expected_binding=binding,
    )
    # The shared ActionHost anchor changes only after the terminal record has
    # been durably appended and returned.
    inputs.anchor["latest_receipt"] = latest_terminal
    validated = live_attempt_consumption.verify_campaign_consumption(
        root,
        claim_receipt=claim,
        latest_receipt=latest_terminal,
        expected_binding=latest_terminal.to_plain()["binding"],
        outcome_receipt=outcome_bytes,
        receipt_path=receipt_path,
    )
    independently_validated = live_attempt_consumption.validate_campaign_consumption(
        root,
        validated.report,
        claim_receipt=claim,
        latest_receipt=latest_terminal,
        expected_binding=latest_terminal.to_plain()["binding"],
        outcome_receipt=outcome_bytes,
        receipt_path=receipt_path,
    )
    _require(independently_validated.report == validated.report,
             "independent_report_binding")
    return _issue_execution(LiveQualificationExecution(
        _AUTHORITY,
        inputs=inputs,
        root=root,
        claim=claim,
        latest=latest_terminal,
        outcome_bytes=outcome_bytes,
        validated_report=validated.report,
        terminal_artifact=artifact,
        terminal_original_json=original_json,
        receipt_path=receipt_path,
        receipt_sha256=receipt_sha256,
        owner_result=owner_result,
        owner_projection=projection,
    ))


def _revalidate_execution(execution: LiveQualificationExecution):
    _issued_execution(execution)
    _require(execution.claim.to_plain().get("phase") == "live_attempt"
             and execution.claim.to_plain().get("status") == "CLAIMED"
             and execution.latest.to_plain().get("phase") == "live_attempt"
             and execution.latest.to_plain().get("status") in TERMINAL_OUTCOMES,
             "execution_chain_shape")
    if execution.owner_result is None:
        _require(execution.owner_projection is None, "owner_result_binding")
    elif execution.owner_projection is not None:
        result_type, _runner, validator = _owner_boundary()
        current_projection = _owner_projection(
            result_type,
            validator,
            execution.owner_result,
            execution.inputs.owner_request,
        )
        _require(current_projection == execution.owner_projection,
            "owner_result_post_record_mutation",
        )
        current = current_projection.to_plain()
        if execution.receipt_path is not None:
            _require(
                current["status"] == "PASS"
                and _freeze_terminal_artifact(
                    current["terminal_artifact"], "owner_terminal_artifact"
                ) == execution.terminal_artifact,
                "owner_terminal_artifact_binding",
            )
        elif current["status"] != "PASS" and current["receipt_path"] is None:
            _require(
                _freeze_terminal_artifact(
                    current["terminal_artifact"], "owner_terminal_artifact"
                ) == execution.terminal_artifact,
                "owner_terminal_artifact_binding",
            )
        else:
            _require(
                execution.terminal_artifact.to_plain().get("schema")
                == TERMINAL_ARTIFACT_SCHEMA,
                "owner_terminal_artifact_binding",
            )
    original = _unique_json(execution.terminal_original_json, "terminal_original")
    if execution.receipt_path is None:
        _require(original == execution.terminal_artifact.to_plain()
                 and original.get("schema") != live_attempt_consumption.RECEIPT_SCHEMA
                 and execution.receipt_sha256 is None, "failure_receipt_binding")
    else:
        receipt, receipt_sha256 = live_attempt_consumption.read_promotion_receipt(
            execution.receipt_path
        )
        raw = _read_exact_receipt_bytes(execution.receipt_path)
        _require(receipt_sha256 == execution.receipt_sha256
                 and _sha(raw) == execution.receipt_sha256
                 and _unique_json(raw.decode("utf-8"), "receipt") == receipt
                 and receipt == original, "receipt_post_record_mutation")
    envelope = _unique_json(execution.outcome_bytes.decode("utf-8"), "outcome")
    _require(envelope == {
        "schema": consumption.OUTCOME_SCHEMA,
        "phase": "live_attempt",
        "claim_sha256": execution.claim.digest(),
        "outcome": execution.latest.to_plain()["status"],
        "transport": {
            "schema": consumption.TRANSPORT_SCHEMA,
            "status": "VALIDATED" if execution.receipt_path is not None else "REFUSED",
            "original_receipt_json": execution.terminal_original_json,
        },
    }, "outcome_original_binding")
    validated = live_attempt_consumption.validate_campaign_consumption(
        execution.root,
        execution.validated_report,
        claim_receipt=execution.claim,
        latest_receipt=execution.latest,
        expected_binding=execution.latest.to_plain()["binding"],
        outcome_receipt=execution.outcome_bytes,
        receipt_path=execution.receipt_path,
    )
    _require(validated.report == execution.validated_report, "validated_report_binding")
    return validated


def live_report(execution) -> rv.FrozenValue:
    """Return the independently replayed report for an exact issued execution."""

    _revalidate_execution(execution)
    return execution.validated_report


def completion_facts(execution) -> tuple[str, ...]:
    """Expose only the two durable live-attempt facts after a fresh replay."""

    return live_attempt_consumption.completion_facts(_revalidate_execution(execution))


def completion_originals(execution) -> dict:
    """Return the exact custody objects the completion gate must consume."""

    _revalidate_execution(execution)
    return {
        "claim_receipt": execution.claim,
        "latest_receipt": execution.latest,
        "outcome_receipt": execution.outcome_bytes,
        "validated_report": execution.validated_report,
        "terminal_artifact": execution.terminal_artifact,
        "terminal_original_json": execution.terminal_original_json,
        "promotion_receipt_path": execution.receipt_path,
        "promotion_receipt_sha256": execution.receipt_sha256,
        "owner_result": execution.owner_result,
        "owner_projection": execution.owner_projection,
    }


__all__ = [
    "SCHEMA",
    "LiveQualificationInputs",
    "LiveQualificationExecution",
    "prepare_live_qualification",
    "execute_live_qualification",
    "live_report",
    "completion_facts",
    "completion_originals",
]
