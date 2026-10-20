"""Same-process custody for the fixed Issue 170 physical release operation.

The fixed release entry point returns a source-issued opaque physical result.
This reader retains that exact result or failure and contributes facts only
after the release module's independent physical-result validator accepts it.

Custody outranks fingerprint fidelity once the effect has run. Every step that
executes after _RELEASE_ENTRYPOINT returns is total: it degrades to a fixed
deterministic marker instead of raising, so a retained original can never be
destroyed by its own fingerprint or by a post-effect capture. Degradation is
fail-closed for authority, because a degraded capture can never equal the
before capture and therefore grants no physical fact, and fail-open for
custody, because the exact original object stays reachable and re-validatable.
"""
from __future__ import annotations

from dataclasses import dataclass
import array
import collections
import hashlib
import math
import os
from pathlib import Path
import stat
import types
import weakref

from lifecycle_conformance import action_authority, reference_values as rv, values
import orch_dork_release_marketplace as release_marketplace
import orch_dork_runtime_package as runtime_package


REPORT_SCHEMA = "orch-dork/release-execution-report/v1"
_AUTHORITY = object()
_ISSUED = {}
_ROOT = Path(__file__).resolve().parents[4]
_RELEASE_ENTRYPOINT = release_marketplace.release_and_install_physical
_PHYSICAL_VALIDATOR = release_marketplace.validate_release_physical_result
_LOCAL_MODULES = (release_marketplace, runtime_package, action_authority)
_SOURCE_PINS = {Path(module.__file__).resolve(): hashlib.sha256(
    Path(module.__file__).read_bytes()).hexdigest() for module in _LOCAL_MODULES}
# ActionHost is the final fixed caller for the physical release reader.  Bind
# its source path into the reviewed guard without importing it: importing the
# caller here would create a cycle while a source-path digest is sufficient to
# make caller-byte drift refuse the literal guard when that guard is activated.
_ACTION_HOST_CALLER_PATH = (
    _ROOT / "skills/orch-dork/scripts/lifecycle_conformance/action_host.py"
)
# Reviewed literal over _LOCAL_MODULES plus the final ActionHost caller
# surface.  It is intentionally not derived from current bytes at runtime:
# doing so would let modified source authorize itself.  Focused provider-free
# tests patch this value with their separately calculated fixture pin.
_ACCEPTED_RELEASE_GUARD_SHA256 = "6a947453a851a2ed7997ec50baa9bf2b5c879fdddb6ca4f043f61f94f01025bd"
_PATH_FIELDS = frozenset({"release_root", "codex_executable", "codex_home", "home_directory"})
_DIGEST_DEPTH_LIMIT = 48
# 2048 bits renders as at most 617 decimal digits, below the smallest ceiling
# sys.set_int_max_str_digits accepts, so a passed-through integer can never
# reach the interpreter digit limit whatever the process has configured.
_DIGEST_INT_BIT_LIMIT = 2048
_UNRENDERABLE = "$unrenderable"
_SLOT_DESCRIPTOR = type(rv.FrozenValue.__dict__["_canonical_text"])
# Content-bound container shapes that carry neither __dict__ nor __slots__, so
# binding them by identity alone would leave in-place mutation of a retained
# original invisible. Each entry is re-iterable: a one-shot iterator is never
# walked, because consuming it would destroy the custody it is meant to bind.
_ORDERED_CONTAINERS = (collections.deque, array.array,
                       type({}.keys()), type({}.values()), type({}.items()),
                       type(collections.OrderedDict().keys()),
                       type(collections.OrderedDict().values()),
                       type(collections.OrderedDict().items()))
_UNORDERED_CONTAINERS = (set, frozenset)
_BUFFER_CONTAINERS = (bytes, bytearray, memoryview)
_MAPPING_PROXY = types.MappingProxyType
# Plain builtin shapes can never be an opaque source-owned physical result,
# whatever module a subclass declares itself in.
_PLAIN_TYPES = (dict, list, tuple, set, frozenset, str, bytes, bytearray,
                int, float, complex, bool, type(None))
_DEGRADED_CAPTURE = rv.freeze({"$type": "unavailable", "capture": "post_effect"})


def _refuse(reason: str) -> None:
    raise values.LifecycleContractError("release_execution:" + reason)


def _text(value) -> str:
    """Render one value as text without ever letting a hostile __str__ escape."""
    try:
        rendered = str(value)
    except BaseException:
        return _UNRENDERABLE
    return rendered if type(rendered) is str else _UNRENDERABLE


def _attribute(item, name, default=None):
    """Read one attribute without ever letting a hostile lookup escape."""
    try:
        return getattr(item, name, default)
    except BaseException:
        return default


def _bounded_int(item: int):
    """Render one integer so canonical JSON can never hit the digit ceiling."""
    width = item.bit_length()
    if width <= _DIGEST_INT_BIT_LIMIT:
        return item
    return {"$type": "int", "bit_length": width, "value_sha256": hashlib.sha256(
        item.to_bytes((width // 8) + 2, "big", signed=True)).hexdigest()}


def _key(key) -> str:
    """Render one mapping key as text, preserving oversized integer content."""
    if type(key) is str:
        return key
    if type(key) is int and key.bit_length() > _DIGEST_INT_BIT_LIMIT:
        return "$int:" + hashlib.sha256(
            key.to_bytes((key.bit_length() // 8) + 2, "big", signed=True)).hexdigest()
    return _text(key)


def _order_key(rendered) -> tuple:
    """Total, deterministic sort key for one already-rendered element.

    An unordered container has no stable iteration order, so binding it in
    iteration order would make the digest differ between runs of the same
    unmutated object and strand a completed release. Ordering by the element's
    own canonical text is stable across runs, and comparing only strings can
    never invoke a hostile __lt__ or fail on mutually unorderable elements.
    The second component only separates elements whose canonical text could
    not be computed; equal first components already render identically.
    """
    try:
        return (values.canonical_json(rendered), "")
    except BaseException:
        return (_UNRENDERABLE, _text(rendered))


def _buffer_content(item) -> dict:
    """Bind the exact bytes of a buffer, total and without trusting __bytes__.

    The C buffer protocol is read through memoryview because a subclass can
    override __bytes__ to report content it does not hold, and a released or
    non-contiguous buffer must degrade to a marker rather than erase the
    surrounding node.
    """
    for read in (lambda: memoryview(item).tobytes(), lambda: bytes(item)):
        try:
            data = read()
        except BaseException:
            continue
        if type(data) is not bytes:
            continue
        return {"length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    return {"length": _UNRENDERABLE, "sha256": _UNRENDERABLE}


def _state(item) -> dict:
    """Instance state of one opaque original, without invoking any property.

    The contract retains a source-owned physical result object rather than a
    mapping, so binding only its identity would leave post-issue mutation of
    that object undetectable. Instance __dict__ entries and declared slots are
    read directly, which covers real instance state while never triggering a
    computed property, __getattr__ fallback, or descriptor the original did
    not already store.
    """
    fields = {}
    try:
        mapping = object.__getattribute__(item, "__dict__")
    except BaseException:
        mapping = None
    if type(mapping) is dict:
        try:
            fields.update(mapping)
        except BaseException:
            return {"$state": _UNRENDERABLE}
    try:
        owners = type(item).__mro__
    except BaseException:
        return fields
    for owner in owners:
        try:
            names = owner.__dict__.get("__slots__", ())
            names = (names,) if type(names) is str else tuple(names)
        except BaseException:
            continue
        for name in names:
            descriptor = owner.__dict__.get(name)
            if type(descriptor) is not _SLOT_DESCRIPTOR:
                continue
            try:
                fields[name] = descriptor.__get__(item, owner)
            except BaseException:
                fields[name] = _UNRENDERABLE
    return fields


def _digest(value) -> str:
    """Bounded, cycle-safe content fingerprint of one retained original.

    Fingerprinting must never raise, for any input, at any call site. The
    original release return or terminal failure stays in custody even when it
    is cyclic, deeply nested, carries a non-finite float or an integer past
    the interpreter digit ceiling, renders itself with a hostile __str__, or
    exposes hostile attribute lookup. Degradation is per node, so one hostile
    field reduces only itself to a stable same-process marker while every
    sibling stays bound by content, and no degraded rendering grants a fact.
    """
    def named(item) -> str:
        return _text(_attribute(type(item), "__module__")) + "." + _text(
            _attribute(type(item), "__qualname__"))

    def state_of(item, depth, nested):
        return {_key(key): plain(child, depth + 1, nested)
                for key, child in _state(item).items()}

    def render(item, depth, seen):
        if item is None or type(item) is bool or type(item) is str:
            return item
        if type(item) is int:
            return _bounded_int(item)
        if type(item) is float:
            return item if math.isfinite(item) else {"$type": "float", "value": repr(item)}
        if type(item) is rv.FrozenValue:
            return {"$type": "FrozenValue", "digest": item.digest()}
        if isinstance(item, Path):
            return {"$type": "Path", "value": _text(item)}
        if isinstance(item, BaseException):
            return {"$type": named(item), "message_sha256": hashlib.sha256(
                _text(item).encode("utf-8", errors="replace")).hexdigest()}
        marker = id(item)
        if depth >= _DIGEST_DEPTH_LIMIT or marker in seen:
            return {"$type": "bounded", "identity": marker}
        nested = seen | {marker}
        if isinstance(item, dict):
            body = {_key(key): plain(child, depth + 1, nested) for key, child in item.items()}
            return body if type(item) is dict else {
                "$type": named(item), "identity": marker, "items": body,
                "state": state_of(item, depth, nested)}
        if isinstance(item, (list, tuple)):
            body = [plain(child, depth + 1, nested) for child in item]
            return body if type(item) in (list, tuple) else {
                "$type": named(item), "identity": marker, "items": body,
                "state": state_of(item, depth, nested)}
        if isinstance(item, _BUFFER_CONTAINERS):
            body = _buffer_content(item)
            return body if type(item) in _BUFFER_CONTAINERS else {
                "$type": named(item), "identity": marker, "buffer": body,
                "state": state_of(item, depth, nested)}
        if isinstance(item, range):
            # A range is immutable and can describe more elements than could
            # ever be walked, so bind its three defining integers directly.
            return {"$type": "range", "start": _bounded_int(item.start),
                    "stop": _bounded_int(item.stop), "step": _bounded_int(item.step)}
        if isinstance(item, _MAPPING_PROXY):
            return {"$type": "mappingproxy",
                    "items": {_key(key): plain(child, depth + 1, nested)
                              for key, child in item.items()}}
        if isinstance(item, _UNORDERED_CONTAINERS):
            body = sorted((plain(child, depth + 1, nested) for child in item),
                          key=_order_key)
            return ({"$type": "set" if type(item) is set else "frozenset",
                     "items": body} if type(item) in _UNORDERED_CONTAINERS else {
                "$type": named(item), "identity": marker, "items": body,
                "state": state_of(item, depth, nested)})
        if isinstance(item, _ORDERED_CONTAINERS):
            body = [plain(child, depth + 1, nested) for child in item]
            typecode = _attribute(item, "typecode")
            return ({"$type": named(item), "items": body,
                     "typecode": typecode if type(typecode) is str else None}
                    if type(item) in _ORDERED_CONTAINERS else {
                "$type": named(item), "identity": marker, "items": body,
                "typecode": typecode if type(typecode) is str else None,
                "state": state_of(item, depth, nested)})
        return {"$type": named(item), "identity": marker,
                "state": state_of(item, depth, nested)}

    def plain(item, depth, seen):
        try:
            return render(item, depth, seen)
        except BaseException:
            return {"$type": "unreadable", "identity": id(item)}

    rendered = plain(value, 0, frozenset())
    try:
        return values.canonical_digest(rendered)
    except BaseException:
        # Total last resort, hashed directly so no encoder can be reached.
        return hashlib.sha256(
            ("release_execution:undigestable:%d" % id(value)).encode("ascii")).hexdigest()


def _action_fingerprint(inputs) -> tuple:
    report = _attribute(inputs, "report")
    return (id(inputs), None if type(report) is not rv.FrozenValue else report.digest(),
        id(_attribute(inputs, "evidence")), id(_attribute(inputs, "sources")),
        id(_attribute(inputs, "registry_components")), id(_attribute(inputs, "host_runs")),
        id(_attribute(inputs, "consumption_anchor")),
        _text(_attribute(inputs, "original_root", "")),
        _text(_attribute(inputs, "candidate_root", "")))


@dataclass(frozen=True, init=False)
class ReleaseExecution:
    """Opaque original release return or terminal failure retained in one PID."""

    action_inputs: action_authority.ReleaseActionInputs
    claim: action_authority.ReleaseInstallClaim
    paths: rv.FrozenValue
    invocation: rv.FrozenValue
    original_result: object
    original_failure: BaseException | None
    source_before: rv.FrozenValue
    source_after: rv.FrozenValue
    runtime_before: rv.FrozenValue
    runtime_after: rv.FrozenValue
    candidate_binding: rv.FrozenValue
    physical_context: rv.FrozenValue

    def __init__(self, authority, **fields):
        if authority is not _AUTHORITY:
            _refuse("factory_required")
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, fields[name])


def _fingerprint(execution: ReleaseExecution) -> tuple:
    fields = {}
    for name in ReleaseExecution.__dataclass_fields__:
        try:
            fields[name] = getattr(execution, name)
        except AttributeError:
            _refuse("issued_object_binding")
    frozen = (fields["paths"], fields["invocation"], fields["source_before"],
              fields["source_after"], fields["runtime_before"], fields["runtime_after"],
              fields["candidate_binding"], fields["physical_context"])
    if any(type(value) is not rv.FrozenValue for value in frozen):
        _refuse("issued_object_binding")
    original = fields["original_result"]
    if type(original) is release_marketplace.ReleasePhysicalResult:
        # The physical result retains a claim whose action inputs retain the
        # deliberately mutable consumption anchor.  Recording the terminal
        # outcome advances that anchor.  Bind every physical result field
        # directly while stopping at the claim's immutable identity and
        # receipt, so the execution survives its own durable transition.
        claim = _attribute(original, "claim")
        cleanups = _attribute(original, "cleanup_observations", ())
        original_fingerprint = (
            id(original), id(claim),
            (claim.receipt.digest()
             if type(claim) is action_authority.ReleaseInstallClaim else None),
            id(_attribute(original, "report")),
            _digest(_attribute(original, "report")),
            _digest(_attribute(original, "context")),
            _digest(_attribute(original, "physical_observation")),
            id(_attribute(original, "release_host_check")),
            _digest(_attribute(original, "release_host_check")),
            id(_attribute(original, "marketplace_build")),
            _digest(_attribute(original, "marketplace_build")),
            id(_attribute(original, "installation")),
            _digest(_attribute(original, "installation")),
            (tuple((id(row), _digest(row)) for row in cleanups)
             if type(cleanups) is tuple else _UNRENDERABLE),
        )
    else:
        original_fingerprint = (id(original), _digest(original))
    return (_action_fingerprint(fields["action_inputs"]), id(fields["claim"]),
        fields["claim"].receipt.digest() if type(fields["claim"])
        is action_authority.ReleaseInstallClaim else None,
        tuple(value.digest() for value in frozen), original_fingerprint,
        id(fields["original_failure"]),
        _digest(fields["original_failure"]))


def _issue(execution: ReleaseExecution) -> ReleaseExecution:
    identity = id(execution)
    _ISSUED[identity] = (weakref.ref(execution, lambda _: _ISSUED.pop(identity, None)),
                         os.getpid(), _fingerprint(execution), execution.claim)
    return execution


def _terminalize_issued_rejection(record, execution, error) -> None:
    """Spend the original claim when its issued execution has been altered.

    ``ReleaseExecution`` objects are created only after the physical entrypoint
    returns.  When the original object in this process no longer matches its
    issuance fingerprint, use the claim retained at issuance time rather than
    the mutable field on the rejected object.  A copied, forged, or forked
    object has no such matching issuance record and cannot terminalize another
    execution's claim.
    """

    if (type(execution) is not ReleaseExecution or record is None
            or record[0]() is not execution or record[1] != os.getpid()):
        return
    _record_terminal_failure(record[3], error)


def _issued(execution) -> None:
    record = _ISSUED.get(id(execution))
    if (type(execution) is not ReleaseExecution or record is None
            or record[0]() is not execution or record[1] != os.getpid()):
        _refuse("issued_object_binding")
    try:
        valid = record[2] == _fingerprint(execution)
    except BaseException as error:
        _terminalize_issued_rejection(record, execution, error)
        raise
    if not valid:
        error = values.LifecycleContractError("release_execution:issued_object_binding")
        _terminalize_issued_rejection(record, execution, error)
        raise error


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_ISSUED.clear)


def _verify_sources() -> dict:
    pins = {}
    for module in _LOCAL_MODULES:
        path = Path(module.__file__).resolve(strict=True)
        try:
            relative = path.relative_to(_ROOT).as_posix()
        except ValueError:
            _refuse("source_origin")
        expected = _SOURCE_PINS.get(path)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if expected is None or actual != expected:
            _refuse("source_drift")
        pins[relative] = actual
    if (release_marketplace.release_and_install_physical is not _RELEASE_ENTRYPOINT
            or getattr(_RELEASE_ENTRYPOINT, "__module__", None) != release_marketplace.__name__):
        _refuse("release_entrypoint")
    if (getattr(release_marketplace, "validate_release_physical_result", None)
            is not _PHYSICAL_VALIDATOR
            or getattr(_PHYSICAL_VALIDATOR, "__module__", None)
            != release_marketplace.__name__):
        _refuse("physical_validator_drift")
    return pins


def _release_guard_sha256() -> str:
    """Hash the reviewed dependency set without making it self-authorizing."""

    rows = {}
    paths = [Path(module.__file__).resolve(strict=True) for module in _LOCAL_MODULES]
    paths.append(_ACTION_HOST_CALLER_PATH.resolve(strict=True))
    for path in paths:
        try:
            relative = path.relative_to(_ROOT).as_posix()
        except ValueError:
            _refuse("source_origin")
        rows[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values.canonical_digest(rows)


def _source_inventory(root: Path) -> rv.FrozenValue:
    rows = {}
    for directory, names, files in os.walk(root):
        names[:] = sorted(name for name in names if name not in (".git", "__pycache__"))
        for name in names:
            if (Path(directory) / name).is_symlink():
                _refuse("source_symlink")
        for name in sorted(files):
            if name.endswith(".pyc"):
                continue
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or path.is_symlink():
                _refuse("source_file")
            data = path.read_bytes()
            rows[path.relative_to(root).as_posix()] = {
                "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                "mode": stat.S_IMODE(info.st_mode)}
    if not rows:
        _refuse("source_empty")
    return rv.freeze({"entries": rows, "inventory_sha256": values.canonical_digest(rows)})


def _runtime_identity(root: Path) -> rv.FrozenValue:
    entries, version, _manifest = runtime_package._projectable_source_entries(
        root, runtime_package.RUNTIME_ALLOWLIST)
    hashes = {row["path"]: row["sha256"] for row in entries}
    package = runtime_package._report(version, entries)
    return rv.freeze({"version": version, "entry_hashes": hashes,
        "runtime_inventory_sha256": values.canonical_digest(hashes),
        "package_digest": package["package_digest"]})


def _retained(capture, root: Path) -> rv.FrozenValue:
    """Capture post-effect state without ever destroying the retained original.

    A concurrently vanished, unreadable, or replaced source tree must not turn
    a completed release into a lost original. The fixed degraded marker can
    never equal a real inventory, so source_unchanged stays false and no
    physical fact is granted.
    """
    try:
        return capture(root)
    except BaseException:
        return _DEGRADED_CAPTURE


def _candidate_binding(inputs) -> rv.FrozenValue:
    evidence = _attribute(inputs, "evidence")
    components = evidence.get("components", ()) if type(evidence) is dict else ()
    if type(components) not in (list, tuple):
        return rv.freeze({"status": "UNAVAILABLE_MECHANICAL"})
    rows = [row for row in components if type(row) is dict
            and row.get("kind") == "candidate_identity_transition"]
    if len(rows) != 1:
        return rv.freeze({"status": "UNAVAILABLE_MECHANICAL"})
    row = rows[0]
    return rv.freeze({"status": "CAPTURED", "case_id": _key(row.get("case_id")),
        "material_sha256": _digest(row.get("material")),
        "originals_sha256": _digest(row.get("originals"))})


def _candidate_transition(inputs) -> rv.FrozenValue:
    """Return the exact cachebuster transition retained by action authority."""

    evidence = _attribute(inputs, "evidence")
    components = evidence.get("components", ()) if type(evidence) is dict else ()
    rows = [row for row in components if type(row) is dict
            and row.get("kind") == "candidate_identity_transition"]
    if len(rows) != 1 or type(rows[0].get("originals")) is not dict:
        _refuse("candidate_transition")
    transition = rows[0]["originals"].get("report")
    if type(transition) is not rv.FrozenValue:
        _refuse("candidate_transition")
    return transition


def _original_action_inputs(inputs) -> None:
    """Require the exact action inputs issued by prepare_release_action."""
    try:
        action_authority._issued(inputs)
    except BaseException:
        _refuse("action_inputs_binding")


def _fixed_paths(inputs, supplied) -> tuple[dict, Path]:
    if type(inputs) is not action_authority.ReleaseActionInputs:
        _refuse("action_inputs_type")
    _original_action_inputs(inputs)
    if type(supplied) is not dict or set(supplied) != _PATH_FIELDS:
        _refuse("paths_shape")
    try:
        original = Path(inputs.original_root)
        candidate_raw = Path(inputs.candidate_root)
        original_resolved = original.resolve(strict=True)
        candidate = candidate_raw.resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError):
        _refuse("candidate_root")
    if (original.is_symlink() or original_resolved != _ROOT or not original_resolved.is_dir()):
        _refuse("original_root_binding")
    if (candidate_raw.is_symlink() or not candidate.is_dir()
            or candidate == _ROOT or candidate == original_resolved):
        _refuse("candidate_origin")
    paths = {}
    for name in sorted(_PATH_FIELDS):
        value = supplied[name]
        if not isinstance(value, (str, os.PathLike)):
            _refuse("path:" + name)
        raw = os.fspath(value)
        if type(raw) is not str or not raw or "\x00" in raw:
            _refuse("path:" + name)
        path = Path(raw)
        if not path.is_absolute() or path.is_symlink():
            _refuse("path:" + name)
        paths[name] = str(path)
    release_root = Path(paths["release_root"])
    executable = Path(paths["codex_executable"])
    if (release_root.exists() or release_root == candidate or release_root == original_resolved
            or not executable.is_file() or not os.access(executable, os.X_OK)):
        _refuse("fixed_path_state")
    for name in ("codex_home", "home_directory"):
        if not Path(paths[name]).is_dir():
            _refuse("fixed_path_state")
    return paths, candidate


def _fixed_health(inputs) -> dict:
    report = _attribute(inputs, "report")
    if type(report) is not rv.FrozenValue:
        _refuse("completion_report")
    data = report.to_plain()
    if type(data) is not dict:
        _refuse("completion_report")
    facts = data.get("facts")
    if type(facts) not in (list, tuple):
        _refuse("completion_not_release_ready")
    if (data.get("status") != "PASS" or data.get("campaign_authorized") is not True
            or data.get("release_authorized") is not True
            or "full_suite_same_runtime" not in facts):
        _refuse("completion_not_release_ready")
    return {"status": "PASS", "checks": ["full-tests"],
            "runtime": {"name": "python3", "status": "PASS"}}


def _physical_context(
    candidate: Path,
    source_before: rv.FrozenValue,
    runtime_before: rv.FrozenValue,
    transition: rv.FrozenValue,
) -> rv.FrozenValue:
    source = source_before.to_plain()
    runtime = runtime_before.to_plain()
    if type(source) is not dict or type(runtime) is not dict:
        _refuse("physical_context")
    return rv.freeze(
        {
            "schema": release_marketplace.PHYSICAL_CONTEXT_SCHEMA,
            "candidate_root": str(candidate),
            "source_inventory_sha256": source["inventory_sha256"],
            "runtime_package_sha256": runtime["package_digest"],
            "candidate_transition_sha256": transition.digest(),
        }
    )


def _record_terminal_failure(claim, error: BaseException) -> None:
    """Persist one spent failed claim without ever reopening its operation slots."""

    record = action_authority._operation_record(claim)
    if record.get("outcome_recorded") is True:
        return
    if record["state"] in {"HOST_READY", "COMPLETE"}:
        action_authority._fail_release_install_terminal_validation(claim, error)
    action_authority.record_release_install_failure(claim, error)


def execute_release(original_action_inputs, fixed_release_paths) -> ReleaseExecution:
    """Claim once, run the fixed physical entrypoint once, and retain custody."""

    source_pins = _verify_sources()
    paths, candidate = _fixed_paths(original_action_inputs, fixed_release_paths)
    health = _fixed_health(original_action_inputs)
    if (_ACCEPTED_RELEASE_GUARD_SHA256 is None
            or _release_guard_sha256() != _ACCEPTED_RELEASE_GUARD_SHA256):
        _refuse("release_guard_dependency_pending")
    before = _source_inventory(candidate)
    runtime_before = _runtime_identity(candidate)
    candidate_binding = _candidate_binding(original_action_inputs)
    transition = _candidate_transition(original_action_inputs)
    context = _physical_context(candidate, before, runtime_before, transition)
    invocation = rv.freeze({"candidate_root": str(candidate), "paths": paths,
        "source_pins": source_pins, "source_before_sha256": before.digest(),
        "runtime_before_sha256": runtime_before.digest(),
        "candidate_binding_sha256": candidate_binding.digest(),
        "physical_context_sha256": context.digest(),
        "action_fingerprint_sha256": _digest(_action_fingerprint(original_action_inputs)),
        "health_source": "validated original completion facts", "retry_permitted": False})
    claim = action_authority.claim_release_install(
        original_action_inputs,
        source_root=candidate,
        release_root=paths["release_root"],
    )
    original = failure = None
    try:
        original = _RELEASE_ENTRYPOINT(
            candidate,
            paths["release_root"],
            health_evidence=health,
            codex_executable=paths["codex_executable"],
            codex_home=paths["codex_home"],
            home_directory=paths["home_directory"],
            action_claim=claim,
            physical_context=context,
        )
    except BaseException as error:
        failure = error
    # Post-effect captures are total by design: custody of the original is
    # retained even if the candidate tree becomes unreadable after the effect.
    after = _retained(_source_inventory, candidate)
    runtime_after = _retained(_runtime_identity, candidate)
    execution = _issue(ReleaseExecution(
        _AUTHORITY,
        action_inputs=original_action_inputs,
        claim=claim,
        paths=rv.freeze(paths),
        invocation=invocation,
        original_result=original,
        original_failure=failure,
        source_before=before,
        source_after=after,
        runtime_before=runtime_before,
        runtime_after=runtime_after,
        candidate_binding=candidate_binding,
        physical_context=context,
    ))
    if failure is not None:
        _record_terminal_failure(claim, failure)
        return execution
    try:
        _validate_durable_release_execution(execution, claim)
    except BaseException as error:
        _record_terminal_failure(claim, error)
    return execution


def _physical_validation(execution: ReleaseExecution, *, strict: bool = False):
    original = execution.original_result
    current = getattr(release_marketplace, "validate_release_physical_result", None)
    if current is not _PHYSICAL_VALIDATOR:
        _refuse("physical_validator_drift")
    if (original is None or isinstance(original, _PLAIN_TYPES)
            or type(original) is not release_marketplace.ReleasePhysicalResult):
        return None
    try:
        checked = _PHYSICAL_VALIDATOR(original)
    except values.LifecycleContractError:
        if strict:
            raise
        return None
    except BaseException:
        if strict:
            _refuse("physical_validation")
        return None
    if type(checked) is not dict:
        if strict:
            _refuse("physical_validation")
        return None
    required = {"valid", "facts", "report_sha256", "source_inventory_sha256",
                "runtime_package_sha256", "candidate_transition_sha256",
                "release_host_sha256", "build_sha256", "install_sha256",
                "cache_inventory_sha256", "mcp_observation_sha256", "cleanup_sha256"}
    context = execution.physical_context.to_plain()
    valid = (
        set(checked) == required
        and checked["valid"] is True
        and checked["facts"] == ["release_host_consumed", "install_parity_mcp_consumed"]
        and checked["source_inventory_sha256"] == context["source_inventory_sha256"]
        and checked["runtime_package_sha256"] == context["runtime_package_sha256"]
        and checked["candidate_transition_sha256"] == context["candidate_transition_sha256"]
        and all(type(checked[name]) is str and len(checked[name]) == 64
                for name in required if name.endswith("_sha256"))
    )
    if not valid:
        if strict:
            _refuse("physical_validation")
        return None
    return checked


def release_report(execution) -> rv.FrozenValue:
    """Revalidate retained originals and expose a non-authoritative diagnostic."""

    _issued(execution)
    source_pins = _verify_sources()
    try:
        candidate = Path(execution.action_inputs.candidate_root).resolve(strict=True)
        current = _source_inventory(candidate)
        current_runtime = _runtime_identity(candidate)
    except BaseException:
        current = current_runtime = _DEGRADED_CAPTURE
    unchanged = (execution.source_before == execution.source_after == current
                 and execution.runtime_before == execution.runtime_after == current_runtime)
    degraded = (execution.source_after == _DEGRADED_CAPTURE
                or execution.runtime_after == _DEGRADED_CAPTURE
                or current == _DEGRADED_CAPTURE or current_runtime == _DEGRADED_CAPTURE)
    operation = action_authority._operation_record(execution.claim)
    terminal_failure = operation.get("state") == "FAILED"
    checked = (_physical_validation(execution)
               if execution.original_failure is None and not terminal_failure else None)
    physical = checked is not None and unchanged
    status = ("PASS" if physical else "FAILED"
              if execution.original_failure is not None or terminal_failure
              else "BLOCKED_PHYSICAL_ORIGINAL_REQUIRED")
    body = {"schema": REPORT_SCHEMA, "status": status,
        "physical_execution_validated": physical,
        "facts": checked["facts"] if physical else [],
        "source_unchanged": unchanged,
        "post_effect_capture": "DEGRADED" if degraded else "COMPLETE",
        "source_inventory_sha256": current.digest(),
        "runtime_inventory_sha256": current_runtime.digest(),
        "candidate_binding_sha256": execution.candidate_binding.digest(),
        "physical_context_sha256": execution.physical_context.digest(),
        "runtime_source_pins": source_pins,
        "action_inputs_sha256": _digest(_action_fingerprint(execution.action_inputs)),
        "fixed_paths_sha256": execution.paths.digest(),
        "invocation_sha256": execution.invocation.digest(),
        "original_result_type": (None if execution.original_result is None else
            _text(_attribute(type(execution.original_result), "__module__")) + "." +
            _text(_attribute(type(execution.original_result), "__qualname__"))),
        "original_result_sha256": _digest(execution.original_result),
        "failure_type": (None if execution.original_failure is None else
            _text(_attribute(type(execution.original_failure), "__module__")) + "." +
            _text(_attribute(type(execution.original_failure), "__qualname__"))),
        "failure_sha256": _digest(execution.original_failure),
        "physical_validation": checked,
        "diagnostic_only": not physical, "release_authorized": False,
        "qualification_authorized": False, "promotion_authorized": False}
    body["report_sha256"] = values.canonical_digest(body)
    return rv.freeze(body)


def _validate_durable_release_execution(execution, claim):
    """Authority-only reader used by action_authority before durable success."""

    _issued(execution)
    _verify_sources()
    if (type(claim) is not action_authority.ReleaseInstallClaim
            or execution.claim is not claim
            or execution.action_inputs is not claim.inputs
            or execution.original_failure is not None):
        _refuse("durable_reader_binding")
    action_authority._issued(claim)
    checked = _physical_validation(execution, strict=True)
    if checked is None:
        _refuse("physical_validation")
    candidate = Path(claim.inputs.candidate_root).resolve(strict=True)
    current = _source_inventory(candidate)
    current_runtime = _runtime_identity(candidate)
    if not (execution.source_before == execution.source_after == current
            and execution.runtime_before == execution.runtime_after == current_runtime):
        _refuse("candidate_changed_after_effect")
    return execution.original_result


def finalize_release(execution):
    """Write the sole successful durable outcome after physical validation."""

    _issued(execution)
    return action_authority.record_release_install_success(execution.claim, execution)


def completion_facts(execution) -> tuple[str, ...]:
    """Return exact physical facts only after the opaque-original validator."""
    report = release_report(execution).to_plain()
    return tuple(report["facts"]) if report["physical_execution_validated"] else ()


__all__ = ["REPORT_SCHEMA", "ReleaseExecution", "execute_release",
           "finalize_release", "release_report", "completion_facts"]
