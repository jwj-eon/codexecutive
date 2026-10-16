"""Bounded Issue 170 custody for the manifest-selected release profiles.

The Linux supervisor is a separate subreaper. Only that process owns/reaps
invocation descendants, including detached sessions. Test output is opaque:
a separate collection process and the fixed runner's private completion
channel supply collection/completion evidence. These are reviewed Python
tests, not a sandbox for hostile code that attacks its interpreter or kernel.
No persisted JSON, copied dataclass, or fork-inherited object grants custody.
"""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import shutil
import socket
import stat
import subprocess
import sys
import sysconfig
import tempfile
import time
from types import MappingProxyType
import unittest
import weakref

# -I -S excludes cwd, PYTHON*, site.py, .pth and startup customization. Load
# stdlib first, then add this exact package's scripts directory explicitly.
if __name__ == "__main__":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from lifecycle_conformance import reference_values as rv, values
import lifecycle_conformance as package_namespace
import orch_dork_runtime_package as runtime_package

INVOCATION_SCHEMA = "orch-dork/lifecycle-host-invocation/v2"
RESULT_SCHEMA = "orch-dork/lifecycle-host-result/v2"
READBACK_SCHEMA = "orch-dork/lifecycle-host-readback/v2"
TEST_SET_SCHEMA = "orch-dork/lifecycle-test-run-attestation/v2"
STDOUT_LIMIT = STDERR_LIMIT = CONTROL_LIMIT = 65_536
REPORT_LIMIT = 16 * 1024 * 1024
# No same-process release campaign may exceed the release tier's aggregate
# ceiling. Manifest groups partition across four concurrently started profiles;
# each profile is independently capped below this shared campaign deadline.
MAX_TIMEOUT_SECONDS = 1_800
TEST_TIER_MANIFEST_SCHEMA = "orch-dork/test-tier-manifest/v2"
TEST_TIER_MANIFEST_PATH = ".github/test-tiers.json"
_MANIFEST_NAME_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_CLEANUP_SECONDS = 3.0
_AUTHORITY = object()
_ISSUED = {}
_RUNNER = Path(__file__).resolve()
_LOADED_RUNNER_SHA = hashlib.sha256(_RUNNER.read_bytes()).hexdigest()


def _loaded_origin(module):
    """Derive one dependency's reader origin from its own loaded state.

    A package supplies executable submodules from the head of its __path__,
    which is not always the directory holding the initializer that bound the
    name. Bare `discover -s tests` binds this package name to the test-tree
    initializer, whose only act is to insert the library directory at that
    head; the bounded child imports the library directly. Resolving the
    initializer that __path__ actually selects makes the reader identity the
    same file in both processes and independent of ambient import order.
    """
    located = getattr(module, "__path__", None)
    if located:
        return Path(located[0]).resolve() / "__init__.py"
    return Path(module.__file__).resolve()


_LOCAL_MODULES = (package_namespace, rv, values, runtime_package)
_LOADED_LOCAL = {_loaded_origin(m): hashlib.sha256(
    _loaded_origin(m).read_bytes()).hexdigest() for m in _LOCAL_MODULES}


_CUSTODY_FACTS = ("host_attestation_valid", "runtime_identity_attested",
                 "source_custody_complete", "output_custody_complete",
                 "exit_custody_complete", "cleanup_custody_complete")
_PERSISTENCE = "process_local_witness_required_through_gate_and_candidate_claim"

# -B disables writes only. Install source-only loaders from frozen importlib
# before importing even this runner's dependencies, so excluded caches cannot
# supply executable bytes. Keep this fixed bootstrap in the bound argv.
_SOURCE_BOOTSTRAP = """import sys
import _frozen_importlib_external as loaders
def source_code(self, fullname):
    path = self.get_filename(fullname)
    return self.source_to_code(self.get_data(path), path)
def refuse_bytecode(self, fullname):
    raise ImportError('host_attestation:source_only_import:' + fullname)
loaders.SourceFileLoader.get_code = source_code
loaders.SourcelessFileLoader.get_code = refuse_bytecode
del sys.argv[0]
__file__ = sys.argv[0]
with open(__file__, 'rb') as source:
    code = compile(source.read(), __file__, 'exec')
exec(code)
"""


@dataclass(frozen=True)
class _Profile:
    skip_reasons: tuple[str, ...] = ()
    skip_prefixes: tuple[str, ...] = ()


# Actual capability exclusions remain named, bounded and visible. They cannot
# contribute execution credit for a skipped case to the production reader.
_CAPABILITY_SKIPS = (
    "Linux process profile", "Linux peer/process profile",
    "Linux Python 3.12 native fixture", "Linux Python 3.12 host fixture",
    "Python 3.12 monitoring", "Python 3.12 monitoring fixture",
    "POSIX worker process groups", "POSIX replay pool",
)
HOST_ATTESTATION_PROFILE_ENV = "ORCH_DORK_HOST_ATTESTATION_PROFILE"
NESTED_STAGE_L_SKIP_REASON = "Stage L host campaign already active"
_PROFILES = MappingProxyType({
    "campaign": _Profile(_CAPABILITY_SKIPS + (NESTED_STAGE_L_SKIP_REASON,)),
    "focused": _Profile(),
    "rehearsal": _Profile(),
    "full_suite": _Profile(_CAPABILITY_SKIPS + (
        "real Codex CLI is unavailable", "real Codex executable unavailable",
        "contained host capture is not available",
        "host-local v6 campaign ledger is not present", "no recorded campaigns",
        "no recorded campaigns on this host", "not every recorded campaign is present",
        "v6 ledger absent", "successor ledger absent",
        "model-coordinate checkout is not present on this host",
        "Issue 33 preserved plan artifact is not present on this host",
        "bwrap not installed",
    ), ("bwrap run not permitted on this host: ",)),
})


@dataclass(frozen=True)
class FreshWitness:
    artifact_root: str
    device: int
    inode: int
    invocation_id: str
    result_file_sha256: str
    _authority: object


@dataclass(frozen=True)
class HostRun:
    artifact_root: Path
    witness: FreshWitness


@dataclass(frozen=True)
class ValidatedAttestation:
    report: rv.FrozenValue
    _authority: object


def _require(condition, reason):
    if condition is not True:
        raise values.LifecycleContractError("host_attestation:" + reason)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _fingerprint(value):
    if type(value) is FreshWitness:
        return (value.artifact_root, value.device, value.inode, value.invocation_id,
                value.result_file_sha256, id(value._authority))
    if type(value) is ValidatedAttestation:
        return (value.report.digest(), id(value._authority))
    return None


def _issue(value):
    identity = id(value)
    _ISSUED[identity] = (weakref.ref(value, lambda _: _ISSUED.pop(identity, None)),
                         os.getpid(), _fingerprint(value))
    return value


def _issued(value):
    record = _ISSUED.get(id(value))
    _require(record is not None and record[0]() is value
             and record[1] == os.getpid() and record[2] == _fingerprint(value),
             "issued_object_binding")


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_ISSUED.clear)


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique,
                          parse_constant=lambda _: _require(False, "json_constant"))
    except (UnicodeError, ValueError) as exc:
        raise values.LifecycleContractError("host_attestation:original_json") from exc


def _equal(left, right):
    return rv.freeze(left) == rv.freeze(right)


def _write_create_only(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _safe_root(path, label, *, must_exist):
    _require(isinstance(path, (str, os.PathLike)), label)
    raw = os.fspath(path)
    _require(type(raw) is str and bool(raw) and "\x00" not in raw, label)
    root = Path(raw).absolute()
    _require(root == root.resolve(), label + "_symlink_or_alias")
    _require(root.is_dir() if must_exist else not root.exists(),
             label + ("_missing" if must_exist else "_exists"))
    return root


def _source_generation(root):
    entries = {}
    for directory, names, files in os.walk(root):
        names[:] = sorted(n for n in names if n not in (".git", "__pycache__"))
        for name in names:
            _require(not (Path(directory) / name).is_symlink(), "source_directory_symlink")
        for name in sorted(files):
            if name == ".git" or name.endswith(".pyc"):
                continue
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            _require(stat.S_ISREG(info.st_mode), "source_not_regular:" + relative)
            data = path.read_bytes()
            entries[relative] = {"sha256": _sha(data), "bytes": len(data),
                                 "mode": stat.S_IMODE(info.st_mode)}
    _require(bool(entries), "source_empty")
    return {"entries": entries, "inventory_sha256": values.canonical_digest(entries),
            "entry_count": len(entries)}


def _private_source_generation(source_generation):
    """Project raw source identity onto the mode-safe private topology."""
    entries = {
        relative: {**entry, "mode": entry["mode"] & ~0o022}
        for relative, entry in source_generation["entries"].items()
    }
    return {"entries": entries, "inventory_sha256": values.canonical_digest(entries),
            "entry_count": len(entries)}


def _runtime_identity(root):
    entries, version, _ = runtime_package._projectable_source_entries(
        root, runtime_package.RUNTIME_ALLOWLIST)
    hashes = {entry["path"]: entry["sha256"] for entry in entries}
    return {"version_before_cachebuster": version,
            "manifest_sha256": hashes[runtime_package.MANIFEST_PATH],
            "runtime_entry_hashes": hashes,
            "runtime_inventory_sha256": values.canonical_digest(hashes),
            "package_digest_before_cachebuster": runtime_package._report(
                version, entries)["package_digest"]}


def _origin_in_source(actual, source):
    """Re-root one canonical reader origin onto the projected source tree.

    The anchor is derived from this runner's own loaded location, so the
    scripts directory is never restated as a literal. An origin outside that
    anchor is refused by name rather than mapped onto an unrelated file or
    escaping as an opaque ValueError.
    """
    anchor = _RUNNER.parents[1]
    _require(actual.is_relative_to(anchor), "dependency_origin_anchor")
    return source / "skills/orch-dork/scripts" / actual.relative_to(anchor)


def _reader_origins(source):
    """Bind loaded core reader origins; the source tree binds test dependencies."""
    scripts = source / "skills/orch-dork/scripts"
    _require(_sha(_RUNNER.read_bytes()) == _LOADED_RUNNER_SHA, "loaded_runner_drift")
    target = scripts / "lifecycle_conformance/host_attestation.py"
    _require(_sha(target.read_bytes()) == _LOADED_RUNNER_SHA, "runner_source_binding")
    local = {"lifecycle_conformance.host_attestation": {
        "path": str(target), "sha256": _LOADED_RUNNER_SHA}}
    for module in _LOCAL_MODULES:
        actual = _loaded_origin(module)
        _require(actual in _LOADED_LOCAL and _sha(actual.read_bytes()) == _LOADED_LOCAL[actual],
                 "loaded_dependency_drift")
        selected = _origin_in_source(actual, source)
        _require(selected.is_file(), "dependency_source_missing")
        _require(_sha(selected.read_bytes()) == _LOADED_LOCAL[actual], "dependency_source_binding")
        local[module.__name__] = {"path": str(selected), "sha256": _LOADED_LOCAL[actual]}
    stdlib = Path(sysconfig.get_path("stdlib")).resolve()
    standard = {}
    for module in (unittest, unittest.loader, unittest.runner, unittest.result,
                   unittest.case, unittest.suite, json, subprocess, socket, selectors):
        actual = Path(module.__file__).resolve()
        _require(actual.is_relative_to(stdlib)
                 and "site-packages" not in actual.parts and "dist-packages" not in actual.parts,
                 "stdlib_origin")
        standard[module.__name__] = {"path": str(actual), "sha256": _sha(actual.read_bytes())}
    python = Path(sys.executable).resolve(strict=True)
    return {"local": local, "stdlib": standard,
            "python": {"path": str(python), "sha256": _sha(python.read_bytes())}}


def _manifest_name(value):
    return (type(value) is str and bool(value) and len(value) <= 128
            and set(value) <= _MANIFEST_NAME_CHARACTERS
            and all(part for part in value.split("-")))


def _release_manifest(source):
    # This is intentionally an independent physical-boundary parser, not a
    # call into .github/scripts/run_tests.py. The release runner and the
    # attestation host must each reject malformed selection authority using
    # their own source-pinned reader; sharing the runner parser would make its
    # mutable import surface authoritative inside the Stage L process.
    path = source / TEST_TIER_MANIFEST_PATH
    _require(path.is_file() and not path.is_symlink()
             and path.resolve().is_relative_to(source), "release_manifest_path")
    raw = path.read_bytes()
    _require(len(raw) <= REPORT_LIMIT, "release_manifest_size")
    manifest = _json(raw)
    _require(type(manifest) is dict and set(manifest) == {"schema", "tiers"}
             and manifest["schema"] == TEST_TIER_MANIFEST_SCHEMA
             and type(manifest["tiers"]) is dict
             and "release" in manifest["tiers"], "release_manifest_schema")
    release = manifest["tiers"]["release"]
    _require(type(release) is dict and set(release) == {
        "aggregate_timeout_seconds", "groups", "action_host_profiles",
        "contracts", "downstream_gates",
    }, "release_manifest_fields")
    aggregate = release["aggregate_timeout_seconds"]
    _require(type(aggregate) is int and aggregate == MAX_TIMEOUT_SECONDS,
             "release_manifest_aggregate")
    groups = release["groups"]
    _require(type(groups) is list and bool(groups), "release_manifest_groups")
    by_name = {}
    targets = []
    for group in groups:
        _require(type(group) is dict and set(group) == {
            "name", "timeout_seconds", "tests",
        }, "release_manifest_group_shape")
        name, timeout, tests = group["name"], group["timeout_seconds"], group["tests"]
        _require(_manifest_name(name) and name not in by_name,
                 "release_manifest_group_name")
        _require(type(timeout) is int and 0 < timeout <= aggregate,
                 "release_manifest_group_timeout")
        _require(type(tests) is list and bool(tests)
                 and all(type(test) is str and bool(test) and len(test) <= 512
                         for test in tests)
                 and len(tests) == len(set(tests)), "release_manifest_group_tests")
        by_name[name] = {"tests": tuple(tests), "timeout_seconds": timeout}
        targets.extend(tests)
    for index, left in enumerate(targets):
        _require(not any(left == right or left.startswith(right + ".")
                         or right.startswith(left + ".")
                         for right in targets[index + 1:]),
                 "release_manifest_overlapping_tests")

    profiles = release["action_host_profiles"]
    _require(type(profiles) is dict and set(profiles) == set(_PROFILES),
             "release_manifest_profiles")
    assigned = []
    selected = {}
    for profile in _PROFILES:
        names = profiles[profile]
        _require(type(names) is list and bool(names)
                 and all(type(name) is str and name in by_name for name in names)
                 and len(names) == len(set(names)), "release_manifest_partition")
        timeout_seconds = sum(by_name[name]["timeout_seconds"] for name in names)
        _require(timeout_seconds <= aggregate,
                 "release_manifest_profile_timeout")
        assigned.extend(names)
        selected[profile] = {
            "groups": list(names),
            "tests": [test for name in names for test in by_name[name]["tests"]],
            "timeout_seconds": timeout_seconds,
        }
    _require(len(assigned) == len(set(assigned)) and set(assigned) == set(by_name),
             "release_manifest_partition")

    contracts = release["contracts"]
    _require(type(contracts) is list and bool(contracts), "release_manifest_contracts")
    represented = set()
    identities = set()
    for contract in contracts:
        _require(type(contract) is dict and set(contract) == {
            "id", "assertion", "groups", "tests",
        }, "release_manifest_contract_shape")
        identity = contract["id"]
        names = contract["groups"]
        tests = contract["tests"]
        _require(_manifest_name(identity) and identity not in identities
                 and type(contract["assertion"]) is str
                 and bool(contract["assertion"].strip())
                 and len(contract["assertion"]) <= 1_000
                 and type(names) is list and bool(names)
                 and all(type(name) is str and name in by_name for name in names)
                 and type(tests) is list and bool(tests)
                 and all(type(test) is str and bool(test) and len(test) <= 512
                         for test in tests),
                 "release_manifest_contract")
        contract_targets = [
            test for name in names for test in by_name[name]["tests"]
        ]
        _require(all(any(test == target or test.startswith(target + ".")
                         for target in contract_targets) for test in tests),
                 "release_manifest_contract_tests")
        identities.add(identity)
        represented.update(names)
    _require(represented == set(by_name), "release_manifest_contract_coverage")
    downstream = release["downstream_gates"]
    _require(type(downstream) is list, "release_manifest_downstream")
    downstream_identities = set()
    for gate in downstream:
        _require(type(gate) is dict and set(gate) == {
            "id", "assertion", "budget_seconds",
        }, "release_manifest_downstream")
        identity = gate["id"]
        _require(_manifest_name(identity) and identity not in downstream_identities
                 and type(gate["assertion"]) is str
                 and bool(gate["assertion"].strip())
                 and len(gate["assertion"]) <= 1_000
                 and type(gate["budget_seconds"]) is int
                 and 0 < gate["budget_seconds"] <= 86_400,
                 "release_manifest_downstream")
        downstream_identities.add(identity)
    return {"path": TEST_TIER_MANIFEST_PATH, "sha256": _sha(raw),
            "schema": TEST_TIER_MANIFEST_SCHEMA,
            "aggregate_timeout_seconds": aggregate, "profiles": selected}


def _profile_contract(source, profile):
    selected = _PROFILES[profile]
    manifest = _release_manifest(source)
    profile_selection = manifest["profiles"][profile]
    return {"test_targets": profile_selection["tests"],
            "release_groups": profile_selection["groups"],
            "timeout_seconds": profile_selection["timeout_seconds"],
            "release_manifest": {key: manifest[key] for key in (
                "path", "sha256", "schema", "aggregate_timeout_seconds")},
            "minimum_tests": 1,
            "collection_policy": "separate_loader_equal_execution_collection_and_completed_ids",
            "execution_topology": (
                "fresh_interpreter_private_source_owned_process_group_per_module"
            ),
            "skip_policy": {"maximum": 64, "exact_reasons": list(selected.skip_reasons),
                            "reason_prefixes": list(selected.skip_prefixes)}}


def _argv(source, profile, role, *args):
    return [str(Path(sys.executable).resolve()), "-I", "-S", "-B",
            "-c", _SOURCE_BOOTSTRAP,
            str(source / "skills/orch-dork/scripts/lifecycle_conformance/host_attestation.py"),
            role, profile, *map(str, args)]


def _children():
    # Kernel ABI path, assembled portably; no host-specific checkout or temp root.
    proc = Path(os.sep) / "proc" / str(os.getpid()) / "task"
    children = set()
    for thread in proc.iterdir():
        children.update(map(int, (thread / "children").read_text().split()))
    return sorted(children)


def _subreaper():
    _require(sys.platform.startswith("linux") and hasattr(os, "pidfd_open")
             and hasattr(signal, "pidfd_send_signal"), "containment_unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    _require(libc.prctl(36, 1, 0, 0, 0) == 0, "subreaper_unavailable")
    enabled = ctypes.c_int()
    _require(libc.prctl(37, ctypes.byref(enabled), 0, 0, 0) == 0
             and enabled.value == 1, "subreaper_unverified")
    _require(_children() == [], "supervisor_not_exclusive")


def _drain_owned():
    """Kill/reap only this dedicated subreaper's direct/adopted children.

    A child reparents here when its own parent EXITS, not when that parent is
    reaped, so a detached or double-forked child cannot escape by changing its
    session and no descendant is held by retaining its parent's corpse. PID
    reuse is excluded by the pidfd, which is opened before the signal is sent
    and therefore names one exact process for the lifetime of that send;
    retaining corpses would not add to it, and it costs an owned group's
    liveness signal because a corpse stays a member of its process group.
    Corpses are therefore reaped during the run by _reap_adopted_corpses, and
    this drain kills and reaps whatever remains once the runner has exited.
    """
    deadline = time.monotonic() + _CLEANUP_SECONDS
    leaked = False
    while time.monotonic() < deadline:
        children = _children()
        leaked = leaked or bool(children)
        for pid in children:
            try:
                fd = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(fd)
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
            except ChildProcessError:
                # ECHILD plus the kernel child inventory is the closure proof.
                return leaked, "observed_complete" if not _children() else "unknown"
        time.sleep(0.01)
    return leaked, "unknown"


def _reap_adopted_corpses(runner_pid):
    """Reap already-exited adopted children while the runner still runs.

    A child is reparented here when its own parent exits, not when that parent
    is reaped, so retaining a corpse releases no descendant and protects no
    pidfd: a zombie's PID is already unavailable for reuse. Retaining it does
    keep the corpse in its process group, so an owned group the runner has
    already killed and verified still answers a group-liveness probe for the
    whole bounded cleanup window, and the runner cannot observe its own
    cleanup. WNOHANG consumes only an already-exited child, so a live escapee
    is left untouched for the leak census. The runner is excluded because its
    own handle owns that reap.
    """
    reaped = 0
    for pid in _children():
        if pid == runner_pid:
            continue
        try:
            if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG) is not None:
                reaped += 1
        except (ChildProcessError, ProcessLookupError, OSError):
            continue
    return reaped


def _send(peer, value):
    wire = _json_bytes(value)
    _require(len(wire) <= CONTROL_LIMIT, "control_limit")
    peer.sendall(wire)


def _supervisor_main(profile, manifest_sha256, descriptor, seconds):
    peer = socket.socket(fileno=descriptor)
    source = Path.cwd()
    interrupted = []
    signal.signal(signal.SIGUSR1, lambda *_: interrupted.append(True))
    report = {"schema": "orch-dork/lifecycle-supervisor/v1",
              "collection": None, "execution": None, "phases": [],
              "cleanup": "unknown", "descendant_leak_observed": False,
              "failure": None}
    deadline = time.monotonic() + seconds
    telemetry_ready = False
    try:
        _subreaper()
        telemetry_ready = True
        report["origins"] = _reader_origins(source)
        for phase in ("collect", "execute"):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or interrupted:
                report["failure"] = "timeout_or_interrupted"
                break
            parent, child = socket.socketpair()
            try:
                process = subprocess.Popen(_argv(
                    source, profile, "--runner", manifest_sha256,
                    phase, child.fileno()),
                    cwd=source, env=dict(os.environ), stdin=subprocess.DEVNULL,
                    pass_fds=(child.fileno(),), close_fds=True, start_new_session=True)
                child.close()
                parent.setblocking(False)
                wire = bytearray()
                eof = False
                phase_failure = None
                while True:
                    try:
                        chunk = parent.recv(16_384)
                        if not chunk:
                            eof = True
                        wire.extend(chunk)
                        if len(wire) > CONTROL_LIMIT:
                            phase_failure = "control_limit"
                            break
                    except BlockingIOError:
                        pass
                    if process.poll() is not None:
                        # Complete buffered control after exit; never wait on
                        # an escaped process that inherited the endpoint.
                        while not eof:
                            try:
                                chunk = parent.recv(16_384)
                                if not chunk:
                                    eof = True
                                wire.extend(chunk)
                                if len(wire) > CONTROL_LIMIT:
                                    phase_failure = "control_limit"
                                    break
                            except BlockingIOError:
                                break
                        break
                    if interrupted or time.monotonic() >= deadline:
                        phase_failure = "timeout_or_interrupted"
                        break
                    _reap_adopted_corpses(process.pid)
                    time.sleep(0.01)
                exit_code = process.poll()
                leaked, cleanup = _drain_owned()
                report["cleanup"] = cleanup
                # A killed running leader is a timeout; remaining children
                # after a normally exited leader are an observed leak.
                escaped = leaked and exit_code is not None
                report["descendant_leak_observed"] |= escaped
                row = {"phase": phase, "exit_code": exit_code,
                       "cleanup": cleanup, "descendant_leak_observed": escaped}
                report["phases"].append(row)
                if phase_failure or cleanup != "observed_complete" or escaped or exit_code != 0:
                    report["failure"] = (phase_failure or
                        ("cleanup_unknown" if cleanup != "observed_complete" else
                         "descendant_leak" if escaped else "nonzero_exit"))
                if wire and len(wire) <= CONTROL_LIMIT:
                    try:
                        parsed = _json(bytes(wire))
                        report["collection" if phase == "collect" else "execution"] = parsed
                    except values.LifecycleContractError:
                        report["failure"] = "runner_record_invalid"
                else:
                    report["failure"] = report["failure"] or "runner_record_missing"
                if report["failure"]:
                    break
            finally:
                parent.close()
                child.close()
        _, report["cleanup"] = _drain_owned()
    except BaseException as error:
        report["failure"] = "supervisor:" + type(error).__name__
        # Failure of this dedicated telemetry seam must never imply closure.
        if telemetry_ready:
            try:
                _, report["cleanup"] = _drain_owned()
            except BaseException:
                report["cleanup"] = "unknown"
    try:
        _send(peer, report)
    finally:
        peer.close()
    return 0


def _execute(source, profile, environment, timeout, manifest_sha256):
    """Read original bytes and a supervisor-only channel with bounded cleanup."""
    parent, child = socket.socketpair()
    started = time.monotonic()
    process = subprocess.Popen(
        _argv(source, profile, "--supervise", manifest_sha256,
              child.fileno(), timeout),
        cwd=source, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        pass_fds=(child.fileno(),), start_new_session=True)
    child.close()
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray(), "control": bytearray()}
    streams = ((process.stdout, "stdout"), (process.stderr, "stderr"), (parent, "control"))
    for stream, label in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, label)
    reason = None
    stop_at = None
    try:
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if reason is None and now - started >= timeout:
                reason = "timeout"
            if reason and stop_at is None:
                stop_at = now
                if process.poll() is None:
                    process.send_signal(signal.SIGUSR1)
            if stop_at is not None and now - stop_at > 2 * _CLEANUP_SECONDS + 1:
                reason = "cleanup_unknown"
                if process.poll() is None:
                    process.kill()
                break
            for key, _ in selector.select(0.02):
                label = key.data
                try:
                    data = os.read(key.fd, 16_384)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                available = CONTROL_LIMIT - len(buffers[label])
                buffers[label].extend(data[:available])
                if len(data) > available and reason is None:
                    reason = label + "_limit"
        process.wait(timeout=_CLEANUP_SECONDS)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=_CLEANUP_SECONDS)
        selector.close()
        for stream, _ in streams:
            stream.close()
    supervisor = None
    try:
        if buffers["control"]:
            supervisor = _json(bytes(buffers["control"]))
    except values.LifecycleContractError:
        pass
    cleanup = "unknown"
    leaked = False
    if type(supervisor) is dict and process.returncode == 0:
        cleanup = supervisor.get("cleanup", "unknown")
        leaked = supervisor.get("descendant_leak_observed") is True
        reason = reason or supervisor.get("failure")
    if cleanup != "observed_complete":
        reason = "cleanup_unknown"
    phases = supervisor.get("phases", []) if type(supervisor) is dict else []
    code = phases[-1].get("exit_code") if phases else None
    return {"stdout": bytes(buffers["stdout"]), "stderr": bytes(buffers["stderr"]),
            "control": bytes(buffers["control"]),
            "observed": {"exit_code": code, "termination_reason": reason,
                         "cleanup": cleanup, "descendant_leak_observed": leaked,
                         "supervisor_exit_code": process.returncode,
                         "elapsed_seconds": time.monotonic() - started},
            "supervisor": supervisor}


def _test_module(source, target):
    """Return the longest source-module prefix without importing the target."""
    parts = target.split(".")
    for length in range(len(parts), 0, -1):
        candidate = source.joinpath(*parts[:length]).with_suffix(".py")
        if candidate.is_file():
            return ".".join(parts[:length])
    return target


def _module_units(source, tests):
    """Partition ordered selectors exactly as the release runner does."""
    units = []
    indexes = {}
    for target in tests:
        module = _test_module(source, target)
        if module not in indexes:
            indexes[module] = len(units)
            units.append((module, []))
        units[indexes[module]][1].append(target)
    return units


def _load_suite(profile, expected_manifest_sha256, selected):
    source = Path.cwd()
    contract = _profile_contract(source, profile)
    _require(contract["release_manifest"]["sha256"] == expected_manifest_sha256,
             "release_manifest_binding")
    units = _module_units(source, contract["test_targets"])
    _require(type(selected) is list and bool(selected)
             and all(type(item) is str for item in selected)
             and selected in [tests for _, tests in units], "module_selection")
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromNames(selected)
    _require(not loader.errors, "collection_import_error")
    return suite


def _iter_cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter_cases(item)
        else:
            yield item


def _clean_source_commit(source):
    """Return the exact clean source commit, or None for a projected fixture."""
    marker = source / ".git"
    if not marker.exists():
        _require(not marker.is_symlink(), "module_source_identity")
        return None

    def git(*arguments):
        completed = subprocess.run(
            ["git", "-C", str(source), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
        )
        _require(completed.returncode == 0, "module_source_identity")
        return completed.stdout.strip()

    top = Path(git("rev-parse", "--show-toplevel")).resolve()
    commit = git("rev-parse", "HEAD")
    dirty = git("status", "--porcelain=v1", "--untracked-files=all")
    _require(top == source and len(commit) == 40
             and all(character in "0123456789abcdef" for character in commit)
             and dirty == "", "module_source_identity")
    return commit


def _clone_private_module_source(source, checkout, commit):
    """Clone the same clean detached topology used by the release runner."""
    clone = subprocess.run(
        [
            "git", "clone", "--quiet", "--no-hardlinks", "--no-checkout",
            str(source), str(checkout),
        ],
        capture_output=True,
        timeout=120,
        umask=0o022,
    )
    _require(clone.returncode == 0, "module_source_identity")
    alternates = checkout / ".git/objects/info/alternates"
    _require(not alternates.exists(), "module_source_identity")

    common = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "--git-common-dir"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    _require(common.returncode == 0, "module_source_identity")
    source_common = Path(common.stdout.strip())
    if not source_common.is_absolute():
        source_common = (source / source_common).resolve()
    checkout_objects = checkout / ".git/objects"
    for copied in checkout_objects.rglob("*"):
        if copied.is_file():
            original = source_common / "objects" / copied.relative_to(
                checkout_objects)
            _require(not (original.is_file() and os.path.samefile(copied, original)),
                     "module_source_identity")

    checked_out = subprocess.run(
        [
            "git", "-C", str(checkout), "checkout", "--quiet", "--detach",
            commit,
        ],
        capture_output=True,
        timeout=120,
        umask=0o022,
    )
    _require(checked_out.returncode == 0, "module_source_identity")
    observed = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    dirty = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain=v1"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    _require(observed.returncode == 0 and observed.stdout.strip() == commit
             and dirty.returncode == 0 and dirty.stdout == "",
             "module_source_identity")


def _prepare_private_module_source(source, expected_generation, identity):
    """Materialize one immutable source snapshot with release-clone topology."""
    temporary = Path(os.environ["TMPDIR"])
    container = Path(tempfile.mkdtemp(prefix=identity + "-", dir=temporary))
    checkout = container / "source"
    try:
        commit = _clean_source_commit(source)
        if commit is None:
            shutil.copytree(
                source,
                checkout,
                ignore=shutil.ignore_patterns(".git"),
            )
        else:
            _clone_private_module_source(source, checkout, commit)
        # A development worktree can inherit umask 002 while a release clone is
        # created under umask 022.  Normalize only group/world write bits on the
        # private twin.  Raw source generation remains exact for before/after
        # drift detection; bytes and executable bits still bind both trees.
        for directory, _names, files in os.walk(checkout):
            path = Path(directory)
            mode = stat.S_IMODE(path.stat().st_mode)
            normalized = mode & ~0o022
            if normalized != mode:
                path.chmod(normalized)
            _require(stat.S_IMODE(path.stat().st_mode) & 0o022 == 0,
                     "module_source_directory_mode")
            for name in files:
                file_path = path / name
                if file_path.name == ".git" or file_path.name.endswith(".pyc"):
                    continue
                info = file_path.lstat()
                _require(stat.S_ISREG(info.st_mode), "module_source_identity")
                file_mode = stat.S_IMODE(info.st_mode)
                normalized_file_mode = file_mode & ~0o022
                if normalized_file_mode != file_mode:
                    file_path.chmod(normalized_file_mode)
                _require(stat.S_IMODE(file_path.stat().st_mode) & 0o022 == 0,
                         "module_source_file_mode")
        _require(_equal(_source_generation(source), expected_generation),
                 "module_source_drift")
        _require(commit is None or _clean_source_commit(source) == commit,
                 "module_source_drift")
        _require(_equal(_source_generation(checkout),
                        _private_source_generation(expected_generation)),
                 "module_source_identity")
        _require(commit is None or _clean_source_commit(checkout) == commit,
                 "module_source_identity")
        return container, checkout
    except BaseException as error:
        if not _remove_private_module_source(container):
            raise values.LifecycleContractError(
                "host_attestation:module_source_cleanup"
            ) from error
        raise


def _remove_private_module_source(container):
    try:
        shutil.rmtree(container)
    except OSError:
        return False
    return not container.exists()


def _module_runner_main(profile, manifest_sha256, phase, descriptor, selected_json):
    peer = socket.socket(fileno=descriptor)
    selected = _json(selected_json.encode("utf-8"))
    sys.path.extend([str(Path.cwd() / "skills/orch-dork/scripts"), str(Path.cwd())])
    os.environ[HOST_ATTESTATION_PROFILE_ENV] = profile
    suite = _load_suite(profile, manifest_sha256, selected)
    case_ids = [test.id() for test in _iter_cases(suite)]
    _require(case_ids and len(case_ids) == len(set(case_ids)), "empty_or_duplicate_collection")
    record = {"phase": phase, "case_ids": case_ids, "completion": None}
    if phase == "execute":
        started, stopped, skipped = [], [], []
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                started.append(test.id())
                super().startTest(test)
            def stopTest(self, test):
                stopped.append(test.id())
                super().stopTest(test)
            def addSkip(self, test, reason):
                skipped.append({"case_id": test.id(), "reason": reason})
                super().addSkip(test, reason)
        result = unittest.TextTestRunner(verbosity=1, resultclass=Result).run(suite)
        record["completion"] = {
            "tests_run": result.testsRun, "successful": result.wasSuccessful(),
            "started": _case_references(case_ids, started),
            "stopped": _case_references(case_ids, stopped),
            "skipped": skipped, "errors": len(result.errors), "failures": len(result.failures)}
    _send(peer, record)
    peer.close()
    return 0 if phase == "collect" or record["completion"]["successful"] else 1


def _case_references(case_ids, observed):
    """Name each observed case by its collection index where it has one.

    A module record already carries every collected id once.  Repeating them
    for the started and stopped lists tripled the record, and generation 49's
    153-test controller module crossed the control channel.  Ids outside the
    collection (class-level error holders) stay literal.
    """

    index = {case_id: position for position, case_id in enumerate(case_ids)}
    return [index.get(case_id, case_id) for case_id in observed]


def _resolve_case_references(case_ids, references):
    resolved = []
    for reference in references:
        if type(reference) is int and 0 <= reference < len(case_ids):
            resolved.append(case_ids[reference])
        elif type(reference) is str:
            resolved.append(reference)
        else:
            raise values.LifecycleContractError("host_attestation:module_execution")
    return resolved


def _run_private_module(checkout, profile, manifest_sha256, phase, selected):
    parent, child = socket.socketpair()
    wire = bytearray()
    try:
        process = subprocess.Popen(
            _argv(
                checkout, profile, "--module-runner", manifest_sha256, phase,
                child.fileno(), json.dumps(selected, separators=(",", ":")),
            ),
            cwd=checkout,
            env=dict(os.environ),
            stdin=subprocess.DEVNULL,
            pass_fds=(child.fileno(),),
            close_fds=True,
            start_new_session=True,
        )
        child.close()
        parent.setblocking(False)
        eof = False
        while process.poll() is None:
            try:
                chunk = parent.recv(16_384)
                if not chunk:
                    eof = True
                wire.extend(chunk)
                _require(len(wire) <= CONTROL_LIMIT, "module_control_limit")
            except BlockingIOError:
                pass
            time.sleep(0.01)
        while not eof:
            try:
                chunk = parent.recv(16_384)
                if not chunk:
                    eof = True
                wire.extend(chunk)
                _require(len(wire) <= CONTROL_LIMIT, "module_control_limit")
            except BlockingIOError:
                break
        record = _json(bytes(wire))
        _require(type(record) is dict and set(record) == {
            "phase", "case_ids", "completion",
        } and record["phase"] == phase, "module_record")
        case_ids = record["case_ids"]
        _require(type(case_ids) is list and bool(case_ids)
                 and len(case_ids) == len(set(case_ids))
                 and all(type(item) is str for item in case_ids), "module_collection")
        if phase == "collect":
            _require(record["completion"] is None and process.returncode == 0,
                     "module_collection_exit")
        else:
            completion = record["completion"]
            _require(type(completion) is dict and set(completion) == {
                "tests_run", "successful", "started", "stopped", "skipped",
                "errors", "failures",
            } and type(completion["tests_run"]) is int
                and type(completion["successful"]) is bool
                and type(completion["started"]) is list
                and type(completion["stopped"]) is list
                and type(completion["skipped"]) is list
                and type(completion["errors"]) is int
                and type(completion["failures"]) is int
                and process.returncode == (0 if completion["successful"] else 1),
                "module_execution")
            completion["started"] = _resolve_case_references(
                case_ids, completion["started"]
            )
            completion["stopped"] = _resolve_case_references(
                case_ids, completion["stopped"]
            )
        return record
    finally:
        parent.close()
        child.close()


def _runner_main(profile, manifest_sha256, phase, descriptor):
    peer = socket.socket(fileno=descriptor)
    source = Path.cwd()
    origins = _reader_origins(source)
    contract = _profile_contract(source, profile)
    _require(contract["release_manifest"]["sha256"] == manifest_sha256,
             "release_manifest_binding")
    expected_generation = _source_generation(source)
    units = _module_units(source, contract["test_targets"])
    module_records = []
    for index, (_module, selected) in enumerate(units, 1):
        container, checkout = _prepare_private_module_source(
            source, expected_generation, f"i170-{profile}-{phase}-{index:03d}")
        try:
            module_records.append(_run_private_module(
                checkout, profile, manifest_sha256, phase, selected))
        finally:
            _require(_remove_private_module_source(container), "module_source_cleanup")
    case_ids = [case_id for item in module_records for case_id in item["case_ids"]]
    _require(case_ids and len(case_ids) == len(set(case_ids)), "empty_or_duplicate_collection")
    collection = {"case_count": len(case_ids),
                  "case_ids_sha256": values.canonical_digest(case_ids)}
    record = {"phase": phase, "profile": profile, "collection": collection,
              "origins": origins, "completion": None}
    if phase == "execute":
        completions = [item["completion"] for item in module_records]
        started = [case_id for item in completions for case_id in item["started"]]
        stopped = [case_id for item in completions for case_id in item["stopped"]]
        record["completion"] = {
            "tests_run": sum(item["tests_run"] for item in completions),
            "successful": all(item["successful"] for item in completions),
            "started_count": len(started),
            "started_sha256": values.canonical_digest(started),
            "stopped_count": len(stopped),
            "stopped_sha256": values.canonical_digest(stopped),
            "skipped": [skip for item in completions for skip in item["skipped"]],
            "errors": sum(item["errors"] for item in completions),
            "failures": sum(item["failures"] for item in completions),
        }
    _require(_equal(expected_generation, _source_generation(source)), "reader_origin_drift")
    _require(_equal(origins, _reader_origins(source)), "reader_origin_drift")
    _send(peer, record)
    peer.close()
    return 0 if phase == "collect" or record["completion"]["successful"] else 1


def _test_observation(supervisor, profile, origins):
    """Derive expected/observed collection exclusively from runner channels."""
    observation = {"expected_collection": None, "observed_collection": None,
                   "completion": None, "matched": False}
    if type(supervisor) is not dict or not _equal(supervisor.get("origins"), origins):
        return observation
    expected, executed = supervisor.get("collection"), supervisor.get("execution")
    for record, phase in ((expected, "collect"), (executed, "execute")):
        if type(record) is not dict or set(record) != {
                "phase", "profile", "collection", "origins", "completion"}:
            return observation
        if record["phase"] != phase or record["profile"] != profile or not _equal(
                record["origins"], origins):
            return observation
    observation.update(expected_collection=expected["collection"],
                       observed_collection=executed["collection"],
                       completion=executed["completion"])
    collection, completion = expected["collection"], executed["completion"]
    if (type(collection) is not dict or set(collection) != {"case_count", "case_ids_sha256"}
            or type(collection["case_count"]) is not int or collection["case_count"] <= 0
            or type(completion) is not dict or set(completion) != {
                "tests_run", "successful", "started_count", "started_sha256",
                "stopped_count", "stopped_sha256", "skipped", "errors", "failures"}):
        return observation
    count, digest = collection["case_count"], collection["case_ids_sha256"]
    if (not _equal(collection, executed["collection"]) or expected["completion"] is not None
            or not _equal([completion[k] for k in ("tests_run", "started_count", "stopped_count")],
                          [count, count, count])
            or completion["started_sha256"] != digest or completion["stopped_sha256"] != digest
            or completion["successful"] is not True or completion["errors"] != 0
            or completion["failures"] != 0):
        return observation
    skipped = completion["skipped"]
    policy = _PROFILES[profile]
    if type(skipped) is not list or len(skipped) > min(count, 64):
        return observation
    seen = set()
    for item in skipped:
        if type(item) is not dict or set(item) != {"case_id", "reason"}:
            return observation
        name, reason = item["case_id"], item["reason"]
        if type(name) is not str or name in seen or type(reason) is not str:
            return observation
        seen.add(name)
        if reason not in policy.skip_reasons and not any(
                reason.startswith(prefix) for prefix in policy.skip_prefixes):
            return observation
    observation["matched"] = True
    return observation


def _execution_status(result):
    observed = result["observed"]
    if observed["cleanup"] != "observed_complete":
        return "BLOCKED"
    passing = (observed["termination_reason"] is None and observed["exit_code"] == 0
               and observed["supervisor_exit_code"] == 0
               and observed["descendant_leak_observed"] is False
               and result["test_observation"]["matched"] is True
               and result["temporary_root_empty"] is True
               and result["temporary_root_removed"] is True
               and _equal(result["source_before"], result["source_after"])
               and _equal(result["runtime_before"], result["runtime_after"]))
    return "PASS" if passing else "FAIL"


def run(profile, *, source_root, output_root, timeout_seconds):
    """Mint one witness for two bounded fixed invocations: collect and execute."""
    _require(type(profile) is str and profile in _PROFILES, "profile")
    _require(type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds)
             and 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS, "timeout")
    source = _safe_root(source_root, "source_root", must_exist=True)
    output = _safe_root(output_root, "output_root", must_exist=False)
    _require(source != output and source not in output.parents and output not in source.parents,
             "root_overlap")
    before = _source_generation(source)
    runtime = _runtime_identity(source)
    origins = _reader_origins(source)
    contract = _profile_contract(source, profile)
    _require(timeout_seconds <= contract["timeout_seconds"], "profile_timeout")
    manifest_sha256 = contract["release_manifest"]["sha256"]
    invocation = {"schema": INVOCATION_SCHEMA, "profile": profile, "cwd": str(source),
                  "contract": contract, "origins": origins,
                  "argv_profile": _argv(
                      source, profile, "--supervise", manifest_sha256),
                  "limits": {"timeout_seconds": timeout_seconds, "stdout_bytes": STDOUT_LIMIT,
                             "stderr_bytes": STDERR_LIMIT, "control_bytes": CONTROL_LIMIT},
                  "source_before": before, "runtime_before": runtime,
                  "nonce": os.urandom(32).hex()}
    identity = values.canonical_digest(invocation)
    invocation["invocation_id"] = identity
    output.mkdir(mode=0o700)
    _write_create_only(output / "invocation.json", _json_bytes(invocation))
    with tempfile.TemporaryDirectory(prefix="i170-host-") as temporary:
        home = Path(temporary) / "home"
        home.mkdir(mode=0o700)
        environment = {
            "PATH": os.defpath,
            "LANG": "C.UTF-8",
            "HOME": str(home),
            "TMPDIR": temporary,
            # The direct runners use -B, but release tests can spawn nested
            # Python processes. Keep those descendants from racing compiled
            # caches into the shared source checkout used by other profiles.
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        captured = _execute(
            source, profile, environment, float(timeout_seconds), manifest_sha256)
        if home.exists() and not any(home.iterdir()):
            home.rmdir()
        temporary_empty = not any(Path(temporary).iterdir())
    result = {"schema": RESULT_SCHEMA, "profile": profile, "invocation_id": identity,
              "source_before": before, "source_after": _source_generation(source),
              "runtime_before": runtime, "runtime_after": _runtime_identity(source),
              "observed": captured["observed"],
              "test_observation": _test_observation(captured["supervisor"], profile, origins),
              "temporary_root_empty": temporary_empty,
              "temporary_root_removed": not Path(temporary).exists()}
    outputs = {}
    for label in ("stdout", "stderr", "control"):
        data = captured[label]
        name = label + ".log"
        _write_create_only(output / name, data)
        outputs[name] = {"sha256": _sha(data), "bytes": len(data),
                         "complete": captured["observed"]["termination_reason"] is None}
    result["outputs"] = outputs
    result["status"] = _execution_status(result)
    data = _json_bytes(result)
    _require(len(data) <= REPORT_LIMIT, "result_size")
    _write_create_only(output / "result.json", data)
    info = output.stat()
    witness = _issue(FreshWitness(str(output), info.st_dev, info.st_ino, identity,
                                  _sha(data), _AUTHORITY))
    return HostRun(output, witness)


def _read_file(root, name, limit):
    path = root / name
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                 and stat.S_IMODE(info.st_mode) == 0o600, "original_custody:" + name)
        data = stream.read(limit + 1)
        _require(len(data) <= limit, "original_size:" + name)
    return data


def readback(*, source_root, artifact_root, witness=None, expected_invocation_id=None):
    """JSON validates transport; exact issued objects additionally bind custody."""
    if witness is not None:
        _require(type(witness) is FreshWitness, "witness_type")
        _issued(witness)
    source = _safe_root(source_root, "source_root", must_exist=True)
    artifact = _safe_root(artifact_root, "artifact_root", must_exist=True)
    info = artifact.stat()
    _require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
             "artifact_custody")
    try:
        invocation = _json(_read_file(artifact, "invocation.json", REPORT_LIMIT))
        result_bytes = _read_file(artifact, "result.json", REPORT_LIMIT)
    except FileNotFoundError as exc:
        raise values.LifecycleContractError("host_attestation:original_missing") from exc
    result = _json(result_bytes)
    _require(type(invocation) is dict and set(invocation) == {
        "schema", "profile", "cwd", "contract", "origins", "argv_profile", "limits",
        "source_before", "runtime_before", "nonce", "invocation_id"}, "invocation_shape")
    _require(invocation["schema"] == INVOCATION_SCHEMA
             and type(invocation["profile"]) is str and invocation["profile"] in _PROFILES,
             "invocation_profile")
    profile = invocation["profile"]
    material = {k: v for k, v in invocation.items() if k != "invocation_id"}
    _require(invocation["invocation_id"] == values.canonical_digest(material), "invocation_digest")
    _require(expected_invocation_id is None or expected_invocation_id == invocation["invocation_id"],
             "stale_invocation")
    _require(invocation["cwd"] == str(source)
             and _equal(invocation["contract"], _profile_contract(source, profile))
             and _equal(invocation["argv_profile"], _argv(
                 source, profile, "--supervise",
                 invocation["contract"]["release_manifest"]["sha256"]))
             and _equal(invocation["origins"], _reader_origins(source)), "invocation_contract")
    limits = invocation["limits"]
    _require(type(limits) is dict and set(limits) == {
        "timeout_seconds", "stdout_bytes", "stderr_bytes", "control_bytes"}
        and type(limits["timeout_seconds"]) in (int, float)
        and math.isfinite(limits["timeout_seconds"])
        and 0 < limits["timeout_seconds"] <= MAX_TIMEOUT_SECONDS
        and _equal([limits[k] for k in ("stdout_bytes", "stderr_bytes", "control_bytes")],
                   [STDOUT_LIMIT, STDERR_LIMIT, CONTROL_LIMIT]), "invocation_limits")
    _require(type(result) is dict and set(result) == {
        "schema", "profile", "invocation_id", "source_before", "source_after",
        "runtime_before", "runtime_after", "observed", "test_observation",
        "temporary_root_empty", "temporary_root_removed", "outputs", "status"},
        "result_shape")
    _require(result["schema"] == RESULT_SCHEMA and result["profile"] == profile
             and result["invocation_id"] == invocation["invocation_id"], "result_identity")
    _require(_equal(result["source_before"], invocation["source_before"])
             and _equal(result["runtime_before"], invocation["runtime_before"]), "before_binding")
    _require(_equal(result["source_after"], _source_generation(source))
             and _equal(result["runtime_after"], _runtime_identity(source)), "stale_source")
    outputs = {}
    for name in ("stdout.log", "stderr.log", "control.log"):
        data = _read_file(artifact, name, CONTROL_LIMIT)
        outputs[name] = data
        _require(_equal(result["outputs"].get(name), {
            "sha256": _sha(data), "bytes": len(data),
            "complete": result["observed"]["termination_reason"] is None}),
            "output_binding:" + name)
    try:
        supervisor = _json(outputs["control.log"]) if outputs["control.log"] else None
    except values.LifecycleContractError:
        supervisor = None
    _require(_equal(result["test_observation"],
                    _test_observation(supervisor, profile, invocation["origins"])),
             "test_observation")
    _require(result["status"] == _execution_status(result), "forged_status")
    fresh = witness is not None
    if fresh:
        _require(witness.artifact_root == str(artifact) and witness.device == info.st_dev
                 and witness.inode == info.st_ino and witness.invocation_id == result["invocation_id"]
                 and witness.result_file_sha256 == _sha(result_bytes), "witness_binding")
    status = result["status"] if fresh else "BLOCKED"
    facts = list(_CUSTODY_FACTS) if status == "PASS" and profile == "campaign" else []
    report = rv.freeze({"schema": READBACK_SCHEMA, "status": status, "profile": profile,
        "invocation_id": result["invocation_id"], "transport_integrity": "PASS",
        "execution_custody": "PASS" if fresh else "BLOCKED",
        "execution_status": result["status"], "completion_facts": facts,
        "source_generation_sha256": result["source_after"]["inventory_sha256"],
        "runtime_identity": result["runtime_after"], "origins": invocation["origins"],
        "observed": result["observed"], "outputs": result["outputs"],
        "test_observation": result["test_observation"],
        "campaign_scope": "exact_invoked_scope_host_custody_only",
        "persistence_limitation": _PERSISTENCE,
        "limitation": "reviewed_test_interpreter_not_a_hostile_python_sandbox"})
    return _issue(ValidatedAttestation(report, _AUTHORITY if fresh else None))


def completion_facts(attestation):
    _require(type(attestation) is ValidatedAttestation, "attestation_type")
    _issued(attestation)
    report = attestation.report.to_plain()
    _require(attestation._authority is _AUTHORITY and report["status"] == "PASS",
             "fresh_attestation")
    return tuple(report["completion_facts"])


def profile_timeout_seconds(profile, *, source_root):
    """Return the manifest-derived ceiling for one explicit release profile."""
    _require(type(profile) is str and profile in _PROFILES, "profile")
    source = _safe_root(source_root, "source_root", must_exist=True)
    return _profile_contract(source, profile)["timeout_seconds"]


def release_manifest_identity(*, source_root):
    """Return the independently parsed manifest authority for Stage L."""
    source = _safe_root(source_root, "source_root", must_exist=True)
    return rv.freeze(_release_manifest(source))


def validate_test_run_set(attestations):
    _require(type(attestations) is dict and set(attestations) == {
        "focused", "rehearsal", "full_suite"}, "test_set_profiles")
    reports = {}
    for profile, attestation in attestations.items():
        _require(type(attestation) is ValidatedAttestation, "test_set_authority")
        _issued(attestation)
        report = attestation.report.to_plain()
        _require(attestation._authority is _AUTHORITY and report["status"] == "PASS"
                 and report["profile"] == profile, "test_set_run")
        reports[profile] = report
    _require(len({values.canonical_digest(row["runtime_identity"])
                  for row in reports.values()}) == 1
             and len({row["source_generation_sha256"] for row in reports.values()}) == 1,
             "test_set_runtime_drift")
    return rv.freeze({"schema": TEST_SET_SCHEMA, "status": "PASS",
        "profiles": {name: reports[name]["invocation_id"] for name in sorted(reports)},
        "runtime_identity": reports["focused"]["runtime_identity"],
        "source_generation_sha256": reports["focused"]["source_generation_sha256"],
        "facts": ["focused_tests_same_runtime", "rehearsal_same_runtime", "full_suite_same_runtime"]})


__all__ = ["INVOCATION_SCHEMA", "RESULT_SCHEMA", "READBACK_SCHEMA", "TEST_SET_SCHEMA",
           "HOST_ATTESTATION_PROFILE_ENV", "NESTED_STAGE_L_SKIP_REASON",
           "FreshWitness", "HostRun", "ValidatedAttestation", "run", "readback",
           "completion_facts", "profile_timeout_seconds", "release_manifest_identity",
           "validate_test_run_set"]

if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[2] in _PROFILES:
        role, profile, manifest_sha256 = sys.argv[1:4]
        if role == "--supervise":
            raise SystemExit(_supervisor_main(
                profile, manifest_sha256, int(sys.argv[4]), float(sys.argv[5])))
        if role == "--runner":
            raise SystemExit(_runner_main(
                profile, manifest_sha256, sys.argv[4], int(sys.argv[5])))
    if len(sys.argv) == 7 and sys.argv[1] == "--module-runner" and sys.argv[2] in _PROFILES:
        raise SystemExit(_module_runner_main(
            sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), sys.argv[6]))
    raise SystemExit(2)
