"""Trusted local Git delivery, preparatory source for Issue 225.

PublicationReceiver has no mission ownership or verification authority. Its
REQUIRED host authorization_guard(request) context must independently validate
the exact protected verification, current ticket revision, ownership and
authorization generation, and hold them through settlement. It yields a
HeldAuthorization bound to the COMPLETE request and already-held protective
flock descriptors. The supervisor and actual Git inherit those descriptors.
The guard must close, never LOCK_UN, on parent loss; canonical claims must stay
held for UNKNOWN. Root must compose this with Control Tower/RunEngine/store.
Fixture guards prove the fd seam, not that canonical mission join.

Custody and Git metadata must be physically inaccessible to candidates/workers.
Private modes and advisory locks are not containment against the same uid.
The journal records delivery only. publish never retries. Explicit resume can
append ONE continuation of a normally exited, nonzero transaction with complete
receiver-observed cessation, exact retained command/config identity, absent
marker and fresh full-request authorization. Original records stay immutable.
Missing/partial receipts, pre-launch gaps, timeout, signal loss, output loss and
exhausted continuation stay UNKNOWN; neither PID/lease/lock nor ref absence is
cessation proof. This bounded API cannot recover every safe pre-effect cut.
It performs no tracker edit, model call, remote publication or integration.
Linux/local-filesystem only; no power-loss atomicity or multi-ref read snapshot
is claimed. Trusted Git executable/configuration and host custody are inputs,
not worker-supplied plugin capabilities.
"""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import ctypes
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Callable, ContextManager

if __name__ == "__main__":
    # The fixed -I supervisor omits its trusted script directory from sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from orch_dork_evidence_core import legacy_ascii_bytes

STREAM_LIMIT = 65_536
MAX_REQUEST_BYTES = 16_384
SCHEMA = "orch-dork/mission-publication-request/v1"
MARKER_PREFIX = "refs/orch-dork/publications/"
_OID = re.compile(r"[0-9a-f]{40}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_ZERO = "0" * 40


CLEANUP_SCHEMA = 'orch-dork/mission-publication-cleanup-readback/v1'


class PublicationRefusal(ValueError):
    """A pre-effect refusal. UNKNOWN is returned for uncertain delivery."""


def _canonical(value: dict) -> bytes:
    return legacy_ascii_bytes(value)


@dataclass(frozen=True)
class PublicationRequest:
    operation_id: str
    repository: str  # exact canonical common Git directory, not a cwd alias
    target_ref: str
    expected_old: str
    new_commit: str
    new_tree: str
    mission_id: str
    ticket_id: str
    ticket_revision: str
    ownership_generation: int
    verification_evidence_sha256: str
    authorization_generation: int

    @classmethod
    def from_recorded_wire(cls, value):
        """Read the closed original request without resolving historical paths."""
        from orch_dork_evidence_core import require_dataclass_wire
        require_dataclass_wire(value, cls, SCHEMA,
            shape_error=PublicationRefusal('request:wire_shape_invalid'),
            schema_error=PublicationRefusal('request:schema_invalid'))
        request = cls(**{key: item for key, item in value.items() if key != 'schema'})
        request.validate()
        return request

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical({"schema": SCHEMA, **asdict(self)})

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    def validate(self) -> None:
        for value in (self.operation_id, self.mission_id, self.ticket_id):
            if type(value) is not str or not _ID.fullmatch(value):
                raise PublicationRefusal("request:identifier_invalid")
        for value in (self.expected_old, self.new_commit, self.new_tree):
            if type(value) is not str or not _OID.fullmatch(value):
                raise PublicationRefusal("request:object_invalid")
        for value in (self.ticket_revision, self.verification_evidence_sha256):
            if type(value) is not str or not _SHA.fullmatch(value):
                raise PublicationRefusal("request:digest_invalid")
        for value in (self.ownership_generation, self.authorization_generation):
            if type(value) is not int or not 0 < value <= 2**63 - 1:
                raise PublicationRefusal("request:generation_invalid")
        if (type(self.repository) is not str or type(self.target_ref) is not str
                or not self.target_ref.startswith("refs/heads/")
                or len(self.canonical_bytes) > MAX_REQUEST_BYTES):
            raise PublicationRefusal("request:shape_invalid")


def publication_marker_ref(request: PublicationRequest) -> str:
    """Derive the exact local marker ref for the original closed request."""
    request.validate()
    return MARKER_PREFIX + hashlib.sha256(request.operation_id.encode()).hexdigest()


def publication_marker_oid(request: PublicationRequest) -> str:
    """Derive the Git blob identity of every canonical request byte."""
    request.validate()
    raw = request.canonical_bytes
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


@dataclass(frozen=True)
class HeldAuthorization:
    """Only a trusted host guard may supply this exact verification/current join.

    fds are already-held protective locks, retained across exec until every
    possible effect child has ceased. Holding an arbitrary fd is insufficient:
    Root's guard must prevent authorization revocation/reassignment while held.
    """

    request_sha256: str
    fds: tuple[int, ...]


def _require_held_descriptor(fd: int, delivery_fd: int) -> None:
    info = os.fstat(fd)
    delivery_info = os.fstat(delivery_fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1
            or (info.st_dev, info.st_ino) == (delivery_info.st_dev, delivery_info.st_ino)):
        raise PublicationRefusal("authorization:descriptor_unsafe")
    # Opening through /proc creates a DIFFERENT open file description. A bare
    # fd without a held flock cannot protect a late child. This verifies the
    # kernel lock exists; its canonical mission meaning is still Root's seam.
    probe = os.open(f"/proc/self/fd/{fd}", os.O_RDWR | os.O_CLOEXEC)
    try:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        raise PublicationRefusal("authorization:descriptor_unheld")
    finally:
        os.close(probe)  # never unlock an inherited open file description


def _private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, exist_ok=True)
    _check_directory(path)


def _check_directory(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise PublicationRefusal("custody:directory_unsafe")


def _open(path: Path, flags: int) -> int:
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(fd)
    if not _regular_file_owned(info):
        os.close(fd)
        raise PublicationRefusal("custody:file_unsafe")
    return fd


def _regular_file_owned(info) -> bool:
    """Canonical regular-file predicate: S_ISREG + own uid + single link + 0o600.

    Both the post-open descriptor check in _open and the stager pre-open
    refusal of FIFO/device/symlink share this single body. The caller raises
    its own refusal type; the exception moment (before vs after os.open)
    stays the caller's responsibility.
    """
    return (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600)


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _create(path: Path, raw: bytes) -> None:
    """Never replace, remove, or repair a partial immutable delivery record."""
    fd = _open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    _sync_directory(path.parent)


def _read(path: Path, limit: int = STREAM_LIMIT) -> bytes:
    fd = _open(path, os.O_RDONLY)
    try:
        raw = os.read(fd, limit + 1)
        if len(raw) > limit:
            raise PublicationRefusal("custody:record_oversized")
        return raw
    finally:
        os.close(fd)


def _system_path() -> str:
    """Only absolute platform search directories; never a cwd component."""
    return os.pathsep.join(part for part in os.defpath.split(os.pathsep)
                           if part and Path(part).is_absolute())


def _git_environment() -> dict[str, str]:
    # Nothing inherited: GIT_DIR, work tree, index, objects, config parameters,
    # HOME, LD/PYTHON injection and hooks cannot redirect the command.
    return {"PATH": _system_path(), "LC_ALL": "C", "HOME": "/nonexistent",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0"}


def _git_argv(executable: str, repository: str, args: list[str]) -> list[str]:
    return [executable, "--no-optional-locks", "--git-dir=" + repository,
            "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-c", "core.logAllRefUpdates=false", *args]


def _census() -> list[dict]:
    """Linux identities, bounded census; errors never establish cessation."""
    rows = []
    for count, path in enumerate(Path("/proc").iterdir()):
        if count > 65_536:
            raise OSError("process:census_exhausted")
        if not path.name.isdecimal():
            continue
        try:
            raw = (path / "stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            continue
        fields = raw[raw.rfind(")") + 2:].split()
        rows.append({"pid": int(path.name), "ppid": int(fields[1]),
                     "pgid": int(fields[2]), "start_ticks": int(fields[19])})
    return rows


def _owned() -> list[dict]:
    rows = _census()
    parents = {os.getpid()}
    found = []
    while True:
        children = [row for row in rows if row["ppid"] in parents
                    and row["pid"] not in parents]
        if not children:
            return found
        found.extend(children)
        parents.update(row["pid"] for row in children)


def _kill_owned(row: dict) -> None:
    # Signal only a current actual descendant with the same kernel identity.
    fd = os.pidfd_open(row["pid"])
    try:
        if row in _owned():
            signal.pidfd_send_signal(fd, signal.SIGKILL)
    finally:
        os.close(fd)


def _supervise(command_path: Path) -> int:
    """Small dedicated subreaper; parent death does not unlock effect/auth fds.

    Every command uses this same closed environment and bounded capture. No
    explicit LOCK_UN exists. Escaped grandchildren reparent to this supervisor
    and must be reaped and observed absent before a complete receipt is written.
    """
    config_bytes = _read(command_path)
    config = json.loads(config_bytes)
    directory = command_path.parent
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        return 2
    started = time.monotonic()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    observed = {}
    reason = "exited"
    process = None
    process_identity = None
    supervisor_identity = None
    complete = False
    selector = selectors.DefaultSelector()
    remaining = []
    group_remaining = None
    try:
        process = subprocess.Popen(
            config["argv"], cwd=config["repository"], env=_git_environment(),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, close_fds=True, pass_fds=tuple(config["fds"]),
        )
        # Observe before poll/wait can reap the direct child. Even a fast exit
        # still has its actual zombie identity; no PID-absence inference.
        identities = _census()
        process_identity = next(row for row in identities if row["pid"] == process.pid)
        supervisor_identity = next(row for row in identities if row["pid"] == os.getpid())
        for name in ("stdout", "stderr"):
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        pending = memoryview(bytes.fromhex(config["stdin_hex"]))
        os.set_blocking(process.stdin.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        deadline = started + config["timeout_seconds"]
        cleanup_deadline = deadline + 1.0
        while True:
            process.poll()
            if process.returncode is not None:
                while True:
                    try:
                        pid, _ = os.waitpid(-1, os.WNOHANG)
                        if not pid:
                            break
                    except ChildProcessError:
                        break
            remaining = _owned()
            observed.update({(row["pid"], row["start_ticks"]): row for row in remaining})
            if not remaining and process.returncode is not None and not selector.get_map():
                group_remaining = [row for row in _census() if row["pgid"] == process.pid]
                if not group_remaining:
                    complete = True
                    break
            if time.monotonic() >= deadline or reason != "exited":
                if reason == "exited":
                    reason = "timeout"
                for row in remaining:
                    try:
                        _kill_owned(row)
                    except ProcessLookupError:
                        pass
                if time.monotonic() >= cleanup_deadline:
                    break
            for key, _ in selector.select(0.01):
                if key.data == "stdin":
                    try:
                        if pending:
                            pending = pending[os.write(key.fd, pending):]
                        if not pending:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    except BrokenPipeError:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                name = key.data
                chunk = os.read(key.fd, min(4096, STREAM_LIMIT - len(buffers[name]) + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                else:
                    space = STREAM_LIMIT - len(buffers[name])
                    buffers[name].extend(chunk[:space])
                    if len(chunk) > space:
                        reason = "output_limit"
                        # Retain the original bounded prefix and stop reading
                        # this stream. Draining excess one byte per census can
                        # exhaust cleanup time after the child has already gone.
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
        process.poll()
    except (OSError, ValueError, IndexError, StopIteration) as error:
        reason = "supervision_unknown:" + type(error).__name__
    finally:
        selector.close()
    if process is not None and process.returncode is not None and process.returncode < 0 and reason == "exited":
        reason = "child_signal_loss"
    for name, raw in buffers.items():
        _create(directory / name, bytes(raw))
    outcome = {"argv": config["argv"], "exit_code": process.returncode if process else None,
               "process_identity": process_identity, "supervisor_identity": supervisor_identity,
               "command_sha256": hashlib.sha256(config_bytes).hexdigest(),
               "environment": _git_environment(),
               "reason": reason, "duration_seconds": time.monotonic() - started,
               "capture_complete": reason != "output_limit",
               "stdout_sha256": hashlib.sha256(buffers["stdout"]).hexdigest(),
               "stderr_sha256": hashlib.sha256(buffers["stderr"]).hexdigest(),
               "cleanup": {"complete": complete, "remaining": remaining,
                           "pgid": process.pid if process else None,
                           "group_remaining": group_remaining,
                           "observed": list(observed.values())}}
    _create(directory / "outcome.json", _canonical(outcome))
    return 0 if complete else 2


@dataclass(frozen=True)
class _ValidationCommand:
    args: tuple[str, ...]
    allowed: tuple[int, ...]
    expected: str | None
    refusal_reason: str | None


@dataclass(frozen=True)
class _CleanupPlan:
    validations: tuple[_ValidationCommand, ...]
    ordinary_args: frozenset[tuple[str, ...]]
    marker_query: tuple[str, ...]

    def marker_object(self, args: tuple[str, ...]) -> str | None:
        if args in self.ordinary_args:
            return None
        if (len(args) == 3 and args[0] == 'cat-file' and args[1] in {'-t', 'blob'}
                and _OID.fullmatch(args[2])):
            return args[2]
        raise PublicationRefusal('cleanup:command_unowned')


@dataclass(frozen=True)
class _CommandCapture:
    command_bytes: bytes
    outcome_bytes: bytes
    streams: dict
    supervisor_exit_sha256: str | None


@dataclass(frozen=True)
class _CommandReadback:
    report: dict
    args: tuple[str, ...]
    config: dict
    outcome: dict
    marker_object: str | None


@dataclass(frozen=True)
class _CleanupJournal:
    request_bytes: bytes
    intent_bytes: bytes | None
    intent: dict | None
    continuation_bytes: bytes | None
    continuation: dict | None
    commands: tuple[_CommandReadback, ...]


class PublicationReceiver:
    """One trusted repository/ref receiver. Repeated publish reconciles only.

    git_executable is a trusted host input; tests may name an explicit wrapper
    that runs real Git. Wrapper exits and actual Git results remain distinct.
    Host guard exceptions should use PublicationRefusal for typed refusal.
    """

    def __init__(self, custody: str | Path, *, repository: str | Path,
                 target_ref: str,
                 authorization_guard: Callable[[PublicationRequest], ContextManager[HeldAuthorization]],
                 git_executable: str | None = None, timeout_seconds: float = 3.0):
        if not callable(authorization_guard):
            raise PublicationRefusal("authorization:guard_required")
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not 0.05 <= timeout_seconds <= 10):
            raise PublicationRefusal("receiver:timeout_invalid")
        self.repository = Path(repository)
        if (not self.repository.is_absolute()
                or str(self.repository.resolve(strict=True)) != str(self.repository)):
            raise PublicationRefusal("repository:not_canonical")
        info = self.repository.stat()
        self.repository_identity = (info.st_dev, info.st_ino)
        self.custody = Path(custody)
        if (not self.custody.is_absolute() or self.custody.resolve() != self.custody
                or self.custody == self.repository or self.repository in self.custody.parents
                or self.custody in self.repository.parents):
            raise PublicationRefusal("custody:path_unsafe")
        _private_dir(self.custody)
        _sync_directory(self.custody.parent)
        self.target_ref = target_ref
        self.authorization_guard = authorization_guard
        if git_executable is None:
            git_executable = shutil.which("git", path=_system_path())
            if git_executable is None:
                raise PublicationRefusal("git:executable_unavailable")
        executable = Path(git_executable)
        if not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK):
            raise PublicationRefusal("git:executable_invalid")
        self.git_executable = str(executable.resolve())
        self.timeout_seconds = timeout_seconds

    def operation_directory(self, request: PublicationRequest) -> Path:
        """Delivery journal path, for trusted host evidence retention/recovery."""
        request.validate()
        return self.custody / hashlib.sha256(request.operation_id.encode()).hexdigest()

    def marker_ref(self, request: PublicationRequest) -> str:
        return publication_marker_ref(request)

    def observe_or_read_target(self, operation_id: str, *, baseline: str | None = None,
                               interface_contracts: list | tuple = ()) -> dict:
        """Observe once or reprove that exact original journal after restart.

        Existing complete reads stay historical; partial original custody
        refuses without a replacement read. This conveys no publication
        permission and never repairs or refreshes retained evidence.
        """
        contracts = self._target_contracts(operation_id, baseline, interface_contracts)
        directory = self.custody / "target-observations" / hashlib.sha256(operation_id.encode()).hexdigest()
        if not os.path.lexists(directory):
            self.observe_target(operation_id, baseline=baseline, interface_contracts=contracts)
        return self.read_target_observation(operation_id, baseline=baseline,
                                            interface_contracts=contracts)

    def observe_target(self, operation_id: str, *, baseline: str | None = None,
                       interface_contracts: list | tuple = ()) -> dict:
        """Retain one fresh read of this receiver's actual target commit/tree.

        This issues only bounded read commands and conveys no publication
        permission. The completion host still owns current revision, scope,
        dependency checks and exact-result verification; publication must use
        a conditional update against the observed commit. A retained read is
        historical evidence, not an atomic or continuously current snapshot.
        Reusing its identity refuses instead of presenting cached data as fresh.
        """
        contracts = self._target_contracts(operation_id, baseline, interface_contracts)
        info = self.repository.stat()
        if ((info.st_dev, info.st_ino) != self.repository_identity
                or self.repository.resolve(strict=True) != self.repository):
            raise PublicationRefusal("repository:binding_changed")
        parent = self.custody / "target-observations"
        _private_dir(parent)
        directory = parent / hashlib.sha256(operation_id.encode()).hexdigest()
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError as error:
            raise PublicationRefusal("target:observation_already_retained") from error
        _sync_directory(parent)
        caller = next(row for row in _census() if row['pid'] == os.getpid())
        request = {**self._target_request(operation_id, baseline, contracts), 'caller': caller}
        _create(directory / 'request.json', _canonical(request))
        report = {"schema": "orch-dork/mission-target-observation/v1",
                  "operation_id": operation_id, "repository": str(self.repository),
                  "repository_identity": list(self.repository_identity),
                  "target_ref": self.target_ref, "commit": None, "tree": None,
                  "baseline": baseline, "interface_contracts": contracts,
                  "contract_observations": [],
                  "status": "UNKNOWN", "reason": "target:observation_incomplete",
                  "commands": [], "publication_authorized": False,
                  "evidence_path": str(directory / "result.json")}
        try:
            deadline = time.monotonic() + 10.0

            def read(args, *, binary=False):
                # Do not start another read after the aggregate creation budget.
                # The last command retains its existing bounded cleanup interval.
                if time.monotonic() >= deadline:
                    raise PublicationRefusal("target:read_unsettled")
                row = self._command(directory, args)
                report["commands"].append(row)
                if not row["cleanup"]["complete"] or row.get("reason") != "exited":
                    raise PublicationRefusal("target:read_unsettled")
                if row["exit_code"] != 0:
                    raise PublicationRefusal("target:read_refused")
                return (_read(Path(row["command_directory"]) / "stdout") if binary
                        else row["stdout"].strip())

            self._target_values(report, read)
        except PublicationRefusal as error:
            report.update(status="UNKNOWN" if str(error) == "target:read_unsettled" else "REFUSED",
                          reason=str(error))
        except (OSError, KeyError, TypeError, ValueError) as error:
            report.update(reason="target:observation_unavailable:" + type(error).__name__)
        retained = self._retained_target_report(report)
        _create(directory / "result.json", _canonical(retained))
        _create(directory / "result.sha256", hashlib.sha256(_canonical(retained)).hexdigest().encode())
        return retained

    @staticmethod
    def _retained_target_report(report):
        """The exact bytes every reader can reprove within STREAM_LIMIT.

        A report whose embedded command captures exceed the bound is retained
        as a refusal naming its ordered command directories and a digest of
        the full rows, so the original reads stay provable and settle as a
        recorded failure instead of an unreadable success.
        """
        if len(_canonical(report)) <= STREAM_LIMIT:
            return report
        rows = report["commands"]
        bounded = {**report, "commit": None, "tree": None, "contract_observations": [],
                   "status": "REFUSED", "reason": "target:observation_oversized", "commands": [],
                   "command_directories": [row["command_directory"] for row in rows],
                   "commands_sha256": hashlib.sha256(_canonical({"commands": rows})).hexdigest()}
        if len(_canonical(bounded)) > STREAM_LIMIT:
            raise PublicationRefusal("target:observation_oversized")
        return bounded

    def _target_contracts(self, operation_id, baseline, interface_contracts):
        if (type(operation_id) is not str or not _ID.fullmatch(operation_id)
                or type(self.target_ref) is not str
                or not re.fullmatch(r"refs/heads/[A-Za-z0-9_./-]{1,128}", self.target_ref)
                or baseline is not None and (type(baseline) is not str or not _OID.fullmatch(baseline))
                or type(interface_contracts) not in (list, tuple)
                or len(interface_contracts) > 64
                or interface_contracts and baseline is None):
            raise PublicationRefusal("target:observation_input_invalid")
        from orch_dork_mission_scope import normalize_scope, ScopeRefusal
        contracts = []
        for item in interface_contracts:
            try:
                if (type(item) is not dict or set(item) != {"path", "sha256"}
                        or item["path"] == "." or type(item["sha256"]) is not str
                        or not _SHA.fullmatch(item["sha256"])):
                    raise ScopeRefusal("invalid interface contract")
                normalize_scope([item["path"]])
            except (ScopeRefusal, KeyError, TypeError) as error:
                raise PublicationRefusal("target:interface_contract_invalid") from error
            contracts.append(dict(item))
        paths = [item["path"] for item in contracts]
        if paths != sorted(set(paths)):
            raise PublicationRefusal("target:interface_contract_invalid")
        return contracts

    def _target_request(self, operation_id, baseline, contracts):
        return {'schema': 'orch-dork/mission-target-read-request/v1', 'operation_id': operation_id,
                'repository': str(self.repository), 'repository_identity': list(self.repository_identity),
                'target_ref': self.target_ref, 'baseline': baseline, 'interface_contracts': contracts,
                'git_executable': self.git_executable, 'timeout_seconds': self.timeout_seconds,
                'identity': self._effect_identity()}

    def _read_target_request(self, directory, operation_id, baseline, contracts):
        raw = _read(directory / 'request.json')
        value = json.loads(raw)
        expected = self._target_request(operation_id, baseline, contracts)
        if (type(value) is not dict or set(value) != {*expected, 'caller'}
                or any(value[name] != item for name, item in expected.items())
                or type(value['caller']) is not dict
                or set(value['caller']) != {'pid', 'ppid', 'pgid', 'start_ticks'}
                or any(type(item) is not int or item < 0 for item in value['caller'].values())
                or not value['caller']['pid'] or not value['caller']['start_ticks']
                or raw != _canonical(value)):
            raise PublicationRefusal('target:request_binding_changed')
        return value, raw

    def _target_values(self, report, read):
        """Interpret the same ordered read protocol live and during recovery."""
        def contract_entry(commit, path):
            raw = read(["ls-tree", "-z", "--full-tree", commit,
                        "--", ":(literal)" + path], binary=True)
            if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
                raise PublicationRefusal("target:interface_contract_changed")
            head, actual_path = raw[:-1].split(b"\t", 1)
            mode, kind, oid = head.decode("ascii").split(" ")
            if (actual_path.decode("utf-8") != path or kind != "blob"
                    or mode not in ("100644", "100755") or not _OID.fullmatch(oid)):
                raise PublicationRefusal("target:interface_contract_changed")
            return mode, oid

        read(["check-ref-format", self.target_ref])
        common = read(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        if common != str(self.repository):
            raise PublicationRefusal("repository:binding_changed")
        commit = read(["rev-parse", "--verify", self.target_ref])
        if not _OID.fullmatch(commit) or read(["cat-file", "-t", commit]) != "commit":
            raise PublicationRefusal("target:commit_required")
        tree = read(["rev-parse", commit + "^{tree}"])
        if not _OID.fullmatch(tree):
            raise PublicationRefusal("target:tree_invalid")
        if report["baseline"] is not None:
            read(["merge-base", "--is-ancestor", report["baseline"], commit])
        for item in report["interface_contracts"]:
            original_entry = contract_entry(report["baseline"], item["path"])
            current_entry = contract_entry(commit, item["path"])
            if current_entry != original_entry:
                raise PublicationRefusal("target:interface_contract_changed")
            raw = read(["cat-file", "blob", current_entry[1]], binary=True)
            actual_sha256 = hashlib.sha256(raw).hexdigest()
            if actual_sha256 != item["sha256"]:
                raise PublicationRefusal("target:interface_contract_changed")
            report["contract_observations"].append({
                "path": item["path"], "sha256": actual_sha256,
                "git_mode": current_entry[0], "blob": current_entry[1]})
        after = self.repository.stat()
        if ((after.st_dev, after.st_ino) != self.repository_identity
                or self.repository.resolve(strict=True) != self.repository):
            raise PublicationRefusal("repository:binding_changed")
        report.update(status="PASS", reason="target:observed", commit=commit, tree=tree)

    def read_target_observation(self, operation_id: str, *, baseline: str | None = None,
                                interface_contracts: list | tuple = ()) -> dict:
        """Reprove original read bytes and physical cleanup without running Git.

        This cannot refresh an old target observation. Missing, changed, partial
        or still-running commands refuse; callers retain completion ownership.
        """
        contracts = self._target_contracts(operation_id, baseline, interface_contracts)
        directory = self.custody / "target-observations" / hashlib.sha256(operation_id.encode()).hexdigest()
        try:
            _check_directory(self.custody)
            _check_directory(directory.parent)
            _check_directory(directory)
            self._read_target_request(directory, operation_id, baseline, contracts)
            raw = _read(directory / "result.json")
            original = json.loads(raw)
            if (_read(directory / "result.sha256") != hashlib.sha256(raw).hexdigest().encode()
                    or raw != _canonical(original)
                    or original.get("operation_id") != operation_id
                    or original.get("schema") != "orch-dork/mission-target-observation/v1"
                    or original.get("repository") != str(self.repository)
                    or original.get("repository_identity") != list(self.repository_identity)
                    or original.get("target_ref") != self.target_ref
                    or original.get("baseline") != baseline
                    or original.get("interface_contracts") != contracts
                    or original.get("publication_authorized") is not False
                    or original.get("evidence_path") != str(directory / "result.json")):
                raise PublicationRefusal("target:observation_changed")
            oversized = original.get("reason") == "target:observation_oversized"
            if oversized:
                # Rows are reread from their original receipts and bound by digest below.
                directories = original.get("command_directories")
                if original["commands"] != [] or type(directories) is not list or any(
                        type(item) is not str for item in directories):
                    raise PublicationRefusal("target:observation_changed")
                rows = [None] * len(directories)
                paths = [Path(item) for item in directories]
            else:
                rows = original["commands"]
                if type(rows) is not list or "command_directories" in original:
                    raise PublicationRefusal("target:commands_invalid")
                paths = [Path(row["command_directory"]) for row in rows]
            if not 1 <= len(rows) <= 6 + 3 * len(contracts):
                raise PublicationRefusal("target:commands_invalid")
            command_root = directory / "commands"
            _check_directory(command_root)
            if (len(set(paths)) != len(paths) or set(command_root.iterdir()) != set(paths)
                    or any(path.parent != command_root for path in paths)):
                raise PublicationRefusal("target:command_inventory_changed")
            replay = {**{key: value for key, value in original.items()
                         if key not in ("command_directories", "commands_sha256")},
                      "commit": None, "tree": None, "contract_observations": [],
                      "status": "UNKNOWN", "reason": "target:observation_incomplete", "commands": []}
            cursor = 0
            cleanup = []

            def read(args, *, binary=False):
                nonlocal cursor
                if cursor >= len(rows):
                    # A read stopped by the aggregate creation budget retained only
                    # its settled prefix; replay reproduces that same refusal.
                    if (original.get("status"), original.get("reason")) == ("UNKNOWN", "target:read_unsettled"):
                        raise PublicationRefusal("target:read_unsettled")
                    raise PublicationRefusal("target:commands_incomplete")
                row, path = rows[cursor], paths[cursor]
                cursor += 1
                _check_directory(path)
                config = json.loads(_read(path / "command.json"))
                if config != {"argv": _git_argv(self.git_executable, str(self.repository), args),
                              "repository": str(self.repository), "stdin_hex": "", "fds": [],
                              "timeout_seconds": self.timeout_seconds}:
                    raise PublicationRefusal("target:command_binding_changed")
                observed = self._outcome(path)
                if (row is not None and observed != row) or not observed["cleanup"]["complete"]:
                    raise PublicationRefusal("target:command_capture_changed")
                cleanup.append(_CommandReadback(observed, tuple(args), config, observed, None))
                replay["commands"].append(observed)
                if observed.get("reason") != "exited":
                    raise PublicationRefusal("target:read_unsettled")
                if observed["exit_code"] != 0:
                    raise PublicationRefusal("target:read_refused")
                return _read(path / "stdout") if binary else observed["stdout"].strip()

            try:
                self._target_values(replay, read)
            except PublicationRefusal as error:
                replay.update(status="UNKNOWN" if str(error) == "target:read_unsettled" else "REFUSED",
                              reason=str(error))
            if cursor != len(rows) or self._retained_target_report(replay) != original:
                raise PublicationRefusal("target:observation_changed")
            self._cleanup_processes(tuple(cleanup))
            return original
        except PublicationRefusal:
            raise
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            raise PublicationRefusal("target:observation_unavailable") from error

    def read_target_cleanup(self, operation_id: str, *, baseline: str | None = None,
                            interface_contracts: list | tuple = ()) -> dict:
        """Observe original read-only command cessation without accepting a target.

        A partial caller must have ceased and every original command must have
        complete retained captures. Missing receipts remain unknown even after
        PID disappearance. No command, repair or replacement is performed.
        Root keeps canonical exclusion through its subsequent settlement intent.
        """
        proof = {'schema': 'orch-dork/mission-target-cleanup-readback/v1', 'operation_id': operation_id,
                 'repository': str(self.repository), 'target_ref': self.target_ref, 'baseline': baseline,
                 'interface_contracts': [], 'request_sha256': None, 'result_sha256': None,
                 'status': 'UNKNOWN', 'resolution': 'UNKNOWN', 'original_status': None,
                 'reason': 'cleanup:unproved', 'commands': [], 'qualification': False}
        try:
            contracts = self._target_contracts(operation_id, baseline, interface_contracts)
            proof['interface_contracts'] = contracts
            parent = self.custody / 'target-observations'
            directory = parent / hashlib.sha256(operation_id.encode()).hexdigest()
            _check_directory(self.custody)
            if not os.path.lexists(directory):
                return {**proof, 'status': 'OBSERVED', 'resolution': 'NO_EFFECT', 'reason': 'cleanup:not_started'}
            _check_directory(parent)
            _check_directory(directory)
            request, raw = self._read_target_request(directory, operation_id, baseline, contracts)
            proof['request_sha256'] = hashlib.sha256(raw).hexdigest()
            # Either retained result file marks a completed read; a missing or
            # replaced result must refuse through the full reader, never fall
            # through to the partial-read path.
            if os.path.lexists(directory / 'result.json') or os.path.lexists(directory / 'result.sha256'):
                original = self.read_target_observation(operation_id, baseline=baseline,
                                                        interface_contracts=contracts)
                return {**proof, 'status': 'OBSERVED', 'resolution': 'CESSATED',
                        'original_status': original['status'], 'reason': 'cleanup:complete',
                        'result_sha256': hashlib.sha256(_read(directory / 'result.json')).hexdigest(),
                        'commands': original['commands']}
            caller = request['caller']
            if any(row['pid'] == caller['pid'] and row['start_ticks'] == caller['start_ticks'] for row in _census()):
                raise PublicationRefusal('cleanup:original_caller_busy')
            command_root = directory / 'commands'
            if os.path.lexists(command_root):
                _check_directory(command_root)
            paths = [] if not os.path.lexists(command_root) else list(command_root.iterdir())
            if not paths:
                # No retained command receipt cannot distinguish a read that never
                # ran a command from one whose receipts are gone; stay unknown.
                raise PublicationRefusal('cleanup:commands_unavailable')
            if len(paths) > 6 + 3 * len(contracts):
                raise PublicationRefusal('cleanup:command_inventory_invalid')
            readbacks = []
            for path in sorted(paths):
                _check_directory(path)
                config = json.loads(_read(path / 'command.json'))
                argv = config['argv']
                prefix = _git_argv(self.git_executable, str(self.repository), [])
                args = argv[len(prefix):]
                if (argv[:len(prefix)] != prefix or config != {
                        'argv': argv, 'repository': str(self.repository), 'stdin_hex': '', 'fds': [],
                        'timeout_seconds': self.timeout_seconds} or not self._target_read_args(args, baseline, contracts)):
                    raise PublicationRefusal('cleanup:command_unowned')
                row = self._outcome(path)
                if (row['cleanup']['complete'] is not True or row.get('capture_complete') is not True
                        or type(row['exit_code']) is not int):
                    raise PublicationRefusal('cleanup:original_capture_unproved')
                readbacks.append(_CommandReadback(row, tuple(args), config, row, None))
            self._cleanup_processes(tuple(readbacks))
            return {**proof, 'status': 'OBSERVED', 'resolution': 'CESSATED', 'reason': 'cleanup:partial_read_ceased',
                    'original_status': 'UNKNOWN', 'commands': [row.report for row in readbacks]}
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            reason = (str(error) if isinstance(error, PublicationRefusal) and str(error)
                      else 'cleanup:unavailable:' + type(error).__name__)
            return {**proof, 'reason': reason}

    def _target_read_args(self, args, baseline, contracts):
        """The closed nonmutating vocabulary for a partial original read."""
        if args in (['check-ref-format', self.target_ref],
                    ['rev-parse', '--path-format=absolute', '--git-common-dir'],
                    ['rev-parse', '--verify', self.target_ref]):
            return True
        if len(args) == 3 and args[0] == 'cat-file' and args[1] in ('-t', 'blob'):
            return bool(_OID.fullmatch(args[2]))
        if len(args) == 2 and args[0] == 'rev-parse' and args[1].endswith('^{tree}'):
            return bool(_OID.fullmatch(args[1][:-7]))
        if len(args) == 4 and args[:2] == ['merge-base', '--is-ancestor']:
            return args[2] == baseline and bool(_OID.fullmatch(args[3]))
        if len(args) == 6 and args[:3] == ['ls-tree', '-z', '--full-tree'] and args[4] == '--':
            return bool(_OID.fullmatch(args[3])) and args[5] in [':(literal)' + item['path'] for item in contracts]
        return False

    def _command(self, directory: Path, args: list[str], data: bytes = b"",
                 fds: tuple[int, ...] = (), *, effect: bool = False,
                 continuation: dict | None = None) -> dict:
        commands = directory / "commands"
        _private_dir(commands)
        command_dir = commands / uuid.uuid4().hex
        _private_dir(command_dir)
        _sync_directory(commands)
        argv = _git_argv(self.git_executable, str(self.repository), args)
        config = {"argv": argv, "repository": str(self.repository), "stdin_hex": data.hex(),
                  "fds": list(fds), "timeout_seconds": self.timeout_seconds}
        if effect:
            config["identity"] = self._effect_identity()
        config_path = command_dir / "command.json"
        config_bytes = _canonical(config)
        _create(config_path, config_bytes)
        if effect:
            _create(directory / ("effect.json" if continuation is None else "continuation.json"), _canonical({
                "command": command_dir.name,
                "command_sha256": hashlib.sha256(config_bytes).hexdigest(),
                **(continuation or {}),
            }))
        helper_streams = [_open(command_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                          for name in ("supervisor.stdout", "supervisor.stderr")]
        try:
            helper = subprocess.Popen(
                [sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                 "--supervise", str(config_path)],
                stdin=subprocess.DEVNULL, stdout=helper_streams[0], stderr=helper_streams[1],
                env=_git_environment(), cwd=directory, start_new_session=True,
                close_fds=True, pass_fds=fds,
            )
        finally:
            for fd in helper_streams:
                os.close(fd)
        try:
            helper.wait(timeout=self.timeout_seconds + 2)
        except subprocess.TimeoutExpired:
            # Its fd copies still hold ownership; no replacement or unlock.
            return {"exit_code": None, "reason": "supervisor_unsettled",
                    "cleanup": {"complete": False}, "command_directory": str(command_dir)}
        _create(command_dir / "supervisor-exit.json", _canonical({"exit_code": helper.returncode}))
        return self._outcome(command_dir, supervisor_exit=helper.returncode)

    def _outcome(self, directory: Path, *, supervisor_exit: int | None = None) -> dict:
        try:
            outcome = json.loads(_read(directory / "outcome.json"))
            cleanup = outcome["cleanup"]
            if (type(cleanup["complete"]) is not bool
                    or type(outcome["capture_complete"]) is not bool
                    or (outcome["exit_code"] is not None and type(outcome["exit_code"]) is not int)
                    or (cleanup["complete"] and (outcome["exit_code"] is None
                        or cleanup["remaining"] != [] or cleanup["group_remaining"] != []))):
                raise PublicationRefusal("custody:cleanup_inconsistent")
            command_bytes = _read(directory / "command.json")
            if (outcome["command_sha256"] != hashlib.sha256(command_bytes).hexdigest()
                    or outcome["argv"] != json.loads(command_bytes)["argv"]
                    or outcome["environment"] != _git_environment()):
                raise PublicationRefusal("custody:command_changed")
            config = json.loads(command_bytes)
            if "identity" in config or "process_identity" in outcome:
                direct, supervisor = outcome["process_identity"], outcome["supervisor_identity"]
                for row in (direct, supervisor, *cleanup["observed"]):
                    if (type(row) is not dict or set(row) != {"pid", "ppid", "pgid", "start_ticks"}
                            or any(type(value) is not int or value < 0 for value in row.values())
                            or not row["pid"] or not row["pgid"] or not row["start_ticks"]):
                        raise PublicationRefusal("custody:process_identity_invalid")
                if (direct["ppid"] != supervisor["pid"] or direct["pgid"] != direct["pid"]
                        or cleanup["pgid"] != direct["pgid"]
                        or any(row["pid"] == direct["pid"] and row != direct
                               for row in cleanup["observed"])):
                    raise PublicationRefusal("custody:cleanup_identity_inconsistent")
            for name in ("stdout", "stderr"):
                raw = _read(directory / name)
                if hashlib.sha256(raw).hexdigest() != outcome[name + "_sha256"]:
                    raise PublicationRefusal("custody:stream_changed")
                outcome[name] = raw.decode("utf-8", "replace")
            if supervisor_exit is None:
                try:
                    receipt = json.loads(_read(directory / "supervisor-exit.json"))
                    if set(receipt) != {"exit_code"} or type(receipt["exit_code"]) is not int:
                        raise PublicationRefusal("custody:supervisor_exit_invalid")
                    supervisor_exit = receipt["exit_code"]
                except FileNotFoundError:
                    pass  # parent loss can leave the independently written outcome
            if cleanup["complete"] and supervisor_exit not in (None, 0):
                raise PublicationRefusal("custody:supervisor_exit_inconsistent")
            outcome["command_directory"] = str(directory)
            outcome["supervisor_exit"] = supervisor_exit
            return outcome
        except (OSError, ValueError, KeyError):
            return {"exit_code": None, "reason": "outcome_unknown",
                    "cleanup": {"complete": False}, "command_directory": str(directory)}

    def _git(self, directory: Path, args: list[str], data: bytes = b"",
             allowed: tuple[int, ...] = (0,)) -> str:
        row = self._command(directory, args, data)
        if (not row["cleanup"]["complete"] or row.get("reason") != "exited"
                or row["exit_code"] not in allowed):
            raise PublicationRefusal("git:validation_failed")
        return row["stdout"].strip()

    def _validate_git(self, request: PublicationRequest, directory: Path) -> None:
        info = self.repository.stat()
        if ((info.st_dev, info.st_ino) != self.repository_identity
                or self.repository.resolve() != self.repository
                or request.repository != str(self.repository)
                or request.target_ref != self.target_ref):
            raise PublicationRefusal("repository:binding_changed")
        for command in self._validation_commands(request):
            actual = self._git(directory, list(command.args), allowed=command.allowed)
            if command.expected is not None and actual != command.expected:
                raise PublicationRefusal(command.refusal_reason)

    def _validation_commands(self, request: PublicationRequest) -> tuple[_ValidationCommand, ...]:
        """The original ordered preflight, also the historical command vocabulary."""
        commands = [
            _ValidationCommand(('rev-parse', '--path-format=absolute', '--git-common-dir'),
                               (0,), request.repository, 'repository:identity_invalid'),
            _ValidationCommand(('rev-parse', '--show-object-format'), (0,),
                               'sha1', 'repository:identity_invalid'),
            _ValidationCommand(('check-ref-format', request.target_ref), (0,), None, None),
        ]
        commands.extend(_ValidationCommand(('symbolic-ref', '-q', ref), (0, 1), '',
                                           'ref:symbolic_forbidden')
                        for ref in (request.target_ref, self.marker_ref(request)))
        commands.extend(_ValidationCommand(('cat-file', '-t', oid), (0,), expected,
                                           'object:type_invalid')
                        for oid, expected in ((request.new_commit, 'commit'), (request.new_tree, 'tree')))
        if request.expected_old != _ZERO:
            commands.append(_ValidationCommand(('cat-file', '-t', request.expected_old), (0,),
                                               'commit', 'object:old_not_commit'))
        commands.append(_ValidationCommand(('rev-parse', request.new_commit + '^{tree}'), (0,),
                                           request.new_tree, 'object:verified_tree_changed'))
        return tuple(commands)

    def _cleanup_plan(self, request: PublicationRequest) -> _CleanupPlan:
        validations = self._validation_commands(request)
        marker_query = ('rev-parse', '--verify', '--quiet', self.marker_ref(request))
        ordinary = frozenset(command.args for command in validations) | {
            ('hash-object', '-w', '--stdin'), marker_query,
            ('rev-parse', '--verify', '--quiet', request.target_ref)}
        return _CleanupPlan(validations, ordinary, marker_query)

    @contextmanager
    def _ownership(self, directory: Path, *, create: bool = True):
        fd = _open(directory / "delivery.lock",
                   os.O_RDWR | os.O_CREAT if create else os.O_RDONLY)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise PublicationRefusal("delivery:busy") from error
            yield fd
        finally:
            # fd-associated lock stays held by inherited helper/Git descriptors.
            os.close(fd)

    def publish(self, request: PublicationRequest) -> dict:
        return self._receive(request, may_start=True)

    def resume(self, request: PublicationRequest) -> dict:
        """Explicit one-continuation seam; never accepts caller cessation facts.

        Only the receiver's complete normal-exit receipt can prove this cut.
        Root still owns claims, completion capacity and canonical authorization.
        Old journals without executable/supervisor/repository identity can be
        historically read, but cannot be continued by this bounded API.
        """
        return self._receive(request, may_start=False, resume=True)

    @staticmethod
    def _cleanup_bytes(path: Path, limit: int = STREAM_LIMIT) -> bytes:
        # Refuse FIFO/device/symlink before an open that could block.
        if not _regular_file_owned(path.lstat()):
            raise PublicationRefusal("custody:file_unsafe")
        return _read(path, limit)

    @staticmethod
    def _cleanup_value(raw: bytes, *, value: dict | None = None) -> dict:
        value = json.loads(raw) if value is None else value
        if type(value) is not dict or _canonical(value) != raw:
            raise PublicationRefusal('cleanup:record_noncanonical')
        return value

    def _cleanup_json(self, path: Path, limit: int = STREAM_LIMIT) -> tuple[bytes, dict]:
        raw = self._cleanup_bytes(path, limit)
        return raw, self._cleanup_value(raw)

    @staticmethod
    def _cleanup_report(value: dict) -> dict:
        result = {**value, "readback_sha256": hashlib.sha256(_canonical(value)).hexdigest()}
        if len(_canonical(result)) > STREAM_LIMIT:
            raise PublicationRefusal("cleanup:report_oversized")
        return result

    def _cleanup_capture(self, command: Path) -> _CommandCapture:
        _check_directory(command)
        required = {'command.json', 'outcome.json', 'stdout', 'stderr',
                    'supervisor.stdout', 'supervisor.stderr'}
        names = {p.name for p in command.iterdir()}
        if not required <= names or names - required - {'supervisor-exit.json'}:
            raise PublicationRefusal('cleanup:command_partial_or_unowned')
        command_raw = self._cleanup_bytes(command / 'command.json')
        outcome_raw, retained = self._cleanup_json(command / 'outcome.json')
        if (set(retained) != {'argv', 'exit_code', 'process_identity', 'supervisor_identity',
                'command_sha256', 'environment', 'reason', 'duration_seconds',
                'capture_complete', 'stdout_sha256', 'stderr_sha256', 'cleanup'}
                or type(retained['cleanup']) is not dict
                or set(retained['cleanup']) != {'complete', 'remaining', 'pgid', 'group_remaining', 'observed'}
                or type(retained['duration_seconds']) not in (float, int)
                or not math.isfinite(retained['duration_seconds']) or retained['duration_seconds'] < 0):
            raise PublicationRefusal('cleanup:outcome_invalid')
        streams = {}
        for name in ('stdout', 'stderr', 'supervisor.stdout', 'supervisor.stderr'):
            raw = self._cleanup_bytes(command / name)
            streams[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
        supervisor_exit_sha = None
        if 'supervisor-exit.json' in names:
            raw, _ = self._cleanup_json(command / 'supervisor-exit.json')
            supervisor_exit_sha = hashlib.sha256(raw).hexdigest()
        return _CommandCapture(command_raw, outcome_raw, streams, supervisor_exit_sha)

    def _cleanup_command(self, request: PublicationRequest, command: Path,
                         plan: _CleanupPlan, *, intent: dict | None) -> _CommandReadback:
        capture = self._cleanup_capture(command)
        marker_object = None
        if intent is not None:
            config, outcome = self._effect(request, command.parent.parent, intent)
            self._cleanup_value(capture.command_bytes, value=config)
            args = tuple(config['argv'][-3:])  # _effect validated the full fixed argv.
            role = 'effect'
        else:
            config = self._cleanup_value(capture.command_bytes)
            prefix = _git_argv(config.get('argv', [None])[0], request.repository, [])
            if (config.get('repository') != request.repository or type(config.get('argv')) is not list
                    or not config['argv'] or type(config['argv'][0]) is not str
                    or not Path(config['argv'][0]).is_absolute()
                    or config['argv'][:len(prefix)] != prefix):
                raise PublicationRefusal('cleanup:command_binding_invalid')
            args = tuple(config['argv'][len(prefix):])
            marker_object = plan.marker_object(args)
            if (set(config) != {'argv', 'repository', 'stdin_hex', 'fds', 'timeout_seconds'}
                    or config['fds'] != []
                    or config['stdin_hex'] != (request.canonical_bytes.hex()
                        if args == ('hash-object', '-w', '--stdin') else '')
                    or type(config['timeout_seconds']) not in (int, float)
                    or not math.isfinite(config['timeout_seconds'])
                    or not 0.05 <= config['timeout_seconds'] <= 10):
                raise PublicationRefusal('cleanup:command_unowned')
            outcome = self._outcome(command)
            role = 'preflight_or_observation'
        if outcome['cleanup'].get('complete') is not True:
            raise PublicationRefusal('cleanup:cessation_unproved')
        report = {'command': command.name, 'role': role,
            'command_sha256': hashlib.sha256(capture.command_bytes).hexdigest(),
            'outcome_sha256': hashlib.sha256(capture.outcome_bytes).hexdigest(),
            'supervisor_exit_sha256': capture.supervisor_exit_sha256, 'streams': capture.streams,
            'exit_code': outcome['exit_code'], 'reason': outcome['reason'],
            'capture_complete': outcome['capture_complete'],
            'process_identity': outcome['process_identity'],
            'supervisor_identity': outcome['supervisor_identity'], 'cleanup': outcome['cleanup']}
        return _CommandReadback(report, args, config, outcome, marker_object)

    def _cleanup_journal(self, request: PublicationRequest, directory: Path,
                         plan: _CleanupPlan) -> _CleanupJournal:
        request_raw, _ = self._cleanup_json(directory / 'request.json', MAX_REQUEST_BYTES)
        if request_raw != request.canonical_bytes:
            raise PublicationRefusal('request:id_conflict')
        names = {p.name for p in directory.iterdir()}
        if names - {'request.json', 'delivery.lock', 'commands', 'effect.json', 'continuation.json'}:
            raise PublicationRefusal('cleanup:operation_unowned')
        commands_root = directory / 'commands'
        _check_directory(commands_root)
        intents = {}
        intent_raw = intent = None
        if 'effect.json' in names:
            intent_raw, intent = self._cleanup_json(directory / 'effect.json')
            if set(intent) != {'command', 'command_sha256'}:
                raise PublicationRefusal('delivery:binding_inconsistent')
            intents[intent['command']] = intent
        continuation_raw = continuation = None
        if 'continuation.json' in names:
            if intent is None:
                raise PublicationRefusal('recovery:chain_inconsistent')
            continuation_raw, continuation = self._cleanup_json(directory / 'continuation.json')
            intents[continuation['command']] = continuation
        commands = []
        observed_markers = set()
        marker_reads = set()
        for count, command in enumerate(sorted(commands_root.iterdir())):
            if count >= STREAM_LIMIT or not re.fullmatch(r'[0-9a-f]{32}', command.name):
                raise PublicationRefusal('cleanup:command_unowned')
            readback = self._cleanup_command(request, command, plan, intent=intents.get(command.name))
            commands.append(readback)
            if readback.args == plan.marker_query:
                marker = readback.outcome['stdout'].strip()
                if (readback.outcome['exit_code'] == 0 and readback.outcome['reason'] == 'exited'
                        and readback.outcome['capture_complete'] and _OID.fullmatch(marker)):
                    observed_markers.add(marker)
            if readback.marker_object is not None:
                marker_reads.add(readback.marker_object)
        by_command = {command.report['command']: command for command in commands}
        if not commands or not intents.keys() <= by_command.keys():
            raise PublicationRefusal('cleanup:commands_unavailable')
        if not marker_reads <= observed_markers:
            raise PublicationRefusal('cleanup:command_unowned')
        if continuation is not None:
            if continuation['command'] == intent['command']:
                raise PublicationRefusal('recovery:chain_inconsistent')
            original = by_command[intent['command']]
            self._continued_effect(request, directory, intent_raw, intent, original.config, original.outcome)
        if intent is None and not self._no_effect_cut(plan, commands):
            raise PublicationRefusal('cleanup:consumed_operation_unproved')
        return _CleanupJournal(request_raw, intent_raw, intent, continuation_raw, continuation, tuple(commands))

    @staticmethod
    def _cleanup_processes(commands: tuple[_CommandReadback, ...]) -> None:
        # Original complete receipts remain mandatory, even when every PID is absent.
        live = {row['pid']: row for row in _census()}
        for readback in commands:
            command = readback.report
            for identity in (command['process_identity'], command['supervisor_identity'],
                             *command['cleanup']['observed']):
                current = live.get(identity['pid'])
                if current and all(current[key] == identity[key] for key in ('pgid', 'start_ticks')):
                    raise PublicationRefusal('cleanup:process_busy')
            if any(row['pgid'] == command['cleanup']['pgid'] for row in live.values()):
                raise PublicationRefusal('cleanup:group_busy')

    def read_cleanup(self, request: PublicationRequest) -> dict:
        """Read original physical cleanup; never authorize, start or accept delivery.

        Complete retained supervisor evidence is mandatory independently of PID
        or marker absence. A consumed request without an effect needs a complete
        original preflight refusal prefix or the legacy full preparation
        inventory. Unowned or partial commands refuse. Original nonaccepting
        outcomes stay unchanged; consuming the request prevents another start.
        """
        base = {"schema": CLEANUP_SCHEMA,
            "status": "UNKNOWN", "resolution": "UNKNOWN", "reason": "cleanup:unproved",
            "operation_id": None, "request_sha256": None, "request_record_sha256": None,
            "effect": None, "continuation": None, "commands": [],
            "retain_claims": True, "qualification": False}
        try:
            if type(request) is not PublicationRequest:
                raise PublicationRefusal("request:closed_type_required")
            request.validate()
            base.update(operation_id=request.operation_id, request_sha256=request.sha256)
            if request.repository != str(self.repository) or request.target_ref != self.target_ref:
                raise PublicationRefusal("repository:binding_changed")
            _check_directory(self.custody)
            directory = self.operation_directory(request)
            _check_directory(directory)
            if not _regular_file_owned((directory / "delivery.lock").lstat()):
                raise PublicationRefusal("custody:file_unsafe")
            with self._ownership(directory, create=False):
                journal = self._cleanup_journal(request, directory, self._cleanup_plan(request))
                self._cleanup_processes(journal.commands)
                return self._cleanup_report({**base, 'status': 'OBSERVED',
                    'resolution': 'CESSATED' if journal.intent is not None else 'NO_EFFECT',
                    'reason': 'cleanup:complete',
                    'request_record_sha256': hashlib.sha256(journal.request_bytes).hexdigest(),
                    'effect': None if journal.intent is None else {
                        'sha256': hashlib.sha256(journal.intent_bytes).hexdigest(), 'record': journal.intent},
                    'continuation': None if journal.continuation is None else {
                        'sha256': hashlib.sha256(journal.continuation_bytes).hexdigest(), 'record': journal.continuation},
                    'commands': [command.report for command in journal.commands]})
        except PublicationRefusal as error:
            base["reason"] = str(error)
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            base["reason"] = "cleanup:unavailable:" + type(error).__name__
        return self._cleanup_report(base)

    def _no_effect_cut(self, plan: _CleanupPlan, receipts: list[_CommandReadback]) -> bool:
        """Recognize original refusal from retained commands, without replaying it."""
        started = Counter(readback.args for readback in receipts)
        preparation = {command.args for command in plan.validations} | {('hash-object', '-w', '--stdin')}
        if not set(started) <= preparation:
            return False
        if preparation <= set(started):
            return True  # Existing journals consumed after the full preflight.
        if not 1 <= len(receipts) <= len(plan.validations):
            return False
        prefix = plan.validations[:len(receipts)]
        if started != Counter(command.args for command in prefix):
            return False
        remaining = list(receipts)
        for command in prefix[:-1]:
            for index, readback in enumerate(remaining):
                outcome = readback.outcome
                if (readback.args == command.args and outcome['reason'] == 'exited'
                        and outcome['capture_complete'] and outcome['exit_code'] in command.allowed
                        and (command.expected is None or outcome['stdout'].strip() == command.expected)):
                    remaining.pop(index)
                    break
            else:
                return False
        command = prefix[-1]
        readback = remaining[0]
        outcome = readback.outcome
        return (readback.args == command.args and outcome['reason'] == 'exited'
                and outcome['capture_complete']
                and ((outcome['exit_code'] > 0 and outcome['exit_code'] not in command.allowed)
                     or (outcome['exit_code'] in command.allowed and command.expected is not None
                         and outcome['stdout'].strip() != command.expected)))

    def reconcile(self, request: PublicationRequest) -> dict:
        """Read historical delivery, without entering current authorization.

        No repository, journal or lock file is created/changed. Bounded read
        commands use private temporary observation scratch, never historical
        custody. Their hooks/environment/cleanup use the same supervisor.
        This does not authorize any effect or release canonical mission claims.
        """
        base = {"status": "UNKNOWN", "reason": "delivery:unsettled", "effect": None,
                "retain_claims": True, "qualification": False}
        try:
            if type(request) is not PublicationRequest:
                raise PublicationRefusal("request:closed_type_required")
            request.validate()
            directory = self.operation_directory(request)
            base.update(operation_id=request.operation_id, request_sha256=request.sha256,
                        marker_ref=self.marker_ref(request))
            _check_directory(directory)
            with self._ownership(directory, create=False):
                if _read(directory / "request.json", MAX_REQUEST_BYTES) != request.canonical_bytes:
                    raise PublicationRefusal("request:id_conflict")
                with tempfile.TemporaryDirectory(prefix="od-publication-observe-") as scratch:
                    observations = Path(scratch)
                    self._validate_git(request, observations)
                    return self._settle(request, directory, base, observations=observations)
        except PublicationRefusal as error:
            # Invalid/different requests refuse. Unavailable or unsafe retained
            # custody/Git observations cannot turn uncertain history into a
            # settled refusal, even though the read command itself refused.
            base.update(reason=str(error), status="REFUSED" if str(error).startswith("request:")
                        else "UNKNOWN")
        except (OSError, ValueError, KeyError, TypeError) as error:
            base["reason"] = "receiver:unavailable:" + type(error).__name__
        return base

    def _receive(self, request: PublicationRequest, *, may_start: bool,
                 resume: bool = False) -> dict:
        base = {"status": "REFUSED", "reason": "request:invalid", "effect": None,
                "retain_claims": True, "qualification": False}
        try:
            if type(request) is not PublicationRequest:
                raise PublicationRefusal("request:closed_type_required")
            request.validate()
            directory = self.operation_directory(request)
            _private_dir(directory)
            _sync_directory(self.custody)
            base.update(operation_id=request.operation_id, request_sha256=request.sha256,
                        marker_ref=self.marker_ref(request))
            with self._ownership(directory) as lock:
                try:
                    retained = _read(directory / "request.json", MAX_REQUEST_BYTES)
                except FileNotFoundError:
                    retained = None
                if retained is not None and retained != request.canonical_bytes:
                    raise PublicationRefusal("request:id_conflict")
                if retained is not None:
                    try:
                        (directory / 'effect.json').lstat()
                    except FileNotFoundError:
                        # Consumption is irreversible even when original cleanup
                        # is incomplete. Only read_cleanup can prove a safe cut.
                        return {**base, 'status': 'UNKNOWN', 'reason':
                            'recovery:cessation_unproved' if resume else 'delivery:consumed_without_effect'}
                with self.authorization_guard(request) as held:
                    if (type(held) is not HeldAuthorization or held.request_sha256 != request.sha256
                            or type(held.fds) is not tuple or not 1 <= len(held.fds) <= 8
                            or len(set(held.fds)) != len(held.fds)):
                        raise PublicationRefusal("authorization:binding_invalid")
                    for fd in held.fds:
                        if type(fd) is not int or fd <= 2 or fd == lock:
                            raise PublicationRefusal("authorization:descriptor_invalid")
                        _require_held_descriptor(fd, lock)
                    if retained is None and may_start:
                        # Consume exactly once under original authority, before
                        # any supervised preflight can fail or lose its parent.
                        _create(directory / "request.json", request.canonical_bytes)
                    self._validate_git(request, directory)
                    if retained is not None or not may_start:
                        result = self._settle(request, directory, base)
                        if not resume or result["status"] == "LANDED":
                            return result
                        if (result["status"] != "REFUSED"
                                or result["reason"] != "git:transaction_refused"):
                            return {**result, "status": "UNKNOWN",
                                    "prior_reason": result["reason"], "reason": "recovery:cessation_unproved"}
                        if (directory / "continuation.json").exists():
                            return {**result, "status": "UNKNOWN", "reason": "recovery:bound_exhausted"}
                        original_bytes = _read(directory / "effect.json")
                        original = json.loads(original_bytes)
                        config, outcome = self._effect(request, directory, original)
                        if (not self._safe_cut(outcome) or config.get("identity") != self._effect_identity()
                                or config["argv"][0] != self.git_executable
                                or config["timeout_seconds"] != self.timeout_seconds):
                            return {**result, "status": "UNKNOWN", "reason": "recovery:identity_or_cut_unproved"}
                        links = self._continuation_links(request, original_bytes, original, directory)
                        marker_oid = self._git(directory, ["hash-object", "-w", "--stdin"], request.canonical_bytes)
                        if marker_oid != self._marker_oid(request):
                            return {**result, "status": "UNKNOWN", "reason": "marker:object_invalid"}
                        self._command(directory, ["update-ref", "--stdin", "--no-deref"],
                                      self._transaction(request, marker_oid), (lock, *held.fds),
                                      effect=True, continuation=links)
                        return self._settle(request, directory, base)
                    marker_oid = self._git(directory, ["hash-object", "-w", "--stdin"], request.canonical_bytes)
                    self._command(directory, ["update-ref", "--stdin", "--no-deref"],
                                  self._transaction(request, marker_oid), (lock, *held.fds), effect=True)
                    return self._settle(request, directory, base)
        except PublicationRefusal as error:
            base["reason"] = str(error)
            if str(error) == "delivery:busy":
                base["status"] = "UNKNOWN"
        except (OSError, ValueError, KeyError, TypeError) as error:
            base.update(status="UNKNOWN", reason="receiver:unavailable:" + type(error).__name__)
        return base

    def _transaction(self, request: PublicationRequest, marker_oid: str) -> bytes:
        return ("start\n"
                f"update {request.target_ref} {request.new_commit} {request.expected_old}\n"
                f"create {self.marker_ref(request)} {marker_oid}\n"
                "prepare\ncommit\n").encode("ascii")

    def _marker_oid(self, request: PublicationRequest) -> str:
        return publication_marker_oid(request)

    def _effect_identity(self) -> dict:
        return {"repository_identity": list(self.repository_identity),
                "executable_sha256": hashlib.sha256(Path(self.git_executable).read_bytes()).hexdigest(),
                "supervisor_sha256": hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()}

    @staticmethod
    def _safe_cut(outcome: dict) -> bool:
        return (outcome["cleanup"]["complete"] and outcome.get("reason") == "exited"
                and outcome.get("capture_complete") and type(outcome["exit_code"]) is int
                and outcome["exit_code"] > 0 and outcome.get("process_identity") is not None
                and outcome.get("supervisor_identity") is not None)

    def _continuation_links(self, request: PublicationRequest, original_bytes: bytes,
                            original: dict, directory: Path) -> dict:
        return {"request_sha256": request.sha256,
                "original_effect_sha256": hashlib.sha256(original_bytes).hexdigest(),
                "original_command_sha256": original["command_sha256"],
                "previous_outcome_sha256": hashlib.sha256(_read(
                    directory / "commands" / original["command"] / "outcome.json")).hexdigest()}

    def _effect(self, request: PublicationRequest, directory: Path, intent: dict) -> tuple[dict, dict]:
        command = intent["command"]
        if type(command) is not str or not re.fullmatch(r"[0-9a-f]{32}", command):
            raise PublicationRefusal("delivery:binding_inconsistent")
        command_dir = directory / "commands" / command
        _check_directory(directory / "commands")
        _check_directory(command_dir)
        config_bytes = _read(command_dir / "command.json")
        config = json.loads(config_bytes)
        keys = {"argv", "repository", "stdin_hex", "fds", "timeout_seconds"}
        if "identity" in config:
            keys.add("identity")
        if (set(config) != keys
                or hashlib.sha256(config_bytes).hexdigest() != intent["command_sha256"]
                or config["repository"] != request.repository
                or type(config["argv"]) is not list or not config["argv"]
                or not Path(config["argv"][0]).is_absolute()
                or config["argv"] != _git_argv(config["argv"][0], request.repository,
                                               ["update-ref", "--stdin", "--no-deref"])
                or config["stdin_hex"] != self._transaction(request, self._marker_oid(request)).hex()
                or type(config["fds"]) is not list or not 2 <= len(config["fds"]) <= 9
                or any(type(fd) is not int or fd <= 2 for fd in config["fds"])
                or len(set(config["fds"])) != len(config["fds"])
                or type(config["timeout_seconds"]) not in (float, int)
                or not math.isfinite(config["timeout_seconds"])
                or not 0.05 <= config["timeout_seconds"] <= 10):
            raise PublicationRefusal("delivery:binding_inconsistent")
        if "identity" in config:
            identity = config["identity"]
            if (set(identity) != {"repository_identity", "executable_sha256", "supervisor_sha256"}
                    or identity["repository_identity"] != list(self.repository_identity)
                    or not _SHA.fullmatch(identity["executable_sha256"])
                    or not _SHA.fullmatch(identity["supervisor_sha256"])):
                raise PublicationRefusal("delivery:binding_inconsistent")
        return config, self._outcome(command_dir)

    def _continued_effect(self, request, directory, original_bytes, intent, config, outcome):
        """Validate the one original continuation chain for either readback."""
        try:
            continuation = json.loads(_read(directory / "continuation.json"))
        except FileNotFoundError:
            return None
        links = self._continuation_links(request, original_bytes, intent, directory)
        if (set(continuation) != {"command", "command_sha256", *links}
                or any(continuation[key] != value for key, value in links.items())
                or not self._safe_cut(outcome)):
            raise PublicationRefusal("recovery:chain_inconsistent")
        next_config, next_outcome = self._effect(request, directory, continuation)
        if ({key: value for key, value in config.items() if key != "fds"}
                != {key: value for key, value in next_config.items() if key != "fds"}):
            raise PublicationRefusal("recovery:chain_inconsistent")
        return next_outcome

    def _settle(self, request: PublicationRequest, directory: Path, base: dict,
                *, observations: Path | None = None) -> dict:
        result = {**base, "status": "UNKNOWN", "reason": "delivery:unsettled"}
        observations = directory if observations is None else observations
        try:
            if _read(directory / "request.json", MAX_REQUEST_BYTES) != request.canonical_bytes:
                return result
            original_bytes = _read(directory / "effect.json")
            intent = json.loads(original_bytes)
            if set(intent) != {"command", "command_sha256"}:
                return result
            config, outcome = self._effect(request, directory, intent)
            result["effect"] = outcome
            try:
                next_outcome = self._continued_effect(request, directory, original_bytes, intent, config, outcome)
            except PublicationRefusal as error:
                if str(error) != "recovery:chain_inconsistent":
                    raise
                return {**result, "reason": str(error)}
            if next_outcome is not None:
                result["original_effect"] = outcome
                outcome = next_outcome
                result["effect"] = outcome
            if (not outcome["cleanup"]["complete"] or outcome.get("reason") != "exited"
                    or not outcome.get("capture_complete")):
                return result
            marker = self._git(observations, ["rev-parse", "--verify", "--quiet", self.marker_ref(request)], allowed=(0, 1))
            target = self._git(observations, ["rev-parse", "--verify", "--quiet", request.target_ref], allowed=(0, 1))
            if target and not _OID.fullmatch(target):
                return {**result, "reason": "target:observation_invalid"}
            result.update(current_target_oid=target or None, observed_marker_oid=marker or None,
                          target_marker_snapshot_atomic=False)
            if marker:
                if self._git(observations, ["cat-file", "-t", marker]) != "blob":
                    return {**result, "reason": "marker:conflict"}
                # No strip: marker binds every complete immutable request byte.
                row = self._command(observations, ["cat-file", "blob", marker])
                if (row["exit_code"] != 0 or not row["cleanup"]["complete"]
                        or row.get("reason") != "exited"
                        or row["stdout"].encode() != request.canonical_bytes):
                    return {**result, "reason": "marker:conflict"}
                return {**result, "status": "LANDED", "reason": "marker:exact",
                        "landed_commit": request.new_commit, "landed_tree": request.new_tree}
            if outcome["exit_code"] != 0:
                return {**result, "status": "REFUSED", "reason": "git:transaction_refused"}
            return {**result, "reason": "marker:missing_after_exit"}
        except (OSError, ValueError, KeyError, TypeError):
            return result


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--supervise":
        raise SystemExit(_supervise(Path(sys.argv[2])))
    raise SystemExit("No public CLI; use the required trusted host guard/context.")
