"""Trusted-host exact diff staging; bounded Issue225 component, no admission.

Only the canonical repository's content-addressed objects may be added. Git
uses an isolated index in an existing private directory outside source,
workspace and delivery custody. No target ref, checkout or source index is
written. Root supplies already collected bytes and owns provenance, policy,
canonical sealing and later verification/publication authority.

The existing fixed action-host capture observes physical process identities
and bounds each stream. Its literal cleanup=True is required; uncertainty
retains UNKNOWN, never a replacement operation. Eight seconds of the fixed
ten-second command budget are reserved for that helper's worst cleanup path.
The trusted host's bounded regular-file I/O is not a new killable executor.
Retained records are private/create-only delivery evidence, not a second
mission owner or a signature against an actor with the same host uid.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time


import orch_dork_mission_publication as publication
from orch_dork_evidence_core import legacy_ascii_bytes
from lifecycle_conformance import action_host
import orch_dork_mission_scope as mission_scope
from orch_dork_mission_scope import ScopeRefusal, normalize_scope, path_in_scope

LIMIT = 65_536
TOTAL_SECONDS = 10.0
_CLEANUP_RESERVE = 8.0
_REQUEST_BINDING_FIELDS = ("repository", "baseline", "diff_sha256", "policy_sha256", "scope")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT = shutil.which("git", path=publication._system_path()) if publication._system_path() else None
if _GIT is not None:
    _GIT = str(Path(_GIT).resolve(strict=True))
_IDENTITY = {
    "GIT_AUTHOR_NAME": "Orch Dork Candidate", "GIT_AUTHOR_EMAIL": "candidate@invalid",
    "GIT_COMMITTER_NAME": "Orch Dork Candidate", "GIT_COMMITTER_EMAIL": "candidate@invalid",
    "GIT_AUTHOR_DATE": "946684800 +0000", "GIT_COMMITTER_DATE": "946684800 +0000",
}


class StagingRefusal(ValueError):
    """Closed input/configuration changed or is unsafe; no candidate authority."""


class StagingBusy(StagingRefusal):
    """The original operation is held; its evidence is not yet readable."""

    reason = "operation:busy"

    def __init__(self):
        super().__init__(self.reason)


class _End(Exception):
    def __init__(self, status, reason):
        self.status, self.reason = status, reason


def _canonical(value: dict) -> bytes:
    return legacy_ascii_bytes(value, limit=LIMIT,
                              refusal=StagingRefusal("custody:record_oversized"))


def _request_fields(request) -> dict:
    """Project the five bounding fields shared by StagingRequest/StagingResult.

    Kept flat at top level so ``asdict(result)`` stays wire-compatible with the
    frozen 55a1ed0 receipt shape; this single projection replaces the prior
    in-line ``binding.pop``/loop duplication in ``_result`` and the manual
    re-projection in ``_retained``.
    """
    source = asdict(request) if type(request) is StagingRequest else {}
    return {name: source.get(name, () if name == "scope" else "")
            for name in _REQUEST_BINDING_FIELDS}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _oid(kind: str, raw: bytes) -> str:
    return hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def _directory(value, *, private=False) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise StagingRefusal("input:path_alias")
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or private and stat.S_IMODE(info.st_mode) != 0o700):
        raise StagingRefusal("custody:directory_unsafe")
    return path


def _collected_workspace(value) -> Path:
    """Bind a workspace identity after collection may have removed its leaf.

    The existing canonical parent is still required. No directory is created,
    a symlink or unsafe existing leaf still refuses, and this identity grants
    no permission to recreate a worker workspace.
    """
    path = Path(value)
    if os.path.lexists(path):
        return _directory(path)
    _directory(path.parent)
    return path


def _overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _existing_file(path: Path):
    # Pre-open: refuse FIFO/device/symlink before the blocking open; the
    # receiver's post-open fd check still re-applies the same predicate
    # through publication._regular_file_owned against tampering.
    if not publication._regular_file_owned(path.lstat()):
        raise StagingRefusal("custody:file_unsafe")


def _read(path: Path) -> bytes:
    _existing_file(path)
    return publication._read(path)


def _pin(path: Path) -> dict:
    path = path.resolve(strict=True)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise StagingRefusal("runtime:nonregular")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while raw := stream.read(LIMIT):
            digest.update(raw)
    after = path.stat()
    if (info.st_dev, info.st_ino, info.st_ctime_ns, info.st_size) != (
            after.st_dev, after.st_ino, after.st_ctime_ns, after.st_size):
        raise StagingRefusal("runtime:changed")
    return {"path": str(path), "sha256": digest.hexdigest(), "device": info.st_dev,
            "inode": info.st_ino, "ctime_ns": info.st_ctime_ns, "size": info.st_size}


@dataclass(frozen=True)
class StagingRequest:
    operation_id: str
    repository: str
    baseline: str
    diff_sha256: str
    policy_sha256: str
    scope: tuple[str, ...] = (".",)

    def validate(self):
        if (type(self.operation_id) is not str or not _ID.fullmatch(self.operation_id)
                or type(self.repository) is not str or str(Path(self.repository)) != self.repository
                or type(self.baseline) is not str or not _SHA1.fullmatch(self.baseline)
                or type(self.diff_sha256) is not str or not _SHA256.fullmatch(self.diff_sha256)
                or type(self.policy_sha256) is not str or not _SHA256.fullmatch(self.policy_sha256)
                or type(self.scope) is not tuple):
            raise StagingRefusal("request:invalid")
        try:
            if normalize_scope(self.scope) != self.scope:
                raise ScopeRefusal("scope is not canonical")
        except ScopeRefusal as error:
            raise StagingRefusal("request:invalid_scope") from error
        _directory(self.repository)


@dataclass(frozen=True)
class StagingResult:
    status: str
    reason: str
    repository: str
    baseline: str
    diff_sha256: str
    policy_sha256: str
    scope: tuple[str, ...]
    commit: str | None = None
    tree: str | None = None
    evidence_path: str | None = None
    qualification: bool = False
    retain_claims: bool = True


class CandidateStager:
    """Trusted Root input only. Exact retries read; partial operations never rerun.

    Root provisions private custody/index roots. The index root must be outside
    custody, source and workspace. No directories are provisioned by construction.
    A create-only operation directory is the cross-process start claim; parent
    loss cannot turn its existence into permission to start again.
    """

    def __init__(self, custody, *, index_root, source_root, workspace_root):
        self.custody = _directory(custody, private=True)
        self.index_root = _directory(index_root, private=True)
        self.source_root = _directory(source_root)
        self.workspace_root = _collected_workspace(workspace_root)
        for private in (self.custody, self.index_root):
            for exposed in (self.source_root, self.workspace_root):
                if _overlap(private, exposed):
                    raise StagingRefusal("custody:source_overlap")
        if _overlap(self.custody, self.index_root):
            raise StagingRefusal("index:custody_overlap")
        if _GIT is None:
            raise StagingRefusal("git:unavailable")

    def operation_directory(self, request: StagingRequest) -> Path:
        return self.custody / _sha(request.operation_id.encode("ascii"))

    def _validate_input(self, request, diff):
        if type(request) is not StagingRequest:
            raise StagingRefusal("request:closed_type_required")
        request.validate()
        if type(diff) is not bytes or not 0 < len(diff) <= LIMIT:
            raise StagingRefusal("diff:bounds")
        if _sha(diff) != request.diff_sha256:
            raise StagingRefusal("diff:digest_mismatch")
        for path in (self.custody, self.index_root):
            _directory(path, private=True)
        self._repository(request)

    def read_staged_evidence(self, request: StagingRequest, diff: bytes) -> tuple[StagingResult, bytes]:
        """Revalidate the original STAGED result and exact journal without effects.

        Uses the same closed inputs, configuration/source binding and retained
        command/stream proof as stage's retry. A held operation raises
        StagingBusy with stage's operation:busy reason. Missing, partial,
        changed or non-STAGED evidence refuses without creating a replacement.
        Journal bytes are returned from the same held read lock as their proof.
        This is trusted host evidence, never verification or qualification.
        """
        try:
            self._validate_input(request, diff)
            binding = _canonical(self._binding(request))
            result, raw = self._retained_evidence(
                self.operation_directory(request), request, diff, binding)
        except StagingRefusal:
            raise
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise StagingRefusal("evidence:unavailable_or_changed") from error
        if raw is None and result.reason == StagingBusy.reason:
            raise StagingBusy()
        if result.status != "STAGED" or raw is None:
            raise StagingRefusal("evidence:staging_unproved")
        return result, raw

    def _binding(self, request):
        return {"request": asdict(request), "configuration": {
            "custody": str(self.custody), "index_root": str(self.index_root),
            "source_root": str(self.source_root), "workspace_root": str(self.workspace_root),
            "git": _pin(Path(_GIT)), "total_seconds": TOTAL_SECONDS,
            "cleanup_reserve_seconds": _CLEANUP_RESERVE, "stream_limit": LIMIT,
            "identity": _IDENTITY, "runtime": [_pin(Path(p)) for p in
                (__file__, publication.__file__, action_host.__file__, mission_scope.__file__)],
        }}

    def read_cleanup(self, request: StagingRequest, diff: bytes) -> dict:
        """Read the original bounded stage's cessation, preserving its verdict.

        Complete original captures are required for every owned command. A
        partial or busy operation remains unknown; no Git command is executed
        and no journal or index is repaired. Root holds canonical exclusion
        while using NO_EFFECT for an operation that never started.
        """
        proof = {'schema': 'orch-dork/candidate-staging-cleanup-readback/v1',
                 'operation_id': None, 'request_sha256': None, 'binding_sha256': None,
                 'status': 'UNKNOWN', 'resolution': 'UNKNOWN', 'reason': 'cleanup:unproved',
                 'original_status': None, 'result_sha256': None, 'commands': [],
                 'qualification': False}
        try:
            self._validate_input(request, diff)
            binding = _canonical(self._binding(request))
            proof.update(operation_id=request.operation_id,
                         request_sha256=_sha(_canonical(asdict(request))), binding_sha256=_sha(binding))
            directory = self.operation_directory(request)
            if not os.path.lexists(directory):
                return {**proof, 'status': 'OBSERVED', 'resolution': 'NO_EFFECT', 'reason': 'cleanup:not_started'}
            result, raw = self._retained_evidence(directory, request, diff, binding)
            if raw is None:
                raise StagingBusy()
            retained = json.loads(raw)
            commands = retained['commands']
            command_root = directory / 'commands'
            _directory(command_root, private=True)
            paths = [Path(row['command_directory']) for row in commands]
            if (len(paths) != len(set(paths)) or set(paths) != set(command_root.iterdir())
                    or any(row['cleanup'] is not True or type(row['exit_code']) is not int
                           for row in commands)):
                raise StagingRefusal('cleanup:original_commands_unproved')
            return {**proof, 'status': 'OBSERVED', 'resolution': 'CESSATED', 'reason': 'cleanup:complete',
                    'original_status': result.status, 'result_sha256': _sha(raw), 'commands': commands}
        except (OSError, ValueError, KeyError, TypeError) as error:
            # A held operation stays distinguishable from unreadable custody.
            if isinstance(error, StagingBusy):
                reason = StagingBusy.reason
            elif isinstance(error, StagingRefusal) and str(error):
                reason = str(error)
            else:
                reason = 'cleanup:unavailable:' + type(error).__name__
            return {**proof, 'reason': reason}

    def _repository(self, request):
        repo = _directory(request.repository)
        if _overlap(repo, self.custody) or _overlap(repo, self.index_root):
            raise StagingRefusal("repository:custody_overlap")
        _directory(repo / "objects")
        for name in ("objects/info", "objects/pack"):
            if os.path.lexists(repo / name):
                _directory(repo / name)
        for name in ("commondir", "objects/info/alternates", "objects/info/http-alternates"):
            if os.path.lexists(repo / name):
                raise StagingRefusal("repository:control_redirection")
        info = (repo / "config").lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1):
            raise StagingRefusal("repository:config_unsafe")
        return repo

    def _result(self, request, status="UNKNOWN", reason="operation:incomplete", **fields):
        return StagingResult(status=status, reason=reason,
                             **_request_fields(request), **fields)

    def _retained(self, directory, request, diff, binding):
        return self._retained_evidence(directory, request, diff, binding)[0]

    def _retained_evidence(self, directory, request, diff, binding):
        _directory(directory, private=True)
        _existing_file(directory / "operation.lock")
        lock = publication._open(directory / "operation.lock", os.O_RDONLY | os.O_NONBLOCK)
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return self._result(request, reason=StagingBusy.reason), None
            if _read(directory / "request.json") != binding:
                raise StagingRefusal("request:id_conflict")
            if _read(directory / "diff.patch") != diff:
                raise StagingRefusal("diff:retained_changed")
            raw = _read(directory / "result.json")
            if _read(directory / "result.sha256") != _sha(raw).encode():
                raise StagingRefusal("evidence:changed")
            retained = json.loads(raw)
            if retained["binding_sha256"] != _sha(binding):
                raise StagingRefusal("evidence:binding_changed")
            for row in retained["commands"]:
                command = Path(row["command_directory"])
                if command.parent != directory / "commands":
                    raise StagingRefusal("evidence:path_changed")
                _directory(command, private=True)
                if _sha(_read(command / "command.json")) != row["config_sha256"]:
                    raise StagingRefusal("evidence:command_changed")
                if json.loads(_read(command / "outcome.json")) != row:
                    raise StagingRefusal("evidence:outcome_changed")
                for stream in ("stdout", "stderr"):
                    if _sha(_read(command / stream)) != row[stream + "_sha256"]:
                        raise StagingRefusal("evidence:stream_changed")
            result = retained["result"]
            result["scope"] = tuple(result["scope"])
            expected = self._result(request, result["status"], result["reason"],
                                    commit=result["commit"], tree=result["tree"],
                                    evidence_path=str(directory / "result.json"))
            if result != asdict(expected):
                raise StagingRefusal("evidence:result_changed")
            if expected.status == "STAGED":
                if (not _SHA1.fullmatch(expected.commit or "") or not _SHA1.fullmatch(expected.tree or "")
                        or not retained["commands"] or any(row["cleanup"] is not True
                        or row["exit_code"] != 0 or row["termination_reason"] is not None
                        for row in retained["commands"])):
                    raise StagingRefusal("evidence:staging_unproved")
            return expected, raw
        finally:
            os.close(lock)

    def _run(self, directory, args, environment, deadline, commands, *, invalid=False):
        remaining = deadline - time.monotonic() - _CLEANUP_RESERVE
        if remaining <= 0:
            raise _End("UNKNOWN", "git:budget_exhausted")
        timeout = min(remaining, TOTAL_SECONDS - _CLEANUP_RESERVE)
        command = directory / "commands" / f"{len(commands) + 1:02d}"
        command.mkdir(mode=0o700)
        argv = [_GIT, "--no-optional-locks", "--git-dir=" + environment["GIT_COMMON_DIR"],
                "-c", "core.hooksPath=" + os.devnull, "-c", "core.fsmonitor=false",
                "-c", "core.bare=true", "-c", "commit.gpgsign=false",
                "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args]
        config = _canonical({"argv": argv, "environment": environment, "timeout_seconds": timeout})
        publication._create(command / "command.json", config)
        started = time.monotonic()
        observed = action_host._FIXED_RUN_PREFLIGHT_PROCESS(
            argv, cwd=directory, environment=environment, timeout_seconds=timeout)
        streams = {name: observed[name] for name in ("stdout", "stderr")}
        if any(type(raw) is not bytes or len(raw) > LIMIT for raw in streams.values()):
            raise _End("UNKNOWN", "git:capture_unproved")
        for name, raw in streams.items():
            publication._create(command / name, raw)
        row = {"command_directory": str(command), "argv": argv,
               "config_sha256": _sha(config), "exit_code": observed["exit_code"],
               "termination_reason": observed["termination_reason"], "cleanup": observed["cleanup"],
               "duration_seconds": time.monotonic() - started,
               **{name + "_sha256": _sha(raw) for name, raw in streams.items()}}
        publication._create(command / "outcome.json", _canonical(row))
        commands.append(row)
        if observed["cleanup"] is not True:
            raise _End("UNKNOWN", "git:cleanup_unproved")
        if observed["termination_reason"] is not None or time.monotonic() > deadline:
            raise _End("UNKNOWN", "git:execution_unsettled")
        if type(observed["exit_code"]) is not int:
            raise _End("UNKNOWN", "git:exit_unproved")
        if observed["exit_code"] != 0:
            raise _End("REFUSED" if invalid else "FAILED", "git:command_failed")
        return streams["stdout"]

    def stage(self, request: StagingRequest, diff: bytes) -> StagingResult:
        """Stage once or return exact retained evidence; never update any ref."""
        directory, lock, commands, binding = None, None, [], None
        deadline = time.monotonic() + TOTAL_SECONDS
        result = self._result(request)
        owned = False
        try:
            self._validate_input(request, diff)
            binding = _canonical(self._binding(request))
            directory = self.operation_directory(request)
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                return self._retained(directory, request, diff, binding)
            owned = True
            publication._sync_directory(self.custody)
            lock = publication._open(directory / "operation.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            publication._create(directory / "request.json", binding)
            publication._create(directory / "diff.patch", diff)
            indexes = self.index_root / directory.name
            indexes.mkdir(mode=0o700)
            _directory(indexes, private=True)
            publication._sync_directory(self.index_root)
            (directory / "commands").mkdir(mode=0o700)
            environment = {**publication._git_environment(), **_IDENTITY,
                           "GIT_INDEX_FILE": str(indexes / "index"),
                           "GIT_COMMON_DIR": request.repository,
                           "GIT_OBJECT_DIRECTORY": str(Path(request.repository) / "objects"),
                           "GIT_ALTERNATE_OBJECT_DIRECTORIES": "", "GIT_NO_LAZY_FETCH": "1"}
            def git(*args, invalid=False):
                return self._run(directory, list(args), environment, deadline, commands, invalid=invalid)
            if git("rev-parse", "--path-format=absolute", "--git-common-dir", invalid=True).decode().strip() != request.repository:
                raise StagingRefusal("repository:git_binding")
            if git("rev-parse", "--show-object-format", invalid=True) != b"sha1\n":
                raise StagingRefusal("repository:sha1_required")
            baseline = git("cat-file", "commit", request.baseline, invalid=True)
            if _oid("commit", baseline) != request.baseline:
                raise StagingRefusal("baseline:bytes_changed")
            original_tree = git("rev-parse", request.baseline + "^{tree}", invalid=True).decode().strip()
            git("read-tree", request.baseline)
            index = indexes / "index"
            info = index.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise StagingRefusal("index:unsafe")
            git("apply", "--cached", "--binary", "--whitespace=nowarn", "--", str(directory / "diff.patch"))
            tree = git("write-tree").decode().strip()
            if not _SHA1.fullmatch(tree):
                raise StagingRefusal("candidate:tree_invalid")
            if tree == original_tree:
                raise StagingRefusal("candidate:no_change")
            # Compare actual resulting paths, including both sides of renames,
            # rather than trusting a patch header or a worker's scope claim.
            if request.scope != (".",):
                changed = git("diff-tree", "--no-commit-id", "--name-only", "-r",
                              "-z", "--no-renames", request.baseline, tree)
                try:
                    paths = changed.decode("utf-8").split("\0")
                    if paths.pop() != "" or not paths or any(
                            not path_in_scope(path, request.scope) for path in paths):
                        raise ScopeRefusal("candidate changed paths outside the admitted scope")
                except (UnicodeDecodeError, ScopeRefusal) as error:
                    raise StagingRefusal("candidate:scope_violation") from error
            raw_tree = git("cat-file", "tree", tree)
            if _oid("tree", raw_tree) != tree:
                raise StagingRefusal("candidate:tree_bytes_changed")
            commit = git("commit-tree", tree, "-p", request.baseline, "-m", "Orch Dork staged candidate").decode().strip()
            if not _SHA1.fullmatch(commit):
                raise StagingRefusal("candidate:commit_invalid")
            raw_commit = git("cat-file", "commit", commit)
            if (_oid("commit", raw_commit) != commit or not raw_commit.startswith(
                    b"tree " + tree.encode() + b"\nparent " + request.baseline.encode() + b"\n")
                    or raw_commit.split(b"\n\n", 1)[0].count(b"\nparent ") != 1):
                raise StagingRefusal("candidate:commit_bytes_changed")
            result = self._result(request, "STAGED", "candidate:exact", commit=commit, tree=tree,
                                  evidence_path=str(directory / "result.json"))
        except (StagingRefusal, publication.PublicationRefusal) as error:
            result = self._result(request, "REFUSED", str(error))
        except _End as error:
            result = self._result(request, error.status, error.reason)
        except (OSError, ValueError, KeyError, TypeError) as error:
            result = self._result(request, reason="operation:unavailable:" + type(error).__name__)
        finally:
            if owned and binding is not None:
                try:
                    result = self._result(request, result.status, result.reason, commit=result.commit,
                                          tree=result.tree, evidence_path=str(directory / "result.json"))
                    raw = _canonical({"schema": "orch-dork/candidate-staging/v1", "binding_sha256": _sha(binding),
                                 "result": asdict(result), "commands": commands})
                    publication._create(directory / "result.json", raw)
                    publication._create(directory / "result.sha256", _sha(raw).encode())
                except (OSError, ValueError):
                    result = self._result(request, reason="operation:receipt_incomplete")
            if lock is not None:
                os.close(lock)
        return result
