"""Protected exact-candidate verification, a bounded Issue225 component.

Trusted host input pins an enrolled policy outside candidate control. Structural
Python checks see only read-only staged files. Each behavioral check runs the
candidate separately, then its independent oracle sees only externally collected
raw streams and factual exit metadata, with NO candidate code mounted. Candidate
exit zero or self-reported success cannot accept a candidate.

Linux x86-64 / Debian Python3.12/bubblewrap policy only, no dependencies installed.
Candidates contain bounded regular files only, without empty Git subtrees;
each Git object/stream and the sealed evidence record is at most 65,536 bytes.
Fresh namespaces, minimal system mounts, no procfs/home/controller/Git/target or
custody mounts, no inherited host file descriptors, no network and a finite
scratch tmpfs. CPU/address-space/process/file limits are inherited per process;
NPROC is a kernel per-UID bound, not a dedicated mission cgroup allocation.
An outer dedicated subreaper collects original bounded streams, actual exits,
physical process identities and descendant/group cessation. The existing local
receiver supplies its small Linux census/pidfd/private-record primitives only.

Evidence is create-only/fsynced and digest-bound, NOT signed or proof against a
host actor with the same uid. Root must protect enrollment, executables and host
custody and join the exact evidence to canonical current mission authority,
staging/completion capacity and receiver authorization. This component performs
no admission, publication, tracker edit, installation or qualification. Hashes
detect input changes; namespace mounts prevent candidate access. Trusted host
mutation followed by restoration between observations is outside this contract.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ctypes
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import selectors
import shutil
import stat
import subprocess
import sys
import time
import uuid

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import orch_dork_mission_publication as local
import orch_dork_evidence_core as evidence_core

CLEANUP_SCHEMA = 'orch-dork/protected-verification-cleanup/v1'

REQUEST_SCHEMA = "orch-dork/protected-verification-request/v1"
EVIDENCE_SCHEMA = "orch-dork/protected-verification-evidence/v1"
POLICY_SCHEMA = "orch-dork/protected-python-policy/v1"
STREAM_LIMIT = 65_536
MAX_FILES = 128
MAX_CANDIDATE_BYTES = 1_048_576
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FS_ROOT = os.path.abspath(os.sep)
_PYTHON = os.path.join(_FS_ROOT, "usr", "bin", "python3.12")
_SANDBOX_PYTHON = os.path.join(_FS_ROOT, "usr", "bin", "python3")
_STDLIB = os.path.join(_FS_ROOT, "usr", "lib", "python3.12")
_LOADER = os.path.join(_FS_ROOT, "lib64", "ld-linux-x86-64.so.2")
_LIBRARY = os.path.join(_FS_ROOT, "lib", "x86_64-linux-gnu")
_BWRAP = os.path.join(_FS_ROOT, "usr", "bin", "bwrap")
_GIT_SEARCH_PATH = os.pathsep.join(part for part in os.defpath.split(os.pathsep)
                                 if part and os.path.isabs(part))
_GIT = shutil.which("git", path=_GIT_SEARCH_PATH) if _GIT_SEARCH_PATH else None
_DEV = os.path.join(_FS_ROOT, "dev")
_LIMIT_RUNNER = b"""import os, resource, runpy, sys
soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
value = min([int(sys.argv[1]), *[v for v in (soft,hard) if v != resource.RLIM_INFINITY]])
resource.setrlimit(resource.RLIMIT_NPROC, (value,value))
script = sys.argv[2]
if script.startswith('/candidate/'):
    # Restore ordinary script-local imports only inside the candidate sandbox.
    sys.path.insert(0, os.path.dirname(script))
    sys.argv = [script]
    runpy.run_path(script, run_name='__main__')
else:
    # Protected checks retain their original isolated interpreter and path.
    python = os.path.join(os.path.abspath(os.sep), 'usr', 'bin', 'python3')
    os.execv(python, [python,'-I','-S','-B',script])
"""
_MOUNTS = (
    (_PYTHON, _SANDBOX_PYTHON), (_STDLIB, _STDLIB), (_LOADER, _LOADER),
    *((os.path.join(_LIBRARY, name), os.path.join(_LIBRARY, name))
      for name in ("libc.so.6", "libm.so.6", "libz.so.1", "libexpat.so.1")),
)


class VerificationRefusal(ValueError):
    """Invalid or changed trusted input; never a successful verification."""


def _existing_private_dir(path: Path):
    """Validate existing custody without provisioning or following aliases."""
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or path.resolve(strict=True) != path):
        raise VerificationRefusal("custody:directory_unsafe")


def _canonical(value: dict) -> bytes:
    return evidence_core.legacy_ascii_bytes(value)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _environment() -> dict[str, str]:
    # Closed host environment; neither ambient PATH nor Git/Python/loader
    # redirection is inherited. Preserve the receiver's closed boundary PATH;
    # the filtered platform default is used only for absolute Git discovery.
    return {**local._git_environment(), "GIT_NO_LAZY_FETCH": "1"}


def _git_oid(kind: str, raw: bytes) -> str:
    return hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def _tree_oid(manifest: dict) -> str:
    """Reconstruct every subtree from staged paths/modes/verified blob OIDs."""
    tree = {}
    for name, row in manifest.items():
        node = tree
        parts = name.split("/")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = (row["git_mode"], row["blob"])

    def digest(node):
        entries = []
        for name, value in node.items():
            if isinstance(value, tuple):
                mode, oid = value
                sort_name = name
            else:
                mode, oid, sort_name = "40000", digest(value), name + "/"
            raw = mode.encode() + b" " + name.encode("ascii") + b"\0" + bytes.fromhex(oid)
            entries.append((sort_name.encode("ascii"), raw))
        return _git_oid("tree", b"".join(raw for _, raw in sorted(entries)))
    return digest(tree)


def _path(value: str) -> str:
    if (type(value) is not str or len(value) > 240
            or not re.fullmatch(r"[A-Za-z0-9_.\-/]+", value)
            or any(part in ("", ".", "..", ".git") for part in value.split("/"))):
        raise VerificationRefusal("input:path_invalid")
    return value


def verification_policy_digest(value: dict) -> str:
    """Hash the closed retained policy wire without consulting live paths."""
    evidence_core.require_dataclass_wire(
        value, VerificationPolicy, POLICY_SCHEMA,
        shape_error=VerificationRefusal('policy:wire_shape_invalid'),
        schema_error=VerificationRefusal('policy:wire_shape_invalid'))
    if (any(not isinstance(value[field], str) for field in ('policy_id','checks_root','entrypoint'))
            or not isinstance(value['limits'], dict) or not isinstance(value['checks'], list)):
        raise VerificationRefusal('policy:wire_shape_invalid')
    return _sha(_canonical(value))


def successful_command_observation(row: dict) -> bool:
    """Require exact host exits, complete capture and independently proved cleanup."""
    return (isinstance(row, dict) and isinstance(row.get('cleanup'), dict)
            and row['cleanup'].get('complete') is True
            and row.get('capture_complete') is True and row.get('reason') == 'exited'
            and type(row.get('exit_code')) is int and row['exit_code'] == 0
            and type(row.get('supervisor_exit')) is int and row['supervisor_exit'] == 0)



@dataclass(frozen=True)
class VerificationLimits:
    wall_seconds: float = 1.5
    total_seconds: float = 20.0
    cpu_seconds: int = 1
    address_space_bytes: int = 134_217_728
    scratch_bytes: int = 8_388_608
    processes: int = 64

    def validate(self):
        for value, low, high in ((self.wall_seconds, .1, 3), (self.total_seconds, 1, 30)):
            if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
                raise VerificationRefusal("policy:limits_invalid")
        for value, low, high in ((self.cpu_seconds, 1, 3),
                                (self.address_space_bytes, 67_108_864, 536_870_912),
                                (self.scratch_bytes, 1_048_576, 16_777_216),
                                (self.processes, 8, 128)):
            if type(value) is not int or not low <= value <= high:
                raise VerificationRefusal("policy:limits_invalid")


@dataclass(frozen=True)
class CheckDefinition:
    name: str
    path: str
    sha256: str
    kind: str  # structural data check, or independent behavioral output oracle
    stdin: bytes = b""

    def validate(self):
        if (type(self.name) is not str or not _ID.fullmatch(self.name)
                or type(self.sha256) is not str or not _SHA256.fullmatch(self.sha256)
                or type(self.kind) is not str or self.kind not in ("structural", "behavioral")
                or type(self.stdin) is not bytes or len(self.stdin) > 4096
                or (self.kind == "structural" and self.stdin)):
            raise VerificationRefusal("policy:check_invalid")
        if not _path(self.path).endswith(".py"):
            raise VerificationRefusal("policy:python_only")


@dataclass(frozen=True)
class VerificationPolicy:
    policy_id: str
    checks_root: str
    entrypoint: str
    checks: tuple[CheckDefinition, ...]
    limits: VerificationLimits

    def validate(self):
        if (type(self.policy_id) is not str or not _ID.fullmatch(self.policy_id)
                or type(self.checks_root) is not str or not Path(self.checks_root).is_absolute()
                or str(Path(self.checks_root).resolve(strict=True)) != self.checks_root
                or type(self.checks) is not tuple or not 2 <= len(self.checks) <= 8
                or any(type(c) is not CheckDefinition for c in self.checks)
                or len({c.name for c in self.checks}) != len(self.checks)
                or len({c.path for c in self.checks}) != len(self.checks)
                or {c.kind for c in self.checks} != {"structural", "behavioral"}
                or type(self.limits) is not VerificationLimits):
            raise VerificationRefusal("policy:closed_enrollment_required")
        for check in self.checks:
            check.validate()
        if not _path(self.entrypoint).endswith(".py"):
            raise VerificationRefusal("policy:python_only")
        self.limits.validate()

    @property
    def canonical_bytes(self):
        wire = asdict(self)
        wire['checks'] = [{**asdict(c), 'stdin': c.stdin.hex()} for c in self.checks]
        return _canonical({'schema': POLICY_SCHEMA, **wire})

    @property
    def sha256(self):
        return _sha(self.canonical_bytes)


@dataclass(frozen=True)
class VerificationRequest:
    operation_id: str
    repository: str
    commit: str
    tree: str
    mission_id: str
    ticket_id: str
    ticket_revision: str
    ownership_generation: int
    authorization_generation: int
    policy_sha256: str

    @classmethod
    def from_recorded_wire(cls, value):
        """Read one closed retained wire without consulting physical paths."""
        evidence_core.require_dataclass_wire(
            value, cls, REQUEST_SCHEMA,
            shape_error=VerificationRefusal('request:wire_shape_invalid'),
            schema_error=VerificationRefusal('request:schema_invalid'))
        request = cls(**{key:item for key,item in value.items() if key != 'schema'})
        request.validate_identity()
        return request

    def validate_identity(self):
        """Validate the closed recorded request without resolving historical paths."""
        for value in (self.operation_id, self.mission_id, self.ticket_id):
            if type(value) is not str or not _ID.fullmatch(value):
                raise VerificationRefusal("request:identifier_invalid")
        for value in (self.commit, self.tree):
            if type(value) is not str or not _SHA1.fullmatch(value):
                raise VerificationRefusal("request:object_invalid")
        for value in (self.ticket_revision, self.policy_sha256):
            if type(value) is not str or not _SHA256.fullmatch(value):
                raise VerificationRefusal("request:digest_invalid")
        for value in (self.ownership_generation, self.authorization_generation):
            if type(value) is not int or not 0 < value <= 2**63 - 1:
                raise VerificationRefusal("request:generation_invalid")
        if not evidence_core.is_canonical_absolute_path(self.repository):
            raise VerificationRefusal("request:canonical_repository_required")

    def validate(self):
        self.validate_identity()
        if (type(self.repository) is not str or not Path(self.repository).is_absolute()
                or str(Path(self.repository).resolve(strict=True)) != self.repository):
            raise VerificationRefusal("request:canonical_repository_required")

    @property
    def canonical_bytes(self):
        return _canonical({"schema": REQUEST_SCHEMA, **asdict(self)})


def validate_nonaccepting_observation(observed: dict, request: VerificationRequest) -> None:
    """Bind a compact original refusal/unknown cut without accepting checks."""
    request.validate_identity()
    expected_fields = {'schema', 'request_sha256', 'policy_sha256', 'producer_identity', 'result', 'receipt_refs'}
    if (not isinstance(observed, dict) or set(observed) != expected_fields
            or observed['schema'] != 'orch-dork/protected-verification-observation/v1'
            or observed['request_sha256'] != _sha(request.canonical_bytes)
            or observed['policy_sha256'] != request.policy_sha256):
        raise VerificationRefusal('observation:binding_changed')
    producer = observed['producer_identity']
    if (not isinstance(producer, dict) or set(producer) != {path.name for path in _collector_sources()}
            or any(type(value) is not str or not _SHA256.fullmatch(value) for value in producer.values())):
        raise VerificationRefusal('observation:binding_changed')
    result = observed['result']
    if (not isinstance(result, dict) or set(result) != {'status', 'reason', 'qualification', 'retain_claims'}
            or result['status'] not in ('REFUSED', 'UNKNOWN') or type(result['reason']) is not str
            or not result['reason'] or result['qualification'] is not False or result['retain_claims'] is not True):
        raise VerificationRefusal('observation:nonaccepting_required')
    refs = observed['receipt_refs']
    if not isinstance(refs, list) or len(refs) > 256:
        raise VerificationRefusal('observation:path_changed')
    names = set()
    for row in refs:
        if (not isinstance(row, list) or len(row) != 3 or type(row[0]) is not str
                or not re.fullmatch(r'[0-9a-f]{32}', row[0]) or row[0] in names
                or type(row[1]) is not str or not _SHA256.fullmatch(row[1])
                or (row[2] is not None and (type(row[2]) is not str or not _SHA256.fullmatch(row[2])))):
            raise VerificationRefusal('observation:path_changed')
        names.add(row[0])


def validate_retained_evidence(evidence: dict) -> None:
    """Validate the verifier-owned closed wire and complete accepting layout.

    This structural contract does not authenticate custody or run commands.
    Root still binds the original frozen request/policy and actual receiver.
    """
    expected_fields = {"schema", "request", "policy", "runtime_identity",
              "check_identity", "candidate_manifest", "preparation_commands",
              "commands", "status", "reason"}
    if isinstance(evidence, dict) and evidence.get('status') == 'VERIFIED':
        expected_fields |= {'verified_commit', 'verified_tree'}
    if (not isinstance(evidence, dict) or set(evidence) != expected_fields or
            not isinstance(evidence.get("schema"), str) or
            not isinstance(evidence.get("status"), str) or
            not isinstance(evidence.get("reason"), str) or
            not isinstance(evidence.get("request"), dict) or
            not isinstance(evidence.get("policy"), dict) or
            not isinstance(evidence.get("runtime_identity"), dict) or
            not isinstance(evidence.get("check_identity"), dict) or
            not isinstance(evidence.get("candidate_manifest"), dict) or
            not isinstance(evidence.get("preparation_commands"), list) or
            not isinstance(evidence.get("commands"), list)):
        raise VerificationRefusal('evidence:wire_shape_invalid')
    if evidence["schema"] != EVIDENCE_SCHEMA:
        raise VerificationRefusal('evidence:schema_invalid')
    if evidence["status"] not in ("VERIFIED", "FAILED", "STOPPED", "REFUSED", "UNKNOWN"):
        raise VerificationRefusal('evidence:verdict_invalid')
    if not isinstance(evidence["reason"], str) or not evidence["reason"]:
        raise VerificationRefusal('evidence:reason_invalid')
    if evidence["status"] == "VERIFIED":
        for value in ("verified_commit", "verified_tree"):
            entry = evidence.get(value)
            if not isinstance(entry, str) or not _SHA1.fullmatch(entry):
                raise VerificationRefusal('evidence:verified_object_missing')
    else:
        if "verified_commit" in evidence or "verified_tree" in evidence:
            raise VerificationRefusal('evidence:verified_object_unexpected')
    VerificationRequest.from_recorded_wire(evidence['request'])
    policy_digest = verification_policy_digest(evidence['policy'])
    if policy_digest != evidence['request']['policy_sha256']:
        raise VerificationRefusal('evidence:policy_mismatch')
    if len(evidence['preparation_commands']) + len(evidence['commands']) > 256:
        raise VerificationRefusal('evidence:command_limit')
    if evidence['status'] == 'VERIFIED':
        if (evidence['verified_commit'] != evidence['request']['commit'] or
                evidence['verified_tree'] != evidence['request']['tree']):
            raise VerificationRefusal('evidence:verified_object_mismatch')
        validate_verified_command_receipts(evidence)


def validate_verified_command_receipts(evidence):
    """Validate the full host-observed command layout required for VERIFIED.

    The protected verifier records every preparation, candidate and
    independent-oracle run as one command row. VERIFIED requires the
    actual policy check list to include at least one structural and
    one behavioral check, the expected command count and order (one
    candidate run plus one independent-oracle run per behavioral check,
    and one oracle run per structural check), each row's mounts (the
    candidate run mounts the candidate root; the oracle run mounts
    the checks root and observed dir but never the candidate root),
    physical cleanup.complete (must be the exact True), capture_complete
    (must be the exact True), "exited" reason, exit_code 0 (exact int,
    not bool) and supervisor_exit 0 (exact int, not bool). An empty
    commands list, a missing oracle, an oracle that mounts the
    candidate, a non-zero exit, an incomplete cleanup or a row that
    only matches the header VERIFIED without these real receipts
    refuses the current effect; partial evidence never becomes VERIFIED.
    """
    policy = evidence.get("policy", {})
    if not isinstance(policy, dict):
        raise VerificationRefusal('policy:wire_shape_invalid')
    checks = policy.get("checks", [])
    if not isinstance(checks, list) or not checks:
        raise VerificationRefusal('evidence:checks_missing')
    structural = [c for c in checks if isinstance(c, dict) and
                  c.get("kind") == "structural"]
    behavioral = [c for c in checks if isinstance(c, dict) and
                  c.get("kind") == "behavioral"]
    if not structural or not behavioral:
        raise VerificationRefusal('evidence:check_kinds_missing')
    expected_rows = len(structural) + 2 * len(behavioral)
    if (not isinstance(evidence.get("commands"), list) or
            len(evidence["commands"]) != expected_rows):
        raise VerificationRefusal('evidence:command_count_mismatch')
    if (not isinstance(evidence.get("preparation_commands"), list) or
            len(evidence["preparation_commands"]) < 1):
        raise VerificationRefusal('evidence:preparation_missing')
    def _row_shape(row):
        # Host process success belongs to the verifier's shared predicate.
        if not isinstance(row, dict):
            return False
        for key in ("argv", "stdout_sha256", "stderr_sha256",
                    "config_sha256", "outcome_sha256", "command_directory",
                    "mount_destinations", "mount_sources"):
            value = row.get(key)
            if key in ("argv", "mount_destinations", "mount_sources"):
                if not isinstance(value, list):
                    return False
            elif not isinstance(value, str):
                return False
        return True
    def _row_digests(row):
        return (_SHA256.fullmatch(row["stdout_sha256"]) and
                _SHA256.fullmatch(row["stderr_sha256"]) and
                _SHA256.fullmatch(row["config_sha256"]) and
                _SHA256.fullmatch(row["outcome_sha256"]))
    for index, row in enumerate(evidence["preparation_commands"]):
        if not _row_shape(row) or not _row_digests(row) or not successful_command_observation(row):
            raise VerificationRefusal('evidence:preparation_command_unproved')
    # Walk the checks in declared order: for each structural check one
    # command (oracle with candidate+checks mounts, no observed);
    # for each behavioral check two commands (candidate run with
    # candidate mount; oracle run with checks+observed mounts and
    # NO candidate mount).
    cursor = 0
    for check in checks:
        if not isinstance(check, dict):
            raise VerificationRefusal('evidence:check_shape_invalid')
        kind = check.get("kind")
        if kind == "structural":
            row = evidence["commands"][cursor]
            if not _row_shape(row) or not _row_digests(row) or not successful_command_observation(row):
                raise VerificationRefusal('evidence:structural_oracle_unproved')
            if "/candidate" not in row["mount_destinations"]:
                raise VerificationRefusal('evidence:structural_candidate_mount_missing')
            if "/checks" not in row["mount_destinations"]:
                raise VerificationRefusal('evidence:structural_checks_mount_missing')
            if "/observed" in row["mount_destinations"]:
                raise VerificationRefusal('evidence:structural_observed_mount_forbidden')
            cursor += 1
        elif kind == "behavioral":
            if cursor + 1 >= len(evidence["commands"]):
                raise VerificationRefusal('evidence:behavioral_command_missing')
            cand = evidence["commands"][cursor]
            orac = evidence["commands"][cursor + 1]
            if not _row_shape(cand) or not _row_digests(cand) or not successful_command_observation(cand):
                raise VerificationRefusal('evidence:behavioral_candidate_unproved')
            if not _row_shape(orac) or not _row_digests(orac) or not successful_command_observation(orac):
                raise VerificationRefusal('evidence:behavioral_oracle_unproved')
            if "/candidate" not in cand["mount_destinations"]:
                raise VerificationRefusal('evidence:behavioral_candidate_mount_missing')
            if "/checks" in cand["mount_destinations"]:
                raise VerificationRefusal('evidence:behavioral_candidate_checks_forbidden')
            if "/observed" in cand["mount_destinations"]:
                raise VerificationRefusal('evidence:behavioral_candidate_observed_forbidden')
            if "/checks" not in orac["mount_destinations"]:
                raise VerificationRefusal('evidence:behavioral_checks_mount_missing')
            if "/observed" not in orac["mount_destinations"]:
                raise VerificationRefusal('evidence:behavioral_observed_mount_missing')
            if "/candidate" in orac["mount_destinations"]:
                raise VerificationRefusal('evidence:behavioral_oracle_candidate_forbidden')
            cursor += 2
        else:
            raise VerificationRefusal('evidence:check_kind_invalid')


def _file_identity(path: Path) -> dict:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise VerificationRefusal("input:file_identity_invalid")
    return {"dev": info.st_dev, "ino": info.st_ino, "mode": info.st_mode,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def _collector_sources() -> tuple[Path, ...]:
    """The complete private collector import closure, pinned and copied together."""
    return (Path(__file__).resolve(), Path(local.__file__).resolve(),
            Path(evidence_core.__file__).resolve())


def _runtime_identity() -> dict:
    result = {}
    if _GIT is None:
        raise VerificationRefusal("runtime:git_missing")
    collector_sources = tuple(str(path) for path in _collector_sources())
    for source in (*[s for s, _ in _MOUNTS], _BWRAP, _GIT, *collector_sources):
        path = Path(source).resolve(strict=True)
        entries = [path] if path.is_file() else sorted(path.rglob("*"))
        if len(entries) > 8192:
            raise VerificationRefusal("runtime:inventory_exhausted")
        digest = hashlib.sha256()
        total = 0
        for entry in entries:
            info = entry.lstat()
            host_source = source in collector_sources
            # Development source may be group-writable. It is never executed
            # there: commands use protected private snapshots bound below.
            forbidden_mode = 0o002 if host_source else 0o022
            if not stat.S_ISLNK(info.st_mode) and info.st_mode & forbidden_mode:
                raise VerificationRefusal("runtime:writable_system_input")
            digest.update(str(entry.relative_to(path) if entry != path else ".").encode())
            digest.update(str(info.st_mode).encode())
            if entry.is_symlink():
                digest.update(os.readlink(entry).encode())
            elif entry.is_file():
                total += info.st_size
                if total > 268_435_456:
                    raise VerificationRefusal("runtime:inventory_exhausted")
                with entry.open("rb") as stream:
                    while raw := stream.read(65_536):
                        digest.update(raw)
        result[source] = {"resolved": str(path), "dev": path.stat().st_dev,
                          "ino": path.stat().st_ino, "sha256": digest.hexdigest(),
                          "content_sha256": _sha(path.read_bytes()) if path.is_file() else None}
    return result


def _clamp(limits: dict, *, namespace_setup: bool):
    for which, target in ((resource.RLIMIT_CPU, limits["cpu_seconds"]),
                          (resource.RLIMIT_AS, limits["address_space_bytes"]),
                          (resource.RLIMIT_FSIZE, limits["scratch_bytes"]),
                          *(() if namespace_setup else ((resource.RLIMIT_NPROC, limits["processes"]),)),
                          (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CORE, 0)):
        soft, hard = resource.getrlimit(which)
        value = min([target, *[v for v in (soft, hard) if v != resource.RLIM_INFINITY]])
        resource.setrlimit(which, (value, value))


def _supervise(config_path: Path) -> int:
    """Dedicated outer collector. No candidate data/code is imported here.

    Intentional bounded copy of the publication subreaper: verification needs
    per-check resource clamps, mount/stream observations and a census across
    every observed group (including setsid descendants). Publication diagnoses
    a negative exit as child_signal_loss because its delivery may have landed.
    Here a fully captured nonzero/signal exit is FAILED acceptance, with its raw
    host exit preserved; cleanup uncertainty is always UNKNOWN. No effect or
    retry authority follows either verdict. Keep publication's reviewed code
    unchanged; real signal/escaped-child controls cover this difference.
    """
    raw = local._read(config_path)
    config = json.loads(raw)
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        return 2
    started = time.monotonic()
    process = None
    identity = None
    observed = {}
    reaped = []
    complete = False
    reason = "exited"
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    remaining, group_remaining = [], None
    try:
        process = subprocess.Popen(config["argv"], cwd=config["cwd"], env=config["environment"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, close_fds=True,
                                   preexec_fn=lambda: _clamp(config["limits"],
                                                            namespace_setup=config["argv"][0] == _BWRAP))
        identity = next(r for r in local._census() if r["pid"] == process.pid)
        observed[(identity["pid"], identity["start_ticks"])] = identity
        for name in buffers:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        pending = memoryview(bytes.fromhex(config["stdin"]))
        os.set_blocking(process.stdin.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        deadline = started + config["wall_seconds"]
        while time.monotonic() < deadline + 1:
            process.poll()
            if process.returncode is not None:
                while True:
                    try:
                        pid, status = os.waitpid(-1, os.WNOHANG)
                        if not pid:
                            break
                        reaped.append({"pid": pid, "wait_status": status})
                    except ChildProcessError:
                        break
            remaining = local._owned()
            observed.update({(r["pid"], r["start_ticks"]): r for r in remaining})
            if process.returncode is not None and not remaining and not selector.get_map():
                groups = {r["pgid"] for r in observed.values()}
                group_remaining = [r for r in local._census() if r["pgid"] in groups]
                if not group_remaining:
                    complete = True
                    break
            if time.monotonic() >= deadline or reason != "exited":
                if reason == "exited":
                    reason = "timeout"
                for row in remaining:
                    try:
                        local._kill_owned(row)
                    except ProcessLookupError:
                        pass
            for key, _ in selector.select(.01):
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
                    room = STREAM_LIMIT - len(buffers[name])
                    buffers[name].extend(chunk[:room])
                    if len(chunk) > room:
                        reason = "output_limit"
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
        process.poll()
    except (OSError, ValueError, StopIteration, subprocess.SubprocessError) as error:
        reason = "supervision_unknown:" + type(error).__name__
    finally:
        selector.close()
    for name, raw_stream in buffers.items():
        local._create(config_path.parent / name, bytes(raw_stream))
    result = {"argv": config["argv"], "config_sha256": _sha(raw),
              "exit_code": process.returncode if process else None, "reason": reason,
              "process_identity": identity, "duration_seconds": time.monotonic() - started,
              "capture_complete": reason != "output_limit",
              "stdout_sha256": _sha(buffers["stdout"]), "stderr_sha256": _sha(buffers["stderr"]),
              "cleanup": {"complete": complete, "remaining": remaining,
                          "group_remaining": group_remaining, "observed": list(observed.values()),
                          "reaped": reaped}}
    local._create(config_path.parent / "outcome.json", _canonical(result))
    return 0 if complete else 2


class ProtectedVerifier:
    """Host-only enrollment/collection and pure retained reads.

    Construction validates paths/policy without provisioning custody. verify()
    provisions it and owns execution exclusively. read_evidence() opens existing
    private custody/lock read-only, takes a nonblocking shared flock and closes
    it without unlocking explicitly. It never executes, repairs or creates
    evidence. Root still owns canonical authority and the publication join.
    """

    def __init__(self, custody: str | Path, *, policy: VerificationPolicy):
        if type(policy) is not VerificationPolicy:
            raise VerificationRefusal("policy:closed_type_required")
        policy.validate()
        self.policy = policy
        self.custody = Path(custody)
        if not self.custody.is_absolute() or self.custody.resolve() != self.custody:
            raise VerificationRefusal("custody:canonical_path_required")
        checks = Path(policy.checks_root)
        if self.custody == checks or checks in self.custody.parents or self.custody in checks.parents:
            raise VerificationRefusal("custody:checks_overlap")

    def operation_directory(self, request: VerificationRequest) -> Path:
        return self.custody / _sha(request.operation_id.encode())

    def _validate_request(self, request: VerificationRequest):
        if type(request) is not VerificationRequest:
            raise VerificationRefusal("request:closed_type_required")
        request.validate()
        if request.policy_sha256 != self.policy.sha256:
            raise VerificationRefusal("policy:binding_changed")
        repo, checks_root = Path(request.repository), Path(self.policy.checks_root)
        if (repo == self.custody or repo in self.custody.parents or self.custody in repo.parents
                or repo == checks_root or repo in checks_root.parents or checks_root in repo.parents):
            raise VerificationRefusal("input:custody_overlap")

    def _original_evidence(self, directory: Path, request: VerificationRequest) -> dict:
        """Read original request/seal/receipt custody without current check acceptance."""
        original = local._read(directory / "request.json")
        if original != request.canonical_bytes:
            raise VerificationRefusal("request:id_conflict")
        if (directory / "observation.json").exists():
            return self._read_observation(directory, request)
        raw = local._read(directory / "evidence.json")
        digest = local._read(directory / "evidence.sha256").decode()
        if _sha(raw) != digest:
            raise VerificationRefusal("evidence:seal_changed")
        try:
            sealed = json.loads(raw)
        except (ValueError, UnicodeError) as error:
            raise VerificationRefusal("evidence:wire_shape_invalid") from error
        validate_retained_evidence(sealed)
        if sealed["request"] != json.loads(original):
            raise VerificationRefusal("evidence:seal_changed")
        if sealed["policy"] != json.loads(self.policy.canonical_bytes):
            raise VerificationRefusal("policy:binding_changed")
        if sealed["status"] not in ("VERIFIED", "FAILED", "STOPPED", "REFUSED", "UNKNOWN"):
            raise VerificationRefusal("evidence:verdict_invalid")
        if sealed["status"] == "VERIFIED" and (
                sealed["verified_commit"] != request.commit or sealed["verified_tree"] != request.tree):
            raise VerificationRefusal("evidence:candidate_changed")
        self._receipts_unchanged(directory, sealed['preparation_commands'] + sealed['commands'])
        result = {"status": sealed["status"], "reason": sealed["reason"], "qualification": False,
                  "retain_claims": True, "evidence_path": str(directory / "evidence.json"),
                  "evidence_sha256": digest}
        return {'result': result, 'record': sealed, 'path': directory / 'evidence.json', 'sha256': digest}

    def _retained(self, directory: Path, request: VerificationRequest) -> dict:
        original = self._original_evidence(directory, request)
        if original['path'].name == 'evidence.json':
            sealed = original['record']
            self._unchanged(directory, sealed['candidate_manifest'],
                            sealed['check_identity'], sealed['runtime_identity'])
        return original['result']

    @staticmethod
    def _producer_identity():
        return {source.name: _sha(source.read_bytes()) for source in _collector_sources()}

    def _retain_observation(self, directory, request, result):
        """Bounded original nonaccepting cut, without an accepting envelope.

        Compact references retain original command receipts outside the bounded
        aggregate. Missing receipts at this cut stay missing observations, never
        proof of cessation or permission to repeat. No later file arrival can
        upgrade this original REFUSED/UNKNOWN result.
        """
        refs = []
        for command in sorted((directory / "commands").glob("*")):
            config = local._read(command / "command.json")
            try:
                digest = _sha(local._read(command / "receipt.json"))
            except FileNotFoundError:
                digest = None
            refs.append([command.name, _sha(config), digest])
        raw = _canonical({"schema": "orch-dork/protected-verification-observation/v1",
                          "request_sha256": _sha(request.canonical_bytes),
                          "policy_sha256": self.policy.sha256,
                          "producer_identity": self._producer_identity(),
                          "result": result, "receipt_refs": refs})
        if len(raw) > STREAM_LIMIT:
            raise VerificationRefusal("observation:record_oversized")
        local._create(directory / "observation.json", raw)
        local._create(directory / "observation.sha256", _sha(raw).encode())

    def _read_observation(self, directory, request):
        raw = local._read(directory / "observation.json")
        if local._read(directory / "observation.sha256") != _sha(raw).encode():
            raise VerificationRefusal("observation:seal_changed")
        observed = json.loads(raw)
        validate_nonaccepting_observation(observed, request)
        if observed['producer_identity'] != self._producer_identity():
            raise VerificationRefusal('observation:binding_changed')
        result = observed['result']
        rows = []
        for name, config_sha, receipt_sha in observed["receipt_refs"]:
            if not re.fullmatch(r"[0-9a-f]{32}", name):
                raise VerificationRefusal("observation:path_changed")
            command = directory / "commands" / name
            _existing_private_dir(command)
            if _sha(local._read(command / "command.json")) != config_sha:
                raise VerificationRefusal("evidence:command_changed")
            if receipt_sha is not None:
                receipt = local._read(command / "receipt.json")
                if _sha(receipt) != receipt_sha:
                    raise VerificationRefusal("observation:receipt_changed")
                row = json.loads(receipt)
                if row["command_directory"] != str(command):
                    raise VerificationRefusal("observation:path_changed")
                rows.append(row)
        self._receipts_unchanged(directory, rows)
        return {'result': result, 'record': observed,
                'path': directory / 'observation.json', 'sha256': _sha(raw)}

    def read_evidence(self, request: VerificationRequest) -> dict:
        """Read retained identity/effect/cleanup evidence; never start a check.

        Missing/partial/busy custody is UNKNOWN retaining claims. Changed exact
        bindings/inputs/receipts refuse. Returned VERIFIED remains a component
        outcome, requiring Root's canonical current authority before joining.
        """
        return self._read_only(request, self._retained)

    def read_cleanup(self, request: VerificationRequest) -> dict:
        """Prove original no-effect/cessation without changing its verdict.

        The existing operation mutex excludes all original execution, including
        inherited collectors. Exact consumed request and sealed observations
        forbid a same-operation replay. Missing receipts remain uncertainty.
        This is component evidence; Root alone may settle and release a claim.
        """
        return self._read_only(request, self._cleanup)

    def _cleanup(self, directory: Path, request: VerificationRequest) -> dict:
        retained = self._original_evidence(directory, request)
        original, record = retained['result'], retained['record']
        path = retained['path']
        observation = directory / 'observation.json'
        if path == observation:
            refs = record["receipt_refs"]
            if any(digest is None for _, _, digest in refs):
                raise VerificationRefusal("cleanup:original_receipt_missing")
            commands = [json.loads(local._read(directory / "commands" / name / "receipt.json"))
                        for name, _, _ in refs]
        else:
            commands = record["preparation_commands"] + record["commands"]
        command_root = directory / "commands"
        declared = [Path(row["command_directory"]) for row in commands]
        actual = set(command_root.iterdir()) if command_root.exists() else set()
        if len(set(declared)) != len(declared) or set(declared) != actual:
            raise VerificationRefusal("cleanup:command_inventory_changed")
        self._receipts_unchanged(directory, commands)
        identities = []
        receipts = []
        for row in commands:
            command = Path(row["command_directory"])
            completed = row
            late_outcome_sha = None
            if row.get("partial") is True:
                # A later original collector outcome is independent cessation
                # proof, never an upgrade of the retained partial verdict. The
                # shared operation lock also excludes its inherited collector.
                late_raw = local._read(command / "outcome.json")
                completed = json.loads(late_raw)
                if (completed["config_sha256"] != row["config_sha256"]
                        or completed["argv"] != row["argv"]):
                    raise VerificationRefusal("cleanup:collector_binding_changed")
                for name in ("stdout", "stderr"):
                    if _sha(local._read(command / name)) != completed[name+"_sha256"]:
                        raise VerificationRefusal("cleanup:collector_stream_changed")
                late_outcome_sha = _sha(late_raw)
            elif type(row.get("supervisor_exit")) is not int or row["supervisor_exit"] != 0:
                raise VerificationRefusal("cleanup:collector_exit_unproved")
            cleanup = completed.get("cleanup")
            if (type(completed.get("exit_code")) is not int
                    or not isinstance(cleanup, dict) or cleanup.get("complete") is not True
                    or cleanup.get("remaining") != [] or cleanup.get("group_remaining") != []):
                raise VerificationRefusal("cleanup:cessation_unproved")
            observed = cleanup.get("observed")
            direct = completed.get("process_identity")
            if not isinstance(observed, list) or not observed or direct not in observed:
                raise VerificationRefusal("cleanup:process_identity_missing")
            for identity in observed:
                if (not isinstance(identity, dict) or set(identity) != {"pid", "ppid", "pgid", "start_ticks"}
                        or any(type(identity[name]) is not int or identity[name] <= 0
                               for name in ("pid", "ppid", "pgid", "start_ticks"))):
                    raise VerificationRefusal("cleanup:process_identity_invalid")
                identities.append(identity)
            receipts.append({"command_directory": str(command),
                             "config_sha256": row["config_sha256"],
                             "receipt_sha256": _sha(local._read(command / "receipt.json")),
                             "late_outcome_sha256": late_outcome_sha})
        if identities:
            current = local._census()
            if any(live["pgid"] in {identity["pgid"] for identity in identities}
                   or (live["pid"], live["start_ticks"]) in
                   {(identity["pid"], identity["start_ticks"]) for identity in identities}
                   for live in current):
                raise VerificationRefusal("cleanup:original_process_still_active")
        elif path != observation:
            raise VerificationRefusal("cleanup:no_effect_observation_missing")
        return {"schema": CLEANUP_SCHEMA,
                "status": "CESSATED" if commands else "NO_EFFECT",
                "original_status": original["status"], "original_reason": original["reason"],
                "request_sha256": _sha(request.canonical_bytes),
                "observation_path": str(path), "observation_sha256": retained["sha256"],
                "commands": receipts, "qualification": False, "retain_claims": True}

    def _read_only(self, request, reader):
        result = {"status": "UNKNOWN", "reason": "evidence:unavailable",
                  "qualification": False, "retain_claims": True}
        lock = None
        try:
            self._validate_request(request)
            _existing_private_dir(self.custody)
            directory = self.operation_directory(request)
            _existing_private_dir(directory)
            lock = local._open(directory / "operation.lock", os.O_RDONLY)
            try:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return {**result, "reason": "verification:busy"}
            return reader(directory, request)
        except (VerificationRefusal, local.PublicationRefusal) as error:
            return {**result, "status": "REFUSED", "reason": str(error)}
        except (OSError, ValueError, KeyError, TypeError) as error:
            return {**result, "reason": "verification:unavailable:" + type(error).__name__}
        finally:
            if lock is not None:
                os.close(lock)

    def _checks(self) -> tuple[dict, dict]:
        root = Path(self.policy.checks_root)
        info = root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise VerificationRefusal("checks:root_unsafe")
        contents, identities = {}, {}
        for check in self.policy.checks:
            path = root / check.path
            if path.resolve(strict=True) != path:
                raise VerificationRefusal("checks:path_changed")
            before = _file_identity(path)
            raw = local._read(path)
            if before != _file_identity(path) or _sha(raw) != check.sha256:
                raise VerificationRefusal("checks:definition_changed")
            contents[check.path], identities[check.path] = raw, before
        return contents, identities

    def _run(self, directory: Path, argv: list[str], data: bytes, lock: int,
             deadline: float, *, mounts: tuple = (), git: bool = False) -> dict:
        remaining = deadline - time.monotonic()
        if remaining < .05:
            raise VerificationRefusal("verification:total_deadline")
        command = directory / "commands" / uuid.uuid4().hex
        local._private_dir(command.parent)
        local._private_dir(command)
        wall = min(2 if git else self.policy.limits.wall_seconds, remaining)
        config = {"argv": argv, "cwd": str(command), "stdin": data.hex(), "environment": _environment(),
                  "limits": asdict(self.policy.limits), "wall_seconds": wall}
        collector = directory / "collector" / Path(__file__).name
        # Collector copy identities are checked by _unchanged against the
        # enrolled runtime. Do not record a second unconsumed source-pin field.
        local._create(command / "command.json", _canonical(config))
        streams = [local._open(command / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                   for name in ("supervisor.stdout", "supervisor.stderr")]
        try:
            helper = subprocess.Popen([_PYTHON, "-I", "-B", str(collector),
                                       "--supervise", str(command / "command.json")],
                                      cwd=directory, env=_environment(),
                                      stdin=subprocess.DEVNULL, stdout=streams[0], stderr=streams[1],
                                      close_fds=True, pass_fds=(lock,), start_new_session=True)
        finally:
            for fd in streams:
                os.close(fd)
        try:
            helper.wait(timeout=wall + 2)
        except subprocess.TimeoutExpired:
            partial_streams = {}
            for name in ("stdout", "stderr"):
                raw_cut = local._read(command / ("supervisor." + name))
                local._create(command / ("partial.supervisor." + name), raw_cut)
                partial_streams[name] = _sha(raw_cut)
            result = {"partial": True, "argv": argv, "config_sha256": _sha(_canonical(config)),
                      "reason": "supervisor_unsettled", "exit_code": None, "supervisor_exit": None,
                      "capture_complete": False, "cleanup": {"complete": False},
                      "mount_sources": [s for s, _ in mounts], "mount_destinations": [d for _, d in mounts],
                      "partial_supervisor_streams": partial_streams, "command_directory": str(command)}
            local._create(command / "receipt.json", _canonical(result))
            return result
        local._create(command / "supervisor-exit.json", _canonical({"exit_code": helper.returncode}))
        outcome = local._read(command / "outcome.json")
        result = json.loads(outcome)
        if result["config_sha256"] != _sha(_canonical(config)):
            raise VerificationRefusal("evidence:command_changed")
        for name in ("stdout", "stderr"):
            raw = local._read(command / name)
            if _sha(raw) != result[name + "_sha256"]:
                raise VerificationRefusal("evidence:stream_changed")
        result.update(command_directory=str(command), supervisor_exit=helper.returncode,
                      mount_sources=[s for s, _ in mounts], mount_destinations=[d for _, d in mounts],
                      outcome_sha256=_sha(outcome),
                      supervisor_streams={name: _sha(local._read(command / ("supervisor." + name)))
                                          for name in ("stdout", "stderr")})
        receipt = _canonical(result)
        if len(receipt) > STREAM_LIMIT:
            raise VerificationRefusal("evidence:command_record_oversized")
        local._create(command / "receipt.json", receipt)
        return result

    def _git(self, directory, request, args, lock, deadline, receipts) -> bytes:
        argv = [_GIT, "--no-optional-locks", "--git-dir=" + request.repository,
                "-c", "core.hooksPath=" + os.devnull, "-c", "core.fsmonitor=false", *args]
        row = self._run(directory, argv, b"", lock, deadline, git=True)
        receipts.append(row)
        if not self._successful(row):
            raise VerificationRefusal("git:validation_failed")
        return local._read(Path(row["command_directory"]) / "stdout")

    def _stage(self, directory, request, lock, deadline, receipts) -> dict:
        def git(args):
            return self._git(directory, request, args, lock, deadline, receipts)

        if git(["rev-parse", "--path-format=absolute", "--git-common-dir"]).decode().strip() != request.repository:
            raise VerificationRefusal("git:repository_binding")
        if git(["rev-parse", "--show-object-format"]) != b"sha1\n":
            raise VerificationRefusal("git:sha1_required")
        if git(["cat-file", "-t", request.commit]) != b"commit\n":
            raise VerificationRefusal("git:commit_required")
        commit = git(["cat-file", "commit", request.commit])
        if _git_oid("commit", commit) != request.commit:
            raise VerificationRefusal("candidate:commit_bytes_changed")
        if git(["rev-parse", request.commit + "^{tree}"]).decode().strip() != request.tree:
            raise VerificationRefusal("candidate:tree_mismatch")
        tree = git(["cat-file", "tree", request.tree])
        if _git_oid("tree", tree) != request.tree:
            raise VerificationRefusal("candidate:tree_bytes_changed")
        entries = git(["ls-tree", "-rz", request.tree]).split(b"\0")[:-1]
        if not 1 <= len(entries) <= MAX_FILES:
            raise VerificationRefusal("candidate:file_limit")
        manifest, total = {}, 0
        candidate = directory / "candidate"
        local._private_dir(candidate)
        for entry in entries:
            metadata, name = entry.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split(" ")
            try:
                name = _path(name.decode("ascii"))
            except UnicodeDecodeError as error:
                raise VerificationRefusal("input:path_invalid") from error
            if mode not in ("100644", "100755") or kind != "blob" or not _SHA1.fullmatch(oid):
                raise VerificationRefusal("candidate:regular_files_only")
            raw = git(["cat-file", "blob", oid])
            total += len(raw)
            if total > MAX_CANDIDATE_BYTES or _git_oid("blob", raw) != oid:
                raise VerificationRefusal("candidate:blob_changed_or_limit")
            path = candidate / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            local._create(path, raw)
            manifest[name] = {"git_mode": mode, "blob": oid, "sha256": _sha(raw)}
        if self.policy.entrypoint not in manifest:
            raise VerificationRefusal("candidate:entrypoint_missing")
        if _tree_oid(manifest) != request.tree:
            raise VerificationRefusal("candidate:tree_bytes_changed")
        return manifest

    def _unchanged(self, directory: Path, manifest: dict, checks: dict, runtime: dict):
        actual = {str(p.relative_to(directory / "candidate")): _sha(local._read(p))
                  for p in (directory / "candidate").rglob("*") if not p.is_dir()}
        if actual != {name: row["sha256"] for name, row in manifest.items()}:
            raise VerificationRefusal("candidate:staged_bytes_changed")
        _, identities = self._checks()
        if identities != checks:
            raise VerificationRefusal("checks:identity_changed")
        for check in self.policy.checks:
            if _sha(local._read(directory / "checks" / check.path)) != check.sha256:
                raise VerificationRefusal("checks:staged_bytes_changed")
        if _runtime_identity() != runtime:
            raise VerificationRefusal("runtime:identity_changed")
        if local._read(directory / "runner" / "limits.py") != _LIMIT_RUNNER:
            raise VerificationRefusal("runtime:limit_runner_changed")
        for source in _collector_sources():
            # Source snapshots are bounded by the exact enrolled source size;
            # the independent 64-KiB process-stream bound is not a source limit.
            try:
                snapshot = local._read(directory / "collector" / source.name,
                                       limit=source.stat().st_size)
            except local.PublicationRefusal as error:
                if str(error) != "custody:record_oversized":
                    raise
                raise VerificationRefusal("runtime:collector_source_changed") from error
            if _sha(snapshot) != runtime[str(source)]["content_sha256"]:
                raise VerificationRefusal("runtime:collector_source_changed")

    def _receipts_unchanged(self, directory: Path, commands: list[dict]):
        """Read original host command/exit/cleanup/stream records; never rerun."""
        required_observations = {Path(source) for row in commands
                                 for source, target in zip(row["mount_sources"], row["mount_destinations"])
                                 if target == "/observed"}
        for row in commands:
            command = Path(row["command_directory"])
            if (command.parent != directory / "commands"
                    or not re.fullmatch(r"[0-9a-f]{32}", command.name)
                    or command.resolve(strict=True) != command):
                raise VerificationRefusal("evidence:command_path_changed")
            config = local._read(command / "command.json")
            if _sha(config) != row["config_sha256"] or json.loads(config)["argv"] != row["argv"]:
                raise VerificationRefusal("evidence:command_changed")
            if local._read(command / "receipt.json") != _canonical(row):
                raise VerificationRefusal("evidence:receipt_changed")
            if row.get("partial") is True:
                if (row["exit_code"] is not None or row["supervisor_exit"] is not None
                        or row["capture_complete"] is not False or row["cleanup"]["complete"] is not False
                        or row["reason"] != "supervisor_unsettled"):
                    raise VerificationRefusal("evidence:partial_changed")
                for name in ("stdout", "stderr"):
                    if (_sha(local._read(command / ("partial.supervisor." + name)))
                            != row["partial_supervisor_streams"][name]):
                        raise VerificationRefusal("evidence:partial_changed")
                continue  # Later collector files never settle this original cut.
            outcome = local._read(command / "outcome.json")
            if _sha(outcome) != row["outcome_sha256"]:
                raise VerificationRefusal("evidence:outcome_changed")
            if any(row[key] != value for key, value in json.loads(outcome).items()):
                raise VerificationRefusal("evidence:outcome_changed")
            if json.loads(local._read(command / "supervisor-exit.json")) != {"exit_code": row["supervisor_exit"]}:
                raise VerificationRefusal("evidence:exit_changed")
            for name in ("stdout", "stderr"):
                if (_sha(local._read(command / name)) != row[name + "_sha256"]
                        or _sha(local._read(command / ("supervisor." + name))) != row["supervisor_streams"][name]):
                    raise VerificationRefusal("evidence:stream_changed")
            observed = command / "observed"
            if observed in required_observations or observed.exists():
                _existing_private_dir(observed)
                for name in ("stdout", "stderr"):
                    if _sha(local._read(observed / name)) != row[name + "_sha256"]:
                        raise VerificationRefusal("evidence:observed_changed")
                expected = {"exit_code": row["exit_code"], "stdout_sha256": row["stdout_sha256"],
                            "stderr_sha256": row["stderr_sha256"]}
                if local._read(observed / "result.json") != _canonical(expected):
                    raise VerificationRefusal("evidence:observed_changed")

    def _sandbox(self, candidate: Path | None, checks: Path | None,
                 observed: Path | None, script: str) -> tuple[list[str], tuple]:
        mounts = [(str(Path(source).resolve(strict=True)), dest) for source, dest in _MOUNTS]
        for source, dest in ((candidate, "/candidate"), (checks, "/checks"), (observed, "/observed")):
            if source is not None:
                mounts.append((str(source), dest))
        operation = (candidate or checks or observed.parent.parent.parent)
        if candidate is not None or checks is not None:
            operation = operation.parent
        mounts.append((str(operation / "runner"), "/runner"))
        argv = [_BWRAP, "--unshare-all", "--unshare-user", "--die-with-parent", "--new-session",
                "--disable-userns", "--assert-userns-disabled", "--cap-drop", "ALL", "--clearenv"]
        for source, dest in mounts:
            argv += ["--ro-bind", source, dest]
        argv += ["--dev", _DEV, "--remount-ro", _DEV,
                 "--size", str(self.policy.limits.scratch_bytes), "--tmpfs", "/scratch",
                 "--remount-ro", "/", "--setenv", "HOME", "/nonexistent",
                 "--setenv", "LC_ALL", "C", "--setenv", "TMPDIR", "/scratch",
                 "--chdir", "/scratch", "--", _SANDBOX_PYTHON, "-I", "-S", "-B",
                 "/runner/limits.py", str(self.policy.limits.processes), script]
        return argv, tuple(mounts)

    def verify(self, request: VerificationRequest) -> dict:
        result = {"status": "REFUSED", "reason": "request:invalid", "qualification": False,
                  "retain_claims": True}
        directory, lock, evidence = None, None, None
        owns_observation = False
        try:
            self._validate_request(request)
            local._private_dir(self.custody)
            directory = self.operation_directory(request)
            local._private_dir(directory)
            lock = local._open(directory / "operation.lock", os.O_RDWR | os.O_CREAT)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {**result, "status": "UNKNOWN", "reason": "verification:busy"}
            try:
                original = local._read(directory / "request.json")
            except FileNotFoundError:
                original = None
            if original is not None:
                return self._retained(directory, request)
            local._create(directory / "request.json", request.canonical_bytes)
            owns_observation = True
            deadline = time.monotonic() + self.policy.limits.total_seconds
            runtime = _runtime_identity()
            local._private_dir(directory / "collector")
            for source in _collector_sources():
                raw_source = source.read_bytes()
                if _sha(raw_source) != runtime[str(source)]["content_sha256"]:
                    raise VerificationRefusal("runtime:source_changed")
                local._create(directory / "collector" / source.name, raw_source)
            local._private_dir(directory / "runner")
            local._create(directory / "runner" / "limits.py", _LIMIT_RUNNER)
            contents, check_identities = self._checks()
            preparation = []
            manifest = self._stage(directory, request, lock, deadline, preparation)
            local._private_dir(directory / "checks")
            for name, raw in contents.items():
                path = directory / "checks" / name
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                local._create(path, raw)
            evidence = {"schema": EVIDENCE_SCHEMA,
                        "request": json.loads(request.canonical_bytes),
                        "policy": json.loads(self.policy.canonical_bytes),
                        "runtime_identity": runtime, "check_identity": check_identities,
                        "candidate_manifest": manifest, "preparation_commands": preparation,
                        "commands": []}
            result.update(status="VERIFIED", reason="checks:passed")
            for check in self.policy.checks:
                self._unchanged(directory, manifest, check_identities, runtime)
                observed = None
                if check.kind == "behavioral":
                    argv, mounts = self._sandbox(directory / "candidate", None, None,
                                                 "/candidate/" + self.policy.entrypoint)
                    row = self._run(directory, argv, check.stdin, lock, deadline, mounts=mounts)
                    evidence["commands"].append(row)
                    if not self._successful(row):
                        result.update(self._failure(row))
                        break
                    observed = Path(row["command_directory"]) / "observed"
                    local._private_dir(observed)
                    for name in ("stdout", "stderr"):
                        local._create(observed / name, local._read(observed.parent / name))
                    local._create(observed / "result.json", _canonical({"exit_code": row["exit_code"],
                                  "stdout_sha256": row["stdout_sha256"], "stderr_sha256": row["stderr_sha256"]}))
                argv, mounts = self._sandbox(directory / "candidate" if check.kind == "structural" else None,
                                             directory / "checks", observed, "/checks/" + check.path)
                row = self._run(directory, argv, b"", lock, deadline, mounts=mounts)
                evidence["commands"].append(row)
                if not self._successful(row):
                    result.update(self._failure(row))
                    break
            self._unchanged(directory, manifest, check_identities, runtime)
            self._receipts_unchanged(directory, evidence["preparation_commands"] + evidence["commands"])
        except (VerificationRefusal, local.PublicationRefusal) as error:
            result.update(status="REFUSED", reason=str(error))
        except (OSError, ValueError, KeyError, TypeError) as error:
            result.update(status="UNKNOWN", reason="verification:unavailable:" + type(error).__name__)
        finally:
            try:
                if evidence is not None:
                    evidence.update(status=result["status"], reason=result["reason"])
                    if result["status"] == "VERIFIED":
                        evidence.update(verified_commit=request.commit, verified_tree=request.tree)
                    validate_retained_evidence(evidence)
                    raw = _canonical(evidence)
                    if len(raw) > STREAM_LIMIT:
                        raise VerificationRefusal("evidence:record_oversized")
                    local._create(directory / "evidence.json", raw)
                    local._create(directory / "evidence.sha256", _sha(raw).encode())
                    result.update(evidence_path=str(directory / "evidence.json"), evidence_sha256=_sha(raw))
            except (OSError, ValueError) as error:
                result.update(status="UNKNOWN", reason="evidence:unsettled:" + str(error))
            finally:
                if owns_observation and "evidence_path" not in result:
                    try:
                        self._retain_observation(directory, request, result)
                    except (OSError, ValueError, KeyError, TypeError) as error:
                        result.update(status="UNKNOWN", reason="observation:unsettled:" + type(error).__name__)
                if lock is not None:
                    os.close(lock)  # never explicitly unlock an inherited descriptor
        return result

    @staticmethod
    def _successful(row):
        return successful_command_observation(row)

    @staticmethod
    def _failure(row):
        if not row["cleanup"]["complete"]:
            return {"status": "UNKNOWN", "reason": "process:cleanup_unproved"}
        if row["reason"] in ("timeout", "output_limit"):
            return {"status": "STOPPED", "reason": "process:" + row["reason"]}
        return {"status": "FAILED", "reason": "check:nonzero_exit"}


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--supervise":
        raise SystemExit(_supervise(Path(sys.argv[2])))
    raise SystemExit("No public CLI; trusted host enrollment required.")
