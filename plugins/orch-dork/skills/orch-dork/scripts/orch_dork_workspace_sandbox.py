#!/usr/bin/env python3
"""Typed, immutable sandbox-policy records for orch-dork v3 enforcement.

Exact WorkspaceSandboxPolicy fields and bounds (schema
orch-dork/workspace-sandbox-policy/v1): attempt_id and lane_id are
non-empty strings with no NUL bytes; workspace is an existing directory
normalized with os.path.realpath that serves as the disposable namespace
root; writable_roots is a sequence of up to MAX_WRITABLE_ROOTS (6)
distinct real paths each contained in workspace, with no root contained
in another; scratch_dir and tmp_dir are existing directories outside the
policy scope; network_granted is bool (default False, launches isolate
the network by default); command is an absolute argv array, at most
MAX_ARGV_ELEMENTS (64) elements and MAX_ARGV_BYTES (65536) total bytes
with no single argument over MAX_ARG_BYTES (8192), or None to declare no
command; limits is WorkspaceLimits (wall_seconds capped at
MAX_WALL_SECONDS 10.0, and every field is additionally capped at a fixed
v1 ceiling: cpu_seconds MAX_CPU_SECONDS 30.0,
max_address_space_bytes MAX_ADDRESS_SPACE_BYTES 2 GiB, stdout_bytes /
stderr_bytes MAX_OUTPUT_BYTES 4 MiB each -- any widening beyond its fixed
cap is rejected as a limit violation).

The v1 limit fields name exactly what the default executor can enforce
with POSIX mechanisms: wall (deadline wait plus process-group
termination), cpu (RLIMIT_CPU), memory (RLIMIT_AS, which bounds process
virtual address space -- a true RSS ceiling has no portably enforceable
rlimit, so the field is named honestly), and output (bounded capture).
No field is declared that this backend cannot soundly enforce; an
executor that cannot attest the full v1 contract makes launch fail
closed with the stable ENFORCEMENT_UNAVAILABLE reason.

launch(policy, *, plan=None, dry_run=False, executor=None) takes the
authoritative WorkspaceSandboxPolicy, revalidates it, freshly probes
bwrap, and deterministically rebuilds the exact expected bwrap argv and
limits memo from that policy and the observed executable/capabilities.
An optional public plan is never executable on its own: it is compared
field-by-field and byte-for-byte -- executable, argv, chdir/workspace/
scratch/tmp paths, writable roots, network grant, limits and limits
digest, and policy digest -- and any forged or stale value is refused
with PLAN_FORGED before dry-run or execution.

Launch enforcement and the disposable SQLite snapshot adapter live in one
workspace-custody module because they are two sides of the same boundary:
the launch side defines the only namespace a lane may write to, and the
snapshot side captures lane state out of that namespace without touching
live files.  Sharing one module means one reason registry, one
normalized-scope check, and one fail-closed precondition chain govern
both, so a caller cannot mix a custody decision from one with an
execution or evidence capture from the other.

Standard library only.  Nothing in this module spawns a process without an
explicit, injected or default executor, and every execution path fails
closed when a precondition (bwrap availability, temp containment, source
integrity) is not met.  Scratch and tmp tmpfs mounts are sized at
SCRATCH_TMPFS_BYTES (64 MiB) and TMP_TMPFS_BYTES (16 MiB) respectively.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

POLICY_SCHEMA = "orch-dork/workspace-sandbox-policy/v1"
POLICY_VERSION = "workspace-sandbox-policy/v1"

MAX_WRITABLE_ROOTS = 6
MAX_WALL_SECONDS = 10.0
MAX_CPU_SECONDS = 30.0
MAX_ADDRESS_SPACE_BYTES = 2 << 30
MAX_OUTPUT_BYTES = 4 << 20
MAX_ARG_BYTES = 8192
MAX_ARGV_ELEMENTS = 64
MAX_ARGV_BYTES = 65536
SCRATCH_TMPFS_BYTES = 64 << 20
TMP_TMPFS_BYTES = 16 << 20

# The v1 limit contract: the exact field names an executor must attest it
# can enforce with POSIX mechanisms.  No field may be added or removed
# silently; an executor that cannot attest every field makes launch fail
# closed (ENFORCEMENT_UNAVAILABLE).
LIMIT_CONTRACT_FIELDS = (
    "wall_seconds",
    "cpu_seconds",
    "max_address_space_bytes",
    "stdout_bytes",
    "stderr_bytes",
)

REASON_OK = "OK"
REASON_INVALID_FIELD = "INVALID_FIELD"
REASON_ARGV_INVALID = "ARGV_INVALID"
REASON_ARGV_SHELL_INPUT = "ARGV_SHELL_INPUT"
REASON_ARGV_UNAVAILABLE = "ARGV_UNAVAILABLE"
REASON_PATH_INVALID = "PATH_INVALID"
REASON_PATH_NOT_ABSOLUTE = "PATH_NOT_ABSOLUTE"
REASON_PATH_NOT_DISPOSABLE = "PATH_NOT_DISPOSABLE"
REASON_WORKSPACE_MISSING = "WORKSPACE_MISSING"
REASON_WORKSPACE_NOT_DIRECTORY = "WORKSPACE_NOT_DIRECTORY"
REASON_WORKING_DIRECTORY_MISSING = "WORKING_DIRECTORY_MISSING"
REASON_WORKING_DIRECTORY_NOT_DIRECTORY = "WORKING_DIRECTORY_NOT_DIRECTORY"
REASON_WORKING_DIRECTORY_OUTSIDE_WORKSPACE = "WORKING_DIRECTORY_OUTSIDE_WORKSPACE"
REASON_WRITE_ROOT_MISSING = "WRITE_ROOT_MISSING"
REASON_WRITE_ROOT_NOT_DIRECTORY = "WRITE_ROOT_NOT_DIRECTORY"
REASON_WRITE_ROOT_OUTSIDE_WORKSPACE = "WRITE_ROOT_OUTSIDE_WORKSPACE"
REASON_WRITE_ROOT_DUPLICATE = "WRITE_ROOT_DUPLICATE"
REASON_WRITABLE_ROOTS_AMBIGUOUS = "WRITABLE_ROOTS_AMBIGUOUS"
REASON_TOO_MANY_WRITE_ROOTS = "TOO_MANY_WRITE_ROOTS"
REASON_SCRATCH_IN_POLICY_SCOPE = "SCRATCH_IN_POLICY_SCOPE"
REASON_SCRATCH_MISSING = "SCRATCH_MISSING"
REASON_SCRATCH_NOT_DIRECTORY = "SCRATCH_NOT_DIRECTORY"
REASON_TMP_IN_POLICY_SCOPE = "TMP_IN_POLICY_SCOPE"
REASON_TMP_MISSING = "TMP_MISSING"
REASON_TMP_NOT_DIRECTORY = "TMP_NOT_DIRECTORY"
REASON_LIMIT_WIDENING = "LIMIT_WIDENING"
REASON_ENFORCEMENT_UNAVAILABLE = "ENFORCEMENT_UNAVAILABLE"
REASON_PLAN_FORGED = "PLAN_FORGED"
REASON_BWRAP_UNAVAILABLE = "BWRAP_UNAVAILABLE"
REASON_BWRAP_NETWORK_UNSUPPORTED = "BWRAP_NETWORK_UNSUPPORTED"
REASON_BWRAP_NEW_SESSION_UNSUPPORTED = "BWRAP_NEW_SESSION_UNSUPPORTED"
REASON_BWRAP_PROBE_FAILED = "BWRAP_PROBE_FAILED"
REASON_NON_TEMP_EXECUTION = "NON_TEMP_EXECUTION"
REASON_EXECUTION_NONZERO = "EXECUTION_NONZERO"
REASON_EXECUTION_TIMEOUT = "EXECUTION_TIMEOUT"
REASON_SNAPSHOT_SOURCE_MISSING = "SNAPSHOT_SOURCE_MISSING"
REASON_SNAPSHOT_SOURCE_NOT_DB = "SNAPSHOT_SOURCE_NOT_DB"
REASON_SNAPSHOT_SOURCE_LOCKED = "SNAPSHOT_SOURCE_LOCKED"
REASON_SNAPSHOT_SOURCE_UNREADABLE = "SNAPSHOT_SOURCE_UNREADABLE"
REASON_SNAPSHOT_DEST_CONFLICT = "SNAPSHOT_DEST_CONFLICT"
REASON_SNAPSHOT_DEST_DENIED = "SNAPSHOT_DEST_DENIED"
REASON_SNAPSHOT_DEST_UNKNOWN = "SNAPSHOT_DEST_UNKNOWN"
REASON_LAYOUT_UNKNOWN = "LAYOUT_UNKNOWN"

KNOWN_REASONS = frozenset({
    REASON_OK, REASON_INVALID_FIELD,
    REASON_ARGV_INVALID, REASON_ARGV_SHELL_INPUT, REASON_ARGV_UNAVAILABLE,
    REASON_PATH_INVALID, REASON_PATH_NOT_ABSOLUTE, REASON_PATH_NOT_DISPOSABLE,
    REASON_WORKSPACE_MISSING, REASON_WORKSPACE_NOT_DIRECTORY,
    REASON_WORKING_DIRECTORY_MISSING, REASON_WORKING_DIRECTORY_NOT_DIRECTORY,
    REASON_WORKING_DIRECTORY_OUTSIDE_WORKSPACE,
    REASON_WRITE_ROOT_MISSING, REASON_WRITE_ROOT_NOT_DIRECTORY,
    REASON_WRITE_ROOT_OUTSIDE_WORKSPACE, REASON_WRITE_ROOT_DUPLICATE,
    REASON_WRITABLE_ROOTS_AMBIGUOUS, REASON_TOO_MANY_WRITE_ROOTS,
    REASON_SCRATCH_IN_POLICY_SCOPE, REASON_SCRATCH_MISSING,
    REASON_SCRATCH_NOT_DIRECTORY, REASON_TMP_IN_POLICY_SCOPE,
    REASON_TMP_MISSING, REASON_TMP_NOT_DIRECTORY, REASON_LIMIT_WIDENING,
    REASON_ENFORCEMENT_UNAVAILABLE, REASON_PLAN_FORGED,
    REASON_BWRAP_UNAVAILABLE, REASON_BWRAP_NETWORK_UNSUPPORTED,
    REASON_BWRAP_NEW_SESSION_UNSUPPORTED, REASON_BWRAP_PROBE_FAILED,
    REASON_NON_TEMP_EXECUTION, REASON_EXECUTION_NONZERO,
    REASON_EXECUTION_TIMEOUT,
    REASON_SNAPSHOT_SOURCE_MISSING, REASON_SNAPSHOT_SOURCE_NOT_DB,
    REASON_SNAPSHOT_SOURCE_LOCKED, REASON_SNAPSHOT_SOURCE_UNREADABLE,
    REASON_SNAPSHOT_DEST_CONFLICT, REASON_SNAPSHOT_DEST_DENIED,
    REASON_SNAPSHOT_DEST_UNKNOWN, REASON_LAYOUT_UNKNOWN,
})

_SHELL_BASENAMES = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "fish", "ash", "mksh"})
_FS_ROOT = os.path.abspath(os.sep)
_VAR_TMP = os.path.join(_FS_ROOT, "var", "tmp")
_DEV = os.path.join(_FS_ROOT, "dev")
_DEV_PTS = os.path.join(_DEV, "pts")
_DEV_FD = os.path.join(_DEV, "fd")
_DEV_SHM = os.path.join(_DEV, "shm")
_PROC = os.path.join(_FS_ROOT, "proc")
_PROC_SELF_FD = os.path.join(_PROC, "self", "fd")
_DISPOSABLE_PREFIXES = tuple(
    sorted({os.path.realpath(tempfile.gettempdir()), _VAR_TMP, _DEV_SHM}))


def _disposable_prefixes() -> tuple:
    """Namespace prefixes a policy is allowed to bind into."""
    return _DISPOSABLE_PREFIXES


def _path_within(child: str, parent: str) -> bool:
    """True when child equals or sits under parent (real paths)."""
    return child == parent or child.startswith(parent + os.sep)


def _pairwise(paths: list):
    """Deterministic pairwise ordering (original relative order kept)."""
    for i, first in enumerate(paths):
        for second in paths[i + 1:]:
            yield first, second


class SandboxPolicyError(ValueError):
    """Typed policy violation carrying a stable machine-readable reason."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__("%s: %s" % (reason, detail) if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class WorkspaceLimits:
    """Bounded process/resource ceilings for one sandboxed command."""

    wall_seconds: float = MAX_WALL_SECONDS
    cpu_seconds: float = 5.0
    max_address_space_bytes: int = 1 << 30
    stdout_bytes: int = 1 << 20
    stderr_bytes: int = 1 << 20

    def validate(self):
        """Return a failure reason, or None when the limits are well-formed."""
        for name in ("wall_seconds", "cpu_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return REASON_INVALID_FIELD
            if value <= 0:
                return REASON_INVALID_FIELD
        if self.wall_seconds > MAX_WALL_SECONDS:
            return REASON_LIMIT_WIDENING
        for name in LIMIT_CONTRACT_FIELDS:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return REASON_INVALID_FIELD
            if value <= 0:
                return REASON_INVALID_FIELD
        pairs = (
            ("wall_seconds", MAX_WALL_SECONDS),
            ("cpu_seconds", MAX_CPU_SECONDS),
            ("max_address_space_bytes", MAX_ADDRESS_SPACE_BYTES),
            ("stdout_bytes", MAX_OUTPUT_BYTES),
            ("stderr_bytes", MAX_OUTPUT_BYTES),
        )
        for name, cap in pairs:
            if getattr(self, name) > cap:
                return REASON_LIMIT_WIDENING
        return None

    def as_dict(self) -> dict:
        return {
            "wall_seconds": self.wall_seconds,
            "cpu_seconds": self.cpu_seconds,
            "max_address_space_bytes": self.max_address_space_bytes,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
        }


@dataclass(frozen=True)
class WorkspaceSandboxPolicy:
    """One immutable, digest-addressed sandboxing decision for a lane.

    All paths are normalized with os.path.realpath at validation time so
    that a policy can never smuggle a sibling directory into the scope
    through a symlink created after the record is frozen.
    """

    attempt_id: str
    lane_id: str
    workspace: "str | Path"
    writable_roots: tuple
    scratch_dir: "str | Path"
    tmp_dir: "str | Path"
    network_granted: bool = False
    command: tuple = None  # None = no command declared (skips argv rules)
    limits: WorkspaceLimits = WorkspaceLimits()
    working_directory: "str | Path | None" = None
    workspace_write_granted: bool = False

    def __post_init__(self):
        for name in ("attempt_id", "lane_id"):
            value = object.__getattribute__(self, name)
            if not isinstance(value, str) or not value or "\x00" in value:
                raise SandboxPolicyError(
                    REASON_INVALID_FIELD, "%s must be non-empty str" % name)
        if not isinstance(
                object.__getattribute__(self, "network_granted"), bool):
            raise SandboxPolicyError(
                REASON_INVALID_FIELD, "network_granted must be bool")
        if not isinstance(
                object.__getattribute__(self, "workspace_write_granted"), bool):
            raise SandboxPolicyError(
                REASON_INVALID_FIELD, "workspace_write_granted must be bool")
        limits = object.__getattribute__(self, "limits")
        if not isinstance(limits, WorkspaceLimits):
            raise SandboxPolicyError(
                REASON_INVALID_FIELD, "limits must be WorkspaceLimits")
        command = object.__getattribute__(self, "command")
        if command is not None and not isinstance(command, (list, tuple)):
            raise SandboxPolicyError(
                REASON_INVALID_FIELD, "command must be an argv array")
        roots = object.__getattribute__(self, "writable_roots")
        if not isinstance(roots, (list, tuple)):
            raise SandboxPolicyError(
                REASON_INVALID_FIELD, "writable_roots must be a sequence")
        object.__setattr__(self, "writable_roots", tuple(roots))
        object.__setattr__(
            self, "command", None if command is None else tuple(command))

    # -- canonical identity ---------------------------------------------------

    def as_dict(self) -> dict:
        result = {
            "schema": POLICY_SCHEMA,
            "version": POLICY_VERSION,
            "attempt_id": self.attempt_id,
            "lane_id": self.lane_id,
            "workspace": str(self.workspace),
            "writable_roots": [str(root) for root in self.writable_roots],
            "scratch_dir": str(self.scratch_dir),
            "tmp_dir": str(self.tmp_dir),
            "network_granted": self.network_granted,
            "command": list(self.command) if self.command is not None else [],
            "limits": self.limits.as_dict(),
        }
        # Omit default extension fields so historical v1 policy digests remain
        # byte-for-byte stable.  Worker launch opts into both explicitly.
        if self.working_directory is not None:
            result["working_directory"] = str(self.working_directory)
        if self.workspace_write_granted:
            result["workspace_write_granted"] = True
        return result

    def policy_digest(self) -> str:
        payload = json.dumps(self.as_dict(), sort_keys=True,
                             separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # -- validation -------------------------------------------------------------

    def validate(self) -> dict:
        """Check every policy predicate; raise SandboxPolicyError on failure.

        On success the report normalizes each path to a real absolute path
        and deterministically orders the writable roots.
        """
        limits_reason = self.limits.validate()
        if limits_reason is not None:
            raise SandboxPolicyError(limits_reason)

        workspace = _verified_path(
            self.workspace, REASON_WORKSPACE_MISSING,
            REASON_WORKSPACE_NOT_DIRECTORY, is_dir=True)
        working_directory = None
        if self.working_directory is not None:
            working_directory = _verified_path(
                self.working_directory,
                REASON_WORKING_DIRECTORY_MISSING,
                REASON_WORKING_DIRECTORY_NOT_DIRECTORY,
                is_dir=True,
            )
            if not _path_within(working_directory, workspace):
                raise SandboxPolicyError(
                    REASON_WORKING_DIRECTORY_OUTSIDE_WORKSPACE,
                    working_directory,
                )
        if self.command is not None:
            self._validate_argv()

        roots: list = []
        for root in self.writable_roots:
            path = _verified_path(
                root, REASON_WRITE_ROOT_MISSING,
                REASON_WRITE_ROOT_NOT_DIRECTORY, is_dir=True)
            if not _path_within(path, workspace):
                raise SandboxPolicyError(
                    REASON_WRITE_ROOT_OUTSIDE_WORKSPACE, path)
            if path == workspace and not self.workspace_write_granted:
                raise SandboxPolicyError(
                    REASON_WRITE_ROOT_OUTSIDE_WORKSPACE,
                    "workspace itself is not an explicit writable root")
            roots.append(path)
        if len(roots) > MAX_WRITABLE_ROOTS:
            raise SandboxPolicyError(REASON_TOO_MANY_WRITE_ROOTS)
        for lower, upper in _pairwise(roots):
            if lower == upper:
                raise SandboxPolicyError(REASON_WRITE_ROOT_DUPLICATE, lower)
            if _path_within(lower, upper) or _path_within(upper, lower):
                raise SandboxPolicyError(
                    REASON_WRITABLE_ROOTS_AMBIGUOUS,
                    " / ".join((lower, upper)))

        scope_paths = [workspace] + roots
        scratch = _verified_path(
            self.scratch_dir, REASON_SCRATCH_MISSING,
            REASON_SCRATCH_NOT_DIRECTORY, is_dir=True)
        tmp = _verified_path(
            self.tmp_dir, REASON_TMP_MISSING, REASON_TMP_NOT_DIRECTORY,
            is_dir=True)
        if _belongs_to_scope(scratch, scope_paths):
            raise SandboxPolicyError(REASON_SCRATCH_IN_POLICY_SCOPE, scratch)
        if _belongs_to_scope(tmp, scope_paths):
            raise SandboxPolicyError(REASON_TMP_IN_POLICY_SCOPE, tmp)
        if tmp == scratch:
            raise SandboxPolicyError(
                REASON_SCRATCH_IN_POLICY_SCOPE, "scratch equals tmp")

        if working_directory is None:
            working_directory = scratch

        return {
            "reason": REASON_OK,
            "scope": {
                "workspace": workspace,
                "writable_roots": sorted(set(roots)),
                "scratch_dir": scratch,
                "tmp_dir": tmp,
                "working_directory": working_directory,
            },
        }

    # -- argv rules --------------------------------------------------------------

    def _validate_argv(self) -> None:
        command = self.command
        if not isinstance(command, (list, tuple)):
            raise SandboxPolicyError(REASON_ARGV_INVALID)
        if not command or len(command) > MAX_ARGV_ELEMENTS:
            raise SandboxPolicyError(REASON_ARGV_INVALID, "empty or oversized")
        argv_bytes = 0
        for element in command:
            if not isinstance(element, str):
                raise SandboxPolicyError(
                    REASON_ARGV_INVALID, "non-str argv member")
            encoded = element.encode("utf-8")
            if len(encoded) > MAX_ARG_BYTES:
                raise SandboxPolicyError(
                    REASON_ARGV_INVALID, "element exceeds MAX_ARG_BYTES")
            argv_bytes += len(encoded)
        if argv_bytes > MAX_ARGV_BYTES:
            raise SandboxPolicyError(REASON_ARGV_INVALID, "total exceeds")
        program = command[0]
        if Path(program).name in _SHELL_BASENAMES:
            raise SandboxPolicyError(REASON_ARGV_SHELL_INPUT, program)
        if not os.path.isabs(program):
            raise SandboxPolicyError(
                REASON_ARGV_SHELL_INPUT,
                "relative argv0 is shell-ish: %r" % (program,))
        if not (os.path.isfile(program) and os.access(program, os.X_OK)):
            raise SandboxPolicyError(REASON_ARGV_UNAVAILABLE, program)


def _verified_path(value, missing_reason, notdir_reason, is_dir=True) -> str:
    """Apply the shared path predicates in fixed order; return the realpath.

    Order is a contract: type/NUL, absoluteness, disposable-namespace
    containment, then liveness, so an operator gets the most specific
    useful reason for a bad policy field.
    """
    if isinstance(value, (bytes, bytearray)):
        raise SandboxPolicyError(REASON_PATH_INVALID, "binary path")
    try:
        text = os.fspath(value)
    except TypeError:
        raise SandboxPolicyError(
            REASON_PATH_INVALID, "path must be PathLike, got %r" % type(value))
    if not isinstance(text, str) or not text or "\x00" in text:
        raise SandboxPolicyError(REASON_PATH_INVALID, "empty or NUL path")
    if not os.path.isabs(text):
        raise SandboxPolicyError(REASON_PATH_NOT_ABSOLUTE, text)
    resolved = os.path.realpath(text)
    if not any(_path_within(resolved, prefix)
               for prefix in _disposable_prefixes()):
        raise SandboxPolicyError(REASON_PATH_NOT_DISPOSABLE, resolved)
    if not os.path.exists(resolved):
        raise SandboxPolicyError(missing_reason, resolved)
    if is_dir and not os.path.isdir(resolved):
        raise SandboxPolicyError(notdir_reason, resolved)
    return resolved


def _belongs_to_scope(path: str, scope_paths: list) -> bool:
    """True when path equals or sits under any scope path (sibling-prefix
    mismatches are excluded because both are real absolute paths)."""
    return any(path == scope or _path_within(path, scope)
               for scope in scope_paths)

# =============================================================================
# Slice 2: bwrap capability detection and pure launch-plan construction.
#
# The *executor* protocol is the seam: whichever object is injected must
# provide which(name) -> path-or-None and run(argv, timeout=...) ->
# (returncode, stdout, stderr).  The default executor talks to the
# platform; tests inject fakes, so bwrap never has to be installed.
# =============================================================================

@dataclass(frozen=True)
class BwrapFeatures:
    """Observed facts about one bwrap executable (absence = fail-closed)."""

    executable: "str | None" = None
    version: "str | None" = None
    has_network_isolation: bool = False
    has_new_session: bool = False

    @property
    def available(self) -> bool:
        return self.executable is not None


class _DefaultExecutor:
    """Platform executor: stdlib resource/setrlimit, bounded I/O,
    process-group teardown.  Attests the full v1 limit contract.

    Contract honored at ``run`` time (stdlib only):

    * ``max_address_space_bytes`` -- ``RLIMIT_AS`` clamped onto the child
      in the fork ``preexec_fn`` (virtual address space; a true RSS
      rlimit is not portably enforceable, hence the honest field name).
    * ``cpu_seconds`` -- ``RLIMIT_CPU`` on the child; the kernel enforces
      the integer floor, so the child is killed at the floor (never above
      the requested budget).
    * ``stdout_bytes`` / ``stderr_bytes`` -- bounded capture: once a
      stream reaches its bound the collector keeps draining and
      discarding (no writer deadlock, bounded memory) and the collected
      text carries a truncation marker.
    * ``wall_seconds`` -- wall-clock deadline from spawn start; on
      expiry the child's process group is signalled (SIGTERM then
      SIGKILL after a bounded grace) and the group-wait removes the
      whole tree.

    Limit clamping is strictly *lowering*: rlimits may never be raised
    above the current soft/hard values, only tightened, so repeated
    probes and runs cannot trip "cannot raise hard limit".

    Any platform without the required POSIX primitives (no ``resource``
    module, no ``RLIMIT_AS`` / ``RLIMIT_CPU``, or setrlimit failing)
    makes ``run`` fail closed with ENFORCEMENT_UNAVAILABLE rather than
    silently running unbounded.
    """

    # Probe-time defaults; launch() replaces limits with the policy's
    # before any guarded run, so probes never widen the contract.
    limits = WorkspaceLimits(
        wall_seconds=10.0, cpu_seconds=10.0,
        max_address_space_bytes=1 << 30,
        stdout_bytes=1 << 20, stderr_bytes=1 << 20)
    # Attest support for every declared v1 limit field; launch() verifies
    # this mapping key-for-key against LIMIT_CONTRACT_FIELDS.
    attested_limits = {name: True for name in LIMIT_CONTRACT_FIELDS}

    # Namespace collector: per-stream bound and the truncation marker.
    _CHUNK = 65536

    def which(self, name):
        import shutil
        return shutil.which(name)

    # -- rlimit clamping -------------------------------------------------------

    def _clamp_rlimits_for_child(self, limits: WorkspaceLimits):
        """Return a preexec_fn that tightens CPU/AS on the forked child.

        Runs in the child *before exec*, so the tightening is scoped to
        the sandboxed process group and never to this parent interpreter.
        The clamp never exceeds the hard limit: rlimits may only be
        lowered, so the target is min(requested, current soft, current
        hard).  A parent-side getrlimit failure raises
        SandboxPolicyError(ENFORCEMENT_UNAVAILABLE) before the spawn; a
        child-side setrlimit failure kills the child before exec, so the
        guarded run sees a non-zero exit and is refused -- never unbounded.
        """
        import resource

        if not (hasattr(resource, "RLIMIT_AS")
                and hasattr(resource, "RLIMIT_CPU")):
            def _fail():
                raise SandboxPolicyError(
                    REASON_ENFORCEMENT_UNAVAILABLE,
                    "resource module lacks RLIMIT_AS/RLIMIT_CPU; the v1 "
                    "limit contract cannot be attested on this platform")
            return _fail
        as_target = int(limits.max_address_space_bytes)
        cpu_target = int(limits.cpu_seconds)  # kernel enforces the floor

        def _clamp():
            for which, target in ((resource.RLIMIT_AS, as_target),
                                  (resource.RLIMIT_CPU, cpu_target)):
                hard, soft = resource.getrlimit(which)
                # Only ever lower: a -1 (unlimited) side acts as +inf.
                candidates = [target]
                if soft > 0:
                    candidates.append(soft)
                if hard > 0:
                    candidates.append(hard)
                clamped = min(candidates)
                resource.setrlimit(which, (clamped, hard if hard > 0
                                          else clamped))
        try:
            # Exercise the getters in the parent too: a platform whose
            # getrlimit raises (or that cannot surface limits here) must
            # fail the whole launch, not half-enforce in the child.
            resource.getrlimit(resource.RLIMIT_AS)
            resource.getrlimit(resource.RLIMIT_CPU)
        except (OSError, ValueError, OverflowError) as exc:
            raise SandboxPolicyError(
                REASON_ENFORCEMENT_UNAVAILABLE,
                "cannot read current rlimits: %s" % exc)
        return _clamp

    def _clamped_preexec(self, limits: WorkspaceLimits):
        return self._clamp_rlimits_for_child(limits)

    # -- process-group teardown -------------------------------------------------

    def _kill_process_group(self, pid):
        """SIGTERM the group, bounded grace, then SIGKILL; wait it out."""
        import signal
        import time
        try:
            os.killpg(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            try:
                os.killpg(pid, 0)
            except (ProcessLookupError, PermissionError):
                return
            time.sleep(0.05)
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    # -- run -------------------------------------------------------------------

    def run(self, argv, timeout=None, cwd=None, env=None, limits=None):
        """Run *argv* under the v1 limit contract; return (rc, out, err).

        ``limits`` defaults to ``self.limits``; ``timeout`` (when given)
        overrides the wall ceiling.  Fail-closed: any enforcement gap
        raises SandboxPolicyError(ENFORCEMENT_UNAVAILABLE).
        """
        import subprocess

        limits = limits if limits is not None else self.limits
        if not isinstance(limits, WorkspaceLimits):
            raise SandboxPolicyError(
                REASON_ENFORCEMENT_UNAVAILABLE,
                "run() requires a WorkspaceLimits (got %r)" % (limits,))
        preexec = self._clamped_preexec(limits)
        wall = float(limits.wall_seconds) if timeout is None else float(timeout)
        out_bound = int(limits.stdout_bytes)
        err_bound = int(limits.stderr_bytes)

        try:
            proc = subprocess.Popen(
                list(argv), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=cwd, env=env, close_fds=True,
                start_new_session=True, preexec_fn=preexec)
        except (OSError, subprocess.SubprocessError) as exc:
            return (127, "", "spawn failed: %s" % exc)

        # Keep collector state simple: [truncated_flag, data_list, total].
        out_state = [False, [], 0]
        err_state = [False, [], 0]

        def _pump(stream, state, bound):
            while True:
                data = stream.read(self._CHUNK)
                if not data:
                    break
                if not state[0]:
                    if state[2] + len(data) <= bound:
                        state[1].append(data)
                        state[2] += len(data)
                    else:
                        first = bound - state[2]
                        state[1].append(data[:first])
                        state[0] = True
                        state[2] = bound
            stream.close()

        import threading
        out_thread = threading.Thread(
            target=_pump, args=(proc.stdout, out_state, out_bound),
            daemon=True)
        err_thread = threading.Thread(
            target=_pump, args=(proc.stderr, err_state, err_bound),
            daemon=True)
        out_thread.start()
        err_thread.start()

        import time
        start = time.monotonic()
        timed_out = False
        try:
            proc.wait(timeout=max(0.0, wall))
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill_process_group(proc.pid)
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                pass

        for thread in (out_thread, err_thread):
            thread.join(timeout=1.0)

        def _finalize(state, bound, stream_name):
            text = b"".join(state[1]).decode("utf-8", "replace")
            if state[0]:
                text += output_overflow_marker(stream_name, bound)
            return text

        if timed_out:
            wall_used = time.monotonic() - start
            return (None, "",
                    "timed out after %s seconds (wall %.3fs of %.3fs)"
                    % (wall, wall_used, wall))
        return (proc.returncode,
                _finalize(out_state, out_bound, "stdout"),
                _finalize(err_state, err_bound, "stderr"))


def output_overflow_marker(stream_name: str, bound: int) -> str:
    """Stable, honest suffix appended when a stream hit its byte bound.

    The marker names the stream, the bound, and that the surplus was
    discarded -- memory stays bounded, and no byte is silently edited
    to fit.  ``bound`` is the exact configured limit, not a guess.
    """
    return ("[%s-truncated] first %d bytes collected; the remainder was "
            "discarded to enforce the %d-byte bound\n"
            % (stream_name, bound, bound))


def detect_bwrap(executor=None) -> BwrapFeatures:
    """Probe bwrap through *executor* (default: the platform itself).

    SandboxPolicyError(BWRAP_PROBE_FAILED) fires when a probe cannot
    complete; an absent binary is a normal fail-closed result.
    """
    ex = executor or _DefaultExecutor()
    try:
        path = ex.which("bwrap")
    except Exception as exc:
        raise SandboxPolicyError(
            REASON_BWRAP_PROBE_FAILED, "which(bwrap) raised: %s" % exc)
    if not path:
        return BwrapFeatures()
    try:
        rc, out, _ = ex.run([path, "--version"], timeout=10)
        if rc != 0:
            raise RuntimeError("version probe rc=%d" % rc)
        lines = (out or "").strip().splitlines()
        version = lines[0] if lines else None
        rc2, help_text, _ = ex.run([path, "--help"], timeout=10)
        if rc2 != 0:
            raise RuntimeError("help probe rc=%d" % rc2)
    except Exception as exc:
        raise SandboxPolicyError(
            REASON_BWRAP_PROBE_FAILED, "probe failed: %s" % exc)
    return BwrapFeatures(
        executable=path,
        version=version,
        has_network_isolation="--unshare-net" in (help_text or ""),
        has_new_session="--new-session" in (help_text or ""),
    )


def _limits_digest(limits: WorkspaceLimits) -> str:
    """Canonical sha256 over the limit contract's serialized fields."""
    payload = json.dumps(limits.as_dict(), sort_keys=True,
                         separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PlanMemo:
    """Execution-only opaque memo re-derived from the *policy*.

    A public SandboxLaunchPlan must never be executable merely because its
    paths look disposable.  launch() re-derives this exact digest from the
    authoritative WorkspaceSandboxPolicy plus freshly observed bwrap
    features, and byte-for-byte compares it to the carried memo before any
    dry-run or execution.  A forged or stale plan mismatches and is refused
    with PLAN_FORGED.
    """

    executable: str
    argv: tuple
    chdir: str
    workspace: str
    writable_roots: tuple
    scratch_dir: str
    tmp_dir: str
    network_granted: bool
    limits_digest: str
    policy_digest: str


@dataclass(frozen=True)
class SandboxLaunchPlan:
    """Deterministic, immutable bwrap launch for one validated policy.

    A plan is a *description*, not an execution: launch() re-derives the
    enforcement todo from the authoritative policy and observed features,
    and refuses any plan whose memo or byte-critical fields do not match it
    exactly (PLAN_FORGED) before a dry-run or execution.
    """

    executable: str
    argv: tuple
    chdir: str
    workspace: str
    writable_roots: tuple
    scratch_dir: str
    tmp_dir: str
    network_granted: bool
    limits: WorkspaceLimits
    limits_memo: PlanMemo
    policy_digest: str

    def as_dict(self) -> dict:
        return {
            "schema": POLICY_SCHEMA,
            "plan": "workspace-sandbox-launch/v1",
            "executable": self.executable,
            "argv": list(self.argv),
            "chdir": self.chdir,
            "workspace": self.workspace,
            "writable_roots": list(self.writable_roots),
            "scratch_dir": self.scratch_dir,
            "tmp_dir": self.tmp_dir,
            "network_granted": self.network_granted,
            "limits": self.limits.as_dict(),
            "limits_memo": {
                "executable": self.limits_memo.executable,
                "argv": list(self.limits_memo.argv),
                "chdir": self.limits_memo.chdir,
                "workspace": self.limits_memo.workspace,
                "writable_roots": list(self.limits_memo.writable_roots),
                "scratch_dir": self.limits_memo.scratch_dir,
                "tmp_dir": self.limits_memo.tmp_dir,
                "network_granted": self.limits_memo.network_granted,
                "limits_digest": self.limits_memo.limits_digest,
                "policy_digest": self.limits_memo.policy_digest,
            },
            "policy_digest": self.policy_digest,
        }


def build_launch_plan(policy: WorkspaceSandboxPolicy,
                      features: BwrapFeatures,
                      *,
                      workspace_root=None) -> SandboxLaunchPlan:
    """Produce the exact bwrap argv for *policy*; refuse unreliable inputs.

    Pure: re-validate the policy, check the observed bwrap capabilities,
    and freeze the argv.  No filesystem effects, no containment widening.
    """
    scope = policy.validate()["scope"]
    if not features.available:
        raise SandboxPolicyError(REASON_BWRAP_UNAVAILABLE)
    command = policy.command
    if not command:
        raise SandboxPolicyError(
            REASON_ARGV_INVALID,
            "a launch plan requires an explicit command")
    if policy.network_granted and not features.has_network_isolation:
        raise SandboxPolicyError(
            REASON_BWRAP_NETWORK_UNSUPPORTED,
            "cannot honor network grant on this bwrap build")
    if not features.has_new_session:
        raise SandboxPolicyError(
            REASON_BWRAP_NEW_SESSION_UNSUPPORTED,
            "refuse to run without --new-session (no TTY isolation)")

    roots = tuple(os.path.realpath(os.fspath(root))
                  for root in policy.writable_roots)
    if workspace_root is not None:
        root_real = os.path.realpath(os.fspath(workspace_root))
        guarded = {
            "workspace": scope["workspace"],
            "scratch": scope["scratch_dir"],
            "tmp": scope["tmp_dir"],
        }
        for label, path in guarded.items():
            if not _path_within(path, root_real):
                raise SandboxPolicyError(
                    REASON_INVALID_FIELD,
                    "%s escapes declared workspace root" % label)
        for path in scope["writable_roots"]:
            if not _path_within(path, root_real):
                raise SandboxPolicyError(
                    REASON_INVALID_FIELD,
                    "writable root escapes declared workspace root")

    argv = [features.executable, "--ro-bind", _FS_ROOT, _FS_ROOT]
    for root in roots:
        argv += ["--bind", root, root]
    argv += [
        "--size", str(SCRATCH_TMPFS_BYTES), "--tmpfs", scope["scratch_dir"],
        "--size", str(TMP_TMPFS_BYTES), "--tmpfs", scope["tmp_dir"],
        "--tmpfs", _DEV,
        "--dev", _DEV_PTS,
        "--symlink", _PROC_SELF_FD, _DEV_FD,
        "--tmpfs", _DEV_SHM,
        "--proc", _PROC,
        "--unshare-pid", "--unshare-uts", "--unshare-ipc", "--unshare-cgroup",
    ]
    if not policy.network_granted:
        argv.append("--unshare-net")
    argv += [
        "--die-with-parent", "--new-session", "--clearenv",
        "--chdir", scope["working_directory"],
        "--",
    ]
    argv += list(command)
    return SandboxLaunchPlan(
        executable=features.executable,
        argv=tuple(argv),
        chdir=scope["working_directory"],
        workspace=scope["workspace"],
        writable_roots=roots,
        scratch_dir=scope["scratch_dir"],
        tmp_dir=scope["tmp_dir"],
        network_granted=policy.network_granted,
        limits=policy.limits,
        limits_memo=PlanMemo(
            executable=features.executable,
            argv=tuple(argv),
            chdir=scope["working_directory"],
            workspace=scope["workspace"],
            writable_roots=roots,
            scratch_dir=scope["scratch_dir"],
            tmp_dir=scope["tmp_dir"],
            network_granted=policy.network_granted,
            limits_digest=_limits_digest(policy.limits),
            policy_digest=policy.policy_digest(),
        ),
        policy_digest=policy.policy_digest(),
    )


# =============================================================================
# Slice 3: policy-re-derived launch-time enforcement guard.
#
# launch() takes the *authoritative* WorkspaceSandboxPolicy, revalidates it
# fresh, probes bwrap, and deterministically rebuilds the exact expected
# plan/argv from that policy plus the observed executable and capabilities.
# A public SandboxLaunchPlan is never executable on its own: an optional
# plan= argument is compared field-by-field and byte-for-byte (digest
# included) against the re-derived plan and any mismatch -- forged or stale
# executable, argv, cwd, paths, network grant, limits, or policy_digest --
# is refused with PLAN_FORGED before dry-run or execution.  An executor
# that cannot attest and enforce the declared v1 limit contract makes
# launch fail closed with ENFORCEMENT_UNAVAILABLE.  dry_run=True returns the
# exact re-derived argv with zero side effects (probe-only).
# =============================================================================

_SQLITE_MAGIC = b"SQLite format 3\x00"


def _require_attested_executor(executor) -> None:
    """Fail closed unless *executor* attests the full v1 limit contract.

    Every declared WorkspaceLimits field must be enforced by the executor
    for launch to proceed.  An injected executor that cannot demonstrate
    the same contract -- missing ``limits`` (a WorkspaceLimits), or a
    partial/absent ``attested_limits`` mapping whose keys do not equal
    ``LIMIT_CONTRACT_FIELDS`` -- is refused with ENFORCEMENT_UNAVAILABLE
    before any probe or execution.  Default executors always attest.
    """
    if executor is None:
        return
    limits = getattr(executor, "limits", None)
    if not isinstance(limits, WorkspaceLimits):
        raise SandboxPolicyError(
            REASON_ENFORCEMENT_UNAVAILABLE,
            "executor lacks a WorkspaceLimits 'limits'; legacy un-attested "
            "executors cannot bypass the v1 limit contract")
    attestation = getattr(executor, "attested_limits", None)
    if attestation is None or not isinstance(attestation, dict):
        raise SandboxPolicyError(
            REASON_ENFORCEMENT_UNAVAILABLE,
            "executor lacks an 'attested_limits' mapping; legacy un-attested "
            "executors cannot bypass the v1 limit contract")
    try:
        matched = set(attestation) == set(LIMIT_CONTRACT_FIELDS)
    except TypeError:
        matched = False
    if not matched:
        raise SandboxPolicyError(
            REASON_ENFORCEMENT_UNAVAILABLE,
            "executor attested_limits %r does not match the v1 contract %r"
            % (sorted(map(str, attestation)),
               sorted(LIMIT_CONTRACT_FIELDS)))


def launch(policy: WorkspaceSandboxPolicy, *,
           plan: SandboxLaunchPlan | None = None,
           dry_run: bool = False, executor=None) -> dict:
    """Launch from the authoritative *policy*; never from a plan alone.

    The policy is revalidated, bwrap is probed, and the exact expected
    plan/argv is rebuilt from the policy plus observed executable and
    capabilities.  An optional *plan* is then byte-for-byte verified
    against the expected plan (executable, argv, cwd/chdir, paths,
    network_granted, limits digest, policy digest); any forged or stale
    field is refused with PLAN_FORGED before dry-run or execution.  The
    executor must attest and enforce every declared limit field or launch
    fails closed with ENFORCEMENT_UNAVAILABLE.

    dry_run=True returns the re-derived argv as a PLANNED receipt with no
    execution; an execution timeout surfaces as a REFUSED
    EXECUTION_TIMEOUT receipt, never an exception.
    """
    # 1. Revalidate the authoritative policy (all predicates, fresh).
    scope = policy.validate()["scope"]

    # 2. The executor must attest the full v1 limit contract (fail closed).
    ex = executor or _DefaultExecutor()
    _require_attested_executor(ex)

    # 3. Freshly probe bwrap through the executor (fail closed).
    try:
        features = detect_bwrap(executor=ex)
    except SandboxPolicyError:
        raise SandboxPolicyError(
            REASON_BWRAP_UNAVAILABLE,
            "bwrap probe failed or binary vanished; refusing to launch")
    if not features.available:
        raise SandboxPolicyError(REASON_BWRAP_UNAVAILABLE)

    # 4. Deterministically rebuild the exact expected plan/argv.
    expected = build_launch_plan(policy, features)

    # 5. Byte-for-byte verify any supplied plan against the expected plan.
    if plan is not None:
        def _is_forged(field: str, actual, expected_value) -> bool:
            return actual != expected_value

        for label in ("executable", "chdir", "workspace",
                      "scratch_dir", "tmp_dir"):
            if _is_forged(label, getattr(plan, label),
                          getattr(expected, label)):
                raise SandboxPolicyError(
                    REASON_PLAN_FORGED,
                    "%s does not match the re-derived plan" % label)
        if _is_forged("argv", tuple(plan.argv), expected.argv):
            raise SandboxPolicyError(
                REASON_PLAN_FORGED,
                "argv does not match the re-derived plan")
        if _is_forged("writable_roots", tuple(plan.writable_roots),
                      expected.writable_roots):
            raise SandboxPolicyError(
                REASON_PLAN_FORGED,
                "writable_roots do not match the re-derived plan")
        if _is_forged("network_granted", plan.network_granted,
                      expected.network_granted):
            raise SandboxPolicyError(
                REASON_PLAN_FORGED,
                "network_granted does not match the re-derived plan")
        # Limits: the values must match AND the canonical digests must equal
        # the expected limits digest (byte-for-byte, not just equality).
        if (plan.limits != expected.limits
                or _limits_digest(plan.limits)
                != expected.limits_memo.limits_digest):
            raise SandboxPolicyError(
                REASON_PLAN_FORGED,
                "limits do not match the re-derived policy limits")
        if plan.policy_digest != expected.policy_digest:
            raise SandboxPolicyError(
                REASON_PLAN_FORGED,
                "policy_digest does not match the re-derived plan")
        # Final digest backstop: the memo (limits_digest + policy_digest)
        # must also agree byte-for-byte.
        if plan.limits_memo.limits_digest != expected.limits_memo.limits_digest \
                or plan.limits_memo.policy_digest \
                != expected.limits_memo.policy_digest \
                or plan.limits_memo != expected.limits_memo:
            raise SandboxPolicyError(
                REASON_PLAN_FORGED,
                "limits_memo does not match the re-derived plan")

    base = {
        "plan_digest": expected.policy_digest,
        "argv": list(expected.argv),
        "chdir": expected.chdir,
    }
    if dry_run:
        return dict(base, status="PLANNED", executed=False,
                    reason=REASON_OK, exit_code=None)

    timeout = policy.limits.wall_seconds
    try:
        rc, out, err = ex.run(
            list(expected.argv), timeout=timeout,
            cwd=scope["working_directory"], env=None,
            limits=policy.limits)
    except SandboxPolicyError:
        # Enforcement could not be attested/enforced on this platform.
        raise
    except Exception as exc:
        raise SandboxPolicyError(
            REASON_BWRAP_UNAVAILABLE, "launch raised: %s" % exc)
    receipt = dict(
        base, status="EXECUTED", executed=True, reason=REASON_OK,
        exit_code=rc, stdout=out or "", stderr=err or "")
    if rc is None:
        receipt["status"] = "REFUSED"
        receipt["executed"] = False
        receipt["reason"] = REASON_EXECUTION_TIMEOUT
    elif rc != 0:
        receipt["status"] = "REFUSED"
        receipt["executed"] = False
        receipt["reason"] = REASON_EXECUTION_NONZERO
    return receipt


# =============================================================================
# Slice 4: safe SQLite snapshot adapter.
#
# The snapshot is taken with the sqlite3 backup API against a read-only
# source connection.  No file bytes, no -wal/-shm sidecars, no checkpoint
# is ever touched: the source database is never copied or mutated.  A
# snapshot therefore captures the last fully committed database image.
# =============================================================================


def snapshot_sqlite(source, dest_dir, *, dest_name=None) -> dict:
    """Snapshot *source* into *dest_dir* without disturbing the live DB.

    Raises SandboxPolicyError with a stable reason on any refusal; on
    success the receipt carries an absolute dest path of a fresh database
    file equal to the source's last committed image.
    """
    source_path = os.path.realpath(os.fspath(source))
    dest_root = os.path.realpath(os.fspath(dest_dir))
    default_name = os.path.basename(source_path) + "-snap.sqlite"
    name = os.path.basename(os.fspath(dest_name or default_name))
    if not name or "\x00" in name or os.path.dirname(name).strip(os.sep):
        raise SandboxPolicyError(REASON_SNAPSHOT_DEST_DENIED,
                                 "dest_name must be a bare filename")
    dest_path = os.path.join(dest_root, name)
    if not os.path.isfile(source_path):
        raise SandboxPolicyError(
            REASON_SNAPSHOT_SOURCE_MISSING, source_path)
    with open(source_path, "rb", buffering=0) as handle:
        header = handle.read(16)
    if not header.startswith(_SQLITE_MAGIC):
        raise SandboxPolicyError(
            REASON_SNAPSHOT_SOURCE_NOT_DB, source_path)
    if not os.path.isdir(dest_root):
        raise SandboxPolicyError(REASON_SNAPSHOT_DEST_DENIED, dest_root)
    if os.path.exists(dest_path):
        raise SandboxPolicyError(REASON_SNAPSHOT_DEST_CONFLICT, dest_path)

    import sqlite3
    uri = "file:" + source_path + "?mode=ro&nolock=0"
    src = None
    try:
        src = sqlite3.connect(uri, uri=True, timeout=0.3)
        src.execute("PRAGMA query_only = ON")
        # Pre-backup liveness probe: a short-timeout readable query.
        # In rollback-journal mode a live writer holds the database
        # lock and the query busy-times out to OperationalError("...
        # locked"); the WAL engine keeps concurrent readers visible at
        # the last committed image, so a WAL reader can pass.  If that
        # probe cannot see the source, sqlite3.backup() below could
        # stall: refuse outright rather than mount a slow checkpoint.
        try:
            src.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower():
                raise SandboxPolicyError(
                    REASON_SNAPSHOT_SOURCE_LOCKED,
                    "snapshot probe busy on live source: %s" % exc)
            raise SandboxPolicyError(
                REASON_SNAPSHOT_SOURCE_UNREADABLE,
                "snapshot probe failed: %s" % exc)
        sink_ok = False
        sink = sqlite3.connect(dest_path)
        try:
            try:
                src.backup(sink)
                sink_ok = True
            except sqlite3.OperationalError as exc:
                message = str(exc).lower()
                if "locked" in message:
                    raise SandboxPolicyError(
                        REASON_SNAPSHOT_SOURCE_LOCKED,
                        "backup stopped short: %s" % exc)
                raise SandboxPolicyError(
                    REASON_SNAPSHOT_DEST_UNKNOWN,
                    "backup failed on the fresh destination: %s" % exc)
            except sqlite3.Error as exc:
                raise SandboxPolicyError(
                    REASON_SNAPSHOT_DEST_UNKNOWN,
                    "backup failed on the fresh destination: %s" % exc)
        finally:
            sink.close()
            if not sink_ok:
                # A refused snapshot must not leave a partial image behind.
                try:
                    os.unlink(dest_path)
                except OSError:
                    pass
    finally:
        if src is not None:
            src.close()

    # Post-copy verification: the sink must be a well-formed database
    # image.  Reopen the fresh file and run integrity_check before the
    # receipt can claim success.
    with sqlite3.connect(dest_path) as verify:
        verify.execute("PRAGMA query_only = ON")
        status = verify.execute("PRAGMA integrity_check").fetchone()
    if not status or status[0] != "ok":
        raise SandboxPolicyError(
            REASON_SNAPSHOT_DEST_UNKNOWN,
            "snapshot integrity check failed")
    return {"reason": REASON_OK, "dest": dest_path}
