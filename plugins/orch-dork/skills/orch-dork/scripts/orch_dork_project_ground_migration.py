#!/usr/bin/env python3
"""Transactional provider-free project-ground migration and recovery.

Issue 43 keeps compatibility, migration, rollback preservation, exact recovery,
diagnostics, latency accounting, and failure replay behind one state machine.
The MCP-facing evaluator is read-only.  ``apply_project_ground_maintenance`` is
an explicit maintenance seam for disposable fixtures or a separately admitted
no-active-writer gateway; it never selects "latest" or repairs active work.
"""

from __future__ import annotations

from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import threading
import time
from typing import Any, Mapping

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from orch_dork_process_containment import current_dispatch_scope, run_contained


try:
    from orch_dork_hostile_input import PROFILE as HOSTILE_INPUT_PROFILE  # type: ignore
except ImportError:  # pragma: no cover - standalone source execution
    HOSTILE_INPUT_PROFILE = None


PROGRAM_SCHEMA = "orch-dork/project-ground-maintenance-program/v1"
REPORT_SCHEMA = "orch-dork/project-ground-maintenance-report/v1"
GENERATION_SCHEMA = "orch-dork/project-ground-generation/v1"
REPLAY_SCHEMA = "orch-dork/project-ground-qualification-replay/v1"
POLICY_VERSION = "project-ground-migration-policy/v1"

# Issue 49 defensive bounds for one maintenance request/transaction.
PROFILE = HOSTILE_INPUT_PROFILE
DEFENSIVE_PROFILE_SCHEMA = PROFILE.schema if PROFILE is not None else "orch-dork/hostile-input-profile/v1"
MAX_MANIFEST_BYTES = PROFILE.manifest_bytes if PROFILE is not None else 262_144
MAX_DECLARED_PATHS = PROFILE.manifest_paths if PROFILE is not None else 64
MAX_GENERATIONS = PROFILE.manifest_generations if PROFILE is not None else 32
MAX_TRANSITIONS = MAX_GENERATIONS
MAX_STAGED_OPERATIONS = 1
VALIDATION_TIMEOUT_SECONDS = PROFILE.registry_validate_seconds if PROFILE is not None else 5
TRANSACTION_TIMEOUT_SECONDS = PROFILE.registry_commit_seconds if PROFILE is not None else 10
MAX_MAINTENANCE_BYTES = 4 * MAX_MANIFEST_BYTES


class _ReadError(OSError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class _MaintenanceIO:
    """One rooted descriptor reader and cumulative budget for a maintenance call."""

    def __init__(self, roots, deadline, *, max_bytes=MAX_MAINTENANCE_BYTES):
        self.roots = tuple(Path(root).expanduser().resolve(strict=True) for root in roots)
        self.deadline = deadline
        self.remaining = min(max_bytes, MAX_MAINTENANCE_BYTES)

    def check(self):
        scope = current_dispatch_scope()
        if time.monotonic() >= self.deadline or (scope is not None and scope.stopped()):
            raise _ReadError("validation_timeout")

    @staticmethod
    def _safe(metadata, *, directory=False):
        return ((stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode))
                and metadata.st_uid == os.getuid())

    def consume(self, path, *, root=None, retain=False):
        self.check()
        path = Path(path).expanduser().absolute()
        roots = self.roots if root is None else (Path(root).resolve(strict=True),)
        selected = next((r for r in roots if r in self.roots and path.is_relative_to(r)), None)
        if selected is None:
            raise _ReadError("outside_roots")
        relative = path.relative_to(selected)
        if not relative.parts or ".." in relative.parts:
            raise _ReadError("outside_roots")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        with ExitStack() as cleanup:
            directory = os.open(selected, flags | os.O_DIRECTORY)
            cleanup.callback(os.close, directory)
            if not self._safe(os.fstat(directory), directory=True):
                raise _ReadError("unsafe")
            for component in relative.parts[:-1]:
                self.check()
                directory = os.open(component, flags | os.O_DIRECTORY, dir_fd=directory)
                cleanup.callback(os.close, directory)
                if not self._safe(os.fstat(directory), directory=True):
                    raise _ReadError("unsafe")
            descriptor = os.open(relative.name, flags, dir_fd=directory)
            cleanup.callback(os.close, descriptor)
            before = os.fstat(descriptor)
            if not self._safe(before):
                raise _ReadError("unsafe")
            if before.st_size > MAX_MANIFEST_BYTES:
                raise _ReadError("manifest_bytes_limit")
            if before.st_size > self.remaining:
                raise _ReadError("resource_bytes_limit")
            remaining = before.st_size
            digest = hashlib.sha256()
            output = bytearray()
            while remaining:
                self.check()
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    raise _ReadError("changed")
                remaining -= len(chunk)
                self.remaining -= len(chunk)
                digest.update(chunk)
                if retain:
                    output.extend(chunk)
            self.check()
            after = os.fstat(descriptor)
            named = os.stat(relative.name, dir_fd=directory, follow_symlinks=False)
            snapshot = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_mode,
                                      value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if snapshot(before) != snapshot(after) or snapshot(after) != snapshot(named):
                raise _ReadError("changed")
            return bytes(output) if retain else digest.hexdigest()

    def check_missing_parent(self, path, *, root):
        """Validate existing ancestors even when there is no leaf to read."""
        self.check()
        path = Path(path).expanduser().absolute()
        root = Path(root).resolve(strict=True)
        if root not in self.roots or not path.is_relative_to(root):
            raise _ReadError("outside_roots")
        relative = path.relative_to(root)
        if not relative.parts or ".." in relative.parts:
            raise _ReadError("outside_roots")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_DIRECTORY
        with ExitStack() as cleanup:
            directory = os.open(root, flags)
            cleanup.callback(os.close, directory)
            if not self._safe(os.fstat(directory), directory=True):
                raise _ReadError("unsafe")
            for component in relative.parts[:-1]:
                self.check()
                try:
                    directory = os.open(component, flags, dir_fd=directory)
                except FileNotFoundError:
                    # Atomic replacement may create the absent suffix; there
                    # are no further existing ancestors to validate here.
                    return
                cleanup.callback(os.close, directory)
                if not self._safe(os.fstat(directory), directory=True):
                    raise _ReadError("unsafe")


_IO: ContextVar[_MaintenanceIO | None] = ContextVar("maintenance_io", default=None)
_PROCESS_EVIDENCE = threading.local()


@contextmanager
def _io_scope(program, staging_roots=(), *, seconds=VALIDATION_TIMEOUT_SECONDS, max_bytes=MAX_MAINTENANCE_BYTES):
    roots = (program.get("registry_root", ""), program.get("project_root", ""), *staging_roots)
    reader = _MaintenanceIO(roots, time.monotonic() + seconds, max_bytes=max_bytes)
    token = _IO.set(reader)
    try:
        yield reader
    finally:
        _IO.reset(token)


def _file_bytes(path, *, root=None):
    reader = _IO.get()
    if reader is None:
        raise _ReadError("outside_roots")
    return reader.consume(path, root=root, retain=True)


def _file_digest(path, *, root=None):
    reader = _IO.get()
    if reader is None:
        raise _ReadError("outside_roots")
    return reader.consume(path, root=root)

OPERATIONS = frozenset({"inspect", "diagnose", "migrate", "recover"})
STAGES = (
    "transform",
    "validation",
    "hook",
    "publication",
    "install",
    "activation",
)
DIAGNOSTIC_SURFACES = (
    "enrollment",
    "manifest",
    "adapter",
    "installed_plugin",
    "hook",
    "sandbox_gateway",
    "lease",
    "scope",
    "admission",
    "capsule",
    "drift",
)
FAILURE_CASES = (
    "unknown_control_collision",
    "binding_symlink_escape",
    "partial_staging",
    "atomic_activation_failure",
    "registry_missing",
    "registry_corrupt",
    "registry_unreadable",
    "registry_permission_denied",
    "registry_cas_loss",
    "wrong_root",
    "wrong_saved_project",
    "wrong_host",
    "clone_identity",
    "worktree_identity",
    "nested_repository",
    "compatible_pinned_protocol",
    "incompatible_protocol",
    "unsupported_newer_protocol",
    "rolled_back_generation",
    "source_install_mismatch",
    "adapter_deleted",
    "adapter_drift_after_admission",
    "snapshot_missing",
    "snapshot_corrupt",
    "snapshot_unreadable",
    "snapshot_permission_denied",
    "snapshot_rolled_back",
    "hook_absent",
    "hook_untrusted",
    "hook_disabled",
    "hook_timeout",
    "hook_crash",
    "hook_conflict",
    "uncovered_tool",
    "write_stdin_bypass",
    "child_process_bypass",
    "hosted_tool_bypass",
    "external_process_bypass",
    "split_brain_writer",
    "stale_admission",
    "stale_capsule",
    "direct_protected_write",
    "verification_then_mutation",
    "ambiguous_recovery",
    "recovery_user_conflict",
    "cleanup_incomplete",
    "denial_of_service_budget",
)
MODEL_COORDINATE_CASES = (
    "saved_project_mismatch",
    "initial_root_mismatch",
    "host_mismatch",
    "permission_profile_mismatch",
    "checkpoint_mismatch",
    "current_lease_mismatch",
    "already_owner",
    "credential_access",
    "grant_reservation",
    "hosted_call",
    "transfer_request_mismatch",
    "compare_and_swap_loss",
    "direct_lease_file_write",
    "direct_low_level_transfer",
)

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_PROTOCOL = re.compile(r"\Aproject-ground/v([1-9][0-9]*)\Z")
_SENSITIVE = re.compile(
    r"(?:credential|secret|token|password|api[_-]?key|authorization|cookie)",
    re.IGNORECASE,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _count_declared_paths(value: Any, *, _seen: set[int] | None = None) -> int:
    if _seen is None:
        _seen = set()
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in _seen:
            return 0
        _seen.add(marker)
        total = 0
        for key, child in value.items():
            key_text = str(key).lower()
            if any(token in key_text for token in ("path", "locator", "root", "file")):
                if isinstance(child, str):
                    total += 1
                elif isinstance(child, (list, tuple)):
                    total += sum(isinstance(item, str) for item in child)
            total += _count_declared_paths(child, _seen=_seen)
        return total
    if isinstance(value, (list, tuple)):
        marker = id(value)
        if marker in _seen:
            return 0
        _seen.add(marker)
        return sum(_count_declared_paths(item, _seen=_seen) for item in value)
    return 0


def _count_generations(value: Any, *, _seen: set[int] | None = None) -> int:
    if _seen is None:
        _seen = set()
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in _seen:
            return 0
        _seen.add(marker)
        total = sum(_count_generations(child, _seen=_seen) for child in value.values())
        for key in ("generations", "transitions", "events"):
            child = value.get(key)
            if isinstance(child, (list, tuple)):
                total += len(child)
        return total
    if isinstance(value, (list, tuple)):
        marker = id(value)
        if marker in _seen:
            return 0
        _seen.add(marker)
        return sum(_count_generations(item, _seen=_seen) for item in value)
    return 0


def _validate_state_bounds(value: Any, issues: list[str], *, label: str = "program") -> None:
    try:
        encoded = _canonical(value)
    except (TypeError, ValueError, RecursionError):
        _issue(issues, label + ":malformed_json")
        return
    if len(encoded) > MAX_MANIFEST_BYTES:
        _issue(issues, label + ":manifest_bytes_limit")
        _issue(issues, "bounds:manifest_bytes_limit")
    paths = _count_declared_paths(value)
    if paths > MAX_DECLARED_PATHS:
        _issue(issues, label + ":declared_paths_limit")
        _issue(issues, "bounds:declared_paths_limit")
    transitions = _count_generations(value)
    if transitions > MAX_GENERATIONS:
        _issue(issues, label + ":generations_limit")
        _issue(issues, "bounds:generations_limit")
    staged = 0
    if isinstance(value, Mapping):
        for key in ("staged_operations", "staged_activations", "staged_recoveries"):
            raw = value.get(key)
            if isinstance(raw, int) and not isinstance(raw, bool):
                staged += raw
    if staged > MAX_STAGED_OPERATIONS:
        _issue(issues, label + ":staged_operation_limit")
        _issue(issues, "bounds:staged_operation_limit")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _mapping(value: Any, label: str, issues: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return {}
    return value


def _exact(value: Any, keys: set[str], label: str, issues: list[str]) -> Mapping[str, Any]:
    item = _mapping(value, label, issues)
    for key in sorted(keys - set(item)):
        _issue(issues, label + ":missing:" + key)
    for key in sorted(set(item) - keys):
        suffix = "sensitive_unknown" if _SENSITIVE.search(str(key)) else "unknown:" + str(key)
        _issue(issues, label + ":" + suffix)
    return item


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _hash(value: Any, label: str, issues: list[str], *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _issue(issues, label + ":sha256_invalid")
        return None
    return value


def _resolved_file(path: Any, label: str, issues: list[str], *, required: bool = True) -> Path | None:
    if not _text(path):
        _issue(issues, label + ":path_invalid")
        return None
    value = Path(str(path)).expanduser()
    if value.is_symlink():
        _issue(issues, label + ":symlink")
        return None
    try:
        resolved = value.resolve(strict=required)
    except FileNotFoundError:
        _issue(issues, label + ":missing")
        return None
    except PermissionError:
        _issue(issues, label + ":permission_denied")
        return None
    except OSError:
        _issue(issues, label + ":unreadable")
        return None
    if required and not resolved.is_file():
        _issue(issues, label + ":not_file")
        return None
    # Retain the lexical components for the descriptor walk. Resolving them
    # here would hide an intermediate symlink from O_NOFOLLOW.
    return value.absolute()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


def _record_core(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value) for key, value in record.items() if key != "record_sha256"}


def seal_generation_record(record: Mapping[str, Any]) -> dict[str, Any]:
    value = _record_core(record)
    events = value.get("events")
    if isinstance(events, list) and len(events) > MAX_TRANSITIONS:
        raise ValueError("record transitions exceed defensive bound")
    value["record_sha256"] = _sha(value)
    return value


def _validate_record(value: Any, issues: list[str]) -> dict[str, Any] | None:
    item = _exact(
        value,
        {
            "schema",
            "version",
            "status",
            "project_identity_sha256",
            "protocol",
            "security_generation",
            "artifact_sha256",
            "artifact_locator",
            "binding",
            "binding_sha256",
            "previous_record_sha256",
            "events",
            "record_sha256",
        },
        "record",
        issues,
    )
    if item.get("schema") != GENERATION_SCHEMA:
        _issue(issues, "record:schema_invalid")
    if item.get("status") != "active":
        _issue(issues, "record:not_active")
    if type(item.get("version")) is not int or item.get("version", 0) < 1:
        _issue(issues, "record:version_invalid")
    if type(item.get("security_generation")) is not int or item.get("security_generation", 0) < 1:
        _issue(issues, "record:security_generation_invalid")
    if not isinstance(item.get("protocol"), str) or _PROTOCOL.fullmatch(str(item.get("protocol"))) is None:
        _issue(issues, "record:protocol_invalid")
    for key in ("project_identity_sha256", "artifact_sha256", "binding_sha256", "record_sha256"):
        _hash(item.get(key), "record:" + key, issues)
    _hash(item.get("previous_record_sha256"), "record:previous", issues, optional=True)
    if not isinstance(item.get("binding"), Mapping):
        _issue(issues, "record:binding_invalid")
    elif _sha(item.get("binding")) != item.get("binding_sha256"):
        _issue(issues, "record:binding_hash_mismatch")
    if not isinstance(item.get("events"), list):
        _issue(issues, "record:events_invalid")
    elif len(item["events"]) > MAX_TRANSITIONS:
        _issue(issues, "record:transitions_limit")
        _issue(issues, "bounds:generations_limit")
    declared = item.get("record_sha256")
    if isinstance(declared, str) and declared != _sha(_record_core(item)):
        _issue(issues, "record:hash_mismatch")
    return dict(item) if item else None


class _DuplicateJSONKey(ValueError):
    pass


def _json_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _read_json(path: Path, label: str, issues: list[str], *, root=None) -> Mapping[str, Any] | None:
    try:
        raw = _file_bytes(path, root=root)
    except _ReadError as error:
        _issue(issues, label + ":" + error.reason)
        return None
    except FileNotFoundError:
        _issue(issues, label + ":missing")
        return None
    except PermissionError:
        _issue(issues, label + ":permission_denied")
        return None
    except (OSError, UnicodeDecodeError):
        _issue(issues, label + ":unreadable")
        return None
    if len(raw) > MAX_MANIFEST_BYTES:
        _issue(issues, label + ":manifest_bytes_limit")
        return None
    if raw.startswith(b"\xef\xbb\xbf"):
        _issue(issues, label + ":bom_forbidden")
        return None
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_json_object_no_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except UnicodeDecodeError:
        _issue(issues, label + ":utf8_invalid")
        return None
    except _DuplicateJSONKey:
        _issue(issues, label + ":duplicate_key")
        return None
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        _issue(issues, label + ":corrupt")
        return None
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return None
    return value


def _compatibility(value: Any, issues: list[str]) -> dict[str, Any]:
    _validate_state_bounds(value, issues, label="compatibility")
    item = _exact(
        value,
        {
            "active_protocol",
            "target_protocol",
            "supported_protocols",
            "minimum_security_generation",
            "pinned_security_generation",
            "target_security_generation",
            "source_version",
            "installed_version",
            "source_runtime_sha256",
            "installed_runtime_sha256",
        },
        "compatibility",
        issues,
    )
    supported = item.get("supported_protocols")
    if not isinstance(supported, list) or any(not isinstance(protocol, str) or _PROTOCOL.fullmatch(protocol) is None for protocol in supported):
        _issue(issues, "compatibility:supported_protocols_invalid")
        supported = []
    elif len(supported) > MAX_GENERATIONS:
        _issue(issues, "compatibility:generations_limit")
    for key in ("active_protocol", "target_protocol"):
        if not isinstance(item.get(key), str) or _PROTOCOL.fullmatch(str(item.get(key))) is None:
            _issue(issues, "compatibility:" + key + "_invalid")
    for key in ("minimum_security_generation", "pinned_security_generation", "target_security_generation"):
        if type(item.get(key)) is not int or item.get(key, 0) < 1:
            _issue(issues, "compatibility:" + key + "_invalid")
    for key in ("source_runtime_sha256", "installed_runtime_sha256"):
        _hash(item.get(key), "compatibility:" + key, issues)
    if not _text(item.get("source_version")) or not _text(item.get("installed_version")):
        _issue(issues, "compatibility:version_invalid")
    return {**dict(item), "supported_protocols": list(supported)}


def compatibility_decision(value: Mapping[str, Any]) -> tuple[str, list[str]]:
    issues: list[str] = []
    active = value.get("active_protocol")
    target = value.get("target_protocol")
    supported = value.get("supported_protocols", [])
    minimum = value.get("minimum_security_generation")
    pinned = value.get("pinned_security_generation")
    target_generation = value.get("target_security_generation")
    if value.get("source_runtime_sha256") != value.get("installed_runtime_sha256") or value.get("source_version") != value.get("installed_version"):
        _issue(issues, "compatibility:source_install_mismatch")
    if isinstance(pinned, int) and isinstance(minimum, int) and pinned < minimum:
        _issue(issues, "compatibility:rolled_back_security_generation")
    if active not in supported:
        active_version = int(_PROTOCOL.fullmatch(active).group(1)) if isinstance(active, str) and _PROTOCOL.fullmatch(active) else None
        max_supported = max((int(_PROTOCOL.fullmatch(item).group(1)) for item in supported), default=0)
        _issue(issues, "compatibility:unsupported_newer_protocol" if active_version and active_version > max_supported else "compatibility:incompatible_protocol")
    if target not in supported:
        target_version = int(_PROTOCOL.fullmatch(target).group(1)) if isinstance(target, str) and _PROTOCOL.fullmatch(target) else None
        max_supported = max((int(_PROTOCOL.fullmatch(item).group(1)) for item in supported), default=0)
        _issue(issues, "compatibility:unsupported_newer_protocol" if target_version and target_version > max_supported else "compatibility:incompatible_protocol")
    if isinstance(target_generation, int) and isinstance(minimum, int) and target_generation < minimum:
        _issue(issues, "compatibility:target_below_security_minimum")
    if issues:
        if "compatibility:source_install_mismatch" in issues:
            return "SOURCE_INSTALL_MISMATCH", issues
        if any("rolled_back" in issue for issue in issues):
            return "ROLLBACK_BLOCKED", issues
        if any("unsupported_newer" in issue for issue in issues):
            return "UNSUPPORTED_NEWER", issues
        return "INCOMPATIBLE", issues
    if active == target and pinned == target_generation:
        return "EXACT_PIN", []
    if active == target:
        return "COMPATIBLE_PIN", []
    return "MIGRATION_REQUIRED", []


def _target(value: Any, issues: list[str]) -> dict[str, Any]:
    _validate_state_bounds(value, issues, label="target")
    item = _exact(
        value,
        {"protocol", "security_generation", "artifact_source_path", "artifact_sha256", "binding", "stages"},
        "target",
        issues,
    )
    if not isinstance(item.get("protocol"), str) or _PROTOCOL.fullmatch(str(item.get("protocol"))) is None:
        _issue(issues, "target:protocol_invalid")
    if type(item.get("security_generation")) is not int or item.get("security_generation", 0) < 1:
        _issue(issues, "target:security_generation_invalid")
    _hash(item.get("artifact_sha256"), "target:artifact", issues)
    binding = _mapping(item.get("binding"), "target:binding", issues)
    if any(_SENSITIVE.search(str(key)) for key in binding):
        _issue(issues, "target:binding_sensitive")
    stages = _exact(item.get("stages"), set(STAGES), "target:stages", issues)
    for stage in STAGES:
        if stages.get(stage) not in {"PASS", "FAIL", "NOT_RUN"}:
            _issue(issues, "target:stage_invalid:" + stage)
    return {**dict(item), "binding": deepcopy(dict(binding)), "stages": dict(stages)}


def _recovery(value: Any, issues: list[str]) -> dict[str, Any]:
    _validate_state_bounds(value, issues, label="recovery")
    item = _exact(
        value,
        {
            "source_status",
            "source_artifact_path",
            "expected_artifact_sha256",
            "destination_path",
            "destination_expected_sha256",
            "project_identity_sha256",
            "conflicting_user_change",
        },
        "recovery",
        issues,
    )
    if item.get("source_status") not in {"exact", "missing", "corrupt", "stale", "ambiguous", "unreadable"}:
        _issue(issues, "recovery:source_status_invalid")
    for key in ("expected_artifact_sha256", "project_identity_sha256"):
        _hash(item.get(key), "recovery:" + key, issues)
    _hash(item.get("destination_expected_sha256"), "recovery:destination_expected", issues, optional=True)
    if not isinstance(item.get("conflicting_user_change"), bool):
        _issue(issues, "recovery:conflicting_user_change_invalid")
    return dict(item)


def _maintenance(value: Any, issues: list[str]) -> dict[str, Any]:
    _validate_state_bounds(value, issues, label="maintenance")
    item = _exact(value, {"active_writer", "repair_count", "rerun_count", "fresh_admission_sha256", "reason"}, "maintenance", issues)
    if not isinstance(item.get("active_writer"), bool):
        _issue(issues, "maintenance:active_writer_invalid")
    for key in ("repair_count", "rerun_count"):
        if type(item.get(key)) is not int or item.get(key, -1) < 0:
            _issue(issues, "maintenance:" + key + "_invalid")
    _hash(item.get("fresh_admission_sha256"), "maintenance:fresh_admission", issues)
    if not _text(item.get("reason")):
        _issue(issues, "maintenance:reason_invalid")
    return dict(item)


def _live_facts(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(value, set(DIAGNOSTIC_SURFACES), "live_facts", issues)
    result: dict[str, Any] = {}
    for surface in DIAGNOSTIC_SURFACES:
        row = _exact(item.get(surface), {"status", "sha256", "source_pointer"}, "live_facts." + surface, issues)
        if row.get("status") not in {"PASS", "FAIL", "UNKNOWN", "STALE", "MISSING"}:
            _issue(issues, "live_facts:" + surface + ":status_invalid")
        _hash(row.get("sha256"), "live_facts:" + surface, issues, optional=row.get("status") != "PASS")
        result[surface] = dict(row)
    return result


def _timing(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(value, {"known", "budget_ms"}, "timing", issues)
    if not isinstance(item.get("known"), bool):
        _issue(issues, "timing:known_invalid")
    if type(item.get("budget_ms")) is not int or item.get("budget_ms", 0) < 1:
        _issue(issues, "timing:budget_invalid")
    return dict(item)


def _program(program: Any) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    _validate_state_bounds(program, issues)
    item = _exact(
        program,
        {
            "schema",
            "operation",
            "registry_root",
            "project_root",
            "project_identity_sha256",
            "current_record_path",
            "expected_registry",
            "compatibility",
            "target",
            "recovery",
            "maintenance",
            "live_facts",
            "timing",
            "source_pointer",
        },
        "program",
        issues,
    )
    if item.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    if item.get("operation") not in OPERATIONS:
        _issue(issues, "program:operation_invalid")
    _hash(item.get("project_identity_sha256"), "program:project_identity", issues)
    expected = _exact(item.get("expected_registry"), {"version", "record_sha256"}, "expected_registry", issues)
    if type(expected.get("version")) is not int or expected.get("version", 0) < 1:
        _issue(issues, "expected_registry:version_invalid")
    _hash(expected.get("record_sha256"), "expected_registry:record", issues)
    return (
        {
            "schema": PROGRAM_SCHEMA,
            "operation": item.get("operation"),
            "registry_root": item.get("registry_root"),
            "project_root": item.get("project_root"),
            "project_identity_sha256": item.get("project_identity_sha256"),
            "current_record_path": item.get("current_record_path"),
            "expected_registry": dict(expected),
            "compatibility": _compatibility(item.get("compatibility"), issues),
            "target": _target(item.get("target"), issues),
            "recovery": _recovery(item.get("recovery"), issues),
            "maintenance": _maintenance(item.get("maintenance"), issues),
            "live_facts": _live_facts(item.get("live_facts"), issues),
            "timing": _timing(item.get("timing"), issues),
            "source_pointer": item.get("source_pointer"),
        },
        issues,
    )


def _read_current(value: Mapping[str, Any], issues: list[str]) -> tuple[Path | None, dict[str, Any] | None]:
    path = _resolved_file(value.get("current_record_path"), "registry:record", issues)
    if path is None:
        return None, None
    raw = _read_json(path, "registry:record", issues, root=Path(str(value["registry_root"])))
    record = _validate_record(raw, issues) if raw is not None else None
    return path, record


def _diagnostics(value: Mapping[str, Any], issues: list[str], compatibility: str) -> dict[str, Any]:
    surfaces = {
        name: {
            "status": row.get("status"),
            "sha256": row.get("sha256"),
            "source_pointer": row.get("source_pointer"),
        }
        for name, row in value.get("live_facts", {}).items()
    }
    failed = [name for name, row in surfaces.items() if row.get("status") != "PASS"]
    maintenance = value.get("maintenance", {})
    if maintenance.get("repair_count", 0) > 1 or maintenance.get("rerun_count", 0) > 1:
        next_action = "RECORD_BLOCKER"
    elif failed and maintenance.get("repair_count", 0) == 0:
        next_action = "RUN_ONE_BOUNDED_REPAIR"
    elif failed and maintenance.get("rerun_count", 0) == 0:
        next_action = "RERUN_ONCE"
    elif issues:
        next_action = "RECORD_BLOCKER"
    elif value.get("operation") == "migrate":
        next_action = "APPLY_MIGRATION"
    elif value.get("operation") == "recover":
        next_action = "APPLY_RECOVERY"
    else:
        next_action = "NONE"
    return {
        "schema": "orch-dork/project-ground-diagnostic/v1",
        "read_only": True,
        "surfaces": surfaces,
        "compatibility": compatibility,
        "issues": list(issues),
        "safe_next_action": next_action,
    }


def _evaluate_body(program: Any) -> dict[str, Any]:
    started = time.perf_counter()
    value, issues = _program(program)
    registry_root = Path(str(value.get("registry_root", ""))).expanduser()
    project_root = Path(str(value.get("project_root", ""))).expanduser()
    try:
        registry_root = registry_root.resolve(strict=True)
    except (FileNotFoundError, PermissionError, OSError):
        _issue(issues, "registry:root_unavailable")
    try:
        project_root = project_root.resolve(strict=True)
    except (FileNotFoundError, PermissionError, OSError):
        _issue(issues, "project:root_unavailable")
    if registry_root == project_root or _inside(registry_root, project_root):
        _issue(issues, "registry:must_be_external")
    record_path, record = _read_current(value, issues)
    if record is not None:
        if record.get("project_identity_sha256") != value.get("project_identity_sha256"):
            _issue(issues, "registry:project_identity_mismatch")
        expected = value.get("expected_registry", {})
        if record.get("version") != expected.get("version") or record.get("record_sha256") != expected.get("record_sha256"):
            _issue(issues, "registry:compare_and_swap_lost")
        if record.get("protocol") != value.get("compatibility", {}).get("active_protocol"):
            _issue(issues, "compatibility:active_record_protocol_mismatch")
        if record.get("security_generation") != value.get("compatibility", {}).get("pinned_security_generation"):
            _issue(issues, "compatibility:pinned_generation_mismatch")
        artifact = _resolved_file(record.get("artifact_locator"), "registry:active_artifact", issues)
        if artifact is not None:
            if not _inside(artifact, registry_root):
                _issue(issues, "registry:active_artifact_escape")
            try:
                if _file_digest(artifact, root=registry_root) != record.get("artifact_sha256"):
                    _issue(issues, "registry:active_artifact_corrupt")
            except PermissionError:
                _issue(issues, "registry:active_artifact_permission_denied")
            except OSError:
                _issue(issues, "registry:active_artifact_unreadable")
        binding_path = project_root / ".orch-dork" / "project-adapter.json"
        binding_raw = _read_json(binding_path, "project:binding", issues, root=project_root)
        if binding_raw is not None and _sha(binding_raw) != record.get("binding_sha256"):
            _issue(issues, "project:binding_mismatch")

    compatibility, compatibility_issues = compatibility_decision(value.get("compatibility", {}))
    for issue in compatibility_issues:
        _issue(issues, issue)
    maintenance = value.get("maintenance", {})
    if maintenance.get("active_writer"):
        _issue(issues, "maintenance:active_writer")
    if maintenance.get("repair_count", 0) > 1:
        _issue(issues, "maintenance:repair_budget_exhausted")
    if maintenance.get("rerun_count", 0) > 1:
        _issue(issues, "maintenance:rerun_budget_exhausted")
    if maintenance.get("fresh_admission_sha256") != value.get("live_facts", {}).get("admission", {}).get("sha256"):
        _issue(issues, "maintenance:fresh_admission_mismatch")
    failed_facts = [name for name, row in value.get("live_facts", {}).items() if row.get("status") != "PASS"]
    for name in failed_facts:
        _issue(issues, "diagnostic:" + name + ":" + str(value["live_facts"][name].get("status")).lower())

    operation = value.get("operation")
    target = value.get("target", {})
    recovery = value.get("recovery", {})
    if operation == "migrate":
        if record is not None and target.get("security_generation", 0) <= record.get("security_generation", 0):
            _issue(issues, "migration:generation_not_newer")
        if target.get("protocol") != value.get("compatibility", {}).get("target_protocol"):
            _issue(issues, "migration:target_protocol_mismatch")
        if target.get("security_generation") != value.get("compatibility", {}).get("target_security_generation"):
            _issue(issues, "migration:target_generation_mismatch")
        for stage in STAGES:
            if target.get("stages", {}).get(stage) != "PASS":
                _issue(issues, "migration:stage_failed:" + stage)
        artifact = _resolved_file(target.get("artifact_source_path"), "migration:artifact", issues)
        if artifact is not None:
            try:
                if _file_digest(artifact) != target.get("artifact_sha256"):
                    _issue(issues, "migration:artifact_digest_mismatch")
            except PermissionError:
                _issue(issues, "migration:artifact_permission_denied")
            except OSError:
                _issue(issues, "migration:artifact_unreadable")
    elif operation == "recover":
        if recovery.get("source_status") != "exact":
            _issue(issues, "recovery:source_" + str(recovery.get("source_status")))
        if recovery.get("conflicting_user_change"):
            _issue(issues, "recovery:conflicting_user_change")
        if recovery.get("project_identity_sha256") != value.get("project_identity_sha256"):
            _issue(issues, "recovery:project_identity_mismatch")
        source = _resolved_file(recovery.get("source_artifact_path"), "recovery:source", issues)
        if source is not None:
            try:
                digest = _file_digest(source, root=registry_root)
                if digest != recovery.get("expected_artifact_sha256") or (record is not None and digest != record.get("artifact_sha256")):
                    _issue(issues, "recovery:artifact_digest_mismatch")
                if record is not None and source != Path(str(record.get("artifact_locator"))).resolve(strict=True):
                    _issue(issues, "recovery:last_known_good_locator_mismatch")
            except PermissionError:
                _issue(issues, "recovery:source_permission_denied")
            except OSError:
                _issue(issues, "recovery:source_unreadable")
        destination = Path(str(recovery.get("destination_path", ""))).expanduser().absolute()
        if not _inside(destination, project_root):
            _issue(issues, "recovery:destination_escape")
        elif destination.exists():
            try:
                if _file_digest(destination, root=project_root) != recovery.get("destination_expected_sha256"):
                    _issue(issues, "recovery:destination_changed")
            except (PermissionError, OSError):
                _issue(issues, "recovery:destination_unavailable")
        elif recovery.get("destination_expected_sha256") is not None:
            _issue(issues, "recovery:destination_changed")

    diagnostics = _diagnostics(value, issues, compatibility)
    if issues:
        decision = "READ_ONLY" if operation in {"inspect", "diagnose"} else "BLOCKED"
    elif operation == "migrate":
        decision = "READY_TO_MIGRATE"
    elif operation == "recover":
        decision = "READY_TO_RECOVER"
    else:
        decision = "ACTIVE_PINNED"
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    # Inspect/diagnose have a hard provider-free validation ceiling even when
    # the caller supplies an unknown/overly generous timing hint.  A breach
    # remains read-only; it never retries or mutates a generation.
    if operation in {"inspect", "diagnose"} and elapsed_ms > VALIDATION_TIMEOUT_SECONDS * 1000:
        _issue(issues, "maintenance:validation_timeout")
        decision = "READ_ONLY"
        diagnostics = _diagnostics(value, issues, compatibility)
    timing_known = value.get("timing", {}).get("known") is True
    observed_ms = elapsed_ms if timing_known else None
    budget_ms = value.get("timing", {}).get("budget_ms")
    budget_met = None if not timing_known else elapsed_ms <= budget_ms
    if budget_met is False:
        _issue(issues, "timing:budget_exceeded")
        decision = "READ_ONLY" if operation in {"inspect", "diagnose"} else "BLOCKED"
        diagnostics = _diagnostics(value, issues, compatibility)
    report = {
        "schema": REPORT_SCHEMA,
        "policy_version": POLICY_VERSION,
        "status": "PASS" if decision in {"ACTIVE_PINNED", "READY_TO_MIGRATE", "READY_TO_RECOVER"} else "BLOCKED",
        "decision": decision,
        "operation": operation,
        "compatibility": compatibility,
        "record_sha256": record.get("record_sha256") if record is not None else None,
        "record_version": record.get("version") if record is not None else None,
        "active_security_generation": record.get("security_generation") if record is not None else None,
        "previous_generation_preserved": True,
        "mutation_performed": False,
        "issues": list(issues),
        "diagnostic": diagnostics,
        "timing": {
            "known": timing_known,
            "budget_ms": budget_ms,
            "observed_ms": observed_ms,
            "budget_met": budget_met,
            "lightweight_rechecks": ["generation", "lease", "scope"],
        },
        "provider_free": True,
        "hosted_calls": 0,
        "model_calls": 0,
        "credential_reads": 0,
        "task_creations": 0,
        "authority_reservations": 0,
        "automatic_repairs": 0,
        "automatic_reruns": 0,
        "source_pointer": value.get("source_pointer"),
    }
    return {**report, "report_sha256": _sha(report)}


def _atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    encoded = _canonical(value) + b"\n"
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise OSError("manifest exceeds defensive byte bound")
    _atomic_write_bytes(path, encoded)


def _artifact_locator(registry_root: Path, digest: str) -> Path:
    return registry_root / "artifacts" / "sha256" / digest[:2] / digest


def _lock_path(registry_root: Path, identity: str) -> Path:
    return registry_root / "locks" / (identity + ".lock")


@contextmanager
def _maintenance_lock(registry_root, identity):
    reader = _IO.get()
    if reader is None:
        raise _ReadError("outside_roots")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    with ExitStack() as cleanup:
        parent = os.open(registry_root, directory_flags)
        cleanup.callback(os.close, parent)
        if not reader._safe(os.fstat(parent), directory=True):
            raise _ReadError("unsafe")
        try:
            os.mkdir("locks", mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
        locks = os.open("locks", directory_flags, dir_fd=parent)
        cleanup.callback(os.close, locks)
        if not reader._safe(os.fstat(locks), directory=True):
            raise _ReadError("unsafe")
        descriptor = os.open(identity + ".lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=locks)
        cleanup.callback(os.close, descriptor)
        if not reader._safe(os.fstat(descriptor)):
            raise _ReadError("unsafe")
        while True:
            reader.check()
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(0.01, max(0, reader.deadline - time.monotonic())))
        yield


def _install_immutable_artifact(source: Path, target: Path, digest: str) -> None:
    data = _file_bytes(source)
    if _sha_bytes(data) != digest:
        raise ValueError("artifact digest changed")
    if target.exists():
        if target.is_symlink() or _file_digest(target) != digest:
            raise ValueError("artifact collision")
    else:
        _atomic_write_bytes(target, data, mode=0o400)
    os.chmod(target, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def _apply_body(program: Any, *, staging_roots=(), started=None) -> dict[str, Any]:
    started = time.monotonic() if started is None else started
    preview = evaluate_project_ground_maintenance(program, staging_roots=staging_roots)
    if preview.get("decision") not in {"READY_TO_MIGRATE", "READY_TO_RECOVER"}:
        return _record_public_timing({"report": preview}, program, started)["report"]
    value, validation_issues = _program(program)
    if validation_issues:
        return _record_public_timing({"report": preview}, program, started)["report"]
    registry_root = Path(str(value["registry_root"])).resolve(strict=True)
    project_root = Path(str(value["project_root"])).resolve(strict=True)
    record_path = Path(str(value["current_record_path"])).expanduser().absolute()
    binding_path: Path | None = None
    prior_binding: bytes | None = None
    prior_binding_existed = False
    binding_write_started = False
    destination_path: Path | None = None
    prior_destination: bytes | None = None
    prior_destination_existed = False
    destination_write_started = False
    prior_record_bytes: bytes | None = None
    record_write_started = False
    with _maintenance_lock(registry_root, str(value["project_identity_sha256"])):
        try:
            read_issues: list[str] = []
            current_raw = _read_json(record_path, "registry:record", read_issues, root=registry_root)
            current = _validate_record(current_raw, read_issues) if current_raw is not None else None
            expected = value["expected_registry"]
            if read_issues or current is None or current.get("version") != expected.get("version") or current.get("record_sha256") != expected.get("record_sha256"):
                result = dict(preview)
                result.update(status="BLOCKED", decision="PRESERVED_PREVIOUS_GENERATION", issues=[*preview.get("issues", []), *read_issues, "registry:compare_and_swap_lost"])
                result["diagnostic"] = _diagnostics(value, result["issues"], result["compatibility"])
                result["report_sha256"] = _sha({key: item for key, item in result.items() if key != "report_sha256"})
                return _record_public_timing({"report": result}, program, started)["report"]
            prior_record_bytes = _file_bytes(record_path, root=registry_root)
            if _sha(json.loads(prior_record_bytes, object_pairs_hook=_json_object_no_duplicates)) != _sha(current):
                raise ValueError("registry record changed before backup")
            if time.monotonic() - started > TRANSACTION_TIMEOUT_SECONDS:
                raise TimeoutError("maintenance transaction exceeded hard bound")
            if value["operation"] == "migrate":
                target = value["target"]
                source = Path(str(target["artifact_source_path"])).expanduser().absolute()
                locator = _artifact_locator(registry_root, str(target["artifact_sha256"]))
                _install_immutable_artifact(source, locator, str(target["artifact_sha256"]))
                binding_path = project_root / ".orch-dork" / "project-adapter.json"
                prior_binding_existed = binding_path.exists()
                prior_binding = _file_bytes(binding_path, root=project_root) if prior_binding_existed else None
                if not prior_binding_existed:
                    _IO.get().check_missing_parent(binding_path, root=project_root)
                _IO.get().check()
                binding_write_started = True
                _atomic_write_json(binding_path, target["binding"])
                record = seal_generation_record(
                    {
                        "schema": GENERATION_SCHEMA,
                        "version": current["version"] + 1,
                        "status": "active",
                        "project_identity_sha256": value["project_identity_sha256"],
                        "protocol": target["protocol"],
                        "security_generation": target["security_generation"],
                        "artifact_sha256": target["artifact_sha256"],
                        "artifact_locator": str(locator),
                        "binding": target["binding"],
                        "binding_sha256": _sha(target["binding"]),
                        "previous_record_sha256": current["record_sha256"],
                        "events": [
                            *current.get("events", []),
                            {
                                "type": "project_ground.migrated",
                                "from_generation": current["security_generation"],
                                "to_generation": target["security_generation"],
                                "admission_sha256": value["maintenance"]["fresh_admission_sha256"],
                            },
                        ],
                    }
                )
                _IO.get().check()
                record_write_started = True
                _atomic_write_json(record_path, record)
                decision = "MIGRATED"
            else:
                recovery = value["recovery"]
                source = Path(str(recovery["source_artifact_path"])).expanduser().absolute()
                destination = Path(str(recovery["destination_path"])).expanduser().absolute()
                if destination.is_symlink() or not _inside(destination, project_root):
                    raise ValueError("recovery destination escaped")
                destination_path = destination
                prior_destination_existed = destination.exists() and not destination.is_symlink()
                prior_destination = _file_bytes(destination, root=project_root) if prior_destination_existed else None
                if not prior_destination_existed:
                    _IO.get().check_missing_parent(destination, root=project_root)
                expected_destination = recovery.get("destination_expected_sha256")
                if ((prior_destination is None and expected_destination is not None)
                        or (prior_destination is not None and _sha_bytes(prior_destination) != expected_destination)):
                    raise ValueError("recovery destination changed after preview")
                source_bytes = _file_bytes(source, root=registry_root)
                if (_sha_bytes(source_bytes) != recovery["expected_artifact_sha256"]
                        or _sha_bytes(source_bytes) != current["artifact_sha256"]):
                    raise ValueError("recovery source changed after preview")
                _IO.get().check()
                destination_write_started = True
                _atomic_write_bytes(destination, source_bytes)
                record = seal_generation_record(
                    {
                        **_record_core(current),
                        "version": current["version"] + 1,
                        "previous_record_sha256": current["record_sha256"],
                        "events": [
                            *current.get("events", []),
                            {
                                "type": "project_ground.recovered",
                                "security_generation": current["security_generation"],
                                "admission_sha256": value["maintenance"]["fresh_admission_sha256"],
                            },
                        ],
                    }
                )
                _IO.get().check()
                record_write_started = True
                _atomic_write_json(record_path, record)
                decision = "RECOVERED"
            _IO.get().check()
            if time.monotonic() - started > TRANSACTION_TIMEOUT_SECONDS:
                raise TimeoutError("maintenance transaction exceeded hard bound")
            if value["timing"]["known"] and (time.monotonic() - started) * 1000 > value["timing"]["budget_ms"]:
                raise TimeoutError("maintenance timing budget exceeded")
            result = dict(preview)
            result.update(
                status="PASS",
                decision=decision,
                record_sha256=record["record_sha256"],
                record_version=record["version"],
                active_security_generation=record["security_generation"],
                previous_generation_preserved=True,
                mutation_performed=True,
                issues=[],
            )
            result["diagnostic"] = {**_diagnostics(value, [], result["compatibility"]), "safe_next_action": "NONE"}
            _record_public_timing({"report": result}, program, started)
            # Report construction and hashing belong to the transaction.  A
            # late refusal must still enter rollback under this same lock.
            _IO.get().check()
            if (time.monotonic() - started > TRANSACTION_TIMEOUT_SECONDS
                    or (value["timing"]["known"] and
                        (time.monotonic() - started) * 1000 > value["timing"]["budget_ms"])):
                raise TimeoutError("maintenance final report exceeded timing bound")
            return result
        except (FileNotFoundError, PermissionError, OSError, ValueError, json.JSONDecodeError) as error:
            rollback_issues = []
            if record_write_started and prior_record_bytes is not None:
                try:
                    _atomic_write_bytes(record_path, prior_record_bytes)
                except OSError as rollback_error:
                    rollback_issues.append("maintenance:rollback_failed:record:" + type(rollback_error).__name__)
            if binding_write_started and binding_path is not None:
                try:
                    if prior_binding_existed and prior_binding is not None:
                        _atomic_write_bytes(binding_path, prior_binding)
                    elif binding_path.exists():
                        binding_path.unlink()
                except OSError as rollback_error:
                    rollback_issues.append("maintenance:rollback_failed:binding:" + type(rollback_error).__name__)
            if destination_write_started and destination_path is not None:
                try:
                    if prior_destination_existed and prior_destination is not None:
                        _atomic_write_bytes(destination_path, prior_destination)
                    elif destination_path.exists():
                        destination_path.unlink()
                except OSError as rollback_error:
                    rollback_issues.append("maintenance:rollback_failed:destination:" + type(rollback_error).__name__)
            result = dict(preview)
            result.update(
                status="BLOCKED",
                decision="BLOCKED" if rollback_issues else "PRESERVED_PREVIOUS_GENERATION",
                previous_generation_preserved=not rollback_issues,
                mutation_performed=bool(rollback_issues),
                issues=[*preview.get("issues", []), "maintenance:activation_failed:" + type(error).__name__, *rollback_issues],
            )
            result["diagnostic"] = _diagnostics(value, result["issues"], result["compatibility"])
            result["report_sha256"] = _sha({key: item for key, item in result.items() if key != "report_sha256"})
            return _record_public_timing({"report": result}, program, started)["report"]


class ProjectGroundDecisionCache:
    """Cache immutable evaluation while rechecking generation/lease/scope."""

    def __init__(self):
        self._entries: dict[str, tuple[str, dict[str, Any]]] = {}

    @staticmethod
    def _static_key(program: Mapping[str, Any]) -> str:
        value = deepcopy(dict(program))
        value.pop("live_facts", None)
        value.pop("expected_registry", None)
        value.pop("timing", None)
        return _sha(value)

    @staticmethod
    def _dynamic_key(program: Mapping[str, Any]) -> str | None:
        record_path = Path(str(program.get("current_record_path", "")))
        try:
            record_digest = _file_digest(record_path, root=Path(str(program.get("registry_root", ""))))
        except OSError:
            return None
        facts = program.get("live_facts", {}) if isinstance(program.get("live_facts"), Mapping) else {}
        return _sha(
            {
                "record": record_digest,
                "expected": program.get("expected_registry"),
                "facts": facts,
            }
        )

    def evaluate(self, program: Mapping[str, Any]) -> dict[str, Any]:
        static = self._static_key(program)
        cached = self._entries.get(static)
        response = _run_readonly(program, cached=cached, cache_mode=True)
        result = response["report"]
        dynamic = response.get("dynamic")
        if dynamic is not None and result["status"] == "PASS":
            self._entries[static] = (dynamic, deepcopy(result))
        else:
            self._entries.pop(static, None)
        return result


def _blocked_report(program, issue):
    value, issues = _program(program)
    _issue(issues, issue)
    compatibility, _ = compatibility_decision(value.get("compatibility", {}))
    timing = value.get("timing", {})
    report = {
        "schema": REPORT_SCHEMA, "policy_version": POLICY_VERSION,
        "status": "BLOCKED", "decision": "READ_ONLY" if value.get("operation") in {"inspect", "diagnose"} else "BLOCKED",
        "operation": value.get("operation"), "compatibility": compatibility,
        "record_sha256": None, "record_version": None, "active_security_generation": None,
        "previous_generation_preserved": True, "mutation_performed": False,
        "issues": issues, "diagnostic": _diagnostics(value, issues, compatibility),
        "timing": {"known": timing.get("known") is True, "budget_ms": timing.get("budget_ms"),
                   "observed_ms": None, "budget_met": False if timing.get("known") else None,
                   "lightweight_rechecks": ["generation", "lease", "scope"]},
        "provider_free": True, "hosted_calls": 0, "model_calls": 0,
        "credential_reads": 0, "task_creations": 0, "authority_reservations": 0,
        "automatic_repairs": 0, "automatic_reruns": 0,
        "source_pointer": value.get("source_pointer"),
    }
    return {**report, "report_sha256": _sha(report)}


def _execute_readonly(program, *, staging_roots=(), cached=None, cache_mode=False, read_budget=None):
    dynamic = None
    reader = None
    initial_bytes = 0
    try:
        if read_budget is None:
            read_budget = MAX_MAINTENANCE_BYTES
        if type(read_budget) is not int or not 0 <= read_budget <= MAX_MAINTENANCE_BYTES:
            raise _ReadError("resource_bytes_limit")
        value, issues = _program(program)
        if issues:
            raise _ReadError("resource_unavailable")
        with _io_scope(value, staging_roots, max_bytes=read_budget) as reader:
            initial_bytes = reader.remaining
            if cache_mode:
                dynamic = ProjectGroundDecisionCache._dynamic_key(program)
            if dynamic is not None and cached is not None and cached[0] == dynamic:
                report = deepcopy(cached[1])
                hit = True
            else:
                report = _evaluate_body(program)
                hit = False
    except (OSError, ValueError, TypeError) as error:
        reason = error.reason if isinstance(error, _ReadError) else "resource_unavailable"
        report = _blocked_report(program, "maintenance:" + reason)
        hit = False
    if cache_mode:
        report["cache_hit"] = hit
        report["lightweight_rechecks"] = ["generation", "lease", "scope"]
    return {"report": report, "dynamic": dynamic,
            "bytes_read": initial_bytes - reader.remaining if reader is not None else 0}


def _maintenance_argv():
    return [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--read-only-maintenance"]


def _run_readonly(program, *, staging_roots=(), cached=None, cache_mode=False):
    started = time.monotonic()
    scope = current_dispatch_scope()
    if scope is not None:
        scope.managed = True
    caller_reader = _IO.get()
    read_budget = caller_reader.remaining if caller_reader is not None else MAX_MAINTENANCE_BYTES
    job = {"program": program, "staging_roots": [str(root) for root in staging_roots],
           "cached": cached, "cache_mode": cache_mode, "read_budget": read_budget}
    raw = _canonical(job)
    execution = run_contained(_maintenance_argv(), input_bytes=raw,
                              config={"wall_seconds": VALIDATION_TIMEOUT_SECONDS},
                              expect_json=True, scope=scope, surface="maintenance-read")
    # Keep the actual bounded streams and cleanup observation in the calling
    # host thread for diagnostics; none is treated as a model-supplied verdict.
    _PROCESS_EVIDENCE.result = execution
    if execution["status"] == "PASS":
        output = execution["parsed_output"]
        if (isinstance(output, dict) and set(output) == {"report", "dynamic", "bytes_read"}
                and isinstance(output["report"], dict)
                and output["report"].get("schema") == REPORT_SCHEMA
                and output["report"].get("mutation_performed") is False
                and type(output["bytes_read"]) is int and 0 <= output["bytes_read"] <= read_budget):
            if caller_reader is not None:
                caller_reader.remaining -= output["bytes_read"]
                caller_reader.check()
            return _record_public_timing(output, program, started)
    issue = ("maintenance:validation_timeout" if execution.get("reason") == "HARD_WALL_TIMEOUT"
             else "maintenance:evaluation_unavailable")
    report = _blocked_report(program, issue)
    if cache_mode:
        report.update(cache_hit=False, lightweight_rechecks=["generation", "lease", "scope"])
    return _record_public_timing({"report": report, "dynamic": None, "bytes_read": None}, program, started)


def _record_public_timing(output, program, started):
    report = output["report"]
    value, _ = _program(program)
    timing = value["timing"]
    known = timing.get("known") is True
    elapsed_ms = (time.monotonic() - started) * 1000
    budget = timing.get("budget_ms")
    met = elapsed_ms <= budget if known and type(budget) is int else None
    report["timing"].update(known=known, budget_ms=budget,
                           observed_ms=elapsed_ms if known else None, budget_met=met)
    if met is False:
        _issue(report["issues"], "timing:budget_exceeded")
        report.update(status="BLOCKED", decision="READ_ONLY" if report["operation"] in {"inspect", "diagnose"} else "BLOCKED")
        report["diagnostic"] = _diagnostics(value, report["issues"], report["compatibility"])
    report["report_sha256"] = _sha({key: item for key, item in report.items() if key != "report_sha256"})
    return output


def evaluate_project_ground_maintenance(program: Any, *, staging_roots=()) -> dict[str, Any]:
    """Evaluate read-only state in one owned, cancellable bounded process.

    Extra staging roots are a trusted-host argument, never a field accepted
    from the model-callable maintenance program.
    """
    return _run_readonly(program, staging_roots=staging_roots)["report"]


def apply_project_ground_maintenance(program: Any, *, staging_roots=()) -> dict[str, Any]:
    """Keep explicitly admitted transactions in their original host process."""
    started = time.monotonic()
    try:
        value, issues = _program(program)
        if issues:
            result = _blocked_report(program, "maintenance:resource_unavailable")
        else:
            with _io_scope(value, staging_roots, seconds=TRANSACTION_TIMEOUT_SECONDS):
                # _apply_body seals its timing before releasing the transaction
                # lock.  Delivery must not re-veto an already committed result.
                return _apply_body(program, staging_roots=staging_roots, started=started)
    except OSError:
        result = _blocked_report(program, "maintenance:resource_unavailable")
    return _record_public_timing({"report": result}, program, started)["report"]


def replay_project_ground_qualification(observations: Any) -> dict[str, Any]:
    issues: list[str] = []
    _validate_state_bounds(observations, issues, label="observations")
    value = _mapping(observations, "observations", issues)
    disposable = _mapping(value.get("disposable"), "observations.disposable", issues)
    model_coordinate = _mapping(value.get("model_coordinate"), "observations.model_coordinate", issues)
    rows: list[dict[str, Any]] = []
    for subject, required, observed in (
        ("disposable", FAILURE_CASES, disposable),
        ("model_coordinate", MODEL_COORDINATE_CASES, model_coordinate),
    ):
        for case in required:
            status = observed.get(case)
            if status != "PASS":
                _issue(issues, "replay:" + subject + ":" + case + ":missing_or_failed")
            rows.append({"subject": subject, "case": case, "status": status})
        for extra in sorted(set(observed) - set(required)):
            _issue(issues, "replay:" + subject + ":unknown_case:" + str(extra))
    report = {
        "schema": REPLAY_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "complete": not issues,
        "rows": rows,
        "issues": issues,
        "provider_free": True,
        "hosted_calls": 0,
        "model_calls": 0,
        "credential_reads": 0,
        "historical_failures_rewritten": 0,
    }
    return {**report, "report_sha256": _sha(report)}


__all__ = [
    "DIAGNOSTIC_SURFACES",
    "FAILURE_CASES",
    "GENERATION_SCHEMA",
    "MODEL_COORDINATE_CASES",
    "OPERATIONS",
    "POLICY_VERSION",
    "PROGRAM_SCHEMA",
    "ProjectGroundDecisionCache",
    "REPLAY_SCHEMA",
    "REPORT_SCHEMA",
    "STAGES",
    "apply_project_ground_maintenance",
    "compatibility_decision",
    "evaluate_project_ground_maintenance",
    "replay_project_ground_qualification",
    "seal_generation_record",
]


if __name__ == "__main__":
    if sys.argv[1:] != ["--read-only-maintenance"]:
        raise SystemExit(2)
    from orch_dork_hostile_input import parse_bounded_json
    raw = sys.stdin.buffer.read(MAX_MANIFEST_BYTES + 1)
    job = parse_bounded_json(raw)
    if set(job) != {"program", "staging_roots", "cached", "cache_mode", "read_budget"}:
        raise SystemExit(2)
    result = _execute_readonly(**job)
    sys.stdout.buffer.write(_canonical(result) + b"\n")
