#!/usr/bin/env python3
"""Durable provider-free project enrollment for Orch Dork.

The external interface is intentionally small: evaluate one closed enrollment
program, or apply the exact decision under a filesystem compare-and-swap lock.
All identity resolution, collision checks, manifest construction, hashing,
staging, activation, diagnostics, and explicit removal stay inside this module.

The read-only evaluator is exposed through MCP.  The mutating entry point is a
separate explicit maintenance operation and is exercised only in disposable
provider-free fixtures until the later project-ground tickets qualify it.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any, Mapping, Sequence


try:
    from orch_dork_hostile_input import PROFILE as HOSTILE_INPUT_PROFILE  # type: ignore
except ImportError:  # pragma: no cover - standalone source execution
    HOSTILE_INPUT_PROFILE = None


PROGRAM_SCHEMA = "orch-dork/project-enrollment-program/v1"
MANIFEST_SCHEMA = "orch-dork/project-binding/v1"
RECORD_SCHEMA = "orch-dork/project-enrollment-record/v1"
EVENT_SCHEMA = "orch-dork/project-enrollment-event/v1"
REPORT_SCHEMA = "orch-dork/project-enrollment-report/v1"
PROTOCOL = "orch-dork/project-ground/v1"
POLICY_VERSION = "project-ground-policy/v1"

# Issue 41: the enrollment evaluator above remains the Issue 40 maintenance
# surface.  Adapter execution is deliberately described by a separate closed
# contract so callers do not assemble hashing, storage, process, or authority
# checks themselves.
AUTHORIZE_OPERATION_SCHEMA = "orch-dork/project-ground-operation/v1"
AUTHORIZE_CONTEXT_SCHEMA = "orch-dork/project-ground-context/v1"
AUTHORIZE_REPORT_SCHEMA = "orch-dork/project-ground-decision/v1"
ADAPTER_SNAPSHOT_SCHEMA = "orch-dork/project-adapter-snapshot/v1"
ADAPTER_EXECUTION_SCHEMA = "orch-dork/project-adapter-execution/v1"
AUTHORIZE_POLICY_VERSION = "project-ground-authorize-policy/v1"
PROFILE = HOSTILE_INPUT_PROFILE
MAX_ADAPTER_INPUT_BYTES = PROFILE.canonical_json_bytes if PROFILE is not None else 262_144
MAX_ADAPTER_OUTPUT_BYTES = PROFILE.adapter_output_bytes if PROFILE is not None else 131_072
MAX_ADAPTER_TIMEOUT_MS = int((PROFILE.adapter_wall_seconds if PROFILE is not None else 10) * 1000)
# Issue 49 hostile-input limits.  The generic adapter process has a separate
# stricter runtime contract; these values bound enrollment manifests/records
# and all provider-free state loaded by this module.
DEFENSIVE_PROFILE_SCHEMA = PROFILE.schema if PROFILE is not None else "orch-dork/hostile-input-profile/v1"
MAX_MANIFEST_BYTES = PROFILE.manifest_bytes if PROFILE is not None else 262_144
MAX_DECLARED_PATHS = PROFILE.manifest_paths if PROFILE is not None else 64
MAX_GENERATIONS = PROFILE.manifest_generations if PROFILE is not None else 32
MAX_TRANSITIONS = MAX_GENERATIONS
MAX_STAGED_OPERATIONS = 1
VALIDATION_TIMEOUT_SECONDS = PROFILE.registry_validate_seconds if PROFILE is not None else 5
TRANSACTION_TIMEOUT_SECONDS = PROFILE.registry_commit_seconds if PROFILE is not None else 10
_SENSITIVE_KEY = re.compile(
    r"(?:credential|password|passwd|secret|authorization|access[_-]?token|"
    r"refresh[_-]?token|api[_-]?key|private[_-]?key|cookie|prompt|conversation|"
    r"chain[_-]?of[_-]?thought|private[_-]?reasoning|reasoning[_-]?trace|"
    r"sensitive[_-]?config|config[_-]?(?:secret|credential|token))",
    re.IGNORECASE,
)
_LIFECYCLE_BINDINGS = (
    "ticket_admission_sha256",
    "acceptance_resource_closure_sha256",
    "execution_readiness_sha256",
    "lease_sha256",
    "active_controller_sha256",
    "coordinator_capsule_sha256",
    "final_evidence_sha256",
)

OPERATIONS = frozenset({"enroll", "inspect", "unenroll"})
DECISIONS = frozenset(
    {
        "READY_TO_ENROLL",
        "ALREADY_ENROLLED",
        "ACTIVE",
        "READY_TO_UNENROLL",
        "ALREADY_UNENROLLED",
        "READ_ONLY",
        "REFUSED",
        "RECONCILIATION_REQUIRED",
        "MIGRATION_REQUIRED",
        "ENROLLED",
        "UNENROLLED",
        "PARTIAL_STAGED_READ_ONLY",
    }
)
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,255}\Z")
_SHELLS = frozenset({"sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"})
# The project-ground control directory holds the binding manifest and, for a
# project enrolled by guided enrollment (Issue 194), its pinned adapter.
CONTROL_ENTRIES = frozenset({"binding.json", "adapter.py"})
# Dependency and build trees are not the project's own source: a repository
# inside them is not a nested project, and a JavaScript project's
# node_modules alone exceeds the nested-repository scan's bound.
_SCAN_SKIPPED = frozenset({".git", ".orch-dork", "__pycache__", "node_modules", ".venv", "venv", ".tox", "target"})


class ProjectEnrollmentInspectionError(ValueError):
    """Stable refusal while constructing one read-only active inspection."""

    def __init__(self, issues: Sequence[str]):
        self.issues = tuple(sorted(set(issues)))
        super().__init__(";".join(self.issues))


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _count_declared_paths(value: Any, *, _seen: set[int] | None = None) -> int:
    """Count declared path/locator fields without following those paths."""

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
    """Reject an oversized state document before schema expansion/mutation."""

    try:
        encoded = _canonical(value)
    except (TypeError, ValueError, RecursionError):
        _issue(issues, label + ":malformed_json")
        return
    if len(encoded) > MAX_MANIFEST_BYTES:
        _issue(issues, label + ":manifest_bytes_limit")
        _issue(issues, "bounds:manifest_bytes_limit")
    path_count = _count_declared_paths(value)
    if path_count > MAX_DECLARED_PATHS:
        _issue(issues, label + ":declared_paths_limit")
        _issue(issues, "bounds:declared_paths_limit")
    generation_count = _count_generations(value)
    if generation_count > MAX_GENERATIONS:
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


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and "\x00" not in value


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _positive(value: Any) -> bool:
    return type(value) is int and value > 0


def _exact(value: Any, keys: set[str], label: str, issues: list[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return {}
    item = dict(value)
    for key in sorted(keys - set(item)):
        _issue(issues, label + ":missing:" + key)
    for key in sorted(set(item) - keys):
        _issue(issues, label + ":unknown:" + str(key))
    return item


def _logical_identity(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "project_id",
            "host_id",
            "environment_id",
            "saved_project_id",
            "workspace_id",
            "repository_kind",
            "worktree_id",
            "canonical_initial_root",
            "source_pointer",
        },
        "identity",
        issues,
    )
    for field in ("project_id", "host_id", "workspace_id"):
        if not _identifier(item.get(field)):
            _issue(issues, "identity:" + field + "_invalid")
    for field in ("environment_id", "saved_project_id", "worktree_id"):
        if item.get(field) is not None and not _identifier(item.get(field)):
            _issue(issues, "identity:" + field + "_invalid")
    if item.get("repository_kind") not in {"git", "directory"}:
        _issue(issues, "identity:repository_kind_invalid")
    root = item.get("canonical_initial_root")
    if not _text(root) or not Path(root).is_absolute():
        _issue(issues, "identity:canonical_initial_root_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, "identity:source_pointer_invalid")
    return item


def _binding(value: Any, root: Path | None, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "protocol",
            "generation",
            "adapter_command",
            "adapter_sha256",
            "required",
            "source_pointer",
        },
        "binding",
        issues,
    )
    if item.get("protocol") != PROTOCOL:
        _issue(issues, "binding:protocol_unsupported")
    if not _positive(item.get("generation")):
        _issue(issues, "binding:generation_invalid")
    if item.get("required") is not True:
        _issue(issues, "binding:required_invalid")
    if not _digest(item.get("adapter_sha256")):
        _issue(issues, "binding:adapter_sha256_invalid")
    command = item.get("adapter_command")
    if not isinstance(command, list) or not 2 <= len(command) <= 16:
        _issue(issues, "binding:adapter_command_invalid")
        command = []
    elif any(not _text(arg) or len(arg) > 4096 or "\n" in arg or "\r" in arg for arg in command):
        _issue(issues, "binding:adapter_command_invalid")
        command = []
    if command:
        executable = Path(command[0]).name.lower()
        if executable in _SHELLS:
            _issue(issues, "binding:shell_command_refused")
        entry = Path(command[1])
        if entry.is_absolute() or ".." in entry.parts or command[1].startswith("-"):
            _issue(issues, "binding:adapter_path_escape")
        elif root is not None:
            candidate = root / entry
            try:
                resolved_root = root.resolve(strict=True)
                resolved = candidate.resolve(strict=False)
                resolved.relative_to(resolved_root)
            except (OSError, ValueError):
                _issue(issues, "binding:adapter_path_escape")
            else:
                if candidate.is_symlink():
                    _issue(issues, "binding:adapter_symlink")
                elif not candidate.is_file():
                    _issue(issues, "binding:adapter_missing")
                else:
                    try:
                        actual = _sha_bytes(candidate.read_bytes())
                    except OSError as exc:
                        _issue(issues, "binding:adapter_unreadable:" + type(exc).__name__)
                    else:
                        if actual != item.get("adapter_sha256"):
                            _issue(issues, "binding:adapter_digest_mismatch")
    if not _text(item.get("source_pointer")):
        _issue(issues, "binding:source_pointer_invalid")
    return item


def _expected(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(value, {"version", "record_sha256"}, "expected_registry", issues)
    if type(item.get("version")) is not int or item.get("version", -1) < 0:
        _issue(issues, "expected_registry:version_invalid")
    if item.get("record_sha256") is not None and not _digest(item.get("record_sha256")):
        _issue(issues, "expected_registry:record_sha256_invalid")
    if item.get("version") == 0 and item.get("record_sha256") is not None:
        _issue(issues, "expected_registry:initial_hash_not_null")
    if item.get("version", 0) > 0 and item.get("record_sha256") is None:
        _issue(issues, "expected_registry:existing_hash_missing")
    return item


def _maintenance(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(value, {"active_writer", "reason", "source_pointer"}, "maintenance", issues)
    if not isinstance(item.get("active_writer"), bool):
        _issue(issues, "maintenance:active_writer_invalid")
    if not _text(item.get("reason")):
        _issue(issues, "maintenance:reason_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, "maintenance:source_pointer_invalid")
    return item


def _program(value: Any) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    _validate_state_bounds(value, issues)
    item = _exact(
        value,
        {
            "schema",
            "operation",
            "registry_root",
            "project_root",
            "identity",
            "binding",
            "expected_registry",
            "maintenance",
            "source_pointer",
        },
        "program",
        issues,
    )
    if item.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    if item.get("operation") not in OPERATIONS:
        _issue(issues, "program:operation_invalid")
    for field in ("registry_root", "project_root"):
        value_path = item.get(field)
        if not _text(value_path) or not Path(value_path).is_absolute():
            _issue(issues, "program:" + field + "_invalid")
    identity = _logical_identity(item.get("identity"), issues)
    root_value = item.get("project_root")
    root = Path(root_value) if _text(root_value) and Path(root_value).is_absolute() else None
    binding = _binding(item.get("binding"), root if root is not None and root.exists() else None, issues)
    expected = _expected(item.get("expected_registry"), issues)
    maintenance = _maintenance(item.get("maintenance"), issues)
    if not _text(item.get("source_pointer")):
        _issue(issues, "program:source_pointer_invalid")
    item["identity"] = identity
    item["binding"] = binding
    item["expected_registry"] = expected
    item["maintenance"] = maintenance
    return item, issues


def _identity_key(identity: Mapping[str, Any]) -> str:
    return _sha(
        {
            "project_id": identity.get("project_id"),
            "host_id": identity.get("host_id"),
            "environment_id": identity.get("environment_id"),
            "saved_project_id": identity.get("saved_project_id"),
            "workspace_id": identity.get("workspace_id"),
            "repository_kind": identity.get("repository_kind"),
            "worktree_id": identity.get("worktree_id"),
        }
    )


def _record_path(registry_root: Path, identity: Mapping[str, Any]) -> Path:
    return registry_root / "records" / (_identity_key(identity) + ".json")


def _lock_path(registry_root: Path, identity: Mapping[str, Any]) -> Path:
    return registry_root / "locks" / (_identity_key(identity) + ".lock")


def _binding_path(project_root: Path) -> Path:
    return project_root / ".orch-dork" / "binding.json"


class _DuplicateJSONKey(ValueError):
    pass


def _json_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _decode_json_bytes(
    raw_bytes: bytes,
    label: str,
    issues: list[str],
) -> dict[str, Any] | None:
    if len(raw_bytes) > MAX_MANIFEST_BYTES:
        _issue(issues, label + ":manifest_bytes_limit")
        return None
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        _issue(issues, label + ":bom_forbidden")
        return None
    try:
        raw = raw_bytes.decode("utf-8")
        value = json.loads(
            raw,
            object_pairs_hook=lambda pairs: _json_object_no_duplicates(pairs),
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except UnicodeDecodeError:
        _issue(issues, label + ":utf8_invalid")
        return None
    except _DuplicateJSONKey:
        _issue(issues, label + ":duplicate_key")
        return None
    except (TypeError, ValueError, json.JSONDecodeError):
        _issue(issues, label + ":corrupt")
        return None
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return None
    return dict(value)


def _read_json(path: Path, label: str, issues: list[str]) -> dict[str, Any] | None:
    if path.is_symlink():
        _issue(issues, label + ":symlink")
        return None
    try:
        raw_bytes = path.read_bytes()
    except PermissionError:
        _issue(issues, label + ":permission_denied")
        return None
    except OSError as exc:
        _issue(issues, label + ":unreadable:" + type(exc).__name__)
        return None
    return _decode_json_bytes(raw_bytes, label, issues)


def _read_owned_json_no_follow(
    path: Path,
    label: str,
    issues: list[str],
    *,
    private: bool,
) -> dict[str, Any] | None:
    """Read one owner-controlled JSON file through its checked descriptor."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_mode & 0o022
            or (private and details.st_mode & 0o077)
            or (
                hasattr(os, "getuid")
                and details.st_uid != os.getuid()
            )
        ):
            _issue(issues, label + ":unsafe")
            return None
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw_bytes = handle.read(MAX_MANIFEST_BYTES + 1)
    except FileNotFoundError:
        _issue(issues, label + ":missing")
        return None
    except PermissionError:
        _issue(issues, label + ":permission_denied")
        return None
    except OSError:
        _issue(issues, label + ":unsafe")
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return _decode_json_bytes(raw_bytes, label, issues)


def _manifest(value: Any, issues: list[str]) -> dict[str, Any]:
    _validate_state_bounds(value, issues, label="manifest")
    item = _exact(
        value,
        {
            "schema",
            "project_id",
            "protocol",
            "binding_generation",
            "enrollment_identity_sha256",
            "adapter_command",
            "adapter_sha256",
            "required",
        },
        "manifest",
        issues,
    )
    if item.get("schema") != MANIFEST_SCHEMA:
        _issue(issues, "manifest:schema_unsupported")
    if not _identifier(item.get("project_id")):
        _issue(issues, "manifest:project_id_invalid")
    if item.get("protocol") != PROTOCOL:
        _issue(issues, "manifest:protocol_unsupported")
    if not _positive(item.get("binding_generation")):
        _issue(issues, "manifest:generation_invalid")
    for field in ("enrollment_identity_sha256", "adapter_sha256"):
        if not _digest(item.get(field)):
            _issue(issues, "manifest:" + field + "_invalid")
    if not isinstance(item.get("adapter_command"), list):
        _issue(issues, "manifest:adapter_command_invalid")
    if item.get("required") is not True:
        _issue(issues, "manifest:required_invalid")
    return item


def _record_core(record: Mapping[str, Any]) -> dict[str, Any]:
    value = deepcopy(dict(record))
    value.pop("record_sha256", None)
    return value


def _validate_record(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "schema",
            "version",
            "status",
            "enrollment_id",
            "identity",
            "identity_sha256",
            "binding_generation",
            "manifest_sha256",
            "adapter_sha256",
            "protocol",
            "last_known_good",
            "events",
            "record_sha256",
        },
        "record",
        issues,
    )
    if item.get("schema") != RECORD_SCHEMA:
        _issue(issues, "record:schema_unsupported")
    if not _positive(item.get("version")):
        _issue(issues, "record:version_invalid")
    if item.get("status") not in {"active", "unenrolled"}:
        _issue(issues, "record:status_invalid")
    if not _identifier(item.get("enrollment_id")):
        _issue(issues, "record:enrollment_id_invalid")
    if not isinstance(item.get("identity"), Mapping):
        _issue(issues, "record:identity_invalid")
    for field in ("identity_sha256", "manifest_sha256", "adapter_sha256", "record_sha256"):
        if not _digest(item.get(field)):
            _issue(issues, "record:" + field + "_invalid")
    if isinstance(item.get("identity"), Mapping) and item.get("identity_sha256") != _sha(item["identity"]):
        _issue(issues, "record:identity_hash_mismatch")
    if item.get("protocol") != PROTOCOL:
        _issue(issues, "record:protocol_unsupported")
    if not _positive(item.get("binding_generation")):
        _issue(issues, "record:generation_invalid")
    if not isinstance(item.get("last_known_good"), Mapping):
        _issue(issues, "record:last_known_good_invalid")
    events = item.get("events")
    if not isinstance(events, list):
        _issue(issues, "record:events_invalid")
    else:
        if len(events) > MAX_TRANSITIONS:
            _issue(issues, "record:transitions_limit")
            _issue(issues, "bounds:generations_limit")
        for index, event in enumerate(events):
            if not isinstance(event, Mapping) or event.get("schema") != EVENT_SCHEMA or event.get("seq") != index + 1:
                _issue(issues, f"record:events_invalid:{index}")
    if _digest(item.get("record_sha256")) and item.get("record_sha256") != _sha(_record_core(item)):
        _issue(issues, "record:seal_mismatch")
    return item


def _control_entries(root: Path, issues: list[str]) -> list[str]:
    control = root / ".orch-dork"
    if not control.exists() and not control.is_symlink():
        return []
    if control.is_symlink():
        _issue(issues, "control:directory_symlink")
        return []
    if not control.is_dir():
        _issue(issues, "control:not_directory")
        return []
    try:
        entries = sorted(path.name for path in control.iterdir())
    except PermissionError:
        _issue(issues, "control:permission_denied")
        return []
    except OSError as exc:
        _issue(issues, "control:unreadable:" + type(exc).__name__)
        return []
    unknown = [name for name in entries if name not in CONTROL_ENTRIES]
    for name in unknown:
        _issue(issues, "control:unknown_entry:" + name)
    return entries


def _nested_repositories(root: Path, issues: list[str], limit: int = 20_000) -> list[str]:
    found: list[str] = []
    visited = 0
    try:
        for current, directories, files in os.walk(root):
            visited += 1
            if visited > limit:
                _issue(issues, "project:nested_scan_limit")
                break
            current_path = Path(current)
            relative = current_path.relative_to(root)
            if relative != Path(".") and (".git" in directories or ".git" in files):
                found.append(relative.as_posix())
                directories[:] = []
                continue
            directories[:] = [name for name in directories if name not in _SCAN_SKIPPED]
    except (OSError, ValueError) as exc:
        _issue(issues, "project:nested_scan_unavailable:" + type(exc).__name__)
    for value in sorted(found):
        _issue(issues, "project:nested_repository:" + value)
    return sorted(found)


def _observe_project(program: Mapping[str, Any], issues: list[str]) -> dict[str, Any]:
    root = Path(program["project_root"])
    identity = program["identity"]
    observation: dict[str, Any] = {
        "canonical_root": str(root),
        "root_exists": root.exists(),
        "device": None,
        "inode": None,
        "repository_marker": "missing",
        "nested_repositories": [],
    }
    if not root.exists():
        _issue(issues, "project:root_missing")
        return observation
    if root.is_symlink():
        _issue(issues, "project:root_symlink")
        return observation
    if not root.is_dir():
        _issue(issues, "project:root_not_directory")
        return observation
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        _issue(issues, "project:root_unreadable:" + type(exc).__name__)
        return observation
    observation["canonical_root"] = str(resolved)
    if str(resolved) != str(root):
        _issue(issues, "project:root_not_canonical")
    if identity.get("canonical_initial_root") != str(resolved):
        _issue(issues, "identity:canonical_root_mismatch")
    try:
        stat = root.stat()
    except OSError as exc:
        _issue(issues, "project:root_stat_unavailable:" + type(exc).__name__)
    else:
        observation["device"] = stat.st_dev
        observation["inode"] = stat.st_ino
    marker = root / ".git"
    if marker.is_symlink():
        _issue(issues, "project:git_marker_symlink")
    elif marker.is_dir():
        observation["repository_marker"] = "git_directory"
        if identity.get("worktree_id") is not None:
            _issue(issues, "identity:unexpected_worktree_id")
    elif marker.is_file():
        observation["repository_marker"] = "git_file"
        if identity.get("worktree_id") is None:
            _issue(issues, "identity:worktree_id_required")
    elif identity.get("repository_kind") == "git":
        _issue(issues, "project:git_marker_missing")
    if identity.get("repository_kind") == "directory" and marker.exists():
        _issue(issues, "identity:repository_kind_mismatch")
    observation["nested_repositories"] = _nested_repositories(root, issues)
    return observation


def _manifest_for(program: Mapping[str, Any]) -> dict[str, Any]:
    identity = program["identity"]
    binding = program["binding"]
    return {
        "schema": MANIFEST_SCHEMA,
        "project_id": identity["project_id"],
        "protocol": binding["protocol"],
        "binding_generation": binding["generation"],
        "enrollment_identity_sha256": _identity_key(identity),
        "adapter_command": deepcopy(binding["adapter_command"]),
        "adapter_sha256": binding["adapter_sha256"],
        "required": True,
    }


def _record_for(
    program: Mapping[str, Any],
    observation: Mapping[str, Any],
    manifest: Mapping[str, Any],
    record_path: Path,
    binding_path: Path,
) -> dict[str, Any]:
    identity = {
        "logical": deepcopy(program["identity"]),
        "observed_root": {
            "canonical_root": observation.get("canonical_root"),
            "device": observation.get("device"),
            "inode": observation.get("inode"),
            "repository_marker": observation.get("repository_marker"),
        },
    }
    key = _identity_key(program["identity"])
    record: dict[str, Any] = {
        "schema": RECORD_SCHEMA,
        "version": 1,
        "status": "active",
        "enrollment_id": "enrollment-" + key[:24],
        "identity": identity,
        "identity_sha256": _sha(identity),
        "binding_generation": program["binding"]["generation"],
        "manifest_sha256": _sha(manifest),
        "adapter_sha256": program["binding"]["adapter_sha256"],
        "protocol": program["binding"]["protocol"],
        "last_known_good": {
            "record_locator": str(record_path),
            "manifest_locator": str(binding_path),
            "adapter_locator": str(Path(program["project_root"]) / program["binding"]["adapter_command"][1]),
        },
        "events": [
            {
                "schema": EVENT_SCHEMA,
                "seq": 1,
                "type": "project.enrolled",
                "record_version": 1,
                "previous_record_sha256": None,
                "manifest_sha256": _sha(manifest),
                "source_pointer": program["maintenance"]["source_pointer"],
            }
        ],
    }
    record["record_sha256"] = _sha(record)
    return record


def _unenrolled_record(program: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    core = _record_core(current)
    version = current["version"] + 1
    core["version"] = version
    core["status"] = "unenrolled"
    events = deepcopy(current["events"])
    events.append(
        {
            "schema": EVENT_SCHEMA,
            "seq": len(events) + 1,
            "type": "project.unenrolled",
            "record_version": version,
            "previous_record_sha256": current["record_sha256"],
            "manifest_sha256": current["manifest_sha256"],
            "source_pointer": program["maintenance"]["source_pointer"],
        }
    )
    core["events"] = events
    core["record_sha256"] = _sha(core)
    return core


def _logical_matches(program: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    identity = current.get("identity")
    logical = identity.get("logical") if isinstance(identity, Mapping) else None
    return isinstance(logical, Mapping) and dict(logical) == program["identity"]


def build_active_inspection_program(
    project_root: os.PathLike[str] | str,
    registry_root: os.PathLike[str] | str,
    *,
    maintenance_reason: str,
    source_pointer: str,
) -> dict[str, Any]:
    """Construct one full inspection program from the sealed active record.

    The manifest and record are read once through owner-checked, no-follow
    descriptors.  This constructor performs no mutation and grants no
    authority; callers must still pass its whole result to
    ``evaluate_project_enrollment`` and require ``PASS``/``ACTIVE``.
    """

    issues: list[str] = []
    try:
        project = Path(project_root)
        registry = Path(registry_root)
        if not project.is_absolute() or not registry.is_absolute():
            raise ValueError("relative root")
        resolved_project = project.resolve(strict=True)
        resolved_registry = registry.resolve(strict=True)
    except (OSError, ValueError):
        raise ProjectEnrollmentInspectionError(
            ["inspection:root_unavailable"]
        )
    if (
        project != resolved_project
        or registry != resolved_registry
        or not project.is_dir()
        or not registry.is_dir()
        or project.is_symlink()
        or registry.is_symlink()
        or not _text(maintenance_reason)
        or not _text(source_pointer)
    ):
        raise ProjectEnrollmentInspectionError(
            ["inspection:root_or_provenance_invalid"]
        )

    binding_path = _binding_path(project)
    manifest = _read_owned_json_no_follow(
        binding_path,
        "manifest",
        issues,
        private=False,
    )
    if manifest is not None:
        before = len(issues)
        manifest = _manifest(manifest, issues)
        if len(issues) != before:
            manifest = None
    if manifest is None:
        raise ProjectEnrollmentInspectionError(issues)

    identity_key = manifest["enrollment_identity_sha256"]
    record_path = registry / "records" / (identity_key + ".json")
    record = _read_owned_json_no_follow(
        record_path,
        "registry:record",
        issues,
        private=True,
    )
    if record is not None:
        before = len(issues)
        record = _validate_record(record, issues)
        if len(issues) != before:
            record = None
    if record is None:
        raise ProjectEnrollmentInspectionError(issues)

    record_identity = record.get("identity")
    identity = (
        record_identity.get("logical")
        if isinstance(record_identity, Mapping)
        else None
    )
    command = manifest.get("adapter_command")
    last_known_good = record.get("last_known_good")
    adapter_path = (
        project / command[1]
        if isinstance(command, list) and len(command) >= 2
        else project
    )
    manifest_sha256 = _sha(manifest)
    if (
        not isinstance(identity, Mapping)
        or _identity_key(identity) != identity_key
        or record.get("status") != "active"
        or record.get("manifest_sha256") != manifest_sha256
        or record.get("binding_generation")
        != manifest.get("binding_generation")
        or record.get("adapter_sha256") != manifest.get("adapter_sha256")
        or record.get("protocol") != manifest.get("protocol")
        or not isinstance(last_known_good, Mapping)
        or last_known_good.get("record_locator") != str(record_path)
        or last_known_good.get("manifest_locator") != str(binding_path)
        or last_known_good.get("adapter_locator") != str(adapter_path)
    ):
        raise ProjectEnrollmentInspectionError(
            ["inspection:binding_or_record_mismatch"]
        )

    program = {
        "schema": PROGRAM_SCHEMA,
        "operation": "inspect",
        "registry_root": str(registry),
        "project_root": str(project),
        "identity": deepcopy(dict(identity)),
        "binding": {
            "protocol": manifest["protocol"],
            "generation": manifest["binding_generation"],
            "adapter_command": deepcopy(manifest["adapter_command"]),
            "adapter_sha256": manifest["adapter_sha256"],
            "required": manifest["required"],
            "source_pointer": "source:.orch-dork/binding.json#binding",
        },
        "expected_registry": {
            "version": record["version"],
            "record_sha256": record["record_sha256"],
        },
        "maintenance": {
            "active_writer": True,
            "reason": maintenance_reason,
            "source_pointer": source_pointer + "#maintenance",
        },
        "source_pointer": source_pointer,
    }
    normalized, program_issues = _program(program)
    if program_issues or normalized != program:
        raise ProjectEnrollmentInspectionError(
            ["inspection:constructed_program_invalid", *program_issues]
        )
    return deepcopy(program)


def _report(
    *,
    decision: str,
    issues: list[str],
    program: Mapping[str, Any],
    observation: Mapping[str, Any],
    manifest: Mapping[str, Any] | None,
    current_manifest: Mapping[str, Any] | None,
    current_record: Mapping[str, Any] | None,
    proposed_record: Mapping[str, Any] | None,
    record_path: Path,
    binding_path: Path,
    mutation_performed: bool = False,
) -> dict[str, Any]:
    if decision not in DECISIONS:
        raise ValueError("invalid enrollment decision")
    success = decision in {
        "READY_TO_ENROLL",
        "ALREADY_ENROLLED",
        "ACTIVE",
        "READY_TO_UNENROLL",
        "ALREADY_UNENROLLED",
        "ENROLLED",
        "UNENROLLED",
    }
    read_only = decision in {
        "READ_ONLY",
        "REFUSED",
        "RECONCILIATION_REQUIRED",
        "MIGRATION_REQUIRED",
        "PARTIAL_STAGED_READ_ONLY",
    }
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "PASS" if success and not issues else "FAIL",
        "decision": decision,
        "policy_version": POLICY_VERSION,
        "operation": program.get("operation"),
        "project_id": program.get("identity", {}).get("project_id"),
        "identity_key": _identity_key(program.get("identity", {})) if program.get("identity") else None,
        "binding_generation": program.get("binding", {}).get("generation"),
        "manifest_sha256": _sha(manifest) if manifest is not None else None,
        "record_sha256": (
            proposed_record.get("record_sha256")
            if isinstance(proposed_record, Mapping)
            else current_record.get("record_sha256") if isinstance(current_record, Mapping) else None
        ),
        "record_path": str(record_path),
        "binding_path": str(binding_path),
        "read_only": read_only,
        "mutation_performed": mutation_performed,
        "current_manifest": deepcopy(dict(current_manifest)) if isinstance(current_manifest, Mapping) else None,
        "current_record": deepcopy(dict(current_record)) if isinstance(current_record, Mapping) else None,
        "proposed_manifest": deepcopy(dict(manifest)) if isinstance(manifest, Mapping) else None,
        "proposed_record": deepcopy(dict(proposed_record)) if isinstance(proposed_record, Mapping) else None,
        "observation": deepcopy(dict(observation)),
        "issues": sorted(set(issues)),
        "provider_free": True,
        "credential_reads": 0,
        "authority_reservations": 0,
        "hosted_calls": 0,
        "model_calls": 0,
        "task_creations": 0,
        "worker_creations": 0,
        "adapter_executions": 0,
        "hook_changes": 0,
        "sandbox_changes": 0,
    }
    report["report_sha256"] = _sha(report)
    return report


def evaluate_project_enrollment(program: Any) -> dict[str, Any]:
    """Read and evaluate one exact project enrollment without mutating it."""

    value, issues = _program(program)
    fallback_root = Path(value.get("project_root") or "/")
    fallback_registry = Path(value.get("registry_root") or "/")
    identity = value.get("identity") if isinstance(value.get("identity"), Mapping) else {}
    record_path = _record_path(fallback_registry, identity) if identity else fallback_registry / "records" / "invalid.json"
    binding_path = _binding_path(fallback_root)
    if issues:
        return _report(
            decision="REFUSED",
            issues=issues,
            program=value,
            observation={},
            manifest=None,
            current_manifest=None,
            current_record=None,
            proposed_record=None,
            record_path=record_path,
            binding_path=binding_path,
        )

    project_root = Path(value["project_root"])
    registry_root = Path(value["registry_root"])
    record_path = _record_path(registry_root, value["identity"])
    binding_path = _binding_path(project_root)
    try:
        registry_resolved = registry_root.resolve(strict=False)
        project_resolved = project_root.resolve(strict=False)
        registry_resolved.relative_to(project_resolved)
    except ValueError:
        pass
    except OSError as exc:
        _issue(issues, "registry:root_unavailable:" + type(exc).__name__)
    else:
        _issue(issues, "registry:inside_project")
    if registry_root.is_symlink():
        _issue(issues, "registry:root_symlink")
    if registry_root.exists() and not registry_root.is_dir():
        _issue(issues, "registry:not_directory")

    record: dict[str, Any] | None = None
    if record_path.exists() or record_path.is_symlink():
        record = _read_json(record_path, "registry:record", issues)
        if record is not None:
            before = len(issues)
            record = _validate_record(record, issues)
            if len(issues) != before:
                record = None

    observation_issues: list[str] = []
    observation = _observe_project(value, observation_issues)
    _control_entries(project_root, observation_issues) if project_root.exists() else []
    desired_manifest = _manifest_for(value)
    current_manifest: dict[str, Any] | None = None
    if binding_path.exists() or binding_path.is_symlink():
        current_manifest = _read_json(binding_path, "manifest", observation_issues)
        if current_manifest is not None:
            before = len(observation_issues)
            current_manifest = _manifest(current_manifest, observation_issues)
            if len(observation_issues) != before:
                current_manifest = None

    operation = value["operation"]
    fatal = list(issues)
    if operation != "unenroll" or project_root.exists():
        fatal.extend(observation_issues)

    if operation == "enroll":
        if value["maintenance"]["active_writer"]:
            return _report(
                decision="REFUSED",
                issues=fatal + ["maintenance:active_writer"],
                program=value,
                observation=observation,
                manifest=desired_manifest,
                current_manifest=current_manifest,
                current_record=record,
                proposed_record=None,
                record_path=record_path,
                binding_path=binding_path,
            )
        if record is not None:
            if record.get("status") == "unenrolled":
                return _report(
                    decision="MIGRATION_REQUIRED",
                    issues=fatal + ["registry:reenrollment_requires_new_generation"],
                    program=value,
                    observation=observation,
                    manifest=desired_manifest,
                    current_manifest=current_manifest,
                    current_record=record,
                    proposed_record=None,
                    record_path=record_path,
                    binding_path=binding_path,
                )
            exact = (
                not fatal
                and _logical_matches(value, record)
                and record.get("binding_generation") == value["binding"]["generation"]
                and record.get("manifest_sha256") == _sha(desired_manifest)
                and record.get("adapter_sha256") == value["binding"]["adapter_sha256"]
                and current_manifest == desired_manifest
                and record.get("identity", {}).get("observed_root")
                == {
                    "canonical_root": observation.get("canonical_root"),
                    "device": observation.get("device"),
                    "inode": observation.get("inode"),
                    "repository_marker": observation.get("repository_marker"),
                }
            )
            if exact:
                return _report(
                    decision="ALREADY_ENROLLED",
                    issues=[],
                    program=value,
                    observation=observation,
                    manifest=desired_manifest,
                    current_manifest=current_manifest,
                    current_record=record,
                    proposed_record=None,
                    record_path=record_path,
                    binding_path=binding_path,
                )
            return _report(
                decision="RECONCILIATION_REQUIRED",
                issues=fatal + ["registry:active_generation_mismatch"],
                program=value,
                observation=observation,
                manifest=desired_manifest,
                current_manifest=current_manifest,
                current_record=record,
                proposed_record=None,
                record_path=record_path,
                binding_path=binding_path,
            )
        if current_manifest is not None and current_manifest != desired_manifest:
            fatal.append("manifest:unknown_or_mismatched_existing")
        if fatal:
            return _report(
                decision="REFUSED",
                issues=fatal,
                program=value,
                observation=observation,
                manifest=desired_manifest,
                current_manifest=current_manifest,
                current_record=None,
                proposed_record=None,
                record_path=record_path,
                binding_path=binding_path,
            )
        proposed = _record_for(value, observation, desired_manifest, record_path, binding_path)
        return _report(
            decision="READY_TO_ENROLL",
            issues=[],
            program=value,
            observation=observation,
            manifest=desired_manifest,
            current_manifest=current_manifest,
            current_record=None,
            proposed_record=proposed,
            record_path=record_path,
            binding_path=binding_path,
        )

    if operation == "inspect":
        if record is None:
            return _report(
                decision="READ_ONLY",
                issues=issues + observation_issues + ["registry:record_missing"],
                program=value,
                observation=observation,
                manifest=desired_manifest,
                current_manifest=current_manifest,
                current_record=None,
                proposed_record=None,
                record_path=record_path,
                binding_path=binding_path,
            )
        if record.get("status") == "unenrolled":
            return _report(
                decision="ALREADY_UNENROLLED",
                issues=[],
                program=value,
                observation=observation,
                manifest=desired_manifest,
                current_manifest=current_manifest,
                current_record=record,
                proposed_record=None,
                record_path=record_path,
                binding_path=binding_path,
            )
        exact = (
            not fatal
            and _logical_matches(value, record)
            and current_manifest == desired_manifest
            and record.get("manifest_sha256") == _sha(desired_manifest)
            and record.get("binding_generation") == value["binding"]["generation"]
            and record.get("identity", {}).get("observed_root")
            == {
                "canonical_root": observation.get("canonical_root"),
                "device": observation.get("device"),
                "inode": observation.get("inode"),
                "repository_marker": observation.get("repository_marker"),
            }
        )
        return _report(
            decision="ACTIVE" if exact else "READ_ONLY",
            issues=[] if exact else fatal + ["project_ground:identity_or_generation_mismatch"],
            program=value,
            observation=observation,
            manifest=desired_manifest,
            current_manifest=current_manifest,
            current_record=record,
            proposed_record=None,
            record_path=record_path,
            binding_path=binding_path,
        )

    if record is None:
        return _report(
            decision="REFUSED",
            issues=issues + ["registry:record_missing"],
            program=value,
            observation=observation,
            manifest=desired_manifest,
            current_manifest=current_manifest,
            current_record=None,
            proposed_record=None,
            record_path=record_path,
            binding_path=binding_path,
        )
    if record.get("status") == "unenrolled":
        return _report(
            decision="ALREADY_UNENROLLED",
            issues=[],
            program=value,
            observation=observation,
            manifest=desired_manifest,
            current_manifest=current_manifest,
            current_record=record,
            proposed_record=None,
            record_path=record_path,
            binding_path=binding_path,
        )
    removal_issues = list(issues)
    if value["maintenance"]["active_writer"]:
        removal_issues.append("maintenance:active_writer")
    if not _logical_matches(value, record):
        removal_issues.append("registry:identity_mismatch")
    if removal_issues:
        return _report(
            decision="REFUSED",
            issues=removal_issues,
            program=value,
            observation=observation,
            manifest=desired_manifest,
            current_manifest=current_manifest,
            current_record=record,
            proposed_record=None,
            record_path=record_path,
            binding_path=binding_path,
        )
    proposed = _unenrolled_record(value, record)
    return _report(
        decision="READY_TO_UNENROLL",
        issues=[],
        program=value,
        observation=observation,
        manifest=desired_manifest,
        current_manifest=current_manifest,
        current_record=record,
        proposed_record=proposed,
        record_path=record_path,
        binding_path=binding_path,
    )


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    encoded = _canonical(value) + b"\n"
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise OSError("manifest exceeds defensive byte bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(encoded.decode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _cas_matches(expected: Mapping[str, Any], current: Mapping[str, Any] | None) -> bool:
    if current is None:
        return expected.get("version") == 0 and expected.get("record_sha256") is None
    return expected.get("version") == current.get("version") and expected.get("record_sha256") == current.get("record_sha256")


def apply_project_enrollment(program: Any) -> dict[str, Any]:
    """Apply one evaluated enrollment or removal through an atomic record CAS."""

    initial = evaluate_project_enrollment(program)
    if initial["decision"] in {"ALREADY_ENROLLED", "ALREADY_UNENROLLED"}:
        return initial
    if initial["decision"] not in {"READY_TO_ENROLL", "READY_TO_UNENROLL"}:
        return initial
    value, validation_issues = _program(program)
    if validation_issues:
        return initial
    registry_root = Path(value["registry_root"])
    record_path = _record_path(registry_root, value["identity"])
    binding_path = _binding_path(Path(value["project_root"]))
    lock_path = _lock_path(registry_root, value["identity"])
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            current = None
            cas_issues: list[str] = []
            if record_path.exists() or record_path.is_symlink():
                current = _read_json(record_path, "registry:record", cas_issues)
                if current is not None:
                    current = _validate_record(current, cas_issues)
            if cas_issues:
                return _report(
                    decision="READ_ONLY",
                    issues=cas_issues,
                    program=value,
                    observation=initial["observation"],
                    manifest=initial["proposed_manifest"],
                    current_manifest=initial["current_manifest"],
                    current_record=current,
                    proposed_record=None,
                    record_path=record_path,
                    binding_path=binding_path,
                )
            if not _cas_matches(value["expected_registry"], current):
                return _report(
                    decision="READ_ONLY",
                    issues=["registry:compare_and_swap_lost"],
                    program=value,
                    observation=initial["observation"],
                    manifest=initial["proposed_manifest"],
                    current_manifest=initial["current_manifest"],
                    current_record=current,
                    proposed_record=None,
                    record_path=record_path,
                    binding_path=binding_path,
                )
            fresh = evaluate_project_enrollment(value)
            if fresh["decision"] not in {"READY_TO_ENROLL", "READY_TO_UNENROLL"}:
                return fresh
            proposed = fresh["proposed_record"]
            if fresh["decision"] == "READY_TO_ENROLL":
                # Keep the previous repository binding bytes until the record
                # CAS has activated successfully.  Any staged-write failure
                # restores that exact prior generation instead of leaving a
                # half-updated manifest behind.
                prior_binding_existed = binding_path.exists() and not binding_path.is_symlink()
                prior_binding_bytes = binding_path.read_bytes() if prior_binding_existed else None
                try:
                    if fresh["current_manifest"] != fresh["proposed_manifest"]:
                        _atomic_write_json(binding_path, fresh["proposed_manifest"])
                    _atomic_write_json(record_path, proposed)
                except OSError as exc:
                    try:
                        if prior_binding_existed and prior_binding_bytes is not None:
                            descriptor, temporary = tempfile.mkstemp(prefix=binding_path.name + ".restore.", suffix=".tmp", dir=str(binding_path.parent))
                            with os.fdopen(descriptor, "wb") as handle:
                                handle.write(prior_binding_bytes)
                                handle.flush()
                                os.fsync(handle.fileno())
                            os.replace(temporary, binding_path)
                            if os.path.exists(temporary):
                                os.unlink(temporary)
                        # With no prior generation there is no binding to
                        # restore.  Preserve the inert staged manifest so a
                        # later exact rerun can complete activation; it is not
                        # trusted while the external record is absent.
                    except OSError:
                        pass
                    return _report(
                        decision="PARTIAL_STAGED_READ_ONLY",
                        issues=["activation:write_failed:" + type(exc).__name__],
                        program=value,
                        observation=fresh["observation"],
                        manifest=fresh["proposed_manifest"],
                        current_manifest=fresh["current_manifest"],
                        current_record=current,
                        proposed_record=proposed,
                        record_path=record_path,
                        binding_path=binding_path,
                    )
                completed = evaluate_project_enrollment({**value, "operation": "inspect"})
                if completed["decision"] != "ACTIVE":
                    return completed
                completed["decision"] = "ENROLLED"
                completed["mutation_performed"] = True
                completed["report_sha256"] = _sha({k: v for k, v in completed.items() if k != "report_sha256"})
                return completed
            try:
                _atomic_write_json(record_path, proposed)
            except OSError as exc:
                return _report(
                    decision="READ_ONLY",
                    issues=["unenroll:write_failed:" + type(exc).__name__],
                    program=value,
                    observation=fresh["observation"],
                    manifest=fresh["proposed_manifest"],
                    current_manifest=fresh["current_manifest"],
                    current_record=current,
                    proposed_record=proposed,
                    record_path=record_path,
                    binding_path=binding_path,
                )
            completed = evaluate_project_enrollment({**value, "operation": "inspect"})
            completed["decision"] = "UNENROLLED"
            completed["mutation_performed"] = True
            completed["report_sha256"] = _sha({k: v for k, v in completed.items() if k != "report_sha256"})
            return completed
    except PermissionError:
        error = "registry:permission_denied"
    except OSError as exc:
        error = "registry:unavailable:" + type(exc).__name__
    return _report(
        decision="READ_ONLY",
        issues=[error],
        program=value,
        observation=initial["observation"],
        manifest=initial["proposed_manifest"],
        current_manifest=initial["current_manifest"],
        current_record=initial["current_record"],
        proposed_record=None,
        record_path=record_path,
        binding_path=binding_path,
    )


# ---------------------------------------------------------------------------
# Issue 41: immutable executable project-ground adapter


def _authorize_issue(issues: list[str], value: str) -> None:
    """Append one stable, machine-readable authorization reason."""

    if value not in issues:
        issues.append(value)


def _authorize_sensitive(value: Any, path: str, issues: list[str]) -> None:
    """Reject secrets and conversational material before any adapter runs."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if _SENSITIVE_KEY.search(key_text):
                _authorize_issue(issues, "sensitive_field_forbidden:" + path + "." + key_text)
            _authorize_sensitive(child, path + "." + key_text, issues)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _authorize_sensitive(child, f"{path}[{index}]", issues)


def _authorize_digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _authorize_text(value: Any, *, max_length: int = 4096) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and "\x00" not in value
        and len(value) <= max_length
    )


def _authorize_json_bytes(value: Any) -> bytes | None:
    try:
        return _canonical(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _authorize_operation(operation: Any) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    if not isinstance(operation, Mapping):
        return {}, ["operation:not_object"]
    allowed = {"schema", "kind", "input", "source_pointer", "input_schema", "output_schema"}
    for key in sorted(set(operation) - allowed):
        _authorize_issue(issues, "operation:unknown:" + str(key))
    value = dict(operation)
    if value.get("schema") != AUTHORIZE_OPERATION_SCHEMA:
        _authorize_issue(issues, "operation:schema_invalid")
    if not _authorize_text(value.get("kind"), max_length=256):
        _authorize_issue(issues, "operation:kind_invalid")
    if not _authorize_text(value.get("source_pointer")):
        _authorize_issue(issues, "operation:source_pointer_invalid")
    if "input" not in value:
        _authorize_issue(issues, "operation:input_missing")
        value["input"] = {}
    if _authorize_json_bytes(value.get("input")) is None:
        _authorize_issue(issues, "operation:input_not_json")
    else:
        encoded = _authorize_json_bytes(value.get("input")) or b""
        if len(encoded) > MAX_ADAPTER_INPUT_BYTES:
            _authorize_issue(issues, "adapter_input_limit_exceeded")
    _authorize_sensitive(value, "operation", issues)
    return value, issues


def _context_component(value: Any, *names: str) -> Any:
    if not isinstance(value, Mapping):
        return None
    for name in names:
        if name in value:
            return value[name]
    return None


def _authorize_context(live_context: Any) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    if not isinstance(live_context, Mapping):
        return {}, ["context:not_object"]
    # Keep the context closed while accepting the field spellings used by the
    # enrollment record, the Model Coordinate wrapper, and test fixtures.
    allowed = {
        "schema", "source_pointer", "identity", "project_identity", "project_root",
        "workspace_root", "cwd", "binding", "adapter", "authority", "writable_scope",
        "lifecycle", "ticket_admission_sha256", "acceptance_resource_closure_sha256",
        "execution_readiness_sha256", "lease_sha256", "active_controller_sha256",
        "coordinator_capsule_sha256", "final_evidence_sha256", "snapshot", "snapshot_root",
        "snapshot_store_root", "snapshot_locator", "snapshot_sha256", "snapshot_status",
        "snapshot_generation", "minimum_snapshot_generation", "environment",
        "environment_identity", "interpreter", "timeout_ms", "output_limit_bytes",
        "process_group", "input_schema", "output_schema", "writable_scope_sha256",
        "binding_generation", "plugin_version", "host_id", "admission_sha256",
        "acceptance_closure_sha256", "readiness_sha256", "controller_sha256",
        "capsule_sha256", "source_pointer", "ticket_id", "root_task_id",
        "adapter_command", "adapter_sha256", "source_path", "adapter_path", "command",
        "snapshot_store", "lifecycle_bindings",
    }
    for key in sorted(set(live_context) - allowed):
        _authorize_issue(issues, "context:unknown:" + str(key))
    value = dict(live_context)
    if value.get("schema") != AUTHORIZE_CONTEXT_SCHEMA:
        _authorize_issue(issues, "context:schema_invalid")
    if not _authorize_text(value.get("source_pointer")):
        _authorize_issue(issues, "context:source_pointer_invalid")
    identity = value.get("identity", value.get("project_identity"))
    if not isinstance(identity, Mapping):
        _authorize_issue(issues, "context:identity_missing")
    else:
        value["identity"] = dict(identity)
        root = identity.get("canonical_initial_root", identity.get("project_root"))
        if root is not None and (not _authorize_text(root) or not Path(root).is_absolute()):
            _authorize_issue(issues, "context:canonical_root_invalid")
    project_root = value.get("project_root", value.get("workspace_root"))
    if project_root is None and isinstance(identity, Mapping):
        project_root = identity.get("canonical_initial_root")
    if not _authorize_text(project_root) or not Path(project_root).is_absolute():
        _authorize_issue(issues, "context:project_root_invalid")
    else:
        value["project_root"] = str(project_root)

    binding = value.get("binding") if isinstance(value.get("binding"), Mapping) else {}
    adapter = value.get("adapter") if isinstance(value.get("adapter"), Mapping) else {}
    merged = {**dict(binding), **dict(adapter)}
    for alias in ("adapter_command", "adapter_sha256", "source_path", "adapter_path", "command"):
        if alias in value:
            merged.setdefault(alias, value[alias])
    command = merged.get("adapter_command", merged.get("command"))
    if not isinstance(command, list) or len(command) < 2:
        _authorize_issue(issues, "adapter:argv_invalid")
        command = []
    elif any(not _authorize_text(item, max_length=4096) or "\n" in item or "\r" in item for item in command):
        _authorize_issue(issues, "adapter:argv_invalid")
        command = []
    else:
        executable = Path(command[0]).name.lower()
        if executable in _SHELLS or executable in {"env", "xargs"}:
            _authorize_issue(issues, "adapter:shell_command_refused")
        entry = command[1]
        if entry.startswith("-") or Path(entry).is_absolute() or ".." in Path(entry).parts:
            _authorize_issue(issues, "adapter:path_escape")
    digest = merged.get("adapter_sha256", merged.get("source_sha256"))
    if not _authorize_digest(digest):
        _authorize_issue(issues, "adapter:sha256_invalid")
    source_path = merged.get("source_path", merged.get("adapter_path"))
    if source_path is None and command and project_root:
        source_path = str(Path(project_root) / command[1])
    if not _authorize_text(source_path) or not Path(source_path).is_absolute():
        _authorize_issue(issues, "adapter:source_path_invalid")
    elif project_root:
        try:
            Path(source_path).resolve(strict=False).relative_to(Path(project_root).resolve(strict=False))
        except (OSError, ValueError):
            _authorize_issue(issues, "adapter:path_escape")

    snapshot = value.get("snapshot") if isinstance(value.get("snapshot"), Mapping) else {}
    snapshot_root = (
        value.get("snapshot_root")
        or value.get("snapshot_store_root")
        or snapshot.get("root")
        or merged.get("snapshot_root")
    )
    snapshot_locator = value.get("snapshot_locator") or snapshot.get("locator") or merged.get("snapshot_locator")
    snapshot_status = value.get("snapshot_status") or snapshot.get("status") or merged.get("snapshot_status")
    if snapshot_root is not None and (not _authorize_text(snapshot_root) or not Path(snapshot_root).is_absolute()):
        _authorize_issue(issues, "snapshot:root_invalid")
    if snapshot_locator is not None and (not _authorize_text(snapshot_locator) or not Path(snapshot_locator).is_absolute()):
        _authorize_issue(issues, "snapshot:locator_invalid")
    if snapshot_root and project_root:
        try:
            Path(snapshot_root).resolve(strict=False).relative_to(Path(project_root).resolve(strict=False))
        except ValueError:
            pass
        else:
            _authorize_issue(issues, "snapshot:root_inside_project")
    if snapshot_locator and snapshot_root:
        try:
            Path(snapshot_locator).resolve(strict=False).relative_to(Path(snapshot_root).resolve(strict=False))
        except (OSError, ValueError):
            _authorize_issue(issues, "snapshot:locator_escape")
    if snapshot_status is not None and snapshot_status not in {"unbound", "bound", "active", "missing", "rolled_back"}:
        _authorize_issue(issues, "snapshot:status_invalid")

    timeout_ms = value.get("timeout_ms", merged.get("timeout_ms", 30_000))
    if type(timeout_ms) is not int or timeout_ms <= 0 or timeout_ms > MAX_ADAPTER_TIMEOUT_MS:
        _authorize_issue(issues, "adapter:timeout_invalid")
    output_limit = value.get("output_limit_bytes", merged.get("output_limit_bytes", MAX_ADAPTER_OUTPUT_BYTES))
    if type(output_limit) is not int or output_limit <= 0 or output_limit > MAX_ADAPTER_OUTPUT_BYTES:
        _authorize_issue(issues, "adapter:output_limit_invalid")

    cwd = value.get("cwd", merged.get("cwd", project_root))
    if not _authorize_text(cwd) or not Path(cwd).is_absolute():
        _authorize_issue(issues, "adapter:cwd_invalid")
    elif project_root:
        try:
            Path(cwd).resolve(strict=False).relative_to(Path(project_root).resolve(strict=False))
        except (OSError, ValueError):
            _authorize_issue(issues, "adapter:cwd_escape")

    environment = value.get("environment", merged.get("environment", {}))
    if not isinstance(environment, Mapping):
        _authorize_issue(issues, "adapter:environment_invalid")
        environment = {}
    elif "variables" in environment:
        variables = environment.get("variables")
        if not isinstance(variables, Mapping):
            _authorize_issue(issues, "adapter:environment_variables_invalid")
            environment = {}
        else:
            environment = dict(variables)
    for key, item in environment.items():
        if not isinstance(key, str) or not _authorize_text(str(item), max_length=4096):
            _authorize_issue(issues, "adapter:environment_value_invalid")
    environment_identity = value.get("environment_identity", merged.get("environment_identity"))
    if environment_identity is not None and not _authorize_digest(environment_identity):
        _authorize_issue(issues, "adapter:environment_identity_invalid")

    interpreter = value.get("interpreter", merged.get("interpreter"))
    if interpreter is not None and not isinstance(interpreter, Mapping):
        _authorize_issue(issues, "adapter:interpreter_invalid")
    elif isinstance(interpreter, Mapping):
        interpreter_path = interpreter.get("path")
        if interpreter_path is not None and (not _authorize_text(interpreter_path) or not Path(interpreter_path).is_absolute()):
            _authorize_issue(issues, "adapter:interpreter_path_invalid")
        interpreter_digest = interpreter.get("sha256")
        if interpreter_digest is not None and not _authorize_digest(interpreter_digest):
            _authorize_issue(issues, "adapter:interpreter_sha256_invalid")

    lifecycle = value.get("lifecycle") if isinstance(value.get("lifecycle"), Mapping) else {}
    if isinstance(value.get("lifecycle_bindings"), Mapping):
        lifecycle = {**dict(value["lifecycle_bindings"]), **dict(lifecycle)}
    for key in _LIFECYCLE_BINDINGS:
        candidate = lifecycle.get(key)
        if candidate is None:
            candidate = value.get(key)
        if candidate is None:
            # Short aliases are accepted for adapters that use the compact
            # readiness/controller/capsule names.
            candidate = value.get({
                "ticket_admission_sha256": "admission_sha256",
                "acceptance_resource_closure_sha256": "acceptance_closure_sha256",
                "execution_readiness_sha256": "readiness_sha256",
                "active_controller_sha256": "controller_sha256",
                "coordinator_capsule_sha256": "capsule_sha256",
            }.get(key, key))
        if candidate is not None and not _authorize_digest(candidate):
            _authorize_issue(issues, "lifecycle:" + key + "_invalid")

    authority = value.get("authority")
    if authority is not None and not isinstance(authority, Mapping):
        _authorize_issue(issues, "authority:invalid")
    writable_scope = value.get("writable_scope")
    if writable_scope is not None and not isinstance(writable_scope, (Mapping, list, tuple, str)):
        _authorize_issue(issues, "writable_scope:invalid")
    _authorize_sensitive(value, "context", issues)
    value.update({
        "identity": dict(identity) if isinstance(identity, Mapping) else {},
        "binding": {**dict(binding), "adapter_command": command, "adapter_sha256": digest,
                     "source_path": source_path, "snapshot_root": snapshot_root,
                     "snapshot_locator": snapshot_locator, "snapshot_status": snapshot_status},
        "project_root": project_root,
        "snapshot": dict(snapshot),
        "snapshot_root": snapshot_root,
        "snapshot_locator": snapshot_locator,
        "snapshot_status": snapshot_status,
        "timeout_ms": timeout_ms,
        "output_limit_bytes": output_limit,
        "cwd": cwd,
        "environment": dict(environment),
        "environment_identity": environment_identity,
        "interpreter": interpreter,
        "lifecycle": dict(lifecycle),
    })
    return value, issues


def _authorize_snapshot_path(context: Mapping[str, Any], digest: str) -> Path | None:
    root_value = context.get("snapshot_root")
    if not isinstance(root_value, str):
        return None
    root = Path(root_value)
    return root / digest[:2] / digest


def _authorize_read_snapshot(path: Path, digest: str, issues: list[str]) -> bytes | None:
    if path.is_symlink():
        _authorize_issue(issues, "adapter_snapshot_corrupt")
        return None
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        _authorize_issue(issues, "adapter_snapshot_missing")
        return None
    except PermissionError:
        _authorize_issue(issues, "adapter_snapshot_permission_denied")
        return None
    except OSError:
        _authorize_issue(issues, "adapter_snapshot_unreadable")
        return None
    if not stat.S_ISREG(mode):
        _authorize_issue(issues, "adapter_snapshot_corrupt")
        return None
    if not mode & 0o444:
        _authorize_issue(issues, "adapter_snapshot_permission_denied")
        return None
    # A writable active byte set can be replaced between read and exec.  The
    # snapshot must be immutable for the entire admitted attempt.
    if mode & 0o222:
        _authorize_issue(issues, "adapter_snapshot_not_immutable")
        return None
    try:
        data = path.read_bytes()
    except PermissionError:
        _authorize_issue(issues, "adapter_snapshot_permission_denied")
        return None
    except OSError:
        _authorize_issue(issues, "adapter_snapshot_unreadable")
        return None
    if _sha_bytes(data) != digest:
        _authorize_issue(issues, "adapter_snapshot_corrupt")
        return None
    return data


def _authorize_store_snapshot(context: Mapping[str, Any], source: Path, digest: str, issues: list[str]) -> tuple[Path | None, bytes | None, bool]:
    """Read source once and atomically materialize its immutable snapshot."""

    target = _authorize_snapshot_path(context, digest)
    if target is None:
        _authorize_issue(issues, "adapter_snapshot_store_unavailable")
        return None, None, False
    bound = context.get("snapshot_status") in {"bound", "active", "missing", "rolled_back"} or bool(context.get("snapshot_locator"))
    if context.get("snapshot_status") == "rolled_back":
        _authorize_issue(issues, "adapter_snapshot_rolled_back")
        return target, None, False
    if context.get("snapshot_generation") is not None and context.get("minimum_snapshot_generation") is not None:
        if context.get("snapshot_generation") < context.get("minimum_snapshot_generation"):
            _authorize_issue(issues, "adapter_snapshot_rolled_back")
            return target, None, False
    locator = context.get("snapshot_locator")
    if locator:
        target = Path(locator)
    if target.exists() or target.is_symlink():
        return target, _authorize_read_snapshot(target, digest, issues), True
    if bound:
        _authorize_issue(issues, "adapter_snapshot_missing")
        return target, None, True
    try:
        source_mode = source.stat().st_mode
    except FileNotFoundError:
        _authorize_issue(issues, "adapter_source_missing")
        return target, None, False
    except PermissionError:
        _authorize_issue(issues, "adapter_source_permission_denied")
        return target, None, False
    except OSError:
        _authorize_issue(issues, "adapter_source_unreadable")
        return target, None, False
    if not stat.S_ISREG(source_mode):
        _authorize_issue(issues, "adapter_source_unreadable")
        return target, None, False
    if not source_mode & 0o444:
        _authorize_issue(issues, "adapter_source_permission_denied")
        return target, None, False
    try:
        source_bytes = source.read_bytes()
    except PermissionError:
        _authorize_issue(issues, "adapter_source_permission_denied")
        return target, None, False
    except OSError:
        _authorize_issue(issues, "adapter_source_unreadable")
        return target, None, False
    if _sha_bytes(source_bytes) != digest:
        _authorize_issue(issues, "adapter_source_digest_mismatch")
        return target, None, False
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix="adapter-", dir=str(target.parent))
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(source_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o444)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        directory = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError:
        # A concurrent writer may have won the content-addressed slot.  Never
        # overwrite it; validate the winner's bytes below.
        pass
    except PermissionError:
        _authorize_issue(issues, "adapter_snapshot_permission_denied")
        return target, None, False
    except OSError:
        _authorize_issue(issues, "adapter_snapshot_unreadable")
        return target, None, False
    return target, _authorize_read_snapshot(target, digest, issues), False


def _authorize_relation(root: Any, candidate: Any) -> tuple[bool, bool]:
    """Return (preserved, narrowed) for authority/scope envelopes."""

    if candidate is None:
        return True, False
    if not isinstance(root, Mapping):
        return candidate == root, False
    if not isinstance(candidate, Mapping):
        return False, False
    # A missing field means the adapter retained the root value.  An explicit
    # value must remain equal, except that grant/scope collections may shrink.
    for field in ("sandbox_scope_sha256", "sandbox_scope", "approval_policy"):
        if field in candidate and candidate[field] != root.get(field):
            return False, False
    for field in ("external_action_grants", "grants", "paths"):
        if field not in candidate:
            continue
        root_items = root.get(field, [])
        candidate_items = candidate.get(field, [])
        if not isinstance(root_items, (list, tuple)) or not isinstance(candidate_items, (list, tuple)):
            if candidate_items != root_items:
                return False, False
            continue
        def comparable(item: Any) -> Any:
            if isinstance(item, Mapping):
                return {key: value for key, value in item.items() if key != "source_pointer"}
            return item
        root_set = {json.dumps(comparable(item), sort_keys=True, separators=(",", ":")) for item in root_items}
        candidate_set = {json.dumps(comparable(item), sort_keys=True, separators=(",", ":")) for item in candidate_items}
        if not candidate_set.issubset(root_set):
            return False, False
    narrowed = candidate != root
    return True, narrowed


def _authorize_lifecycle(context: Mapping[str, Any]) -> dict[str, Any]:
    lifecycle = dict(context.get("lifecycle") or {})
    aliases = {
        "ticket_admission_sha256": ("admission_sha256",),
        "acceptance_resource_closure_sha256": ("acceptance_closure_sha256",),
        "execution_readiness_sha256": ("readiness_sha256",),
        "active_controller_sha256": ("controller_sha256",),
        "coordinator_capsule_sha256": ("capsule_sha256",),
    }
    for key in _LIFECYCLE_BINDINGS:
        if key in context:
            lifecycle.setdefault(key, context[key])
        for alias in aliases.get(key, ()):
            if alias in context:
                lifecycle.setdefault(key, context[alias])
    return {key: lifecycle[key] for key in _LIFECYCLE_BINDINGS if key in lifecycle}


def _authorize_kill(process: subprocess.Popen[Any]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


def _authorize_execute(
    argv: list[str],
    *,
    cwd: str,
    environment: Mapping[str, Any],
    input_bytes: bytes,
    timeout_ms: int,
    output_limit: int,
) -> dict[str, Any]:
    """Run one shell-free process group with bounded input/output/timeout."""

    env = {str(key): str(value) for key, value in environment.items()}
    if "PATH" not in env:
        env["PATH"] = os.defpath
    started = time.monotonic()
    process: subprocess.Popen[bytes] | None = None
    stdout = b""
    stderr = b""
    timed_out = False
    output_limited = False
    cleanup = "not_started"
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
            close_fds=True,
        )
        try:
            stdout, stderr = process.communicate(input=input_bytes, timeout=timeout_ms / 1000.0)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.output or b""
            stderr = exc.stderr or b""
            _authorize_kill(process)
            try:
                tail_out, tail_err = process.communicate(timeout=1.0)
                stdout += tail_out or b""
                stderr += tail_err or b""
            except subprocess.TimeoutExpired:
                _authorize_kill(process)
                process.wait(timeout=1.0)
        cleanup = "process_group_terminated" if timed_out else "process_group_reaped"
        if len(stdout) + len(stderr) > output_limit:
            output_limited = True
            if process.poll() is None:
                _authorize_kill(process)
                process.wait(timeout=1.0)
            cleanup = "process_group_terminated_output_limit"
    except FileNotFoundError:
        return {
            "status": "DENY", "reason_codes": ["adapter_interpreter_missing"],
            "stdout": b"", "stderr": b"", "exit_code": None,
            "timed_out": False, "output_limited": False, "cleanup": "not_started",
            "elapsed_ms": int((time.monotonic() - started) * 1000), "pid": None,
        }
    except PermissionError:
        return {
            "status": "DENY", "reason_codes": ["adapter_interpreter_permission_denied"],
            "stdout": b"", "stderr": b"", "exit_code": None,
            "timed_out": False, "output_limited": False, "cleanup": "not_started",
            "elapsed_ms": int((time.monotonic() - started) * 1000), "pid": None,
        }
    except OSError:
        return {
            "status": "DENY", "reason_codes": ["adapter_process_unreadable"],
            "stdout": b"", "stderr": b"", "exit_code": None,
            "timed_out": False, "output_limited": False, "cleanup": "not_started",
            "elapsed_ms": int((time.monotonic() - started) * 1000), "pid": None,
        }
    reasons: list[str] = []
    if timed_out:
        reasons.append("adapter_timeout")
    if output_limited:
        reasons.append("adapter_output_limit_exceeded")
    if process is not None and process.returncode not in (0, None) and not reasons:
        reasons.append("adapter_process_failed")
    return {
        "status": "DENY" if reasons else "ALLOW",
        "reason_codes": reasons,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": process.returncode if process is not None else None,
        "timed_out": timed_out,
        "output_limited": output_limited,
        "cleanup": cleanup,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "pid": process.pid if process is not None else None,
    }


def _authorize_report(core: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(core)
    value["report_sha256"] = _sha(value)
    return value


def authorize(operation: Any, live_context: Any) -> dict[str, Any]:
    """Authorize one exact adapter operation through an immutable snapshot.

    This is the only external execution seam.  It never contacts a provider,
    reserves authority, creates a task, or mutates the enrolled repository.
    Adapter bytes are read once into plugin-owned content-addressed storage;
    subsequent calls execute only the verified immutable byte set.
    """

    op, operation_issues = _authorize_operation(operation)
    context, context_issues = _authorize_context(live_context)
    issues = list(operation_issues) + [item for item in context_issues if item not in operation_issues]
    base: dict[str, Any] = {
        "schema": AUTHORIZE_REPORT_SCHEMA,
        "policy_version": AUTHORIZE_POLICY_VERSION,
        "status": "DENY",
        "decision": "DENY",
        "operation_kind": op.get("kind"),
        "project_identity": deepcopy(context.get("identity", {})),
        "binding_generation": context.get("binding_generation", (context.get("binding") or {}).get("generation")),
        "adapter_sha256": (context.get("binding") or {}).get("adapter_sha256"),
        "snapshot": None,
        "authority_preserved": False,
        "authority_narrowed": False,
        "authority_broadened": False,
        "writable_scope_preserved": False,
        "reason_codes": sorted(set(issues)),
        "evidence": {
            "source_pointer": op.get("source_pointer"),
            "context_source_pointer": context.get("source_pointer"),
            "lifecycle": _authorize_lifecycle(context),
            "adapter_execution": None,
        },
        "provider_free": True,
        "credential_reads": 0,
        "authority_reservations": 0,
        "grant_reservations": 0,
        "hosted_calls": 0,
        "model_calls": 0,
        "task_creations": 0,
        "worker_creations": 0,
        "adapter_executions": 0,
        "mutation_performed": False,
    }
    root_authority = context.get("authority")
    if isinstance(root_authority, Mapping) and "root" in root_authority:
        root_authority = root_authority.get("root")
    if isinstance(root_authority, Mapping):
        base["authority_preserved"] = True
    if context.get("writable_scope") is not None:
        base["writable_scope_preserved"] = True
    if issues:
        return _authorize_report(base)

    binding = context["binding"]
    digest = binding["adapter_sha256"]
    source = Path(binding["source_path"])
    snapshot_path, snapshot_bytes, already_bound = _authorize_store_snapshot(context, source, digest, issues)
    base["snapshot"] = {
        "schema": ADAPTER_SNAPSHOT_SCHEMA,
        "sha256": digest,
        "locator": str(snapshot_path) if snapshot_path is not None else None,
        "content_addressed": True,
        "immutable": snapshot_bytes is not None,
        "bound_before_call": already_bound,
        "source_digest": digest,
        "generation": context.get("snapshot_generation"),
    }
    if snapshot_bytes is None or snapshot_path is None:
        base["reason_codes"] = sorted(set(issues))
        return _authorize_report(base)

    command = list(binding["adapter_command"])
    # The manifest command is still the identity input; only its repository
    # entry-point argument is replaced by the immutable snapshot locator.
    command[1] = str(snapshot_path)
    interpreter = context.get("interpreter")
    if isinstance(interpreter, Mapping) and interpreter.get("path"):
        command[0] = str(interpreter["path"])
        expected_interpreter_sha = interpreter.get("sha256")
        if expected_interpreter_sha:
            try:
                actual_interpreter_sha = _sha_bytes(Path(command[0]).read_bytes())
            except (OSError, ValueError):
                _authorize_issue(issues, "adapter_interpreter_unreadable")
            else:
                if actual_interpreter_sha != expected_interpreter_sha:
                    _authorize_issue(issues, "adapter_interpreter_digest_mismatch")
    input_value = op.get("input", {})
    input_bytes = _authorize_json_bytes(input_value)
    if input_bytes is None:
        _authorize_issue(issues, "adapter_input_not_json")
        input_bytes = b""
    output_schema = op.get("output_schema", context.get("output_schema"))
    environment = context.get("environment", {})
    environment_identity = context.get("environment_identity")
    if environment_identity and _sha(environment) != environment_identity:
        _authorize_issue(issues, "adapter_environment_identity_mismatch")
    if issues:
        base["reason_codes"] = sorted(set(issues))
        return _authorize_report(base)
    execution = _authorize_execute(
        command,
        cwd=context["cwd"],
        environment=environment,
        input_bytes=input_bytes,
        timeout_ms=context["timeout_ms"],
        output_limit=context["output_limit_bytes"],
    )
    execution_evidence = {
        "schema": ADAPTER_EXECUTION_SCHEMA,
        "argv": command,
        "cwd": context["cwd"],
        "environment_identity": environment_identity or _sha(environment),
        "timeout_ms": context["timeout_ms"],
        "output_limit_bytes": context["output_limit_bytes"],
        "process_group": {"pid": execution.get("pid"), "start_new_session": True},
        "input_sha256": _sha_bytes(input_bytes),
        "stdout_sha256": _sha_bytes(execution.get("stdout", b"")),
        "stderr_sha256": _sha_bytes(execution.get("stderr", b"")),
        "exit_code": execution.get("exit_code"),
        "elapsed_ms": execution.get("elapsed_ms"),
        "cleanup": execution.get("cleanup"),
        "source_digest": digest,
        "snapshot_digest": _sha_bytes(snapshot_bytes),
    }
    base["evidence"]["adapter_execution"] = execution_evidence
    base["adapter_executions"] = 1
    issues.extend(execution.get("reason_codes", []))
    output_value: Any = None
    stdout = execution.get("stdout", b"")
    if not stdout:
        if not execution.get("reason_codes"):
            _authorize_issue(issues, "adapter_output_missing")
    elif len(stdout) > context["output_limit_bytes"]:
        _authorize_issue(issues, "adapter_output_limit_exceeded")
    else:
        try:
            output_value = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
            _authorize_issue(issues, "adapter_output_invalid")
        else:
            if not isinstance(output_value, Mapping):
                _authorize_issue(issues, "adapter_output_schema_invalid")
            if isinstance(output_value, Mapping):
                _authorize_sensitive(output_value, "adapter_output", issues)
                if isinstance(output_schema, str) and output_value.get("schema") != output_schema:
                    _authorize_issue(issues, "adapter_output_schema_mismatch")
                elif isinstance(output_schema, Mapping):
                    expected_schema = output_schema.get("schema")
                    if expected_schema is not None and output_value.get("schema") != expected_schema:
                        _authorize_issue(issues, "adapter_output_schema_mismatch")
    base["evidence"]["output_sha256"] = _sha(output_value) if output_value is not None else None
    if isinstance(output_value, Mapping):
        # A project-native adapter may return its own provider-free decision
        # envelope (for example Model Coordinate's PASS/REFUSED preflight
        # report).  A successful process and valid JSON are not themselves an
        # authorization grant: propagate an explicit adapter denial and its
        # sanitized reason list through the generic closed result.
        adapter_status = output_value.get("status")
        adapter_decision = output_value.get("decision")
        if adapter_status in {"REFUSED", "DENY", "FAIL", "BLOCK"} or adapter_decision in {"DENY", "REFUSED", "BLOCK"}:
            output_issues = output_value.get("issues", output_value.get("reason_codes", []))
            if isinstance(output_issues, (list, tuple)):
                for reason in output_issues:
                    if isinstance(reason, str):
                        _authorize_issue(issues, reason)
            if not output_issues:
                _authorize_issue(issues, "adapter_output_denied")
        candidate_authority = output_value.get("authority", output_value.get("delegated_authority"))
        preserved, narrowed = _authorize_relation(root_authority, candidate_authority)
        base["authority_preserved"] = preserved
        base["authority_narrowed"] = narrowed
        base["authority_broadened"] = not preserved
        if not preserved:
            _authorize_issue(issues, "authority_broadened")
        candidate_scope = output_value.get("writable_scope")
        root_scope = context.get("writable_scope")
        scope_preserved, _ = _authorize_relation(root_scope, candidate_scope)
        base["writable_scope_preserved"] = scope_preserved
        if not scope_preserved:
            _authorize_issue(issues, "writable_scope_broadened")
        candidate_lifecycle = output_value.get("lifecycle", output_value.get("bindings", {}))
        if candidate_lifecycle is not None and not isinstance(candidate_lifecycle, Mapping):
            _authorize_issue(issues, "lifecycle_binding_invalid")
        elif isinstance(candidate_lifecycle, Mapping):
            for key, expected in _authorize_lifecycle(context).items():
                if key in candidate_lifecycle and candidate_lifecycle.get(key) != expected:
                    _authorize_issue(issues, "lifecycle_binding_mismatch:" + key)
    base["output"] = deepcopy(dict(output_value)) if isinstance(output_value, Mapping) else None
    base["reason_codes"] = sorted(set(issues))
    if not issues:
        base["status"] = "ALLOW"
        base["decision"] = "ALLOW"
    return _authorize_report(base)


def _load_program(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provider-free Orch Dork project enrollment")
    parser.add_argument("operation", choices=("evaluate", "apply"))
    parser.add_argument("program")
    args = parser.parse_args(argv)
    program = _load_program(args.program)
    result = evaluate_project_enrollment(program) if args.operation == "evaluate" else apply_project_enrollment(program)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "PROGRAM_SCHEMA",
    "MANIFEST_SCHEMA",
    "RECORD_SCHEMA",
    "EVENT_SCHEMA",
    "REPORT_SCHEMA",
    "PROTOCOL",
    "POLICY_VERSION",
    "AUTHORIZE_OPERATION_SCHEMA",
    "AUTHORIZE_CONTEXT_SCHEMA",
    "AUTHORIZE_REPORT_SCHEMA",
    "ADAPTER_SNAPSHOT_SCHEMA",
    "ADAPTER_EXECUTION_SCHEMA",
    "AUTHORIZE_POLICY_VERSION",
    "ProjectEnrollmentInspectionError",
    "build_active_inspection_program",
    "evaluate_project_enrollment",
    "apply_project_enrollment",
    "authorize",
]
