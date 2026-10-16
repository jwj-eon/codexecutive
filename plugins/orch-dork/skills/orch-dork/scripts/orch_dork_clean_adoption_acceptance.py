#!/usr/bin/env python3
"""Provider-free clean-machine adoption acceptance.

This module is the small, disposable acceptance seam for Issue 45.  It models
the boundary between a repository checkout (which may carry a binding) and the
machine-local enrollment registry (which is the trust anchor).  Merely finding
the binding never grants write authority: an explicit adoption must reconcile
all identity, generation, adapter, authority, and scope facts before the
registry is activated.

The evaluator is read-only.  ``apply_clean_adoption`` is the only mutating
entry point and writes a project binding plus a registry record through a
compare-and-swap style snapshot.  ``simulate_fresh_task_boundary`` evaluates a
fresh v2 ticket admission after adoption; it never creates a task, worker, or
provider call and deliberately does not inspect ``AGENTS.md``.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping, Sequence


PROGRAM_SCHEMA = "orch-dork/clean-adoption-program/v1"
ADOPTION_SCHEMA = "orch-dork/clean-adoption-binding/v1"
RECORD_SCHEMA = "orch-dork/clean-adoption-record/v1"
REPORT_SCHEMA = "orch-dork/clean-adoption-report/v1"
FRESH_BOUNDARY_SCHEMA = "orch-dork/fresh-task-boundary/v1"
PROTOCOL = "project-ground/v1"
POLICY_VERSION = "clean-adoption-policy/v1"
TICKET_ADMISSION_SCHEMA = "orch-dork/ticket-admission/v2"
TICKET_ADMISSION_POLICY_VERSION = "classification-policy/v2"

READ_ONLY = "READ_ONLY"
REFUSED = "REFUSED"
READY_TO_ADOPT = "READY_TO_ADOPT"
ADOPTED = "ADOPTED"
ALREADY_ADOPTED = "ALREADY_ADOPTED"
RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
PRESERVED_PRIOR_GENERATION = "PRESERVED_PRIOR_GENERATION"
FRESH_BOUNDARY_PASS = "FRESH_BOUNDARY_PASS"
FRESH_BOUNDARY_BLOCKED = "FRESH_BOUNDARY_BLOCKED"

ATOMIC_ADMITTED = "ATOMIC_ADMITTED"
ORCHESTRATION_PLAN_REQUIRED = "ORCHESTRATION_PLAN_REQUIRED"

_DIGEST_LENGTH = 64
_IDENTITY_FIELDS = (
    "project_id",
    "host_id",
    "environment_id",
    "saved_project_id",
    "workspace_id",
    "repository_kind",
    "clone_id",
    "worktree_id",
    "canonical_initial_root",
)
_RECONCILIATION_FIELDS = (
    "project_id",
    "host_id",
    "environment_id",
    "saved_project_id",
    "workspace_id",
    "repository_kind",
    "clone_id",
    "worktree_id",
    "canonical_initial_root",
    "protocol",
    "generation",
    "adapter_sha256",
    "authority_sha256",
    "writable_scope_sha256",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


sha256 = json_sha256


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == _DIGEST_LENGTH and all(c in "0123456789abcdef" for c in value)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and "\x00" not in value


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _first(value: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in value and value[name] is not None:
            return value[name]
    return default


def _issue(issues: list[str], issue: str) -> None:
    if issue not in issues:
        issues.append(issue)


def _load_ticket_admission():
    path = Path(__file__).with_name("orch_dork_ticket_admission.py")
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("orch_dork_ticket_admission_clean_adoption", path)
    if spec is None or spec.loader is None:
        return None
    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except (ImportError, OSError, RuntimeError, ValueError):
        return None


ticket_admission = _load_ticket_admission()


def _project_root(program: Mapping[str, Any]) -> Path:
    raw = _first(program, "project_root", "canonical_root", default="/")
    return Path(raw) if _text(raw) and Path(raw).is_absolute() else Path("/")


def _registry_root(program: Mapping[str, Any]) -> Path:
    raw = _first(program, "registry_root", "enrollment_root", default="/")
    return Path(raw) if _text(raw) and Path(raw).is_absolute() else Path("/")


def binding_path(program: Mapping[str, Any]) -> Path:
    root = _project_root(program)
    raw = _first(program, "binding_path")
    if _text(raw) and Path(raw).is_absolute():
        return Path(raw)
    return root / ".orch-dork" / "binding.json"


def state_path(program: Mapping[str, Any]) -> Path:
    root = _registry_root(program)
    raw = _first(program, "record_path", "state_path")
    if _text(raw) and Path(raw).is_absolute():
        return Path(raw)
    identity = _normalise_identity(_mapping(program.get("identity")))
    return root / "records" / (json_sha256(identity) + ".json")


def _normalise_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    result["project_id"] = _first(value, "project_id", "id")
    result["host_id"] = _first(value, "host_id", "host")
    result["environment_id"] = _first(value, "environment_id", "environment")
    result["saved_project_id"] = _first(value, "saved_project_id", "saved_id")
    result["workspace_id"] = _first(value, "workspace_id", "workspace")
    result["repository_kind"] = _first(value, "repository_kind", "repo_kind", default="git")
    result["clone_id"] = _first(value, "clone_id", "clone_identity", "clone_worktree_id")
    result["worktree_id"] = _first(value, "worktree_id", "worktree")
    result["canonical_initial_root"] = _first(value, "canonical_initial_root", "canonical_root", "root")
    return result


def _adapter_relpath(binding: Mapping[str, Any]) -> str | None:
    path = _first(binding, "adapter_path", "adapter_locator")
    if _text(path):
        return str(path)
    command = _first(binding, "adapter_command", "command")
    if isinstance(command, list) and len(command) >= 2 and _text(command[1]):
        return str(command[1])
    return None


def _normalise_binding(value: Mapping[str, Any], root: Path, issues: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "protocol": _first(value, "protocol", default=PROTOCOL),
        "generation": _first(value, "generation", "binding_generation"),
        "adapter_sha256": _first(value, "adapter_sha256", "adapter_digest"),
        "adapter_path": _adapter_relpath(value),
        "required": _first(value, "required", default=True),
        "adoption_state": _first(value, "adoption_state", default="unadopted"),
    }
    if result["protocol"] != PROTOCOL:
        _issue(issues, "binding:protocol_mismatch")
    if type(result["generation"]) is not int or result["generation"] <= 0:
        _issue(issues, "binding:generation_invalid")
    if not _digest(result["adapter_sha256"]):
        _issue(issues, "binding:adapter_digest_invalid")
    if not _text(result["adapter_path"]):
        _issue(issues, "binding:adapter_path_invalid")
    elif Path(result["adapter_path"]).is_absolute() or ".." in Path(result["adapter_path"]).parts:
        _issue(issues, "binding:adapter_path_escape")
    if result["required"] is not True:
        _issue(issues, "binding:required_invalid")
    if result["adoption_state"] not in {"unadopted", "adopted"}:
        _issue(issues, "binding:adoption_state_invalid")
    if _text(result["adapter_path"]):
        candidate = root / str(result["adapter_path"])
        try:
            resolved_root = root.resolve(strict=True)
            resolved_candidate = candidate.resolve(strict=False)
            resolved_candidate.relative_to(resolved_root)
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
                    if _digest(result["adapter_sha256"]) and actual != result["adapter_sha256"]:
                        _issue(issues, "binding:adapter_digest_mismatch")
    return result


def _normalise_authority(value: Any) -> tuple[dict[str, Any], str]:
    authority = deepcopy(dict(value)) if isinstance(value, Mapping) else {"scope": value}
    # Credential-like keys are never read or persisted by this acceptance.
    for key in list(authority):
        if any(token in str(key).lower() for token in ("credential", "secret", "token", "password", "api_key", "private_key")):
            authority.pop(key, None)
    return authority, json_sha256(authority)


def _normalise_scope(value: Any) -> tuple[Any, str]:
    scope = deepcopy(value)
    return scope, json_sha256(scope)


def _live_environment(program: Mapping[str, Any], identity: Mapping[str, Any], issues: list[str]) -> dict[str, Any]:
    root = _project_root(program)
    result: dict[str, Any] = {
        "host_id": identity.get("host_id"),
        "environment_id": identity.get("environment_id"),
        "canonical_root": str(root),
        "device": None,
        "inode": None,
    }
    if not root.exists():
        _issue(issues, "project:root_missing")
        return result
    if root.is_symlink():
        _issue(issues, "project:root_symlink")
        return result
    if not root.is_dir():
        _issue(issues, "project:root_not_directory")
        return result
    try:
        resolved = root.resolve(strict=True)
        stat = root.stat()
    except OSError as exc:
        _issue(issues, "project:root_unreadable:" + type(exc).__name__)
        return result
    result.update({"canonical_root": str(resolved), "device": stat.st_dev, "inode": stat.st_ino})
    initial = identity.get("canonical_initial_root")
    if initial != str(resolved):
        _issue(issues, "identity:canonical_root_mismatch")
    marker = root / ".git"
    kind = identity.get("repository_kind")
    if kind == "git" and not marker.exists():
        _issue(issues, "project:git_marker_missing")
    if marker.is_symlink():
        _issue(issues, "project:git_marker_symlink")
    if kind == "directory" and marker.exists():
        _issue(issues, "identity:repository_kind_mismatch")
    return result


def _hook_issues(program: Mapping[str, Any], issues: list[str]) -> dict[str, Any]:
    value = _mapping(_first(program, "hook", "hook_state", default={}))
    result = {
        "enabled": value.get("enabled", True),
        "trusted": value.get("trusted", True),
        "status": value.get("status", "ready"),
        "expected_sha256": value.get("expected_sha256"),
        "observed_sha256": value.get("observed_sha256"),
    }
    if result["enabled"] is not True:
        _issue(issues, "hook:disabled")
    if result["trusted"] is not True:
        _issue(issues, "hook:untrusted")
    if result["status"] not in {"ready", "PASS", "pass"}:
        _issue(issues, "hook:not_ready")
    expected = result.get("expected_sha256")
    observed = result.get("observed_sha256")
    if expected is not None and observed != expected:
        _issue(issues, "hook:digest_mismatch")
    return result


def _read_json(path: Path, label: str, issues: list[str]) -> dict[str, Any] | None:
    if path.is_symlink():
        _issue(issues, label + ":symlink")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _issue(issues, label + ":missing")
        return None
    except PermissionError:
        _issue(issues, label + ":permission_denied")
        return None
    except (OSError, UnicodeError, json.JSONDecodeError):
        _issue(issues, label + ":corrupt")
        return None
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return None
    return dict(value)


def _binding_core(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value.get(key))
        for key in ("protocol", "generation", "adapter_sha256", "adapter_path", "required")
    }


def _identity_core(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: deepcopy(value.get(key)) for key in _IDENTITY_FIELDS}


def _record_core(value: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(value))
    result.pop("record_sha256", None)
    return result


def _validate_record(record: Mapping[str, Any], issues: list[str]) -> dict[str, Any] | None:
    value = dict(record)
    if value.get("schema") != RECORD_SCHEMA:
        _issue(issues, "registry:record_schema_invalid")
    if value.get("status") != "active":
        _issue(issues, "registry:record_not_active")
    if type(value.get("version")) is not int or value.get("version", 0) <= 0:
        _issue(issues, "registry:record_version_invalid")
    digest = value.get("record_sha256")
    if not _digest(digest) or digest != json_sha256(_record_core(value)):
        _issue(issues, "registry:record_seal_mismatch")
    for key in ("identity", "binding", "environment"):
        if not isinstance(value.get(key), Mapping):
            _issue(issues, "registry:record_" + key + "_invalid")
    for key in ("authority_sha256", "writable_scope_sha256"):
        if not _digest(value.get(key)):
            _issue(issues, "registry:record_" + key + "_invalid")
    return value


def _reconciliation(program: Mapping[str, Any], record: Mapping[str, Any] | None, identity: Mapping[str, Any], binding: Mapping[str, Any], authority_sha: str, scope_sha: str, environment: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "project_id": identity.get("project_id"),
        "host_id": identity.get("host_id"),
        "environment_id": identity.get("environment_id"),
        "saved_project_id": identity.get("saved_project_id"),
        "workspace_id": identity.get("workspace_id"),
        "repository_kind": identity.get("repository_kind"),
        "clone_id": identity.get("clone_id"),
        "worktree_id": identity.get("worktree_id"),
        "canonical_initial_root": identity.get("canonical_initial_root"),
        "protocol": binding.get("protocol"),
        "generation": binding.get("generation"),
        "adapter_sha256": binding.get("adapter_sha256"),
        "authority_sha256": authority_sha,
        "writable_scope_sha256": scope_sha,
    }
    actual: dict[str, Any] = {}
    if isinstance(record, Mapping):
        old_identity = _mapping(record.get("identity"))
        old_binding = _mapping(record.get("binding"))
        actual.update({key: old_identity.get(key) for key in _IDENTITY_FIELDS})
        actual.update({"protocol": old_binding.get("protocol"), "generation": old_binding.get("generation"), "adapter_sha256": old_binding.get("adapter_sha256")})
        actual["authority_sha256"] = record.get("authority_sha256")
        actual["writable_scope_sha256"] = record.get("writable_scope_sha256")
        old_environment = _mapping(record.get("environment"))
        if old_environment.get("canonical_root") != environment.get("canonical_root"):
            actual["canonical_initial_root"] = old_environment.get("canonical_root")
    mismatches = [field for field in _RECONCILIATION_FIELDS if field in actual and actual.get(field) != expected.get(field)]
    return {"expected": expected, "actual": actual, "mismatches": mismatches, "reconciled": not mismatches}


def _report(*, decision: str, operation: str | None, issues: Sequence[str], program: Mapping[str, Any], identity: Mapping[str, Any], binding: Mapping[str, Any] | None, environment: Mapping[str, Any], record: Mapping[str, Any] | None, reconciliation: Mapping[str, Any], mutation_performed: bool = False, fresh_boundary: Mapping[str, Any] | None = None) -> dict[str, Any]:
    read_only = decision in {READ_ONLY, REFUSED, RECONCILIATION_REQUIRED, PRESERVED_PRIOR_GENERATION, FRESH_BOUNDARY_BLOCKED}
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "policy_version": POLICY_VERSION,
        "status": "PASS" if decision in {READY_TO_ADOPT, ADOPTED, ALREADY_ADOPTED, FRESH_BOUNDARY_PASS} and not issues else "BLOCKED" if read_only else "FAIL",
        "decision": decision,
        "operation": operation,
        "read_only": read_only,
        "mutation_performed": mutation_performed,
        "identity": deepcopy(dict(identity)),
        "binding": deepcopy(dict(binding)) if isinstance(binding, Mapping) else None,
        "binding_generation": binding.get("generation") if isinstance(binding, Mapping) else None,
        "environment": deepcopy(dict(environment)),
        "reconciliation": deepcopy(dict(reconciliation)),
        "record": deepcopy(dict(record)) if isinstance(record, Mapping) else None,
        "binding_path": str(binding_path(program)),
        "record_path": str(state_path(program)),
        "fresh_boundary": deepcopy(dict(fresh_boundary)) if isinstance(fresh_boundary, Mapping) else None,
        "issues": sorted(set(str(item) for item in issues)),
        "provider_free": True,
        "credential_reads": 0,
        "authority_reservations": 0,
        "hosted_calls": 0,
        "model_calls": 0,
        "task_creations": 0,
        "worker_creations": 0,
        "adapter_executions": 0,
        "hook_changes": 0,
    }
    report["report_sha256"] = json_sha256(report)
    return report


def _prepare(program: Any) -> tuple[dict[str, Any], list[str], dict[str, Any], dict[str, Any], dict[str, Any], str, str, dict[str, Any], dict[str, Any] | None]:
    value = dict(program) if isinstance(program, Mapping) else {}
    issues: list[str] = []
    if value.get("schema") not in {None, PROGRAM_SCHEMA}:
        _issue(issues, "program:schema_invalid")
    project = _project_root(value)
    registry = _registry_root(value)
    if not project.is_absolute():
        _issue(issues, "program:project_root_invalid")
    if not registry.is_absolute():
        _issue(issues, "program:registry_root_invalid")
    identity = _normalise_identity(_mapping(value.get("identity")))
    if not _text(identity.get("project_id")):
        _issue(issues, "identity:project_id_required")
    if not _text(identity.get("host_id")):
        _issue(issues, "identity:host_id_required")
    if not _text(identity.get("environment_id")):
        _issue(issues, "identity:environment_id_required")
    if not _text(identity.get("canonical_initial_root")) or not Path(str(identity.get("canonical_initial_root"))).is_absolute():
        _issue(issues, "identity:canonical_initial_root_invalid")
    if identity.get("repository_kind") not in {"git", "directory"}:
        _issue(issues, "identity:repository_kind_invalid")
    binding = _normalise_binding(_mapping(value.get("binding")), project, issues)
    authority, authority_sha = _normalise_authority(_first(value, "authority", "authority_scope", default={}))
    scope, scope_sha = _normalise_scope(_first(value, "writable_scope", "writable", default=[]))
    # Keep normalized forms in a copy for callers and reports.
    value["identity"] = identity
    value["binding"] = binding
    value["authority"] = authority
    value["writable_scope"] = scope
    environment = _live_environment(value, identity, issues)
    hook = _hook_issues(value, issues)
    value["hook"] = hook
    record: dict[str, Any] | None = None
    record_issues: list[str] = []
    path = state_path(value)
    if path.exists() or path.is_symlink():
        record = _read_json(path, "registry:record", record_issues)
        if record is not None:
            before = len(record_issues)
            record = _validate_record(record, record_issues)
            if len(record_issues) != before:
                record = None
    else:
        # A changed host/root/clone identity must not hide a prior record just
        # because the identity-keyed filename changed.  In a disposable
        # registry, inspect the small records directory as a read-only
        # fallback; reconciliation below decides whether the candidate may
        # ever be adopted.
        records_dir = _registry_root(value) / "records"
        try:
            candidates = sorted(item for item in records_dir.glob("*.json") if item != path and not item.is_symlink())
        except OSError:
            candidates = []
        for candidate in candidates[:16]:
            candidate_issues: list[str] = []
            candidate_value = _read_json(candidate, "registry:record", candidate_issues)
            if candidate_value is None:
                continue
            validated = _validate_record(candidate_value, candidate_issues)
            if validated is not None and not candidate_issues:
                record = validated
                break
        # Absence is a normal blank-machine condition until an adopted marker
        # is observed in the repository binding.
        if record is None and binding.get("adoption_state") == "adopted":
            _issue(record_issues, "registry:lost")
    issues.extend(record_issues)
    return value, issues, identity, binding, environment, authority_sha, scope_sha, hook, record


def evaluate_clean_adoption(program: Any) -> dict[str, Any]:
    """Evaluate an adoption/inspection program without changing disk state."""

    value, issues, identity, binding, environment, authority_sha, scope_sha, _hook, record = _prepare(program)
    operation = value.get("operation")
    if operation not in {None, "inspect", "adopt", "fresh-boundary", "fresh_task", "migrate"}:
        _issue(issues, "program:operation_invalid")
        operation = str(operation)
    reconciliation = _reconciliation(value, record, identity, binding, authority_sha, scope_sha, environment)
    if reconciliation["mismatches"]:
        for field in reconciliation["mismatches"]:
            _issue(issues, "reconciliation:" + field + "_mismatch")

    binding_file = binding_path(value)
    on_disk_binding: dict[str, Any] | None = None
    if binding_file.exists() or binding_file.is_symlink():
        on_disk_binding = _read_json(binding_file, "binding", issues)
    else:
        _issue(issues, "binding:repository_binding_missing")
    if on_disk_binding is not None:
        disk_issues: list[str] = []
        normalized_disk = _normalise_binding(on_disk_binding, _project_root(value), disk_issues)
        if disk_issues:
            issues.extend(disk_issues)
        if _binding_core(normalized_disk) != _binding_core(binding):
            _issue(issues, "binding:repository_binding_mismatch")
        if binding.get("adoption_state") == "adopted" and normalized_disk.get("adoption_state") != "adopted":
            _issue(issues, "binding:adoption_marker_mismatch")
        if record is None and normalized_disk.get("adoption_state") == "adopted":
            _issue(issues, "registry:lost")

    if operation in {None, "inspect"}:
        if record is None:
            return _report(decision=READ_ONLY, operation="inspect", issues=issues + ["enrollment:external_not_enrolled", "registry:external_not_enrolled"], program=value, identity=identity, binding=binding, environment=environment, record=None, reconciliation=reconciliation)
        if issues:
            return _report(decision=READ_ONLY, operation="inspect", issues=issues, program=value, identity=identity, binding=binding, environment=environment, record=record, reconciliation=reconciliation)
        return _report(decision=ALREADY_ADOPTED, operation="inspect", issues=[], program=value, identity=identity, binding=binding, environment=environment, record=record, reconciliation=reconciliation)

    if operation == "adopt":
        if record is not None and record.get("status") == "active":
            if not reconciliation["reconciled"] or issues:
                return _report(decision=RECONCILIATION_REQUIRED, operation=operation, issues=issues or ["adoption:reconciliation_required"], program=value, identity=identity, binding=binding, environment=environment, record=record, reconciliation=reconciliation)
            return _report(decision=ALREADY_ADOPTED, operation=operation, issues=[], program=value, identity=identity, binding=binding, environment=environment, record=record, reconciliation=reconciliation)
        if binding.get("adoption_state") == "adopted":
            _issue(issues, "registry:lost")
        if issues:
            return _report(decision=READ_ONLY if any(item.startswith(("registry:", "binding:", "hook:", "project:", "identity:", "reconciliation:")) for item in issues) else REFUSED, operation=operation, issues=issues, program=value, identity=identity, binding=binding, environment=environment, record=record, reconciliation=reconciliation)
        return _report(decision=READY_TO_ADOPT, operation=operation, issues=[], program=value, identity=identity, binding=binding, environment=environment, record=None, reconciliation=reconciliation)

    if operation == "migrate":
        migration = _mapping(value.get("migration"))
        if migration.get("status") in {"failed", "FAIL", "interrupted", "unknown"}:
            _issue(issues, "migration:failed")
            return _report(decision=PRESERVED_PRIOR_GENERATION, operation=operation, issues=issues, program=value, identity=identity, binding=binding, environment=environment, record=record, reconciliation=reconciliation)
        if record is None:
            _issue(issues, "migration:prior_generation_missing")
        return _report(decision=READ_ONLY, operation=operation, issues=issues + (["migration:not_qualified"] if not issues else []), program=value, identity=identity, binding=binding, environment=environment, record=record, reconciliation=reconciliation)

    return simulate_fresh_task_boundary(value)


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    encoded = (canonical_json(value) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _record_for(value: Mapping[str, Any], identity: Mapping[str, Any], binding: Mapping[str, Any], environment: Mapping[str, Any], authority_sha: str, scope_sha: str) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema": RECORD_SCHEMA,
        "version": 1,
        "status": "active",
        "identity": _identity_core(identity),
        "binding": _binding_core(binding),
        "environment": deepcopy(dict(environment)),
        "authority_sha256": authority_sha,
        "writable_scope_sha256": scope_sha,
        "events": [{"type": "project.adopted", "generation": binding.get("generation"), "source_pointer": value.get("source_pointer", "fixture#program")}],
    }
    record["record_sha256"] = json_sha256(record)
    return record


def apply_clean_adoption(program: Any) -> dict[str, Any]:
    """Apply one explicit adoption, preserving prior bytes on any failure."""

    initial = evaluate_clean_adoption(program)
    if initial["decision"] in {ALREADY_ADOPTED, ADOPTED}:
        return initial
    if initial["decision"] != READY_TO_ADOPT:
        return initial
    value, issues, identity, binding, environment, authority_sha, scope_sha, _hook, current = _prepare(program)
    if issues or current is not None:
        return evaluate_clean_adoption(value)
    bpath = binding_path(value)
    rpath = state_path(value)
    old_binding = bpath.read_bytes() if bpath.exists() and not bpath.is_symlink() else None
    record = _record_for(value, identity, binding, environment, authority_sha, scope_sha)
    disk_binding = dict(_binding_core(binding))
    disk_binding.update({"schema": ADOPTION_SCHEMA, "adoption_state": "adopted", "project_id": identity.get("project_id")})
    try:
        _atomic_write_json(bpath, disk_binding)
        _atomic_write_json(rpath, record)
    except OSError as exc:
        # Restore the exact pre-adoption repository bytes.  A newly staged
        # binding is removed when no previous generation existed.
        try:
            if old_binding is None:
                if bpath.exists():
                    bpath.unlink()
            else:
                bpath.write_bytes(old_binding)
            if rpath.exists() and current is None:
                rpath.unlink()
        except OSError:
            pass
        return _report(decision=READ_ONLY, operation="adopt", issues=["activation:write_failed:" + type(exc).__name__], program=value, identity=identity, binding=binding, environment=environment, record=None, reconciliation=_reconciliation(value, None, identity, binding, authority_sha, scope_sha, environment))
    completed_program = deepcopy(value)
    completed_program["binding"]["adoption_state"] = "adopted"
    completed = evaluate_clean_adoption({**completed_program, "operation": "inspect"})
    if completed.get("decision") not in {ALREADY_ADOPTED}:
        return completed
    completed["decision"] = ADOPTED
    completed["mutation_performed"] = True
    completed["report_sha256"] = json_sha256({key: item for key, item in completed.items() if key != "report_sha256"})
    return completed


def _default_fresh_ticket(value: Mapping[str, Any]) -> dict[str, Any]:
    fresh = _mapping(_first(value, "fresh_task", "fresh_boundary", "ticket", default={}))
    mode = _first(fresh, "mode", "classification_mode", default="atomic")
    lanes = fresh.get("candidate_lanes")
    if not isinstance(lanes, list):
        lanes = []
    if mode == "orchestrated" and not lanes:
        lanes = [
            {"lane_id": "adoption-lane-a", "objective": "reconcile identity", "owned_resources": ["adoption/identity.py"]},
            {"lane_id": "adoption-lane-b", "objective": "validate fresh boundary", "owned_resources": ["adoption/fresh.py"]},
        ]
    return {
        "schema": "orch-dork/ticket-admission-program/v2",
        "ticket_id": _first(fresh, "ticket_id", default="issue45-clean-adoption-fresh"),
        "root_task_id": _first(fresh, "root_task_id", "task_id", default="disposable-fresh-task"),
        "ticket_spec": _first(fresh, "ticket_spec", default={"surface": "clean-adoption"}),
        "acceptance_criteria": _first(fresh, "acceptance_criteria", default=["fresh adoption boundary"]),
        "authority_scope": _first(fresh, "authority_scope", default={"provider_free": True, "writable": []}),
        "writable_scope": _first(fresh, "writable_scope", default=[]),
        "invocation_identity": _first(fresh, "invocation_identity", default={"surface": "orch-dork", "boundary": "fresh"}),
        "classification": {"mode": mode, "evidence": _first(fresh, "evidence", default=(
            {"attempted_decomposition": "identity and boundary are independently owned"} if mode == "orchestrated" else
            {"single_coherent_operation_proof": "one fresh adoption invocation"}
        ))},
        "candidate_lanes": lanes,
    }


def simulate_fresh_task_boundary(program: Any) -> dict[str, Any]:
    """Simulate a fresh task admission after adoption, without task creation."""

    value = dict(program) if isinstance(program, Mapping) else {}
    value["operation"] = "inspect"
    inspected = evaluate_clean_adoption(value)
    if inspected.get("decision") not in {ALREADY_ADOPTED, ADOPTED}:
        inspected["decision"] = FRESH_BOUNDARY_BLOCKED
        inspected["status"] = "BLOCKED"
        inspected["fresh_boundary"] = {"schema": FRESH_BOUNDARY_SCHEMA, "status": "BLOCKED", "task_created": False, "agents_md_dependency": False}
        inspected["report_sha256"] = json_sha256({key: item for key, item in inspected.items() if key != "report_sha256"})
        return inspected
    fresh = _mapping(_first(value, "fresh_task", "fresh_boundary", "ticket", default={}))
    if _first(fresh, "previous_admission", "prior_admission") is not None or value.get("previous_admission") is not None:
        issues = list(inspected.get("issues", [])) + ["fresh_boundary:previous_admission_present"]
        return _report(decision=FRESH_BOUNDARY_BLOCKED, operation="fresh-boundary", issues=issues, program=value, identity=inspected["identity"], binding=inspected["binding"], environment=inspected["environment"], record=inspected.get("record"), reconciliation=inspected["reconciliation"], fresh_boundary={"schema": FRESH_BOUNDARY_SCHEMA, "status": "BLOCKED", "task_created": False, "agents_md_dependency": False})
    if ticket_admission is None:
        return _report(decision=FRESH_BOUNDARY_BLOCKED, operation="fresh-boundary", issues=["fresh_boundary:ticket_admission_unavailable"], program=value, identity=inspected["identity"], binding=inspected["binding"], environment=inspected["environment"], record=inspected.get("record"), reconciliation=inspected["reconciliation"], fresh_boundary={"schema": FRESH_BOUNDARY_SCHEMA, "status": "BLOCKED", "task_created": False, "agents_md_dependency": False})
    ticket = _default_fresh_ticket(value)
    admission = ticket_admission.evaluate_ticket_admission(ticket)
    mode = _first(_mapping(ticket.get("classification")), "mode", default="atomic")
    expected = ORCHESTRATION_PLAN_REQUIRED if mode == "orchestrated" else ATOMIC_ADMITTED
    issues = []
    if admission.get("schema") != TICKET_ADMISSION_SCHEMA:
        issues.append("fresh_boundary:admission_schema_invalid")
    if admission.get("policy_version") != TICKET_ADMISSION_POLICY_VERSION:
        issues.append("fresh_boundary:admission_policy_invalid")
    if not admission.get("fresh"):
        issues.append("fresh_boundary:admission_not_fresh")
    if admission.get("decision") != expected:
        issues.append("fresh_boundary:path_mismatch")
    boundary = {
        "schema": FRESH_BOUNDARY_SCHEMA,
        "status": "PASS" if not issues else "BLOCKED",
        "admission_schema": admission.get("schema"),
        "admission_sha256": admission.get("admission_sha256"),
        "admission_decision": admission.get("decision"),
        "path": "orchestrated" if admission.get("decision") == ORCHESTRATION_PLAN_REQUIRED else "atomic" if admission.get("decision") == ATOMIC_ADMITTED else "refused",
        "fresh": bool(admission.get("fresh")),
        "task_created": False,
        "worker_created": False,
        "agents_md_dependency": False,
        "admission_events": len(admission.get("events", [])),
    }
    decision = FRESH_BOUNDARY_PASS if not issues else FRESH_BOUNDARY_BLOCKED
    return _report(decision=decision, operation="fresh-boundary", issues=issues, program=value, identity=inspected["identity"], binding=inspected["binding"], environment=inspected["environment"], record=inspected.get("record"), reconciliation=inspected["reconciliation"], fresh_boundary={**boundary, "admission": dict(admission)})


def run_clean_adoption_acceptance(program: Any) -> dict[str, Any]:
    """Run inspect, explicit adoption, and fresh-boundary evidence in order."""

    value = deepcopy(dict(program)) if isinstance(program, Mapping) else {}
    inspect = evaluate_clean_adoption({**value, "operation": "inspect"})
    adoption = apply_clean_adoption({**value, "operation": "adopt"})
    fresh = simulate_fresh_task_boundary(value)
    checks = {"read_only_before_adoption": inspect.get("decision") == READ_ONLY, "adopted": adoption.get("decision") in {ADOPTED, ALREADY_ADOPTED}, "fresh_boundary": fresh.get("decision") == FRESH_BOUNDARY_PASS}
    return {"schema": REPORT_SCHEMA, "policy_version": POLICY_VERSION, "status": "PASS" if all(checks.values()) else "BLOCKED", "checks": checks, "inspect": inspect, "adoption": adoption, "fresh_boundary": fresh, "provider_free": True, "hosted_calls": 0, "model_calls": 0, "credential_reads": 0, "task_creations": 0, "report_sha256": json_sha256({"checks": checks, "inspect": inspect.get("report_sha256"), "adoption": adoption.get("report_sha256"), "fresh_boundary": fresh.get("report_sha256")})}


# Friendly aliases used by integration callers and the focused suite.
evaluate_adoption = evaluate_clean_adoption
apply_adoption = apply_clean_adoption
evaluate_clean_adoption_acceptance = evaluate_clean_adoption
apply_clean_adoption_acceptance = apply_clean_adoption
fresh_task_boundary = simulate_fresh_task_boundary
build_fresh_task_boundary = simulate_fresh_task_boundary


def make_fixture_program(base: str | os.PathLike[str], *, operation: str = "inspect", mode: str = "atomic") -> dict[str, Any]:
    """Create a disposable fixture and return its program description."""

    root = Path(base).resolve()
    project = root / "project"
    registry = root / "registry"
    (project / ".git").mkdir(parents=True, exist_ok=True)
    (project / "scripts").mkdir(parents=True, exist_ok=True)
    registry.mkdir(parents=True, exist_ok=True)
    adapter = project / "scripts" / "adapter.py"
    if not adapter.exists():
        adapter.write_text("print('provider-free adapter')\n", encoding="utf-8")
    identity = {
        "project_id": "clean-adoption-project",
        "host_id": "local-disposable-host",
        "environment_id": "codex-disposable",
        "saved_project_id": "saved-clean-adoption",
        "workspace_id": "workspace-clean-adoption",
        "repository_kind": "git",
        "clone_id": "clone-clean-adoption-001",
        "worktree_id": None,
        "canonical_initial_root": str(project),
    }
    binding = {
        "protocol": PROTOCOL,
        "generation": 1,
        "adapter_sha256": _sha_bytes(adapter.read_bytes()),
        "adapter_path": "scripts/adapter.py",
        "required": True,
        "adoption_state": "unadopted",
    }
    binding_file = project / ".orch-dork" / "binding.json"
    binding_file.parent.mkdir(parents=True, exist_ok=True)
    if not binding_file.exists():
        _atomic_write_json(binding_file, {"schema": ADOPTION_SCHEMA, **_binding_core(binding), "adoption_state": "unadopted", "project_id": identity["project_id"]})
    ticket = {"mode": mode}
    return {"schema": PROGRAM_SCHEMA, "operation": operation, "project_root": str(project), "registry_root": str(registry), "identity": identity, "binding": binding, "authority": {"provider_free": True, "external_actions": []}, "writable_scope": {"paths": [".orch-dork"]}, "hook": {"enabled": True, "trusted": True, "status": "ready"}, "fresh_task": ticket, "source_pointer": "fixture.json#program"}


valid_program = make_fixture_program
build_fixture_program = make_fixture_program


def _load_program(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program", help="JSON program path")
    parser.add_argument("--apply", action="store_true", help="apply explicit adoption")
    parser.add_argument("--fresh-boundary", action="store_true", help="simulate a fresh task boundary")
    args = parser.parse_args(argv)
    program = _load_program(args.program)
    if args.fresh_boundary:
        result = simulate_fresh_task_boundary(program)
    elif args.apply:
        result = apply_clean_adoption(program)
    else:
        result = evaluate_clean_adoption(program)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "PROGRAM_SCHEMA", "ADOPTION_SCHEMA", "RECORD_SCHEMA", "REPORT_SCHEMA", "FRESH_BOUNDARY_SCHEMA", "PROTOCOL", "POLICY_VERSION",
    "READ_ONLY", "REFUSED", "READY_TO_ADOPT", "ADOPTED", "ALREADY_ADOPTED", "RECONCILIATION_REQUIRED", "PRESERVED_PRIOR_GENERATION", "FRESH_BOUNDARY_PASS", "FRESH_BOUNDARY_BLOCKED",
    "ATOMIC_ADMITTED", "ORCHESTRATION_PLAN_REQUIRED", "canonical_json", "json_sha256", "sha256", "binding_path", "state_path",
    "evaluate_clean_adoption", "apply_clean_adoption", "simulate_fresh_task_boundary", "run_clean_adoption_acceptance",
    "evaluate_adoption", "apply_adoption", "evaluate_clean_adoption_acceptance", "apply_clean_adoption_acceptance", "fresh_task_boundary", "build_fresh_task_boundary",
    "make_fixture_program", "valid_program", "build_fixture_program",
]
