#!/usr/bin/env python3
"""Provider-free workspace policy for the model-portable worker seam.

This module is deliberately an evaluator, rather than a workspace runner.  A
caller submits a JSON-compatible description of a server-owned disposable
worktree, its registered lane policy, operation records, and the resulting
candidate patch.  The evaluator validates those records and returns a new
JSON-compatible report.  It never invokes a command, resolves a checkout, or
changes a file.

The small public surface is:

``validate_lane_policy(policy)``
    Validate and canonicalise one registered lane policy.
``validate_candidate_diff(record, policy=None, base_revision=None)``
    Parse and validate a submitted candidate patch without applying it.
``evaluate_workspace_program(program)``
    Evaluate one complete provider-free worker attempt.

The schemas are intentionally closed.  The aliases near the end are kept for
callers that used the early names while Issue 30 was being specified.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import shlex
import sys
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


LANE_POLICY_SCHEMA = "orch-dork/worker-lane-policy/v1"
WORKSPACE_PROGRAM_SCHEMA = "orch-dork/worker-workspace-program/v1"
CANDIDATE_DIFF_SCHEMA = "orch-dork/worker-candidate-diff/v1"
REPORT_SCHEMA = "orch-dork/worker-workspace-report/v1"

# A compatibility spelling is useful to adapters which call the policy a
# "registered lane" instead of a lane policy.
POLICY_SCHEMA = LANE_POLICY_SCHEMA
PROGRAM_SCHEMA = WORKSPACE_PROGRAM_SCHEMA
DIFF_SCHEMA = CANDIDATE_DIFF_SCHEMA
SCHEMA = REPORT_SCHEMA

ALLOWED_OPERATIONS = ("inspect", "structured_edit", "focused_test")
TERMINAL_LIFECYCLES = ("completed", "failed", "cancelled", "timed_out")
RESULT_STATUSES = (
    "CANDIDATE_READY",
    "REJECTED",
    "UNAVAILABLE",
    "CANCELLED",
    "TIMED_OUT",
    "DELIVERY_UNCERTAIN",
    "RECOVERY_PENDING",
)

# Keep issue ordering stable so a record has deterministic replay output even
# when a submitted list is in a different order.
ISSUE_ORDER = (
    "schema_invalid",
    "unknown_field",
    "policy_missing",
    "policy_invalid",
    "policy_hash_mismatch",
    "policy_path_invalid",
    "policy_path_overlap",
    "policy_command_invalid",
    "policy_budget_invalid",
    "worktree_missing",
    "worktree_not_server_owned",
    "worktree_not_disposable",
    "worktree_base_revision_missing",
    "worktree_base_revision_unpinned",
    "worktree_base_revision_mismatch",
    "worktree_symlink_escape",
    "baseline_missing",
    "baseline_mismatch",
    "lifecycle_not_terminal",
    "lifecycle_cancellation_mismatch",
    "operation_missing",
    "operation_unknown",
    "operation_sequence_invalid",
    "duplicate_operation",
    "operation_failed",
    "path_invalid",
    "path_absolute",
    "path_parent_traversal",
    "path_unregistered",
    "protected_change",
    "excluded_change",
    "generated_change",
    "rename_detected",
    "network_access",
    "secrets_access",
    "arbitrary_command",
    "nested_worker",
    "evaluator_context",
    "verification_command_mismatch",
    "operation_budget_exhausted",
    "workspace_drift",
    "candidate_missing",
    "canonical_diff_invalid",
    "diff_paths_mismatch",
    "diff_base_revision_mismatch",
    "diff_tampered",
    "cleanup_incomplete",
    "cleanup_missing",
    "cleanup_evidence_missing",
    "cancellation_missing",
    "record_tampered",
)
_ISSUE_INDEX = {value: index for index, value in enumerate(ISSUE_ORDER)}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DRIVE = re.compile(r"^[A-Za-z]:([/\\]|$)")
_UNSAFE_COMMAND = re.compile(r"(?:[;&|<>`$]|\$\(|\b(?:curl|wget|ssh|scp|nc|telnet)\b)")
_SECRET_NAME = re.compile(
    r"(?:^|/)(?:\.env(?:\.|$)|.*(?:secret|credential|token|password|private[_-]?key).*)$",
    re.IGNORECASE,
)


class WorkspacePolicyError(ValueError):
    """Raised only by the optional ``require_*`` helpers."""

    def __init__(self, report: Mapping[str, Any]):
        self.report = dict(report)
        self.issues = list(self.report.get("issues", []))
        super().__init__("worker workspace policy rejected: " + ", ".join(self.issues))


def _canonical(value: Any) -> bytes:
    """Return the one canonical JSON encoding used for all evidence hashes."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    if isinstance(value, bytes):
        payload = value
    else:
        payload = _canonical(value)
    return hashlib.sha256(payload).hexdigest()


def canonical_json(value: Any) -> str:
    """Public deterministic JSON helper for receipt producers and tests."""

    return _canonical(value).decode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Public canonical JSON SHA-256 helper."""

    return _sha256(value)


def _add(issues: list[str], issue: str) -> None:
    if issue not in issues:
        issues.append(issue)


def _ordered(issues: Iterable[str]) -> list[str]:
    return sorted(
        set(issues), key=lambda item: (_ISSUE_INDEX.get(item, len(ISSUE_ORDER)), item)
    )


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and "\x00" not in value


def _digest(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value[7:] if value.startswith("sha256:") else value
    return bool(_HEX64.fullmatch(candidate))


def _digest_value(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return value[7:] if value.startswith("sha256:") else value


def _exact_keys(
    value: Any,
    allowed: set[str],
    path: str,
    issues: list[str],
    *,
    required: set[str] | None = None,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _add(issues, f"{path}:not_object")
        return {}
    unknown = sorted(str(key) for key in value if key not in allowed)
    if unknown:
        # Keep one closed issue code and expose exact fields separately in the
        # report; a model cannot smuggle arbitrary execution controls in.
        _add(issues, "unknown_field")
    for key in sorted(required or set()):
        if key not in value:
            _add(issues, f"{path}:{key}_missing")
    return value


def _alias(mapping: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return default


def _normalize_path(value: Any, *, allow_glob: bool = False) -> tuple[str | None, str | None]:
    """Normalize a policy/record path, returning (path, failure kind)."""

    if not _text(value):
        return None, "invalid"
    raw = str(value).strip()
    if "\\" in raw:
        return None, "invalid"
    if raw.startswith("/") or _DRIVE.match(raw):
        return None, "absolute"
    if raw.startswith("~"):
        return None, "absolute"
    parts = raw.split("/")
    if any(part == ".." for part in parts):
        return None, "parent_traversal"
    if any(part in {"", "."} for part in parts):
        # A leading ./ is not a canonical registered path.  Rejecting it
        # prevents two spellings of the same protected resource.
        return None, "invalid"
    if not allow_glob and any(char in raw for char in "*?["):
        return None, "invalid"
    normalized = PurePosixPath(*parts).as_posix()
    if normalized in {"", "."}:
        return None, "invalid"
    return normalized, None


def _literal_prefix(scope: str) -> str:
    parts: list[str] = []
    for part in scope.split("/"):
        if any(char in part for char in "*?["):
            break
        parts.append(part)
    return "/".join(parts) or "."


def _scope_matches(scope: str, path: str) -> bool:
    if fnmatch.fnmatchcase(path, scope):
        return True
    if any(char in scope for char in "*?["):
        prefix = _literal_prefix(scope).rstrip("/")
        return path == prefix or path.startswith(prefix + "/")
    return path == scope or path.startswith(scope.rstrip("/") + "/")


def _scope_intersects(left: str, right: str) -> bool:
    if _scope_matches(left, right) or _scope_matches(right, left):
        return True
    lp, rp = _literal_prefix(left), _literal_prefix(right)
    return lp == rp or lp.startswith(rp.rstrip("/") + "/") or rp.startswith(lp.rstrip("/") + "/")


def _paths(value: Any, label: str, issues: list[str], *, glob: bool) -> list[str]:
    if not isinstance(value, list):
        _add(issues, f"{label}:not_array")
        return []
    result: list[str] = []
    for item in value:
        normalized, failure = _normalize_path(item, allow_glob=glob)
        if normalized is None:
            _add(issues, "policy_path_invalid" if label.startswith("policy") else "path_invalid")
            if failure == "absolute":
                _add(issues, "path_absolute")
            elif failure == "parent_traversal":
                _add(issues, "path_parent_traversal")
            continue
        if normalized not in result:
            result.append(normalized)
    return sorted(result)


def _safe_command(value: Any) -> bool:
    return _text(value) and not _UNSAFE_COMMAND.search(str(value))


def _canonical_policy_core(value: Mapping[str, Any]) -> dict[str, Any]:
    """Map supported compatibility spellings to the closed policy shape."""

    budgets = _alias(value, "budgets", "operation_budgets", default={})
    if not isinstance(budgets, Mapping):
        budgets = {}
    # Keep both the canonical names and the common short names accepted by
    # early provider-free fixtures.
    normalized_budgets = {
        "max_operations": _alias(budgets, "max_operations", "operations"),
        "max_inspect": _alias(budgets, "max_inspect", "inspect"),
        "max_structured_edit": _alias(
            budgets, "max_structured_edit", "structured_edit", "edit"
        ),
        "max_focused_test": _alias(
            budgets, "max_focused_test", "focused_test", "test"
        ),
        "max_changed_paths": _alias(budgets, "max_changed_paths", "changed_paths"),
        "max_diff_bytes": _alias(budgets, "max_diff_bytes", "diff_bytes"),
    }
    return {
        "schema": value.get("schema"),
        "policy_id": _alias(value, "policy_id", "id"),
        "revision": _alias(value, "revision", "version"),
        "lane_id": _alias(value, "lane_id", "lane"),
        "writable_paths": _alias(value, "writable_paths", "writable", default=[]),
        "protected_paths": _alias(value, "protected_paths", "protected", default=[]),
        "excluded_paths": _alias(value, "excluded_paths", "excluded", default=[]),
        "generated_paths": _alias(value, "generated_paths", "generated", default=[]),
        "verification_commands": _alias(
            value, "verification_commands", "verification", "focused_tests", default=[]
        ),
        "allowed_operations": _alias(
            value, "allowed_operations", "operations", default=list(ALLOWED_OPERATIONS)
        ),
        "budgets": normalized_budgets,
        "source_pointer": _alias(value, "source_pointer", "source"),
    }


def validate_lane_policy(policy: Any) -> dict[str, Any]:
    """Validate one registered lane policy and return a canonical projection."""

    issues: list[str] = []
    if not isinstance(policy, Mapping):
        _add(issues, "policy_invalid")
        core: dict[str, Any] = {}
    else:
        allowed = {
            "schema",
            "policy_id",
            "id",
            "revision",
            "version",
            "lane_id",
            "lane",
            "writable_paths",
            "writable",
            "protected_paths",
            "protected",
            "excluded_paths",
            "excluded",
            "generated_paths",
            "generated",
            "verification_commands",
            "verification",
            "focused_tests",
            "allowed_operations",
            "operations",
            "budgets",
            "operation_budgets",
            "source_pointer",
            "source",
            "policy_sha256",
        }
        _exact_keys(policy, allowed, "policy", issues, required={"schema"})
        core = _canonical_policy_core(policy)

    if core.get("schema") != LANE_POLICY_SCHEMA:
        _add(issues, "schema_invalid")
    for key in ("policy_id", "lane_id"):
        if not _text(core.get(key)):
            _add(issues, "policy_invalid")

    writable = _paths(core.get("writable_paths"), "policy.writable_paths", issues, glob=True)
    protected = _paths(core.get("protected_paths"), "policy.protected_paths", issues, glob=True)
    excluded = _paths(core.get("excluded_paths"), "policy.excluded_paths", issues, glob=True)
    generated = _paths(core.get("generated_paths"), "policy.generated_paths", issues, glob=True)
    if not writable:
        _add(issues, "policy_invalid")

    for left_name, left in (
        ("writable", writable),
        ("protected", protected),
        ("excluded", excluded),
        ("generated", generated),
    ):
        for right_name, right in (("protected", protected), ("excluded", excluded)):
            if left_name == right_name:
                continue
            if left_name == "generated":
                # Generated paths may be declared independently, but are never
                # writable.  This keeps generated output out of candidates.
                pass
            for a in left:
                for b in right:
                    if left_name == "writable" or (left_name == right_name):
                        if _scope_intersects(a, b):
                            _add(issues, "policy_path_overlap")
        if left_name == "writable":
            for a in left:
                for b in generated:
                    if _scope_intersects(a, b):
                        _add(issues, "policy_path_overlap")

    commands_value = core.get("verification_commands")
    commands: list[str] = []
    if not isinstance(commands_value, list):
        _add(issues, "policy_command_invalid")
    else:
        for command in commands_value:
            if not _safe_command(command):
                _add(issues, "policy_command_invalid")
            elif command not in commands:
                commands.append(str(command))
    if not commands:
        _add(issues, "policy_invalid")

    operations = core.get("allowed_operations")
    if not isinstance(operations, list) or not operations:
        _add(issues, "policy_invalid")
        operations = list(ALLOWED_OPERATIONS)
    else:
        for operation in operations:
            if operation not in ALLOWED_OPERATIONS:
                _add(issues, "operation_unknown")
    operations = [item for item in ALLOWED_OPERATIONS if item in operations]

    raw_budgets = core.get("budgets")
    budgets: dict[str, int] = {}
    if not isinstance(raw_budgets, Mapping):
        _add(issues, "policy_budget_invalid")
    else:
        max_ops = raw_budgets.get("max_operations")
        if type(max_ops) is not int or max_ops <= 0:
            _add(issues, "policy_budget_invalid")
            max_ops = 0
        budgets["max_operations"] = max_ops
        defaults = {
            "max_inspect": max_ops,
            "max_structured_edit": max_ops,
            "max_focused_test": max_ops,
            "max_changed_paths": max_ops,
            "max_diff_bytes": 1_000_000,
        }
        for key, default in defaults.items():
            candidate = raw_budgets.get(key, default)
            if type(candidate) is not int or candidate < 0:
                _add(issues, "policy_budget_invalid")
                candidate = 0
            budgets[key] = candidate

    normalized = {
        "schema": LANE_POLICY_SCHEMA,
        "policy_id": core.get("policy_id"),
        "revision": core.get("revision"),
        "lane_id": core.get("lane_id"),
        "writable_paths": writable,
        "protected_paths": protected,
        "excluded_paths": excluded,
        "generated_paths": generated,
        "verification_commands": commands,
        "allowed_operations": operations,
        "budgets": budgets,
        "source_pointer": core.get("source_pointer"),
    }
    supplied_hash = policy.get("policy_sha256") if isinstance(policy, Mapping) else None
    computed_hash = _sha256(normalized)
    if supplied_hash is not None:
        if not _digest(supplied_hash) or _digest_value(supplied_hash) != computed_hash:
            _add(issues, "policy_hash_mismatch")
    status = "PASS" if not issues else "FAIL"
    return {
        "schema": LANE_POLICY_SCHEMA,
        "status": status,
        "valid": not issues,
        "issues": _ordered(issues),
        "policy": normalized,
        "policy_sha256": computed_hash,
        "registered": not issues,
    }


def _strip_patch_path(value: str) -> tuple[str | None, str | None]:
    value = value.strip()
    if value == "/dev/null":
        return None, None
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    return _normalize_path(value, allow_glob=False)


def _extract_patch_paths(patch: str) -> tuple[list[str], list[tuple[str, str]], list[str]]:
    changed: list[str] = []
    renames: list[tuple[str, str]] = []
    errors: list[str] = []
    old_path: str | None = None
    new_path: str | None = None
    for raw in patch.splitlines():
        line = raw.rstrip("\r")
        if line.startswith("diff --git "):
            try:
                tokens = shlex.split(line[len("diff --git ") :])
            except ValueError:
                tokens = []
            if len(tokens) >= 2:
                old_path, old_error = _strip_patch_path(tokens[0])
                new_path, new_error = _strip_patch_path(tokens[1])
                if old_error or new_error:
                    errors.append(old_error or new_error or "invalid")
                if old_path:
                    changed.append(old_path)
                if new_path:
                    changed.append(new_path)
                if old_path and new_path and old_path != new_path:
                    renames.append((old_path, new_path))
        elif line.startswith("--- "):
            old_path, error = _strip_patch_path(line[4:].split("\t", 1)[0])
            if error:
                errors.append(error)
            if old_path:
                changed.append(old_path)
        elif line.startswith("+++ "):
            new_path, error = _strip_patch_path(line[4:].split("\t", 1)[0])
            if error:
                errors.append(error)
            if new_path:
                changed.append(new_path)
        elif line.startswith("rename from "):
            old_path, error = _strip_patch_path(line[len("rename from ") :])
            if error:
                errors.append(error)
        elif line.startswith("rename to "):
            new_path, error = _strip_patch_path(line[len("rename to ") :])
            if error:
                errors.append(error)
            if old_path and new_path:
                renames.append((old_path, new_path))
                changed.extend((old_path, new_path))
    return sorted(set(changed)), sorted(set(renames)), errors


def _diff_core(
    *,
    base_revision: Any,
    patch: str,
    changed_paths: Sequence[str],
    renames: Sequence[Sequence[str]],
    generated_paths: Sequence[str],
    status: str,
    source_pointer: Any,
) -> dict[str, Any]:
    return {
        "schema": CANDIDATE_DIFF_SCHEMA,
        "base_revision": base_revision,
        "patch": patch,
        "changed_paths": sorted(set(changed_paths)),
        "renamed_paths": [list(item) for item in sorted(set(tuple(item) for item in renames))],
        "generated_paths": sorted(set(generated_paths)),
        "status": status,
        "source_pointer": source_pointer,
    }


def validate_candidate_diff(
    record: Any,
    policy: Mapping[str, Any] | None = None,
    base_revision: str | None = None,
) -> dict[str, Any]:
    """Extract and validate a canonical candidate diff.

    ``patch`` may be a unified diff string.  Explicit ``changed_paths`` are
    accepted as an additional tamper-evident claim and must agree with paths
    extracted from the patch.  No patch is written or applied.
    """

    issues: list[str] = []
    if not isinstance(record, Mapping):
        _add(issues, "canonical_diff_invalid")
        value: Mapping[str, Any] = {}
    else:
        allowed = {
            "schema",
            "base_revision",
            "patch",
            "unified_diff",
            "text",
            "changed_paths",
            "renamed_paths",
            "renames",
            "generated_paths",
            "status",
            "source_pointer",
            "diff_sha256",
            "canonical_sha256",
            "files",
            "policy_id",
        }
        _exact_keys(record, allowed, "candidate_diff", issues)
        value = record
    if value.get("schema") not in {None, CANDIDATE_DIFF_SCHEMA}:
        _add(issues, "schema_invalid")
    patch_value = _alias(value, "patch", "unified_diff", "text", default="")
    if not isinstance(patch_value, str):
        _add(issues, "canonical_diff_invalid")
        patch = ""
    else:
        patch = patch_value.replace("\r\n", "\n").replace("\r", "\n")
    if not patch.strip():
        _add(issues, "candidate_missing")
    extracted, extracted_renames, extract_errors = _extract_patch_paths(patch)
    if extract_errors:
        _add(issues, "canonical_diff_invalid")
        if "absolute" in extract_errors:
            _add(issues, "path_absolute")
        if "parent_traversal" in extract_errors:
            _add(issues, "path_parent_traversal")

    explicit_paths_value = value.get("changed_paths")
    explicit_paths: list[str] = []
    if explicit_paths_value is not None:
        explicit_paths = _paths(explicit_paths_value, "candidate_diff.changed_paths", issues, glob=False)
        if extracted and set(explicit_paths) != set(extracted):
            _add(issues, "diff_paths_mismatch")
    changed = sorted(set(explicit_paths or extracted))

    renames_value = _alias(value, "renamed_paths", "renames", default=[])
    renames: list[tuple[str, str]] = list(extracted_renames)
    if renames_value:
        if not isinstance(renames_value, list):
            _add(issues, "canonical_diff_invalid")
        else:
            for pair in renames_value:
                if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                    _add(issues, "canonical_diff_invalid")
                    continue
                old, old_error = _normalize_path(pair[0], allow_glob=False)
                new, new_error = _normalize_path(pair[1], allow_glob=False)
                if old_error or new_error or old is None or new is None:
                    _add(issues, "canonical_diff_invalid")
                    if old_error == "absolute" or new_error == "absolute":
                        _add(issues, "path_absolute")
                    if old_error == "parent_traversal" or new_error == "parent_traversal":
                        _add(issues, "path_parent_traversal")
                else:
                    renames.append((old, new))
                    changed.extend((old, new))
    renames = sorted(set(renames))
    if renames:
        _add(issues, "rename_detected")

    generated = _paths(
        value.get("generated_paths", []), "candidate_diff.generated_paths", issues, glob=False
    )
    if generated:
        _add(issues, "generated_change")
    changed = sorted(set(changed))
    supplied_base = value.get("base_revision")
    if base_revision is not None and supplied_base != base_revision:
        _add(issues, "diff_base_revision_mismatch")
    if supplied_base is not None and not _text(supplied_base):
        _add(issues, "canonical_diff_invalid")

    policy_report = validate_lane_policy(policy) if policy is not None else None
    policy_value = policy_report["policy"] if policy_report else None
    if policy_report and not policy_report["valid"]:
        _add(issues, "policy_invalid")
    if policy_value:
        for path in changed:
            if any(_scope_matches(scope, path) for scope in policy_value["excluded_paths"]):
                _add(issues, "excluded_change")
            if any(_scope_matches(scope, path) for scope in policy_value["protected_paths"]):
                _add(issues, "protected_change")
            if any(_scope_matches(scope, path) for scope in policy_value["generated_paths"]):
                _add(issues, "generated_change")
            if not any(_scope_matches(scope, path) for scope in policy_value["writable_paths"]):
                _add(issues, "path_unregistered")
        if len(changed) > policy_value["budgets"].get("max_changed_paths", 0):
            _add(issues, "operation_budget_exhausted")
        if len(patch.encode("utf-8")) > policy_value["budgets"].get("max_diff_bytes", 0):
            _add(issues, "operation_budget_exhausted")

    canonical = _diff_core(
        base_revision=supplied_base,
        patch=patch,
        changed_paths=changed,
        renames=renames,
        generated_paths=generated,
        status=str(value.get("status") or "candidate"),
        source_pointer=value.get("source_pointer"),
    )
    patch_sha = _sha256(patch.encode("utf-8"))
    canonical_sha = _sha256(canonical)
    supplied_patch_hash = _digest_value(value.get("diff_sha256"))
    supplied_canonical_hash = _digest_value(value.get("canonical_sha256"))
    if supplied_patch_hash is not None and supplied_patch_hash != patch_sha:
        _add(issues, "diff_tampered")
    if supplied_canonical_hash is not None and supplied_canonical_hash != canonical_sha:
        _add(issues, "diff_tampered")
    return {
        "schema": CANDIDATE_DIFF_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": _ordered(issues),
        "canonical_diff": canonical,
        "changed_paths": changed,
        "renamed_paths": [list(item) for item in renames],
        "patch_sha256": patch_sha,
        "canonical_sha256": canonical_sha,
        "diff_sha256": canonical_sha,
        "base_revision": supplied_base,
    }


def _validate_worktree(value: Any, issues: list[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _add(issues, "worktree_missing")
        return {}
    allowed = {
        "schema",
        "worktree_id",
        "id",
        "owner",
        "kind",
        "disposable",
        "base_revision",
        "created_from_revision",
        "base_revision_sha256",
        "root_id",
        "workspace_root",
        "path",
        "status",
        "symlinks",
    }
    _exact_keys(value, allowed, "worktree", issues)
    owner = _alias(value, "owner", default="")
    if owner not in {"server", "server-owned", "server_owned"}:
        _add(issues, "worktree_not_server_owned")
    kind = _alias(value, "kind", default="")
    if kind not in {"disposable", "server_owned_disposable", "server-owned-disposable"}:
        _add(issues, "worktree_not_disposable")
    if value.get("disposable") is not True:
        _add(issues, "worktree_not_disposable")
    base = value.get("base_revision")
    if not _text(base):
        _add(issues, "worktree_base_revision_missing")
    elif base.strip().upper() in {"HEAD", "LATEST", "WORKTREE", "CURRENT", "MAIN", "MASTER"}:
        _add(issues, "worktree_base_revision_unpinned")
    created = value.get("created_from_revision")
    if created is not None and created != base:
        _add(issues, "worktree_base_revision_mismatch")
    digest = value.get("base_revision_sha256")
    if digest is not None and not _digest(digest):
        _add(issues, "worktree_base_revision_unpinned")
    symlinks = value.get("symlinks", [])
    if isinstance(symlinks, Mapping):
        symlinks = [{"path": path, "target": target} for path, target in symlinks.items()]
    if not isinstance(symlinks, list):
        _add(issues, "worktree_symlink_escape")
        symlinks = []
    for link in symlinks:
        if not isinstance(link, Mapping):
            _add(issues, "worktree_symlink_escape")
            continue
        path, path_error = _normalize_path(link.get("path"), allow_glob=False)
        target = link.get("target")
        target_path, target_error = _normalize_path(target, allow_glob=False)
        if link.get("escapes") is True or path_error or target_error or target_path is None:
            _add(issues, "worktree_symlink_escape")
        if path is None:
            _add(issues, "worktree_symlink_escape")
    return {
        "worktree_id": _alias(value, "worktree_id", "id"),
        "owner": owner,
        "kind": kind,
        "disposable": value.get("disposable"),
        "base_revision": base,
        "base_revision_sha256": _digest_value(value.get("base_revision_sha256")),
        "status": value.get("status"),
        "root_id": _alias(value, "root_id", "workspace_root", "path"),
    }


def _validate_baseline(value: Any, base_revision: Any, issues: list[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _add(issues, "baseline_missing")
        return {}
    allowed = {"schema", "base_revision", "tree_sha256", "paths", "status", "source_pointer"}
    _exact_keys(value, allowed, "baseline", issues)
    if value.get("base_revision") != base_revision:
        _add(issues, "baseline_mismatch")
    if value.get("tree_sha256") is not None and not _digest(value.get("tree_sha256")):
        _add(issues, "baseline_mismatch")
    if value.get("status") not in {None, "clean", "captured", "sealed"}:
        _add(issues, "baseline_mismatch")
    return dict(value)


def _validate_observation(value: Any, policy: Mapping[str, Any], issues: list[str]) -> dict[str, Any]:
    if value is None:
        return {"status": "clean", "changed_paths": []}
    if not isinstance(value, Mapping):
        _add(issues, "workspace_drift")
        return {"status": "unknown", "changed_paths": []}
    allowed = {"schema", "status", "changed_paths", "baseline_sha256", "final_sha256", "source_pointer"}
    _exact_keys(value, allowed, "workspace_observation", issues)
    changed = _paths(value.get("changed_paths", []), "workspace_observation.changed_paths", issues, glob=False)
    status = value.get("status")
    if status not in {"clean", "unchanged", "drift", "unknown"}:
        _add(issues, "workspace_drift")
    if status in {"drift", "unknown"} or changed:
        _add(issues, "workspace_drift")
    for path in changed:
        if any(_scope_matches(scope, path) for scope in policy["excluded_paths"]):
            _add(issues, "excluded_change")
        if any(_scope_matches(scope, path) for scope in policy["protected_paths"]):
            _add(issues, "protected_change")
        if not any(_scope_matches(scope, path) for scope in policy["writable_paths"]):
            _add(issues, "path_unregistered")
    for key in ("baseline_sha256", "final_sha256"):
        if value.get(key) is not None and not _digest(value.get(key)):
            _add(issues, "workspace_drift")
    return {"status": status, "changed_paths": changed}


def _validate_operation(
    operation: Any,
    index: int,
    policy: Mapping[str, Any],
    issues: list[str],
) -> tuple[str | None, list[str]]:
    if not isinstance(operation, Mapping):
        _add(issues, "operation_missing")
        return None, []
    allowed = {
        "seq",
        "operation_id",
        "id",
        "kind",
        "operation",
        "path",
        "paths",
        "command",
        "status",
        "network",
        "network_access",
        "secrets",
        "secret_access",
        "nested_worker",
        "child_count",
        "children",
        "arbitrary_command",
        "rename",
        "renamed_paths",
        "generated",
        "evaluator_only",
        "hidden",
        "result_sha256",
        "source_pointer",
    }
    _exact_keys(operation, allowed, f"operations[{index}]", issues)
    kind = _alias(operation, "kind", "operation")
    if kind not in ALLOWED_OPERATIONS:
        _add(issues, "operation_unknown")
    seq = operation.get("seq")
    if type(seq) is not int or seq <= 0:
        _add(issues, "operation_sequence_invalid")
    op_id = _alias(operation, "operation_id", "id")
    if not _text(op_id):
        _add(issues, "operation_missing")
    status = operation.get("status", "completed")
    if status not in {"completed", "complete", "passed", "ok", "observed", "accepted"}:
        _add(issues, "operation_failed")
    if any(operation.get(key) is True for key in ("network", "network_access")):
        _add(issues, "network_access")
    if any(operation.get(key) is True for key in ("secrets", "secret_access")):
        _add(issues, "secrets_access")
    if operation.get("arbitrary_command") is True:
        _add(issues, "arbitrary_command")
    if operation.get("nested_worker") is True or operation.get("child_count", 0) not in {None, 0}:
        _add(issues, "nested_worker")
    if operation.get("children") not in (None, [], {}):
        _add(issues, "nested_worker")
    if operation.get("evaluator_only") is True or operation.get("hidden") is True:
        _add(issues, "evaluator_context")
    if operation.get("rename") is True or operation.get("renamed_paths"):
        _add(issues, "rename_detected")
    if operation.get("generated") is True:
        _add(issues, "generated_change")

    paths_value = operation.get("paths")
    if paths_value is None and operation.get("path") is not None:
        paths_value = [operation.get("path")]
    paths: list[str] = []
    if paths_value is not None:
        paths = _paths(paths_value, f"operations[{index}].paths", issues, glob=False)
    if kind in {"inspect", "structured_edit"} and not paths:
        _add(issues, "path_invalid")
    for path in paths:
        if any(_scope_matches(scope, path) for scope in policy["excluded_paths"]):
            _add(issues, "excluded_change")
        if kind == "structured_edit":
            if any(_scope_matches(scope, path) for scope in policy["protected_paths"]):
                _add(issues, "protected_change")
            if any(_scope_matches(scope, path) for scope in policy["generated_paths"]):
                _add(issues, "generated_change")
            if not any(_scope_matches(scope, path) for scope in policy["writable_paths"]):
                _add(issues, "path_unregistered")
        elif kind == "inspect":
            registered = policy["writable_paths"] + policy["protected_paths"]
            if not any(_scope_matches(scope, path) for scope in registered):
                _add(issues, "path_unregistered")

    command = operation.get("command")
    if kind == "focused_test":
        if not _text(command) or command not in policy["verification_commands"]:
            _add(issues, "verification_command_mismatch")
    elif command is not None:
        _add(issues, "arbitrary_command")
    return str(kind) if isinstance(kind, str) else None, paths


def _validate_cleanup(value: Any, *, cancelled: bool, issues: list[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _add(issues, "cleanup_missing")
        _add(issues, "cleanup_incomplete")
        return {"status": "unknown", "worktree": "unknown"}
    allowed = {"status", "worktree", "evidence", "source_pointer", "recovery_id"}
    _exact_keys(value, allowed, "cleanup", issues)
    status = value.get("status")
    worktree = value.get("worktree")
    complete = status == "complete" and worktree in {"destroyed", "durably_marked"}
    if status not in {"complete", "incomplete", "unknown", "pending"}:
        _add(issues, "cleanup_incomplete")
    if not complete:
        _add(issues, "cleanup_incomplete")
    if value.get("evidence") in (None, {}, ""):
        _add(issues, "cleanup_evidence_missing")
    return {
        "status": status,
        "worktree": worktree,
        "complete": complete,
        "recovery_id": value.get("recovery_id"),
    }


def evaluate_workspace_program(program: Any) -> dict[str, Any]:
    """Evaluate one submitted worker workspace record.

    The function is total for JSON-compatible input: malformed input produces a
    rejected report instead of raising.  Its ``executed`` and ``mutated``
    fields are always false by construction.
    """

    issues: list[str] = []
    value: Mapping[str, Any]
    if not isinstance(program, Mapping):
        _add(issues, "schema_invalid")
        value = {}
    else:
        allowed = {
            "schema",
            "program_id",
            "id",
            "assignment",
            "worktree",
            "workspace",
            "lane_policy",
            "policy",
            "baseline",
            "operations",
            "candidate_diff",
            "diff",
            "workspace_observation",
            "drift",
            "lifecycle",
            "status",
            "cancellation",
            "cleanup",
            "children",
            "nested_workers",
            "evidence",
            "source_pointer",
            "program_sha256",
        }
        _exact_keys(program, allowed, "program", issues, required={"schema"})
        value = program
    if value.get("schema") not in {None, WORKSPACE_PROGRAM_SCHEMA}:
        _add(issues, "schema_invalid")

    policy_input = _alias(value, "lane_policy", "policy")
    if policy_input is None:
        _add(issues, "policy_missing")
        policy_report = validate_lane_policy({})
    else:
        policy_report = validate_lane_policy(policy_input)
    if not policy_report["valid"]:
        _add(issues, "policy_invalid")
    policy = policy_report["policy"]

    worktree = _validate_worktree(_alias(value, "worktree", "workspace"), issues)
    base_revision = worktree.get("base_revision")
    _validate_baseline(value.get("baseline"), base_revision, issues)

    operations_value = value.get("operations")
    if not isinstance(operations_value, list):
        _add(issues, "operation_missing")
        operations_value = []
    operation_counts = {kind: 0 for kind in ALLOWED_OPERATIONS}
    seen_ids: set[str] = set()
    previous_seq: int | None = None
    operation_paths: list[str] = []
    for index, operation in enumerate(operations_value):
        op_id = operation.get("operation_id", operation.get("id")) if isinstance(operation, Mapping) else None
        if isinstance(op_id, str):
            if op_id in seen_ids:
                _add(issues, "duplicate_operation")
            seen_ids.add(op_id)
        seq = operation.get("seq") if isinstance(operation, Mapping) else None
        if type(seq) is int:
            if previous_seq is not None and seq <= previous_seq:
                _add(issues, "operation_sequence_invalid")
            previous_seq = seq
        kind, paths = _validate_operation(operation, index, policy, issues)
        operation_paths.extend(paths)
        if kind in operation_counts:
            operation_counts[kind] += 1
    if len(operations_value) > policy["budgets"].get("max_operations", 0):
        _add(issues, "operation_budget_exhausted")
    if operation_counts["inspect"] > policy["budgets"].get("max_inspect", 0):
        _add(issues, "operation_budget_exhausted")
    if operation_counts["structured_edit"] > policy["budgets"].get("max_structured_edit", 0):
        _add(issues, "operation_budget_exhausted")
    if operation_counts["focused_test"] > policy["budgets"].get("max_focused_test", 0):
        _add(issues, "operation_budget_exhausted")

    if value.get("children") not in (None, [], {}):
        _add(issues, "nested_worker")
    if value.get("nested_workers") not in (None, [], {}):
        _add(issues, "nested_worker")

    diff_input = _alias(value, "candidate_diff", "diff")
    if diff_input is None:
        _add(issues, "candidate_missing")
        diff_report = validate_candidate_diff({}, policy=policy, base_revision=base_revision)
    else:
        diff_report = validate_candidate_diff(diff_input, policy=policy, base_revision=base_revision)
    issues.extend(diff_report.get("issues", []))
    if set(diff_report.get("changed_paths", [])) - set(operation_paths):
        # A patch may be produced by a structured edit with paths recorded as
        # a list on the operation.  Every candidate path must have an edit
        # record; inspect/test records alone cannot create a candidate.
        if any(op.get("kind", op.get("operation")) == "structured_edit" for op in operations_value if isinstance(op, Mapping)):
            _add(issues, "diff_paths_mismatch")

    observation_input = _alias(value, "workspace_observation", "drift")
    observation = _validate_observation(observation_input, policy, issues)
    lifecycle = value.get("lifecycle")
    if isinstance(lifecycle, str):
        lifecycle = {"status": lifecycle, "terminal": lifecycle in TERMINAL_LIFECYCLES}
    if not isinstance(lifecycle, Mapping):
        _add(issues, "lifecycle_not_terminal")
        lifecycle = {"status": "unknown", "terminal": False}
    else:
        status = lifecycle.get("status")
        terminal = lifecycle.get("terminal")
        if status not in TERMINAL_LIFECYCLES:
            _add(issues, "lifecycle_not_terminal")
        if terminal is False or (terminal is None and status not in TERMINAL_LIFECYCLES):
            _add(issues, "lifecycle_not_terminal")
    cancellation = value.get("cancellation")
    if cancellation is None:
        cancellation = {"requested": False}
    if not isinstance(cancellation, Mapping):
        _add(issues, "lifecycle_cancellation_mismatch")
        cancellation = {"requested": False}
    cancelled = bool(cancellation.get("requested"))
    lifecycle_status = lifecycle.get("status")
    if cancelled and lifecycle_status not in {"cancelled", "timed_out", "failed"}:
        _add(issues, "lifecycle_cancellation_mismatch")
    if lifecycle_status in {"cancelled", "timed_out"} and not cancelled:
        _add(issues, "cancellation_missing")

    cleanup = _validate_cleanup(value.get("cleanup"), cancelled=cancelled, issues=issues)
    supplied_hash = value.get("program_sha256")
    if supplied_hash is not None:
        core = {str(key): item for key, item in value.items() if key != "program_sha256"}
        if not _digest(supplied_hash) or _digest_value(supplied_hash) != _sha256(core):
            _add(issues, "record_tampered")

    issues = _ordered(issues)
    has_cleanup_failure = "cleanup_incomplete" in issues or "cleanup_missing" in issues
    if has_cleanup_failure:
        result_status = "RECOVERY_PENDING"
    elif cancelled and not issues:
        result_status = "TIMED_OUT" if lifecycle_status == "timed_out" else "CANCELLED"
    elif not issues and lifecycle_status == "completed" and diff_report.get("valid"):
        result_status = "CANDIDATE_READY"
    else:
        result_status = "REJECTED"
    report_core = {
        "schema": REPORT_SCHEMA,
        "status": result_status,
        "validation_status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "program_id": _alias(value, "program_id", "id"),
        "policy_id": policy.get("policy_id"),
        "policy_sha256": policy_report.get("policy_sha256"),
        "worktree_id": worktree.get("worktree_id"),
        "base_revision": base_revision,
        "operation_counts": operation_counts,
        "operations_observed": len(operations_value),
        "canonical_diff": diff_report.get("canonical_diff"),
        "candidate_diff": diff_report,
        "workspace_observation": observation,
        "lifecycle": dict(lifecycle),
        "cancellation": dict(cancellation),
        "cleanup": cleanup,
        "issues": issues,
        "executed": False,
        "mutated": False,
        "provider_free": True,
    }
    report_core["report_sha256"] = _sha256(report_core)
    return report_core


def require_lane_policy(policy: Any) -> dict[str, Any]:
    report = validate_lane_policy(policy)
    if not report["valid"]:
        raise WorkspacePolicyError(report)
    return report


def require_candidate_diff(
    record: Any,
    policy: Mapping[str, Any] | None = None,
    base_revision: str | None = None,
) -> dict[str, Any]:
    report = validate_candidate_diff(record, policy=policy, base_revision=base_revision)
    if not report["valid"]:
        raise WorkspacePolicyError(report)
    return report


def require_workspace_program(program: Any) -> dict[str, Any]:
    report = evaluate_workspace_program(program)
    if report["status"] != "CANDIDATE_READY":
        raise WorkspacePolicyError(report)
    return report


# Compatibility aliases for early callers and hidden provider-free fixtures.
validate_policy = validate_lane_policy
validate_worktree_policy = validate_lane_policy
validate_diff = validate_candidate_diff
extract_canonical_diff = validate_candidate_diff
evaluate_workspace = evaluate_workspace_program
evaluate = evaluate_workspace_program
replay = evaluate_workspace_program


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", action="store_true", help="validate a lane policy")
    parser.add_argument("--diff", action="store_true", help="validate a candidate diff")
    args = parser.parse_args(argv)
    try:
        value = json.load(sys.stdin)
    except (OSError, ValueError) as exc:
        json.dump({"schema": REPORT_SCHEMA, "status": "REJECTED", "issues": ["schema_invalid", str(exc)]}, sys.stdout)
        return 2
    if args.policy:
        result = validate_lane_policy(value)
    elif args.diff:
        result = validate_candidate_diff(value)
    else:
        result = evaluate_workspace_program(value)
    json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sys.stdout.write("\n")
    return 0 if result.get("valid") or result.get("status") in {"CANDIDATE_READY", "CANCELLED", "TIMED_OUT"} else 1


if __name__ == "__main__":  # pragma: no cover - CLI convenience
    raise SystemExit(_main())

