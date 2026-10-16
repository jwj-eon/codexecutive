#!/usr/bin/env python3
"""Provider-free, closed-schema communication contracts for adaptive DAGs.

The module has no transport, filesystem, subprocess, or model-provider seam.
Public ``validate_*`` functions return sanitized reports containing only a
normalized record and its digest.  Public ``seal_*`` functions fail closed
with :class:`ContractValidationError` and never preserve caller-owned traces.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sys
import unicodedata
from typing import Any

try:
    from orch_dork_hostile_input import PROFILE, HostileInputError, canonicalize_bounded_json
except ImportError:  # pragma: no cover - isolated policy loader
    _hostile_path = Path(__file__).resolve().with_name("orch_dork_hostile_input.py")
    _hostile_spec = importlib.util.spec_from_file_location("orch_dork_hostile_input", _hostile_path)
    if _hostile_spec is None or _hostile_spec.loader is None:
        raise
    _hostile = importlib.util.module_from_spec(_hostile_spec)
    sys.modules.setdefault("orch_dork_hostile_input", _hostile)
    _hostile_spec.loader.exec_module(_hostile)
    PROFILE = _hostile.PROFILE
    HostileInputError = _hostile.HostileInputError
    canonicalize_bounded_json = _hostile.canonicalize_bounded_json

try:
    from orch_dork_ownership import OwnershipError, normalize_resource, resource_contains
except ImportError:  # pragma: no cover - isolated policy loader
    _ownership_path = Path(__file__).resolve().with_name("orch_dork_ownership.py")
    _ownership_spec = importlib.util.spec_from_file_location(
        "orch_dork_ownership", _ownership_path
    )
    if _ownership_spec is None or _ownership_spec.loader is None:
        raise
    _ownership = importlib.util.module_from_spec(_ownership_spec)
    sys.modules.setdefault("orch_dork_ownership", _ownership)
    _ownership_spec.loader.exec_module(_ownership)
    OwnershipError = _ownership.OwnershipError
    normalize_resource = _ownership.normalize_resource
    resource_contains = _ownership.resource_contains


TASK_SPEC_SCHEMA = "orch-dork/task-spec/v2"
ARTIFACT_REF_SCHEMA = "orch-dork/artifact-ref/v1"
HANDOFF_RECEIPT_SCHEMA = "orch-dork/handoff-receipt/v1"
VERIFICATION_RECEIPT_SCHEMA = "orch-dork/verification-receipt/v1"
CLAIM_LEDGER_SCHEMA = "orch-dork/claim-ledger/v1"
INCREMENTAL_CLAIM_PACKET_SCHEMA = "orch-dork/incremental-claim-packet/v1"
HANDOFF_PREFLIGHT_SCHEMA = "orch-dork/handoff-preflight/v1"
HANDOFF_PREFLIGHT_CANDIDATE_SCHEMA = (
    "orch-dork/handoff-preflight-candidate/v1"
)
VALIDATION_SCHEMA = "orch-dork/adaptive-contract-validation/v1"

TASK_KINDS = frozenset({"probe", "execute", "join", "verify", "adjudicate"})
RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})
HANDOFF_DISPOSITIONS = frozenset({"complete", "blocked", "needs_decomposition", "failed"})
CLAIM_EPISTEMIC_STATUSES = frozenset(
    {"asserted", "inferred", "reproduced", "verified", "unknown", "contradicted"}
)
CHECK_STATUSES = frozenset({"passed", "failed", "not_run"})
VERIFICATION_DISPOSITIONS = frozenset({"pass", "fail", "inconclusive"})
FINDING_SEVERITIES = frozenset({"info", "warning", "error"})

MAX_RESULT_SUMMARY_BYTES = 2_048
MAX_HANDOFF_CANONICAL_BYTES = 4_800
MAX_HANDOFF_TOKENS = 1_200
MAX_INCREMENTAL_PACKET_CANONICAL_BYTES = 2_400
MAX_INCREMENTAL_PACKET_TOKENS = 600
TOKEN_ESTIMATE_BYTES = 4
MAX_ALLOWED_TOOLS = PROFILE.max_operations

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_MEDIA_TYPE = re.compile(r"\A[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*(?:;[ -~]+)?\Z")
_CONTENT_URI = re.compile(
    r"\A(?:(?:artifact|cas)://sha256/|urn:sha256:)([0-9a-f]{64})\Z"
)

_TASK_KEYS = frozenset(
    {
        "schema",
        "id",
        "kind",
        "goal",
        "rationale",
        "non_goals",
        "dependencies",
        "input_refs",
        "read_scope",
        "write_scope",
        "deliverable",
        "acceptance_checks",
        "executor",
        "model_profile",
        "allowed_tools",
        "risk",
        "budgets",
        "may_request_decomposition",
        "failure_policy",
    }
)
_DELIVERABLE_KEYS = frozenset({"schema", "media_type", "description"})
_ACCEPTANCE_KEYS = frozenset({"id", "description", "required"})
_RISK_KEYS = frozenset({"level", "reasons"})
_BUDGET_KEYS = frozenset(
    {"context_tokens", "output_tokens", "handoff_tokens", "tool_calls", "retries"}
)
_FAILURE_POLICY_KEYS = frozenset({"on_blocked", "on_failed", "on_budget_exhausted"})
_FAILURE_ACTIONS = frozenset({"return_receipt", "stop", "request_decision"})
_ARTIFACT_KEYS = frozenset({"schema", "uri", "sha256", "size_bytes", "media_type"})
_HANDOFF_KEYS = frozenset(
    {
        "schema",
        "disposition",
        "task_spec_sha256",
        "result_summary",
        "claims",
        "artifact_refs",
        "checks",
        "conflicts",
        "unknowns",
        "requested_decisions",
        "raw_trace_ref",
    }
)
_CLAIM_KEYS = frozenset({"id", "statement", "epistemic_status", "evidence_refs"})
_CHECK_KEYS = frozenset({"id", "status", "required", "evidence_refs"})
_CONFLICT_KEYS = frozenset({"id", "statement", "evidence_refs"})
_FORBIDDEN_HISTORY_KEYS = frozenset(
    {
        "transcript",
        "raw_transcript",
        "terminal",
        "terminal_output",
        "stdout",
        "stderr",
        "tool_history",
        "tool_calls",
        "tool_outputs",
        "command_history",
        "session_body",
        "prompt",
        "response_body",
        "private_reasoning",
        "chain_of_thought",
    }
)
_VERIFICATION_KEYS = frozenset(
    {
        "schema",
        "task_spec_sha256",
        "subject_handoff_sha256",
        "artifact_refs",
        "diff_refs",
        "acceptance_criteria",
        "check_results",
        "implementer_identity",
        "verifier",
        "disposition",
        "pass",
        "findings",
    }
)
_VERIFIER_KEYS = frozenset({"identity", "clean_context"})
_FINDING_KEYS = frozenset({"id", "severity", "statement", "evidence_refs"})
_CLAIM_LEDGER_KEYS = frozenset({"schema", "task_spec_sha256", "claims", "artifacts"})
_INCREMENTAL_PACKET_KEYS = frozenset(
    {
        "schema",
        "packet_id",
        "task_spec_sha256",
        "sequence",
        "claims",
        "artifact_refs",
        "checks",
        "usage",
        "source_pointer",
    }
)
_PROGRESS_USAGE_KEYS = frozenset(
    {"status", "input_tokens", "output_tokens", "total_tokens", "tool_calls"}
)
_HANDOFF_PREFLIGHT_KEYS = frozenset(
    {
        "schema",
        "preflight_id",
        "task_spec_sha256",
        "expected_route",
        "observed_route",
        "capability_profile",
        "handoff_receipt",
        "incremental_packets",
        "observed_usage",
        "evidence",
    }
)
_HANDOFF_PREFLIGHT_CANDIDATE_KEYS = frozenset(
    {
        "schema",
        "preflight_id",
        "task_spec_sha256",
        "capability_profile",
        "handoff_receipt",
    }
)
_EXPECTED_ROUTE_KEYS = frozenset({"model", "effort", "context_policy"})
_OBSERVED_ROUTE_KEYS = frozenset(
    {"model", "effort", "context_policy", "session_id"}
)
_PREFLIGHT_EVIDENCE_KEYS = frozenset(
    {"tier", "source_pointer", "source_sha256"}
)


class ContractValidationError(ValueError):
    """A sanitized fail-closed contract denial."""

    def __init__(self, issues: Sequence[str]) -> None:
        self.issues = tuple(sorted(set(str(issue) for issue in issues)))
        super().__init__("adaptive_contract_invalid:" + ",".join(self.issues))


def canonical_bytes(value: Any) -> bytes:
    """Return bounded canonical UTF-8 JSON using the hostile-input profile."""

    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return canonicalize_bounded_json(raw, profile=PROFILE, batch=isinstance(value, list))


def json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _issue(issues: list[str], code: str) -> None:
    if code not in issues:
        issues.append(code)


def _closed(value: Any, keys: frozenset[str], path: str, issues: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, path + ":not_object")
        return {}
    present = set(value)
    for key in sorted(keys - present):
        _issue(issues, path + ":missing:" + key)
    for key in sorted(present - keys):
        _issue(issues, path + ":unknown:" + str(key))
    return value


def _closed_sealable(
    value: Any,
    keys: frozenset[str],
    digest_key: str,
    path: str,
    issues: list[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, path + ":not_object")
        return {}
    present = set(value)
    for key in sorted(keys - present):
        _issue(issues, path + ":missing:" + key)
    for key in sorted(present - keys - {digest_key}):
        _issue(issues, path + ":unknown:" + str(key))
    return value


def _normalized_text(value: Any, path: str, issues: list[str], *, max_bytes: int = 4096) -> str:
    if not isinstance(value, str):
        _issue(issues, path + ":not_text")
        return ""
    result = unicodedata.normalize("NFC", value).strip()
    if not result or len(result.encode("utf-8")) > max_bytes or any(char in result for char in "\x00\r"):
        _issue(issues, path + ":invalid")
        return ""
    return result


def _identifier(value: Any, path: str, issues: list[str]) -> str:
    result = _normalized_text(value, path, issues, max_bytes=256)
    if result and _IDENTIFIER.fullmatch(result) is None:
        _issue(issues, path + ":invalid_identifier")
    return result


def _media_type(value: Any, path: str, issues: list[str]) -> str:
    result = _normalized_text(value, path, issues, max_bytes=256).lower()
    if result and _MEDIA_TYPE.fullmatch(result) is None:
        _issue(issues, path + ":invalid_media_type")
    return result


def _text_list(
    value: Any,
    path: str,
    issues: list[str],
    *,
    identifiers: bool = False,
    allow_empty: bool = True,
) -> list[str]:
    if not isinstance(value, list):
        _issue(issues, path + ":not_array")
        return []
    if len(value) > PROFILE.max_array_items:
        _issue(issues, path + ":too_many_items")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        normal = (
            _identifier(item, f"{path}[{index}]", issues)
            if identifiers
            else _normalized_text(item, f"{path}[{index}]", issues)
        )
        if normal:
            result.append(normal)
    if not allow_empty and not result:
        _issue(issues, path + ":empty")
    if len(result) != len(set(result)):
        _issue(issues, path + ":duplicates")
    return sorted(set(result))


def _has_forbidden_history_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() in _FORBIDDEN_HISTORY_KEYS or _has_forbidden_history_key(child):
                return True
    elif isinstance(value, list):
        return any(_has_forbidden_history_key(child) for child in value)
    return False


def _scope(value: Any, path: str, issues: list[str]) -> str:
    result = _normalized_text(value, path, issues, max_bytes=PROFILE.max_path_bytes)
    if not result:
        return ""
    if result.startswith(("/", "~", "\\")) or ":\\" in result or any(char in result for char in "\n"):
        _issue(issues, path + ":invalid_scope")
        return ""
    candidate = PurePosixPath(result)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        _issue(issues, path + ":invalid_scope")
        return ""
    canonical = candidate.as_posix()
    try:
        resource = normalize_resource(canonical)
    except OwnershipError:
        _issue(issues, path + ":invalid_scope")
        return ""
    if resource["kind"] == "semantic":
        return "semantic:" + str(resource["normalized"])
    return str(resource["normalized"])


def _scope_list(value: Any, path: str, issues: list[str]) -> list[str]:
    if not isinstance(value, list):
        _issue(issues, path + ":not_array")
        return []
    if len(value) > PROFILE.max_array_items:
        _issue(issues, path + ":too_many_items")
        return []
    result = [_scope(item, f"{path}[{index}]", issues) for index, item in enumerate(value)]
    result = [item for item in result if item]
    if len(result) != len(set(result)):
        _issue(issues, path + ":duplicates")
    return sorted(set(result))


def _authorized(requested: str, authorized: str) -> bool:
    try:
        scope = normalize_resource(authorized)
        value = normalize_resource(requested)
    except OwnershipError:
        return False
    return resource_contains(scope, value)


def _normalize_task_spec(
    value: Any,
    issues: list[str],
    *,
    authorized_write_scope: Sequence[str] | None,
) -> dict[str, Any]:
    item = _closed_sealable(value, _TASK_KEYS, "task_spec_sha256", "task_spec", issues)
    if item.get("schema") != TASK_SPEC_SCHEMA:
        _issue(issues, "task_spec:schema_invalid")
    identifier = _identifier(item.get("id"), "task_spec.id", issues)
    kind = item.get("kind")
    if kind not in TASK_KINDS:
        _issue(issues, "task_spec.kind:invalid")

    dependencies = _text_list(item.get("dependencies"), "task_spec.dependencies", issues, identifiers=True)
    if identifier and identifier in dependencies:
        _issue(issues, "task_spec.dependencies:self_reference")

    input_refs: list[dict[str, Any]] = []
    raw_refs = item.get("input_refs")
    if not isinstance(raw_refs, list):
        _issue(issues, "task_spec.input_refs:not_array")
    else:
        for index, raw in enumerate(raw_refs):
            normalized = _normalize_artifact_ref(raw, f"task_spec.input_refs[{index}]", issues)
            if normalized is not None:
                input_refs.append(normalized)
    input_refs.sort(key=lambda ref: (ref["uri"], ref["sha256"]))

    read_scope = _scope_list(item.get("read_scope"), "task_spec.read_scope", issues)
    write_scope = _scope_list(item.get("write_scope"), "task_spec.write_scope", issues)
    if authorized_write_scope is not None:
        authority_issues: list[str] = []
        authority = [_scope(entry, "authorized_write_scope", authority_issues) for entry in authorized_write_scope]
        if authority_issues or not authority:
            _issue(issues, "task_spec.write_scope:authority_invalid")
        for requested in write_scope:
            if not any(_authorized(requested, allowed) for allowed in authority):
                _issue(issues, "task_spec.write_scope:outside_authority:" + requested)

    deliverable = _closed(item.get("deliverable"), _DELIVERABLE_KEYS, "task_spec.deliverable", issues)
    normalized_deliverable = {
        "schema": _identifier(deliverable.get("schema"), "task_spec.deliverable.schema", issues),
        "media_type": _media_type(deliverable.get("media_type"), "task_spec.deliverable.media_type", issues),
        "description": _normalized_text(
            deliverable.get("description"), "task_spec.deliverable.description", issues
        ),
    }

    checks: list[dict[str, Any]] = []
    raw_checks = item.get("acceptance_checks")
    if not isinstance(raw_checks, list) or not raw_checks:
        _issue(issues, "task_spec.acceptance_checks:invalid")
    else:
        seen: set[str] = set()
        for index, raw in enumerate(raw_checks):
            check = _closed(raw, _ACCEPTANCE_KEYS, f"task_spec.acceptance_checks[{index}]", issues)
            check_id = _identifier(check.get("id"), f"task_spec.acceptance_checks[{index}].id", issues)
            if check_id in seen:
                _issue(issues, "task_spec.acceptance_checks:duplicate_id:" + check_id)
            seen.add(check_id)
            required = check.get("required")
            if type(required) is not bool:
                _issue(issues, f"task_spec.acceptance_checks[{index}].required:invalid")
            checks.append(
                {
                    "id": check_id,
                    "description": _normalized_text(
                        check.get("description"),
                        f"task_spec.acceptance_checks[{index}].description",
                        issues,
                    ),
                    "required": required if type(required) is bool else False,
                }
            )
    checks.sort(key=lambda check: check["id"])

    risk = _closed(item.get("risk"), _RISK_KEYS, "task_spec.risk", issues)
    if risk.get("level") not in RISK_LEVELS:
        _issue(issues, "task_spec.risk.level:invalid")
    normalized_risk = {
        "level": risk.get("level"),
        "reasons": _text_list(risk.get("reasons"), "task_spec.risk.reasons", issues, identifiers=True),
    }

    budgets = _closed(item.get("budgets"), _BUDGET_KEYS, "task_spec.budgets", issues)
    normalized_budgets: dict[str, int] = {}
    for field in sorted(_BUDGET_KEYS):
        number = budgets.get(field)
        if type(number) is not int or number < 0 or (field != "retries" and number == 0):
            _issue(issues, "task_spec.budgets." + field + ":invalid")
            number = 0
        normalized_budgets[field] = number

    failure = _closed(
        item.get("failure_policy"),
        _FAILURE_POLICY_KEYS,
        "task_spec.failure_policy",
        issues,
    )
    normalized_failure: dict[str, str] = {}
    for field in sorted(_FAILURE_POLICY_KEYS):
        action = failure.get(field)
        if action not in _FAILURE_ACTIONS:
            _issue(issues, "task_spec.failure_policy." + field + ":invalid")
        normalized_failure[field] = action if isinstance(action, str) else ""

    may_decompose = item.get("may_request_decomposition")
    if type(may_decompose) is not bool:
        _issue(issues, "task_spec.may_request_decomposition:invalid")

    allowed_tools = _text_list(
        item.get("allowed_tools"),
        "task_spec.allowed_tools",
        issues,
        identifiers=True,
    )
    if len(allowed_tools) > MAX_ALLOWED_TOOLS:
        _issue(issues, "task_spec.allowed_tools:too_many_items")

    normalized = {
        "schema": TASK_SPEC_SCHEMA,
        "id": identifier,
        "kind": kind,
        "goal": _normalized_text(item.get("goal"), "task_spec.goal", issues),
        "rationale": _normalized_text(item.get("rationale"), "task_spec.rationale", issues),
        "non_goals": _text_list(item.get("non_goals"), "task_spec.non_goals", issues),
        "dependencies": dependencies,
        "input_refs": input_refs,
        "read_scope": read_scope,
        "write_scope": write_scope,
        "deliverable": normalized_deliverable,
        "acceptance_checks": checks,
        "executor": _identifier(item.get("executor"), "task_spec.executor", issues),
        "model_profile": _identifier(item.get("model_profile"), "task_spec.model_profile", issues),
        "allowed_tools": allowed_tools,
        "risk": normalized_risk,
        "budgets": normalized_budgets,
        "may_request_decomposition": may_decompose if type(may_decompose) is bool else False,
        "failure_policy": normalized_failure,
    }
    supplied_digest = item.get("task_spec_sha256")
    digest = json_sha256(normalized)
    if supplied_digest is not None and supplied_digest != digest:
        _issue(issues, "task_spec:task_spec_sha256_mismatch")
    return normalized


def _report(contract_schema: str, issues: list[str], normalized: dict[str, Any], digest_key: str) -> dict[str, Any]:
    unique = sorted(set(issues))
    if unique:
        return {
            "schema": VALIDATION_SCHEMA,
            "contract_schema": contract_schema,
            "status": "FAIL",
            "valid": False,
            "issues": unique,
            "normalized": None,
            "digest": None,
        }
    digest = json_sha256(normalized)
    sealed = deepcopy(normalized)
    sealed[digest_key] = digest
    return {
        "schema": VALIDATION_SCHEMA,
        "contract_schema": contract_schema,
        "status": "PASS",
        "valid": True,
        "issues": [],
        "normalized": sealed,
        "digest": digest,
    }


def validate_task_spec(
    value: Any,
    *,
    authorized_write_scope: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Validate and normalize one ``task-spec/v2`` without granting authority."""

    issues: list[str] = []
    try:
        normalized = _normalize_task_spec(
            value,
            issues,
            authorized_write_scope=authorized_write_scope,
        )
        canonical_bytes(normalized)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        _issue(issues, "task_spec:hostile_or_non_json_input")
        normalized = {}
    return _report(TASK_SPEC_SCHEMA, issues, normalized, "task_spec_sha256")


def seal_task_spec(
    value: Any,
    *,
    authorized_write_scope: Sequence[str] | None = None,
) -> dict[str, Any]:
    report = validate_task_spec(value, authorized_write_scope=authorized_write_scope)
    if not report["valid"]:
        raise ContractValidationError(report["issues"])
    return report["normalized"]


def _normalize_artifact_ref(value: Any, path: str, issues: list[str]) -> dict[str, Any] | None:
    item = _closed_sealable(value, _ARTIFACT_KEYS, "artifact_ref_sha256", path, issues)
    if item.get("schema") != ARTIFACT_REF_SCHEMA:
        _issue(issues, path + ".schema:invalid")
    digest = item.get("sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        _issue(issues, path + ".sha256:invalid")
        digest = ""
    uri = _normalized_text(item.get("uri"), path + ".uri", issues, max_bytes=PROFILE.max_path_bytes)
    match = _CONTENT_URI.fullmatch(uri) if uri else None
    if match is None:
        _issue(issues, path + ".uri:not_content_addressed")
    elif digest and match.group(1) != digest:
        _issue(issues, path + ".uri:digest_mismatch")
    size = item.get("size_bytes")
    if type(size) is not int or size < 0:
        _issue(issues, path + ".size_bytes:invalid")
        size = 0
    normalized = {
        "schema": ARTIFACT_REF_SCHEMA,
        "uri": uri,
        "sha256": digest,
        "size_bytes": size,
        "media_type": _media_type(item.get("media_type"), path + ".media_type", issues),
    }
    supplied_digest = item.get("artifact_ref_sha256")
    ref_digest = json_sha256(normalized)
    if supplied_digest is not None and supplied_digest != ref_digest:
        _issue(issues, path + ":artifact_ref_sha256_mismatch")
    return normalized


def validate_artifact_ref(value: Any) -> dict[str, Any]:
    """Validate a content-addressed artifact pointer; embedded bytes fail."""

    issues: list[str] = []
    try:
        normalized = _normalize_artifact_ref(value, "artifact_ref", issues) or {}
        canonical_bytes(normalized)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        _issue(issues, "artifact_ref:hostile_or_non_json_input")
        normalized = {}
    return _report(ARTIFACT_REF_SCHEMA, issues, normalized, "artifact_ref_sha256")


def seal_artifact_ref(value: Any) -> dict[str, Any]:
    report = validate_artifact_ref(value)
    if not report["valid"]:
        raise ContractValidationError(report["issues"])
    return report["normalized"]


def _artifact_refs(value: Any, path: str, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, path + ":not_array")
        return []
    if len(value) > PROFILE.max_array_items:
        _issue(issues, path + ":too_many_items")
        return []
    refs: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        ref = _normalize_artifact_ref(raw, f"{path}[{index}]", issues)
        if ref is not None:
            refs.append(ref)
    identities = [(ref["uri"], ref["sha256"]) for ref in refs]
    if len(identities) != len(set(identities)):
        _issue(issues, path + ":duplicates")
    return sorted(refs, key=lambda ref: (ref["uri"], ref["sha256"]))


def _normalize_claims(
    value: Any,
    issues: list[str],
    *,
    root: str = "handoff",
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, root + ".claims:not_array")
        return []
    if len(value) > PROFILE.max_array_items:
        _issue(issues, root + ".claims:too_many_items")
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        path = f"{root}.claims[{index}]"
        item = _closed(raw, _CLAIM_KEYS, path, issues)
        claim_id = _identifier(item.get("id"), path + ".id", issues)
        if claim_id in seen:
            _issue(issues, root + ".claims:duplicate_id:" + claim_id)
        seen.add(claim_id)
        status = item.get("epistemic_status")
        if status not in CLAIM_EPISTEMIC_STATUSES:
            _issue(issues, path + ".epistemic_status:invalid")
        refs = _artifact_refs(item.get("evidence_refs"), path + ".evidence_refs", issues)
        if status in {"reproduced", "verified"} and not refs:
            _issue(issues, path + ":" + str(status) + "_requires_evidence")
        result.append(
            {
                "id": claim_id,
                "statement": _normalized_text(item.get("statement"), path + ".statement", issues),
                "epistemic_status": status,
                "evidence_refs": refs,
            }
        )
    return sorted(result, key=lambda claim: claim["id"])


def _normalize_checks(
    value: Any,
    issues: list[str],
    *,
    root: str = "handoff",
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, root + ".checks:not_array")
        return []
    if len(value) > PROFILE.max_array_items:
        _issue(issues, root + ".checks:too_many_items")
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        path = f"{root}.checks[{index}]"
        item = _closed(raw, _CHECK_KEYS, path, issues)
        check_id = _identifier(item.get("id"), path + ".id", issues)
        if check_id in seen:
            _issue(issues, root + ".checks:duplicate_id:" + check_id)
        seen.add(check_id)
        status = item.get("status")
        if status not in CHECK_STATUSES:
            _issue(issues, path + ".status:invalid")
        required = item.get("required")
        if type(required) is not bool:
            _issue(issues, path + ".required:invalid")
        refs = _artifact_refs(item.get("evidence_refs"), path + ".evidence_refs", issues)
        if status in {"passed", "failed"} and not refs:
            _issue(issues, path + ":result_requires_evidence")
        result.append(
            {
                "id": check_id,
                "status": status,
                "required": required if type(required) is bool else False,
                "evidence_refs": refs,
            }
        )
    return sorted(result, key=lambda check: check["id"])


def _normalize_conflicts(value: Any, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, "handoff.conflicts:not_array")
        return []
    if len(value) > PROFILE.max_array_items:
        _issue(issues, "handoff.conflicts:too_many_items")
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        path = f"handoff.conflicts[{index}]"
        item = _closed(raw, _CONFLICT_KEYS, path, issues)
        conflict_id = _identifier(item.get("id"), path + ".id", issues)
        if conflict_id in seen:
            _issue(issues, "handoff.conflicts:duplicate_id:" + conflict_id)
        seen.add(conflict_id)
        refs = _artifact_refs(item.get("evidence_refs"), path + ".evidence_refs", issues)
        if not refs:
            _issue(issues, path + ":evidence_required")
        result.append(
            {
                "id": conflict_id,
                "statement": _normalized_text(item.get("statement"), path + ".statement", issues),
                "evidence_refs": refs,
            }
        )
    return sorted(result, key=lambda conflict: conflict["id"])


def _bound_task_spec(task_spec: Any, receipt_digest: Any, issues: list[str]) -> dict[str, Any] | None:
    if task_spec is None:
        _issue(issues, "handoff:task_spec_required")
        return None
    report = validate_task_spec(task_spec)
    if not report["valid"]:
        _issue(issues, "handoff:task_spec_invalid")
        return None
    if receipt_digest != report["digest"]:
        _issue(issues, "handoff:task_spec_digest_mismatch")
    return report["normalized"]


def _normalize_handoff(value: Any, task_spec: Any, issues: list[str]) -> dict[str, Any]:
    if _has_forbidden_history_key(value):
        _issue(issues, "handoff:forbidden_embedded_history")
    item = _closed_sealable(value, _HANDOFF_KEYS, "handoff_sha256", "handoff", issues)
    if item.get("schema") != HANDOFF_RECEIPT_SCHEMA:
        _issue(issues, "handoff:schema_invalid")
    disposition = item.get("disposition")
    if disposition not in HANDOFF_DISPOSITIONS:
        _issue(issues, "handoff.disposition:invalid")
    task_digest = item.get("task_spec_sha256")
    if not isinstance(task_digest, str) or _SHA256.fullmatch(task_digest) is None:
        _issue(issues, "handoff.task_spec_sha256:invalid")
    bound_spec = _bound_task_spec(task_spec, task_digest, issues)

    result_summary = _normalized_text(
        item.get("result_summary"),
        "handoff.result_summary",
        issues,
        max_bytes=MAX_RESULT_SUMMARY_BYTES,
    )
    claims = _normalize_claims(item.get("claims"), issues)
    artifacts = _artifact_refs(
        item.get("artifact_refs"), "handoff.artifact_refs", issues
    )
    checks = _normalize_checks(item.get("checks"), issues)
    conflicts = _normalize_conflicts(item.get("conflicts"), issues)
    unknowns = _text_list(item.get("unknowns"), "handoff.unknowns", issues)
    decisions = _text_list(item.get("requested_decisions"), "handoff.requested_decisions", issues)
    raw_trace = item.get("raw_trace_ref")
    normalized_trace = None
    if raw_trace is not None:
        normalized_trace = _normalize_artifact_ref(raw_trace, "handoff.raw_trace_ref", issues)

    if bound_spec is not None:
        expected = {
            check["id"]: check["required"] for check in bound_spec["acceptance_checks"]
        }
        observed = {check["id"]: check for check in checks}
        for check_id, required in expected.items():
            if check_id not in observed:
                _issue(issues, "handoff.checks:missing_acceptance:" + check_id)
            elif required and observed[check_id]["required"] is not True:
                _issue(issues, "handoff.checks:required_flag_mismatch:" + check_id)
        if disposition == "complete":
            for check_id, required in expected.items():
                if required and observed.get(check_id, {}).get("status") != "passed":
                    _issue(issues, "handoff:complete_with_unpassed_required_check:" + check_id)

    if disposition == "complete":
        if unknowns:
            _issue(issues, "handoff:complete_with_unknowns")
        if conflicts:
            _issue(issues, "handoff:complete_with_conflicts")
        if decisions:
            _issue(issues, "handoff:complete_with_requested_decisions")

    indexed_artifacts = {(ref["uri"], ref["sha256"]) for ref in artifacts}
    for collection_name, records in (
        ("claims", claims),
        ("checks", checks),
        ("conflicts", conflicts),
    ):
        for record in records:
            if any(
                (ref["uri"], ref["sha256"]) not in indexed_artifacts
                for ref in record["evidence_refs"]
            ):
                _issue(
                    issues,
                    "handoff."
                    + collection_name
                    + ":evidence_not_indexed:"
                    + record["id"],
                )
    if normalized_trace is not None and (
        normalized_trace["uri"], normalized_trace["sha256"]
    ) not in indexed_artifacts:
        _issue(issues, "handoff.raw_trace_ref:not_indexed")

    normalized = {
        "schema": HANDOFF_RECEIPT_SCHEMA,
        "disposition": disposition,
        "task_spec_sha256": task_digest,
        "result_summary": result_summary,
        "claims": claims,
        "artifact_refs": artifacts,
        "checks": checks,
        "conflicts": conflicts,
        "unknowns": unknowns,
        "requested_decisions": decisions,
        "raw_trace_ref": normalized_trace,
    }
    supplied_digest = item.get("handoff_sha256")
    digest = json_sha256(normalized)
    if supplied_digest is not None and supplied_digest != digest:
        _issue(issues, "handoff:handoff_sha256_mismatch")
    return normalized


def validate_handoff_receipt(value: Any, *, task_spec: Any = None) -> dict[str, Any]:
    """Validate a bounded, digest-bound handoff without retaining raw history."""

    issues: list[str] = []
    canonical_size = 0
    estimated_tokens = 0
    try:
        normalized = _normalize_handoff(value, task_spec, issues)
        canonical_size = len(canonical_bytes(normalized))
        estimated_tokens = (canonical_size + TOKEN_ESTIMATE_BYTES - 1) // TOKEN_ESTIMATE_BYTES
        if canonical_size > MAX_HANDOFF_CANONICAL_BYTES:
            _issue(issues, "handoff:canonical_bytes_exceeded")
        if estimated_tokens > MAX_HANDOFF_TOKENS:
            _issue(issues, "handoff:token_estimate_exceeded")
    except (HostileInputError, TypeError, ValueError, OverflowError):
        _issue(issues, "handoff:hostile_or_non_json_input")
        normalized = {}
    report = _report(HANDOFF_RECEIPT_SCHEMA, issues, normalized, "handoff_sha256")
    report["canonical_bytes"] = canonical_size if report["valid"] else None
    report["estimated_tokens"] = estimated_tokens if report["valid"] else None
    return report


def seal_handoff_receipt(value: Any, *, task_spec: Any = None) -> dict[str, Any]:
    report = validate_handoff_receipt(value, task_spec=task_spec)
    if not report["valid"]:
        raise ContractValidationError(report["issues"])
    return report["normalized"]


# Sentence limits the template instruction states.  The controller cites the
# whole sealed corpus as one artifact, so a receipt filled with long sentences
# at these limits stays well inside MAX_HANDOFF_CANONICAL_BYTES.  Byte limits
# are never stated: bench samples given them counted characters until their
# output budget ran out.
HANDOFF_TEMPLATE_SUMMARY_SENTENCES = 4
# A soft length target the model can follow without counting characters;
# even at eight bytes a word it stays far below MAX_RESULT_SUMMARY_BYTES.
HANDOFF_TEMPLATE_SUMMARY_WORDS = 80
# Claims are optional in the contract.  Rehearsal 31's only defect was a
# mis-copied citation inside its one claim, so the worker leaves claims empty
# and states findings in result_summary; every remaining citation is prefilled.
HANDOFF_TEMPLATE_MAX_CLAIMS = 0

HANDOFF_TEMPLATE_INSTRUCTION = (
    "Return one JSON object whose schema is exactly " + HANDOFF_RECEIPT_SCHEMA
    + ": handoff_receipt_template filled in as your only output, no markdown, "
    "with exactly these " + str(len(_HANDOFF_KEYS)) + " keys and no others: "
    + ", ".join(sorted(_HANDOFF_KEYS))
    + "; never copy fields from the surrounding message into it. Copy schema, task_spec_sha256, "
    "raw_trace_ref and every artifact_refs entry unchanged, and keep each "
    "checks entry's id, required and evidence_refs unchanged; set only its "
    "status. Every evidence_refs entry is one "
    "complete object copied from artifact_refs with all six of its fields "
    "(artifact_ref_sha256, media_type, schema, sha256, size_bytes, uri), "
    "never a URI string. The disposition describes "
    "your task, not the material you reviewed: use complete when you "
    "performed the task and every required check passed, even if you found "
    "defects, gaps or ambiguities in the material, and report those findings "
    "in result_summary. Use blocked, failed or "
    "needs_decomposition only when you could not perform the task itself, and "
    "then list what prevented it as plain-text unknowns or "
    "requested_decisions; complete requires empty conflicts, unknowns and "
    "requested_decisions. Every statement in result_summary must be "
    "directly supported by explicit text in the review_corpus, in wording "
    "close to the excerpt's; do not generalize across items "
    "(each, every, all, consistent, no contradictions), do not count, and do not "
    "infer states the corpus does not state; never report something as "
    "missing, a gap or an ambiguity merely because the corpus does not mention "
    "it, and describe it as an ambiguity only when two passages explicitly "
    "conflict. A reviewer checks every statement against the corpus. "
    "Set disposition to exactly one "
    "of: " + ", ".join(sorted(HANDOFF_DISPOSITIONS)) + ". Write result_summary "
    "as plain text of at most " + str(HANDOFF_TEMPLATE_SUMMARY_SENTENCES)
    + " short sentences, about " + str(HANDOFF_TEMPLATE_SUMMARY_WORDS)
    + " words in total: summarize what you found instead of restating the "
    "corpus. Leave claims as the empty list. "
    "Set each check "
    "status to exactly one of: " + ", ".join(sorted(CHECK_STATUSES))
    + "."
)


def handoff_receipt_template(task_spec: Any, evidence: Any) -> dict[str, Any]:
    """Build the receipt skeleton a governed continuation hands its worker.

    Every value the worker cannot compute is filled: the schema, the bound
    TaskSpec digest, one content-addressed artifact reference per sealed
    evidence item, and each acceptance check's id and required flag.  The
    worker fills disposition, result_summary, claims and check statuses as
    ``HANDOFF_TEMPLATE_INSTRUCTION`` describes.  Generation 49 told the
    worker only the schema name and it invented a field set.
    """

    report = validate_task_spec(task_spec)
    if not report["valid"]:
        raise ContractValidationError(["handoff_template:task_spec_invalid"])
    spec = report["normalized"]
    if spec["deliverable"]["schema"] != HANDOFF_RECEIPT_SCHEMA:
        raise ContractValidationError(["handoff_template:deliverable_not_handoff"])
    if not isinstance(evidence, list) or not evidence:
        raise ContractValidationError(["handoff_template:evidence_required"])
    refs = [
        seal_artifact_ref(
            {
                "schema": ARTIFACT_REF_SCHEMA,
                "uri": "artifact://sha256/" + str(row.get("sha256")),
                "sha256": row.get("sha256"),
                "size_bytes": row.get("size_bytes"),
                "media_type": row.get("media_type"),
            }
        )
        for row in evidence
        if isinstance(row, Mapping)
    ]
    if len(refs) != len(evidence):
        raise ContractValidationError(["handoff_template:evidence_invalid"])
    ordered_refs = sorted(refs, key=lambda ref: (ref["uri"], ref["sha256"]))
    return {
        "schema": HANDOFF_RECEIPT_SCHEMA,
        "task_spec_sha256": report["digest"],
        "disposition": "blocked",
        "result_summary": "",
        "claims": [],
        "artifact_refs": ordered_refs,
        "checks": [
            {
                "id": check["id"],
                "required": check["required"],
                "status": "not_run",
                # Prefilled so a worker sets only the status; run 13's worker
                # cited a bare URI string when left to copy the reference.
                "evidence_refs": [deepcopy(ordered_refs[0])],
            }
            for check in spec["acceptance_checks"]
        ],
        "conflicts": [],
        "unknowns": [],
        "requested_decisions": [],
        "raw_trace_ref": None,
    }


def _task_for_runtime_contract(
    task_spec: Any,
    task_digest: Any,
    issues: list[str],
    *,
    root: str,
) -> dict[str, Any] | None:
    if task_spec is None:
        _issue(issues, root + ":task_spec_required")
        return None
    report = validate_task_spec(task_spec)
    if not report["valid"]:
        _issue(issues, root + ":task_spec_invalid")
        return None
    if task_digest != report["digest"]:
        _issue(issues, root + ":task_spec_digest_mismatch")
    return report["normalized"]


def _progress_usage(value: Any, path: str, issues: list[str]) -> dict[str, Any]:
    item = _closed(value, _PROGRESS_USAGE_KEYS, path, issues)
    status = item.get("status")
    if status != "observed":
        _issue(issues, path + ":runtime_observation_required")
    normalized: dict[str, Any] = {"status": status}
    for field in ("input_tokens", "output_tokens", "total_tokens", "tool_calls"):
        number = item.get(field)
        if type(number) is not int or number < 0:
            _issue(issues, path + "." + field + ":invalid")
            number = 0
        normalized[field] = number
    if normalized["total_tokens"] != (
        normalized["input_tokens"] + normalized["output_tokens"]
    ):
        _issue(issues, path + ":token_arithmetic_invalid")
    return normalized


def _check_task_budgets(
    spec: Mapping[str, Any] | None,
    usage: Mapping[str, Any],
    issues: list[str],
    *,
    root: str,
) -> None:
    if spec is None:
        return
    budgets = spec.get("budgets", {})
    comparisons = (
        ("context_tokens", "input_tokens", "context_budget_exceeded"),
        ("output_tokens", "output_tokens", "output_budget_exceeded"),
        ("tool_calls", "tool_calls", "tool_budget_exceeded"),
    )
    for budget_field, usage_field, issue in comparisons:
        limit = budgets.get(budget_field)
        observed = usage.get(usage_field)
        if type(limit) is int and type(observed) is int and observed > limit:
            _issue(issues, root + ":" + issue)


def _normalize_incremental_claim_packet(
    value: Any,
    task_spec: Any,
    issues: list[str],
) -> dict[str, Any]:
    item = _closed_sealable(
        value,
        _INCREMENTAL_PACKET_KEYS,
        "packet_sha256",
        "incremental",
        issues,
    )
    if item.get("schema") != INCREMENTAL_CLAIM_PACKET_SCHEMA:
        _issue(issues, "incremental:schema_invalid")
    packet_id = _identifier(item.get("packet_id"), "incremental.packet_id", issues)
    task_digest = item.get("task_spec_sha256")
    if not isinstance(task_digest, str) or _SHA256.fullmatch(task_digest) is None:
        _issue(issues, "incremental.task_spec_sha256:invalid")
    spec = _task_for_runtime_contract(
        task_spec,
        task_digest,
        issues,
        root="incremental",
    )
    sequence = item.get("sequence")
    if type(sequence) is not int or sequence < 1:
        _issue(issues, "incremental.sequence:invalid")
        sequence = 0
    claims = _normalize_claims(item.get("claims"), issues, root="incremental")
    artifacts = _artifact_refs(
        item.get("artifact_refs"),
        "incremental.artifact_refs",
        issues,
    )
    checks = _normalize_checks(item.get("checks"), issues, root="incremental")
    if not claims and not checks:
        _issue(issues, "incremental:empty")
    indexed = {(ref["uri"], ref["sha256"]) for ref in artifacts}
    for collection_name, records in (("claims", claims), ("checks", checks)):
        for record in records:
            if any(
                (ref["uri"], ref["sha256"]) not in indexed
                for ref in record["evidence_refs"]
            ):
                _issue(
                    issues,
                    "incremental."
                    + collection_name
                    + ":evidence_not_indexed:"
                    + record["id"],
                )
    usage = _progress_usage(item.get("usage"), "incremental.usage", issues)
    _check_task_budgets(spec, usage, issues, root="incremental")
    normalized = {
        "schema": INCREMENTAL_CLAIM_PACKET_SCHEMA,
        "packet_id": packet_id,
        "task_spec_sha256": task_digest,
        "sequence": sequence,
        "claims": claims,
        "artifact_refs": artifacts,
        "checks": checks,
        "usage": usage,
        "source_pointer": _normalized_text(
            item.get("source_pointer"),
            "incremental.source_pointer",
            issues,
            max_bytes=PROFILE.max_path_bytes,
        ),
    }
    supplied = item.get("packet_sha256")
    digest = json_sha256(normalized)
    if supplied is not None and supplied != digest:
        _issue(issues, "incremental:packet_sha256_mismatch")
    return normalized


def validate_incremental_claim_packet(
    value: Any,
    *,
    task_spec: Any = None,
) -> dict[str, Any]:
    """Validate one compact evidence-backed progress packet."""

    issues: list[str] = []
    canonical_size = 0
    estimated_tokens = 0
    try:
        normalized = _normalize_incremental_claim_packet(value, task_spec, issues)
        canonical_size = len(canonical_bytes(normalized))
        estimated_tokens = (
            canonical_size + TOKEN_ESTIMATE_BYTES - 1
        ) // TOKEN_ESTIMATE_BYTES
        if canonical_size > MAX_INCREMENTAL_PACKET_CANONICAL_BYTES:
            _issue(issues, "incremental:canonical_bytes_exceeded")
        if estimated_tokens > MAX_INCREMENTAL_PACKET_TOKENS:
            _issue(issues, "incremental:token_estimate_exceeded")
    except (HostileInputError, TypeError, ValueError, OverflowError):
        _issue(issues, "incremental:hostile_or_non_json_input")
        normalized = {}
    report = _report(
        INCREMENTAL_CLAIM_PACKET_SCHEMA,
        issues,
        normalized,
        "packet_sha256",
    )
    report["canonical_bytes"] = canonical_size if report["valid"] else None
    report["estimated_tokens"] = estimated_tokens if report["valid"] else None
    return report


def seal_incremental_claim_packet(
    value: Any,
    *,
    task_spec: Any = None,
) -> dict[str, Any]:
    report = validate_incremental_claim_packet(value, task_spec=task_spec)
    if not report["valid"]:
        raise ContractValidationError(report["issues"])
    return report["normalized"]


def _normalize_route(
    value: Any,
    fields: frozenset[str],
    path: str,
    issues: list[str],
) -> dict[str, str]:
    item = _closed(value, fields, path, issues)
    normalized = {
        field: _identifier(item.get(field), path + "." + field, issues)
        for field in sorted(fields)
    }
    if normalized.get("context_policy") != "none":
        _issue(issues, path + ".context_policy:must_be_none")
    return normalized


def _normalize_handoff_preflight_candidate(
    value: Any,
    task_spec: Any,
    issues: list[str],
) -> dict[str, Any]:
    """Normalize only facts a tool-free canary can truthfully author."""

    item = _closed(
        value,
        _HANDOFF_PREFLIGHT_CANDIDATE_KEYS,
        "preflight_candidate",
        issues,
    )
    if item.get("schema") != HANDOFF_PREFLIGHT_CANDIDATE_SCHEMA:
        _issue(issues, "preflight_candidate:schema_invalid")
    preflight_id = _identifier(
        item.get("preflight_id"),
        "preflight_candidate.preflight_id",
        issues,
    )
    task_digest = item.get("task_spec_sha256")
    if not isinstance(task_digest, str) or _SHA256.fullmatch(task_digest) is None:
        _issue(issues, "preflight_candidate.task_spec_sha256:invalid")
    spec = _task_for_runtime_contract(
        task_spec,
        task_digest,
        issues,
        root="preflight_candidate",
    )
    if spec is not None and spec.get("allowed_tools"):
        _issue(issues, "preflight_candidate:canary_tools_present")
    if item.get("capability_profile") != "tool-free-canary":
        _issue(issues, "preflight_candidate:capability_profile_invalid")

    handoff_report = validate_handoff_receipt(
        item.get("handoff_receipt"),
        task_spec=task_spec,
    )
    if not handoff_report["valid"]:
        _issue(issues, "preflight_candidate:handoff_invalid")

    return {
        "schema": HANDOFF_PREFLIGHT_CANDIDATE_SCHEMA,
        "preflight_id": preflight_id,
        "task_spec_sha256": task_digest,
        "capability_profile": item.get("capability_profile"),
        "handoff_receipt": handoff_report.get("normalized"),
    }


def validate_handoff_preflight_candidate(
    value: Any,
    *,
    task_spec: Any = None,
) -> dict[str, Any]:
    """Validate a canary terminal without accepting self-authored runtime facts."""

    issues: list[str] = []
    try:
        normalized = _normalize_handoff_preflight_candidate(
            value,
            task_spec,
            issues,
        )
        canonical_bytes(normalized)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        _issue(issues, "preflight_candidate:hostile_or_non_json_input")
        normalized = {}
    report = _report(
        HANDOFF_PREFLIGHT_CANDIDATE_SCHEMA,
        issues,
        normalized,
        "candidate_sha256",
    )
    report.update(
        {
            "candidate_valid": report["valid"],
            "spawn_permitted": False,
            "evidence_tier": "submitted",
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    )
    return report


def seal_handoff_preflight_candidate(
    value: Any,
    *,
    task_spec: Any = None,
) -> dict[str, Any]:
    """Return the canonical five-field submitted candidate.

    Unlike sealable runtime evidence, the preflight candidate deliberately
    cannot carry self-authored digest evidence.  Its digest remains in the
    validator's whole report for the observer-bound request constructor.
    """

    report = validate_handoff_preflight_candidate(value, task_spec=task_spec)
    if not report["valid"]:
        raise ContractValidationError(report["issues"])
    normalized = deepcopy(report["normalized"])
    normalized.pop("candidate_sha256", None)
    return normalized


def _normalize_handoff_preflight(
    value: Any,
    task_spec: Any,
    issues: list[str],
) -> tuple[dict[str, Any], str | None]:
    item = _closed_sealable(
        value,
        _HANDOFF_PREFLIGHT_KEYS,
        "preflight_sha256",
        "preflight",
        issues,
    )
    if item.get("schema") != HANDOFF_PREFLIGHT_SCHEMA:
        _issue(issues, "preflight:schema_invalid")
    preflight_id = _identifier(
        item.get("preflight_id"), "preflight.preflight_id", issues
    )
    task_digest = item.get("task_spec_sha256")
    if not isinstance(task_digest, str) or _SHA256.fullmatch(task_digest) is None:
        _issue(issues, "preflight.task_spec_sha256:invalid")
    spec = _task_for_runtime_contract(
        task_spec,
        task_digest,
        issues,
        root="preflight",
    )
    if spec is not None and spec.get("allowed_tools"):
        _issue(issues, "preflight:canary_tools_present")
    expected_route = _normalize_route(
        item.get("expected_route"),
        _EXPECTED_ROUTE_KEYS,
        "preflight.expected_route",
        issues,
    )
    observed_route = _normalize_route(
        item.get("observed_route"),
        _OBSERVED_ROUTE_KEYS,
        "preflight.observed_route",
        issues,
    )
    for field in ("model", "effort", "context_policy"):
        if expected_route.get(field) != observed_route.get(field):
            _issue(issues, "preflight:route_mismatch:" + field)
    if item.get("capability_profile") != "tool-free-canary":
        _issue(issues, "preflight:capability_profile_invalid")

    handoff_report = validate_handoff_receipt(
        item.get("handoff_receipt"),
        task_spec=task_spec,
    )
    if not handoff_report["valid"]:
        _issue(issues, "preflight:handoff_invalid")
    handoff = handoff_report.get("normalized")

    raw_packets = item.get("incremental_packets")
    if not isinstance(raw_packets, list) or not raw_packets:
        _issue(issues, "preflight:incremental_packets_required")
        raw_packets = []
    packets: list[dict[str, Any]] = []
    for index, packet in enumerate(raw_packets):
        packet_report = validate_incremental_claim_packet(
            packet,
            task_spec=task_spec,
        )
        if not packet_report["valid"]:
            _issue(issues, f"preflight:incremental_packet_invalid:{index}")
        elif packet_report.get("normalized") is not None:
            packets.append(packet_report["normalized"])
    if [packet.get("sequence") for packet in packets] != list(
        range(1, len(packets) + 1)
    ):
        _issue(issues, "preflight:incremental_sequence_not_contiguous")
    for previous, current in zip(packets, packets[1:]):
        previous_usage = previous.get("usage", {})
        current_usage = current.get("usage", {})
        if any(
            type(previous_usage.get(field)) is int
            and type(current_usage.get(field)) is int
            and current_usage[field] < previous_usage[field]
            for field in ("input_tokens", "output_tokens", "total_tokens", "tool_calls")
        ):
            _issue(issues, "preflight:incremental_usage_not_monotonic")
            break

    observed_usage = _progress_usage(
        item.get("observed_usage"),
        "preflight.observed_usage",
        issues,
    )
    if observed_usage.get("tool_calls") != 0 or any(
        packet.get("usage", {}).get("tool_calls") != 0 for packet in packets
    ):
        _issue(issues, "preflight:canary_tool_calls_observed")
    if packets:
        latest_usage = packets[-1].get("usage", {})
        if any(
            type(latest_usage.get(field)) is int
            and type(observed_usage.get(field)) is int
            and observed_usage[field] < latest_usage[field]
            for field in ("input_tokens", "output_tokens", "total_tokens", "tool_calls")
        ):
            _issue(issues, "preflight:observed_usage_precedes_progress")
    _check_task_budgets(spec, observed_usage, issues, root="preflight")
    if (
        spec is not None
        and handoff_report.get("estimated_tokens") is not None
        and handoff_report["estimated_tokens"] > spec["budgets"]["handoff_tokens"]
    ):
        _issue(issues, "preflight:handoff_budget_exceeded")

    evidence_value = _closed(
        item.get("evidence"),
        _PREFLIGHT_EVIDENCE_KEYS,
        "preflight.evidence",
        issues,
    )
    tier = evidence_value.get("tier")
    if tier != "runtime_observed":
        _issue(issues, "preflight:evidence_not_runtime_observed")
    evidence = {
        "tier": tier,
        "source_pointer": _normalized_text(
            evidence_value.get("source_pointer"),
            "preflight.evidence.source_pointer",
            issues,
            max_bytes=PROFILE.max_path_bytes,
        ),
        "source_sha256": evidence_value.get("source_sha256"),
    }
    if not isinstance(evidence["source_sha256"], str) or _SHA256.fullmatch(
        evidence["source_sha256"]
    ) is None:
        _issue(issues, "preflight.evidence.source_sha256:invalid")

    normalized = {
        "schema": HANDOFF_PREFLIGHT_SCHEMA,
        "preflight_id": preflight_id,
        "task_spec_sha256": task_digest,
        "expected_route": expected_route,
        "observed_route": observed_route,
        "capability_profile": item.get("capability_profile"),
        "handoff_receipt": handoff,
        "incremental_packets": packets,
        "observed_usage": observed_usage,
        "evidence": evidence,
    }
    supplied = item.get("preflight_sha256")
    digest = json_sha256(normalized)
    if supplied is not None and supplied != digest:
        _issue(issues, "preflight:preflight_sha256_mismatch")
    return normalized, tier if isinstance(tier, str) else None


def validate_handoff_preflight(
    value: Any,
    *,
    task_spec: Any = None,
) -> dict[str, Any]:
    """Gate substantive spawn on one route-exact typed-output canary."""

    issues: list[str] = []
    tier = None
    try:
        normalized, tier = _normalize_handoff_preflight(value, task_spec, issues)
        canonical_bytes(normalized)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        _issue(issues, "preflight:hostile_or_non_json_input")
        normalized = {}
    report = _report(
        HANDOFF_PREFLIGHT_SCHEMA,
        issues,
        normalized,
        "preflight_sha256",
    )
    report.update(
        {
            "spawn_permitted": report["valid"],
            "evidence_tier": tier if report["valid"] else "submitted",
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    )
    return report


def seal_handoff_preflight(
    value: Any,
    *,
    task_spec: Any = None,
) -> dict[str, Any]:
    report = validate_handoff_preflight(value, task_spec=task_spec)
    if not report["valid"]:
        raise ContractValidationError(report["issues"])
    return report["normalized"]


def _verification_acceptance(value: Any, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        _issue(issues, "verification.acceptance_criteria:invalid")
        return []
    if len(value) > PROFILE.max_array_items:
        _issue(issues, "verification.acceptance_criteria:too_many_items")
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        path = f"verification.acceptance_criteria[{index}]"
        item = _closed(raw, _ACCEPTANCE_KEYS, path, issues)
        criterion_id = _identifier(item.get("id"), path + ".id", issues)
        if criterion_id in seen:
            _issue(issues, "verification.acceptance_criteria:duplicate_id:" + criterion_id)
        seen.add(criterion_id)
        required = item.get("required")
        if type(required) is not bool:
            _issue(issues, path + ".required:invalid")
        result.append(
            {
                "id": criterion_id,
                "description": _normalized_text(item.get("description"), path + ".description", issues),
                "required": required if type(required) is bool else False,
            }
        )
    return sorted(result, key=lambda criterion: criterion["id"])


def _verification_checks(value: Any, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        _issue(issues, "verification.check_results:invalid")
        return []
    if len(value) > PROFILE.max_array_items:
        _issue(issues, "verification.check_results:too_many_items")
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        path = f"verification.check_results[{index}]"
        item = _closed(raw, _CHECK_KEYS, path, issues)
        check_id = _identifier(item.get("id"), path + ".id", issues)
        if check_id in seen:
            _issue(issues, "verification.check_results:duplicate_id:" + check_id)
        seen.add(check_id)
        status = item.get("status")
        if status not in CHECK_STATUSES:
            _issue(issues, path + ".status:invalid")
        required = item.get("required")
        if type(required) is not bool:
            _issue(issues, path + ".required:invalid")
        refs = _artifact_refs(item.get("evidence_refs"), path + ".evidence_refs", issues)
        result.append(
            {
                "id": check_id,
                "status": status,
                "required": required if type(required) is bool else False,
                "evidence_refs": refs,
            }
        )
    return sorted(result, key=lambda check: check["id"])


def _verification_findings(value: Any, issues: list[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, "verification.findings:not_array")
        return []
    if len(value) > PROFILE.max_array_items:
        _issue(issues, "verification.findings:too_many_items")
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        path = f"verification.findings[{index}]"
        item = _closed(raw, _FINDING_KEYS, path, issues)
        finding_id = _identifier(item.get("id"), path + ".id", issues)
        if finding_id in seen:
            _issue(issues, "verification.findings:duplicate_id:" + finding_id)
        seen.add(finding_id)
        severity = item.get("severity")
        if severity not in FINDING_SEVERITIES:
            _issue(issues, path + ".severity:invalid")
        refs = _artifact_refs(item.get("evidence_refs"), path + ".evidence_refs", issues)
        if not refs:
            _issue(issues, path + ":evidence_required")
        result.append(
            {
                "id": finding_id,
                "severity": severity,
                "statement": _normalized_text(item.get("statement"), path + ".statement", issues),
                "evidence_refs": refs,
            }
        )
    return sorted(result, key=lambda finding: finding["id"])


def _verification_task_spec(task_spec: Any, receipt_digest: Any, issues: list[str]) -> dict[str, Any] | None:
    if task_spec is None:
        _issue(issues, "verification:task_spec_required")
        return None
    report = validate_task_spec(task_spec)
    if not report["valid"]:
        _issue(issues, "verification:task_spec_invalid")
        return None
    if receipt_digest != report["digest"]:
        _issue(issues, "verification:task_spec_digest_mismatch")
    return report["normalized"]


def _verification_handoff(
    handoff_receipt: Any,
    task_spec: Any,
    subject_digest: Any,
    issues: list[str],
) -> dict[str, Any] | None:
    if handoff_receipt is None:
        _issue(issues, "verification:handoff_required")
        return None
    report = validate_handoff_receipt(handoff_receipt, task_spec=task_spec)
    if not report["valid"]:
        _issue(issues, "verification:handoff_invalid")
        return None
    if subject_digest != report["digest"]:
        _issue(issues, "verification:subject_handoff_digest_mismatch")
    return report["normalized"]


def _normalize_verification(
    value: Any,
    task_spec: Any,
    handoff_receipt: Any,
    issues: list[str],
) -> dict[str, Any]:
    if _has_forbidden_history_key(value):
        _issue(issues, "verification:forbidden_embedded_history")
    item = _closed_sealable(
        value,
        _VERIFICATION_KEYS,
        "verification_sha256",
        "verification",
        issues,
    )
    if item.get("schema") != VERIFICATION_RECEIPT_SCHEMA:
        _issue(issues, "verification:schema_invalid")
    task_digest = item.get("task_spec_sha256")
    if not isinstance(task_digest, str) or _SHA256.fullmatch(task_digest) is None:
        _issue(issues, "verification.task_spec_sha256:invalid")
    spec = _verification_task_spec(task_spec, task_digest, issues)
    subject_digest = item.get("subject_handoff_sha256")
    if not isinstance(subject_digest, str) or _SHA256.fullmatch(subject_digest) is None:
        _issue(issues, "verification.subject_handoff_sha256:invalid")
    handoff = _verification_handoff(
        handoff_receipt,
        task_spec,
        subject_digest,
        issues,
    )

    artifacts = _artifact_refs(item.get("artifact_refs"), "verification.artifact_refs", issues)
    diffs = _artifact_refs(item.get("diff_refs"), "verification.diff_refs", issues)
    criteria = _verification_acceptance(item.get("acceptance_criteria"), issues)
    checks = _verification_checks(item.get("check_results"), issues)

    implementer = _identifier(
        item.get("implementer_identity"),
        "verification.implementer_identity",
        issues,
    )
    verifier_value = _closed(item.get("verifier"), _VERIFIER_KEYS, "verification.verifier", issues)
    verifier = {
        "identity": _identifier(
            verifier_value.get("identity"), "verification.verifier.identity", issues
        ),
        "clean_context": verifier_value.get("clean_context")
        if type(verifier_value.get("clean_context")) is bool
        else False,
    }
    if type(verifier_value.get("clean_context")) is not bool:
        _issue(issues, "verification.verifier.clean_context:invalid")

    disposition = item.get("disposition")
    if disposition not in VERIFICATION_DISPOSITIONS:
        _issue(issues, "verification.disposition:invalid")
    passed = item.get("pass")
    if type(passed) is not bool:
        _issue(issues, "verification.pass:invalid")
        passed = False
    if passed != (disposition == "pass"):
        _issue(issues, "verification:disposition_pass_mismatch")
    findings = _verification_findings(item.get("findings"), issues)

    if spec is not None:
        expected = spec["acceptance_checks"]
        if criteria != expected:
            _issue(issues, "verification:acceptance_criteria_mismatch")
        expected_by_id = {criterion["id"]: criterion for criterion in expected}
        checks_by_id = {check["id"]: check for check in checks}
        for check_id, criterion in expected_by_id.items():
            check = checks_by_id.get(check_id)
            if check is None:
                _issue(issues, "verification.check_results:missing_acceptance:" + check_id)
            elif check["required"] != criterion["required"]:
                _issue(issues, "verification.check_results:required_flag_mismatch:" + check_id)

    if passed:
        misleading = False
        if not artifacts:
            _issue(issues, "verification:pass_without_artifacts")
            misleading = True
        if spec is not None and spec["kind"] == "execute" and not diffs:
            _issue(issues, "verification:pass_without_diffs")
            misleading = True
        if handoff is None or handoff["disposition"] != "complete":
            _issue(issues, "verification:pass_without_complete_handoff")
            misleading = True
        elif not {
            (ref["uri"], ref["sha256"]) for ref in handoff["artifact_refs"]
        }.issubset({(ref["uri"], ref["sha256"]) for ref in artifacts}):
            _issue(issues, "verification:handoff_artifacts_not_covered")
            misleading = True
        if implementer and verifier["identity"] == implementer:
            _issue(issues, "verification:implementer_is_verifier")
            misleading = True
        if verifier["clean_context"] is not True:
            _issue(issues, "verification:pass_without_clean_context")
            misleading = True
        for check in checks:
            if check["required"] and check["status"] != "passed":
                misleading = True
            if check["status"] == "passed" and not check["evidence_refs"]:
                _issue(issues, "verification:pass_without_check_evidence")
                misleading = True
        if any(finding["severity"] == "error" for finding in findings):
            misleading = True
        if misleading:
            _issue(issues, "verification:misleading_pass")

    normalized = {
        "schema": VERIFICATION_RECEIPT_SCHEMA,
        "task_spec_sha256": task_digest,
        "subject_handoff_sha256": subject_digest,
        "artifact_refs": artifacts,
        "diff_refs": diffs,
        "acceptance_criteria": criteria,
        "check_results": checks,
        "implementer_identity": implementer,
        "verifier": verifier,
        "disposition": disposition,
        "pass": passed,
        "findings": findings,
    }
    supplied_digest = item.get("verification_sha256")
    digest = json_sha256(normalized)
    if supplied_digest is not None and supplied_digest != digest:
        _issue(issues, "verification:verification_sha256_mismatch")
    return normalized


def validate_verification_receipt(
    value: Any,
    *,
    task_spec: Any = None,
    handoff_receipt: Any = None,
) -> dict[str, Any]:
    """Validate an independent clean-context verification receipt."""

    issues: list[str] = []
    try:
        normalized = _normalize_verification(
            value,
            task_spec,
            handoff_receipt,
            issues,
        )
        canonical_bytes(normalized)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        _issue(issues, "verification:hostile_or_non_json_input")
        normalized = {}
    return _report(
        VERIFICATION_RECEIPT_SCHEMA,
        issues,
        normalized,
        "verification_sha256",
    )


def seal_verification_receipt(
    value: Any,
    *,
    task_spec: Any = None,
    handoff_receipt: Any = None,
) -> dict[str, Any]:
    report = validate_verification_receipt(
        value,
        task_spec=task_spec,
        handoff_receipt=handoff_receipt,
    )
    if not report["valid"]:
        raise ContractValidationError(report["issues"])
    return report["normalized"]


def _normalize_claim_ledger(value: Any, task_spec: Any, issues: list[str]) -> dict[str, Any]:
    if _has_forbidden_history_key(value):
        _issue(issues, "claim_ledger:forbidden_embedded_history")
    item = _closed_sealable(
        value,
        _CLAIM_LEDGER_KEYS,
        "ledger_sha256",
        "claim_ledger",
        issues,
    )
    if item.get("schema") != CLAIM_LEDGER_SCHEMA:
        _issue(issues, "claim_ledger:schema_invalid")
    task_digest = item.get("task_spec_sha256")
    if not isinstance(task_digest, str) or _SHA256.fullmatch(task_digest) is None:
        _issue(issues, "claim_ledger.task_spec_sha256:invalid")
    if task_spec is None:
        _issue(issues, "claim_ledger:task_spec_required")
    else:
        task_report = validate_task_spec(task_spec)
        if not task_report["valid"]:
            _issue(issues, "claim_ledger:task_spec_invalid")
        elif task_digest != task_report["digest"]:
            _issue(issues, "claim_ledger:task_spec_digest_mismatch")

    normalized = {
        "schema": CLAIM_LEDGER_SCHEMA,
        "task_spec_sha256": task_digest,
        "claims": _normalize_claims(item.get("claims"), issues, root="claim_ledger"),
        "artifacts": _artifact_refs(item.get("artifacts"), "claim_ledger.artifacts", issues),
    }
    evidence_identities = {
        (ref["uri"], ref["sha256"])
        for ref in normalized["artifacts"]
    }
    for claim in normalized["claims"]:
        for ref in claim["evidence_refs"]:
            if (ref["uri"], ref["sha256"]) not in evidence_identities:
                _issue(issues, "claim_ledger.claims:evidence_not_in_artifacts:" + claim["id"])
    supplied_digest = item.get("ledger_sha256")
    digest = json_sha256(normalized)
    if supplied_digest is not None and supplied_digest != digest:
        _issue(issues, "claim_ledger:ledger_sha256_mismatch")
    return normalized


def validate_claim_ledger(value: Any, *, task_spec: Any = None) -> dict[str, Any]:
    """Validate the minimal content-addressed claim ledger projection."""

    issues: list[str] = []
    try:
        normalized = _normalize_claim_ledger(value, task_spec, issues)
        canonical_bytes(normalized)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        _issue(issues, "claim_ledger:hostile_or_non_json_input")
        normalized = {}
    return _report(CLAIM_LEDGER_SCHEMA, issues, normalized, "ledger_sha256")


def seal_claim_ledger(value: Any, *, task_spec: Any = None) -> dict[str, Any]:
    report = validate_claim_ledger(value, task_spec=task_spec)
    if not report["valid"]:
        raise ContractValidationError(report["issues"])
    return report["normalized"]
