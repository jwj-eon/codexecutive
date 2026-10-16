#!/usr/bin/env python3
"""Provider-free WorkerTransport wire contracts.

Issue 30 deliberately starts with the contract rather than a model adapter.
This module contains only JSON-compatible validation, canonical hashing, and a
small single-flight transport shell.  It never contacts a provider, starts a
runtime, executes a command, applies a patch, or writes a workspace.

The wire objects are closed dictionaries.  ``validate_*`` functions return a
deterministic report so policy code can inspect all failures at once;
``require_*`` wrappers raise :class:`WorkerContractError` for callers that
need a hard boundary.  ``WorkerCall`` and ``WorkerResult`` are dict subclasses
only to make the public protocol pleasant to use while retaining ordinary
JSON serialisability.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re
import threading
from typing import Any, Callable, Mapping, Sequence


# Versioned wire identities.  Keep aliases below for consumers that use the
# shorter names, but do not accept aliases in validation input.
TRANSPORT_SCHEMA = "orch-dork/worker-transport/v1"
WORKER_CALL_SCHEMA = "orch-dork/worker-call/v1"
WORKER_RESULT_SCHEMA = "orch-dork/worker-result/v1"
MODEL_MANIFEST_SCHEMA = "orch-dork/model-manifest/v1"
HOSTED_WORKER_RESULT_SCHEMA = "orch-dork/hosted-worker-result/v1"
HOSTED_MODEL_MANIFEST_SCHEMA = "orch-dork/hosted-model-manifest/v1"
CAPABILITY_PROFILE_SCHEMA = "orch-dork/capability-profile/v1"
CAPABILITY_PROGRAM_SCHEMA = "orch-dork/capability-program/v1"
VALIDATION_REPORT_SCHEMA = "orch-dork/worker-validation-report/v1"

# Public compatibility aliases.  These are constants, not alternate input
# schemas, so validation remains strict and unambiguous.
CALL_SCHEMA = WORKER_CALL_SCHEMA
RESULT_SCHEMA = WORKER_RESULT_SCHEMA
MANIFEST_SCHEMA = MODEL_MANIFEST_SCHEMA
PROFILE_SCHEMA = CAPABILITY_PROFILE_SCHEMA

RESULT_STATUSES = frozenset(
    {
        "CANDIDATE_READY",
        "REJECTED",
        "UNAVAILABLE",
        "CANCELLED",
        "TIMED_OUT",
        "DELIVERY_UNCERTAIN",
        "RECOVERY_PENDING",
    }
)
CAPABILITY_OUTCOME = "UNSUPPORTED_CAPABILITY"
KNOWN_RESULT_STATUSES = RESULT_STATUSES

_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_FORBIDDEN_KEY = re.compile(
    r"(?:credential|password|passwd|secret|authorization|access[_-]?token|"
    r"refresh[_-]?token|api[_-]?key|private[_-]?key|endpoint|provider|"
    r"(?:^|[_-])url$|command|argv|shell|exec|writable[_-]?path|"
    r"test[_-]?command|retry|fallback|resampl|substitut)",
    re.IGNORECASE,
)
_FORBIDDEN_VALUE = re.compile(
    r"(?:-----BEGIN [^-]*PRIVATE KEY-----|\bBearer\s+\S+|"
    r"\b(?:sk|gh[pousr]|xox[baprs])[-_][A-Za-z0-9_-]{8,}|"
    r"\bAKIA[0-9A-Z]{12,})",
    re.IGNORECASE,
)

_CALL_KEYS = {
    "schema",
    "call_id",
    "assignment",
    "lane_policy",
    "base_revision",
    "required_capabilities",
    "authority_ref",
    "idempotency_key",
    "budgets",
}
_ASSIGNMENT_KEYS = {
    "assignment_id",
    "lane_id",
    "objective",
    "input_sha256",
    "source_pointer",
}
_LANE_POLICY_KEYS = {"policy_id", "policy_revision", "policy_sha256", "registry_ref"}
_BASE_REVISION_KEYS = {"repository_id", "revision", "tree_sha256", "source_pointer"}
_AUTHORITY_KEYS = {"authority_id", "grant_id", "scope_sha256"}
_BUDGET_KEYS = {
    "wall_time_ms",
    "generation_count",
    "token_count",
    "tool_call_count",
    "child_count",
    "concurrency",
}

_RESULT_KEYS = {
    "schema",
    "result_id",
    "call_id",
    "status",
    "candidate",
    "tests",
    "usage",
    "timing",
    "runtime",
    "evidence",
    "reason",
}
_CANDIDATE_KEYS = {"status", "diff", "diff_sha256", "applied"}
_TEST_KEYS = {"status", "report", "report_sha256"}
_USAGE_KEYS = {"status", "input_tokens", "output_tokens", "total_tokens"}
_TIMING_KEYS = {"status", "wall_time_ms"}
_RUNTIME_KEYS = {
    "status",
    "logical_model_id",
    "served_name",
    "checkpoint_revision",
    "runtime_id",
}
_HOSTED_RUNTIME_KEYS = _RUNTIME_KEYS | {"onboarded_profile_sha256"}
_EVIDENCE_KEYS = {
    "status",
    "reference",
    "sha256",
    "call_sha256",
    "manifest_sha256",
}

_MANIFEST_KEYS = {
    "schema",
    "manifest_id",
    "version",
    "logical_model_id",
    "served_names",
    "checkpoint_revision",
    "weight_digest_sha256",
    "context_limit_tokens",
    "output_limit_tokens",
    "protocols",
    "capabilities",
    "quantization",
    "runtime",
    "allowed_tool_profiles",
}
_HOSTED_MANIFEST_KEYS = (
    _MANIFEST_KEYS - {"checkpoint_revision", "weight_digest_sha256", "quantization"}
) | {"onboarded_profile_sha256"}
_QUANTIZATION_KEYS = {"scheme", "bits"}
_RUNTIME_IDENTITY_KEYS = {"name", "version"}
_PROGRAM_KEYS = {
    "schema",
    "program_id",
    "requested_profile",
    "required_capabilities",
    "manifest",
}


class WorkerContractError(ValueError):
    """Raised by ``require_*`` helpers for an invalid closed wire object."""

    def __init__(self, issues: Sequence[str], *, code: str = "INVALID_CONTRACT"):
        self.issues = tuple(sorted({str(item) for item in issues}))
        self.code = str(code)
        text = ", ".join(self.issues) if self.issues else self.code
        super().__init__(f"{self.code}: {text}")


class WorkerValidationError(WorkerContractError):
    """Compatibility name for code that distinguishes validation failures."""


def canonical_json(value: Any) -> str:
    """Serialize JSON-compatible data using one deterministic representation."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise WorkerContractError(("canonical_json:not_json_compatible",)) from exc


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Hash the canonical JSON form of ``value``."""

    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def content_sha256(value: str | bytes) -> str:
    """Hash textual evidence/diffs as bytes, without JSON string quoting."""

    data = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return hashlib.sha256(data).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, fields: set[str], path: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, f"{path}:not_object")
        return False
    keys = set(value)
    for field in sorted(fields - keys):
        _issue(issues, f"{path}:missing:{field}")
    for field in sorted(keys - fields):
        _issue(issues, f"{path}:unknown:{field}")
    return keys == fields


def _identifier(value: Any, path: str, issues: list[str]) -> bool:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _issue(issues, f"{path}:invalid_identifier")
        return False
    return True


def _text(value: Any, path: str, issues: list[str], *, max_len: int = 4096) -> bool:
    if not isinstance(value, str) or not value.strip() or len(value) > max_len:
        _issue(issues, f"{path}:invalid_text")
        return False
    return True


def _digest(value: Any, path: str, issues: list[str]) -> bool:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _issue(issues, f"{path}:sha256_invalid")
        return False
    return True


def _integer(value: Any, path: str, issues: list[str], *, minimum: int = 0) -> bool:
    if type(value) is not int or value < minimum:
        _issue(issues, f"{path}:integer_invalid")
        return False
    return True


def _unique_strings(value: Any, path: str, issues: list[str], *, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list):
        _issue(issues, f"{path}:not_array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not _text(item, f"{path}[{index}]", issues, max_len=256):
            continue
        result.append(item.strip())
    if nonempty and not result:
        _issue(issues, f"{path}:empty")
    if len(result) != len(set(result)):
        _issue(issues, f"{path}:duplicates")
    return result


def _sensitive(value: Any, path: str, issues: list[str]) -> None:
    """Reject credentials and provider details rather than redacting them."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            if _FORBIDDEN_KEY.search(key_text):
                _issue(issues, f"{path}.{key_text}:forbidden_field")
            _sensitive(item, f"{path}.{key_text}", issues)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _sensitive(item, f"{path}[{index}]", issues)
    elif isinstance(value, str) and _FORBIDDEN_VALUE.search(value):
        _issue(issues, f"{path}:sensitive_value_forbidden")


def _copy_mapping(value: Any) -> dict[str, Any]:
    return deepcopy(dict(value)) if isinstance(value, Mapping) else {}


def _report(*, valid: bool, issues: Sequence[str], canonical: Any = None, schema: str | None = None, **extra: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": VALIDATION_REPORT_SCHEMA,
        "validated_schema": schema,
        "status": "PASS" if valid else "FAIL",
        "valid": bool(valid),
        "issues": sorted(set(str(item) for item in issues)),
        "canonical": deepcopy(canonical) if valid else None,
        "canonical_sha256": canonical_sha256(canonical) if valid else None,
    }
    report.update(extra)
    return report


class WorkerCall(dict):
    """JSON-compatible convenience wrapper for a canonical worker call."""

    def __init__(self, value: Mapping[str, Any] | None = None, **fields: Any) -> None:
        if value is not None and fields:
            raise TypeError("WorkerCall accepts a mapping or keyword fields, not both")
        source = dict(value) if value is not None else fields
        super().__init__(deepcopy(source))

    def to_dict(self) -> dict[str, Any]:
        return deepcopy(dict(self))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WorkerCall":
        return cls(value)


class WorkerResult(dict):
    """JSON-compatible convenience wrapper for a canonical worker result."""

    def __init__(self, value: Mapping[str, Any] | None = None, **fields: Any) -> None:
        if value is not None and fields:
            raise TypeError("WorkerResult accepts a mapping or keyword fields, not both")
        source = dict(value) if value is not None else fields
        super().__init__(deepcopy(source))

    def to_dict(self) -> dict[str, Any]:
        return deepcopy(dict(self))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WorkerResult":
        return cls(value)


def _validate_call_value(value: Any) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    if not isinstance(value, Mapping):
        return {}, ["call:not_object"]
    copied = _copy_mapping(value)
    _exact(copied, _CALL_KEYS, "call", issues)
    _sensitive(copied, "call", issues)
    if copied.get("schema") != WORKER_CALL_SCHEMA:
        _issue(issues, "call:schema_invalid")
    _identifier(copied.get("call_id"), "call.call_id", issues)

    assignment = copied.get("assignment")
    _exact(assignment, _ASSIGNMENT_KEYS, "call.assignment", issues)
    assignment_value = assignment if isinstance(assignment, Mapping) else {}
    _identifier(assignment_value.get("assignment_id"), "call.assignment.assignment_id", issues)
    _identifier(assignment_value.get("lane_id"), "call.assignment.lane_id", issues)
    _text(assignment_value.get("objective"), "call.assignment.objective", issues)
    _digest(assignment_value.get("input_sha256"), "call.assignment.input_sha256", issues)
    _text(assignment_value.get("source_pointer"), "call.assignment.source_pointer", issues)

    policy = copied.get("lane_policy")
    _exact(policy, _LANE_POLICY_KEYS, "call.lane_policy", issues)
    policy_value = policy if isinstance(policy, Mapping) else {}
    for field in ("policy_id", "policy_revision", "registry_ref"):
        _identifier(policy_value.get(field), f"call.lane_policy.{field}", issues)
    _digest(policy_value.get("policy_sha256"), "call.lane_policy.policy_sha256", issues)

    base = copied.get("base_revision")
    _exact(base, _BASE_REVISION_KEYS, "call.base_revision", issues)
    base_value = base if isinstance(base, Mapping) else {}
    _identifier(base_value.get("repository_id"), "call.base_revision.repository_id", issues)
    _text(base_value.get("revision"), "call.base_revision.revision", issues, max_len=512)
    _digest(base_value.get("tree_sha256"), "call.base_revision.tree_sha256", issues)
    _text(base_value.get("source_pointer"), "call.base_revision.source_pointer", issues)

    capabilities = _unique_strings(copied.get("required_capabilities"), "call.required_capabilities", issues)
    if any(item.lower() in {"provider", "endpoint", "credentials", "command", "shell"} for item in capabilities):
        _issue(issues, "call.required_capabilities:forbidden_capability")

    authority = copied.get("authority_ref")
    _exact(authority, _AUTHORITY_KEYS, "call.authority_ref", issues)
    authority_value = authority if isinstance(authority, Mapping) else {}
    _identifier(authority_value.get("authority_id"), "call.authority_ref.authority_id", issues)
    _identifier(authority_value.get("grant_id"), "call.authority_ref.grant_id", issues)
    _digest(authority_value.get("scope_sha256"), "call.authority_ref.scope_sha256", issues)

    _text(copied.get("idempotency_key"), "call.idempotency_key", issues, max_len=512)

    budgets = copied.get("budgets")
    _exact(budgets, _BUDGET_KEYS, "call.budgets", issues)
    budget_value = budgets if isinstance(budgets, Mapping) else {}
    for field in ("wall_time_ms", "generation_count", "token_count", "tool_call_count"):
        _integer(budget_value.get(field), f"call.budgets.{field}", issues, minimum=1)
    for field in ("child_count", "concurrency"):
        _integer(budget_value.get(field), f"call.budgets.{field}", issues, minimum=0)
    if isinstance(budget_value.get("concurrency"), int) and budget_value.get("concurrency", 0) == 0:
        _issue(issues, "call.budgets.concurrency:must_be_positive")
    return copied, issues


def validate_worker_call(call: Any) -> dict[str, Any]:
    """Validate and canonicalize one closed :class:`WorkerCall`."""

    copied, issues = _validate_call_value(call.to_dict() if isinstance(call, WorkerCall) else call)
    return _report(valid=not issues, issues=issues, canonical=copied, schema=WORKER_CALL_SCHEMA)


def require_worker_call(call: Any) -> dict[str, Any]:
    report = validate_worker_call(call)
    if report["status"] != "PASS":
        raise WorkerValidationError(report["issues"], code="INVALID_WORKER_CALL")
    return report["canonical"]


def is_hosted_manifest(value: Any) -> bool:
    """Select the hosted manifest wire from its declared closed schema."""
    return isinstance(value, Mapping) and value.get('schema') == HOSTED_MODEL_MANIFEST_SCHEMA


def is_hosted_result(value: Any) -> bool:
    """Select the hosted result wire from its declared closed schema."""
    return isinstance(value, Mapping) and value.get('schema') == HOSTED_WORKER_RESULT_SCHEMA


def _validate_manifest_value(value: Any) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    if not isinstance(value, Mapping):
        return {}, ["manifest:not_object"]
    copied = _copy_mapping(value)
    hosted = is_hosted_manifest(copied)
    _exact(copied, _HOSTED_MANIFEST_KEYS if hosted else _MANIFEST_KEYS, "manifest", issues)
    _sensitive(copied, "manifest", issues)
    if copied.get("schema") not in (MODEL_MANIFEST_SCHEMA, HOSTED_MODEL_MANIFEST_SCHEMA):
        _issue(issues, "manifest:schema_invalid")
    for field in ("manifest_id", "version", "logical_model_id"):
        _identifier(copied.get(field), f"manifest.{field}", issues)
    served = _unique_strings(copied.get("served_names"), "manifest.served_names", issues)
    if len(served) != len(set(served)):
        _issue(issues, "manifest.served_names:duplicates")
    if hosted:
        # The profile is the observed plumbing identity, never a weights hash.
        _digest(copied.get("onboarded_profile_sha256"), "manifest.onboarded_profile_sha256", issues)
    else:
        _identifier(copied.get("checkpoint_revision"), "manifest.checkpoint_revision", issues)
        _digest(copied.get("weight_digest_sha256"), "manifest.weight_digest_sha256", issues)
    for field in ("context_limit_tokens", "output_limit_tokens"):
        if not hosted or copied.get(field) is not None:
            _integer(copied.get(field), f"manifest.{field}", issues, minimum=1)
    context_limit = copied.get("context_limit_tokens")
    output_limit = copied.get("output_limit_tokens")
    if isinstance(context_limit, int) and isinstance(output_limit, int) and output_limit > context_limit:
        _issue(issues, "manifest.output_limit_tokens:exceeds_context")
    _unique_strings(copied.get("protocols"), "manifest.protocols", issues)
    _unique_strings(copied.get("capabilities"), "manifest.capabilities", issues)
    if not hosted:
        quantization = copied.get("quantization")
        _exact(quantization, _QUANTIZATION_KEYS, "manifest.quantization", issues)
        quantization_value = quantization if isinstance(quantization, Mapping) else {}
        _identifier(quantization_value.get("scheme"), "manifest.quantization.scheme", issues)
        _integer(quantization_value.get("bits"), "manifest.quantization.bits", issues, minimum=1)
    runtime = copied.get("runtime")
    _exact(runtime, _RUNTIME_IDENTITY_KEYS, "manifest.runtime", issues)
    runtime_value = runtime if isinstance(runtime, Mapping) else {}
    _identifier(runtime_value.get("name"), "manifest.runtime.name", issues)
    _identifier(runtime_value.get("version"), "manifest.runtime.version", issues)
    _unique_strings(copied.get("allowed_tool_profiles"), "manifest.allowed_tool_profiles", issues)
    return copied, issues


def validate_model_manifest(manifest: Any) -> dict[str, Any]:
    """Validate a versioned model manifest and return its canonical hash."""

    copied, issues = _validate_manifest_value(manifest)
    schema = HOSTED_MODEL_MANIFEST_SCHEMA if is_hosted_manifest(copied) else MODEL_MANIFEST_SCHEMA
    return _report(valid=not issues, issues=issues, canonical=copied, schema=schema)


def require_model_manifest(manifest: Any) -> dict[str, Any]:
    report = validate_model_manifest(manifest)
    if report["status"] != "PASS":
        raise WorkerValidationError(report["issues"], code="INVALID_MODEL_MANIFEST")
    return report["canonical"]


def _validate_result_value(value: Any) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    if not isinstance(value, Mapping):
        return {}, ["result:not_object"]
    copied = _copy_mapping(value)
    _exact(copied, _RESULT_KEYS, "result", issues)
    _sensitive(copied, "result", issues)
    hosted = is_hosted_result(copied)
    if copied.get("schema") not in (WORKER_RESULT_SCHEMA, HOSTED_WORKER_RESULT_SCHEMA):
        _issue(issues, "result:schema_invalid")
    _identifier(copied.get("result_id"), "result.result_id", issues)
    _identifier(copied.get("call_id"), "result.call_id", issues)
    status = copied.get("status")
    if status not in RESULT_STATUSES:
        _issue(issues, "result.status_invalid")
    _text(copied.get("reason"), "result.reason", issues) if status != "CANDIDATE_READY" else (
        _issue(issues, "result.reason_must_be_null") if copied.get("reason") is not None else None
    )
    if status == "CANDIDATE_READY" and not (isinstance(copied.get("reason"), type(None))):
        _issue(issues, "result.reason_must_be_null")

    candidate = copied.get("candidate")
    _exact(candidate, _CANDIDATE_KEYS, "result.candidate", issues)
    candidate_value = candidate if isinstance(candidate, Mapping) else {}
    candidate_status = candidate_value.get("status")
    if candidate_status not in {"ready", "none"}:
        _issue(issues, "result.candidate.status_invalid")
    applied = candidate_value.get("applied")
    if type(applied) is not bool:
        _issue(issues, "result.candidate.applied_invalid")
    elif applied:
        _issue(issues, "result.candidate.auto_apply_forbidden")
    diff = candidate_value.get("diff")
    diff_hash = candidate_value.get("diff_sha256")
    if candidate_status == "ready":
        if not isinstance(diff, str) or not diff:
            _issue(issues, "result.candidate.diff_required")
        else:
            if "\x00" in diff:
                _issue(issues, "result.candidate.diff_nul_forbidden")
            if _FORBIDDEN_VALUE.search(diff):
                _issue(issues, "result.candidate.diff_sensitive_value")
            if not _digest(diff_hash, "result.candidate.diff_sha256", issues):
                pass
            elif diff_hash != content_sha256(diff):
                _issue(issues, "result.candidate.diff_hash_mismatch")
    else:
        if diff is not None or diff_hash is not None:
            _issue(issues, "result.candidate.none_has_diff")

    tests = copied.get("tests")
    _exact(tests, _TEST_KEYS, "result.tests", issues)
    tests_value = tests if isinstance(tests, Mapping) else {}
    test_status = tests_value.get("status")
    if test_status not in {"PASS", "FAIL", "UNKNOWN", "NOT_RUN"}:
        _issue(issues, "result.tests.status_invalid")
    test_report = tests_value.get("report")
    test_hash = tests_value.get("report_sha256")
    if test_status in {"PASS", "FAIL", "UNKNOWN"}:
        if not isinstance(test_report, str) or not test_report:
            _issue(issues, "result.tests.report_required")
        elif not _digest(test_hash, "result.tests.report_sha256", issues):
            pass
        elif test_hash != content_sha256(test_report):
            _issue(issues, "result.tests.report_hash_mismatch")
    elif test_report is not None or test_hash is not None:
        _issue(issues, "result.tests.not_run_has_report")
    if status == "CANDIDATE_READY" and test_status != "PASS":
        _issue(issues, "result.tests.ready_requires_pass")

    usage = copied.get("usage")
    _exact(usage, _USAGE_KEYS, "result.usage", issues)
    usage_value = usage if isinstance(usage, Mapping) else {}
    usage_status = usage_value.get("status")
    if usage_status not in {"exact", "unknown"}:
        _issue(issues, "result.usage.status_invalid")
    usage_values = [usage_value.get(field) for field in ("input_tokens", "output_tokens", "total_tokens")]
    if usage_status == "exact":
        for field in ("input_tokens", "output_tokens", "total_tokens"):
            _integer(usage_value.get(field), f"result.usage.{field}", issues, minimum=0)
        if all(type(item) is int for item in usage_values) and usage_value["total_tokens"] != usage_value["input_tokens"] + usage_value["output_tokens"]:
            _issue(issues, "result.usage.total_mismatch")
    elif any(item is not None for item in usage_values):
        _issue(issues, "result.usage.unknown_has_values")

    timing = copied.get("timing")
    _exact(timing, _TIMING_KEYS, "result.timing", issues)
    timing_value = timing if isinstance(timing, Mapping) else {}
    timing_status = timing_value.get("status")
    if timing_status not in {"exact", "unknown"}:
        _issue(issues, "result.timing.status_invalid")
    if timing_status == "exact":
        _integer(timing_value.get("wall_time_ms"), "result.timing.wall_time_ms", issues, minimum=0)
    elif timing_value.get("wall_time_ms") is not None:
        _issue(issues, "result.timing.unknown_has_value")

    runtime = copied.get("runtime")
    _exact(runtime, _HOSTED_RUNTIME_KEYS if hosted else _RUNTIME_KEYS, "result.runtime", issues)
    runtime_value = runtime if isinstance(runtime, Mapping) else {}
    runtime_status = runtime_value.get("status")
    bound_status = "profile_bound" if hosted else "known"
    if runtime_status not in {bound_status, "unknown"}:
        _issue(issues, "result.runtime.status_invalid")
    runtime_fields = ("logical_model_id", "served_name", "runtime_id")
    if not hosted:
        runtime_fields += ("checkpoint_revision",)
    if runtime_status == bound_status:
        for field in runtime_fields:
            _text(runtime_value.get(field), f"result.runtime.{field}", issues, max_len=1024)
        if hosted:
            _digest(runtime_value.get("onboarded_profile_sha256"), "result.runtime.onboarded_profile_sha256", issues)
    elif any(runtime_value.get(field) is not None for field in runtime_fields) or (
        hosted and runtime_value.get("onboarded_profile_sha256") is not None
    ):
        _issue(issues, "result.runtime.unknown_has_identity")
    if hosted and runtime_value.get("checkpoint_revision") is not None:
        _issue(issues, "result.runtime.hosted_checkpoint_not_observed")
    if status == "CANDIDATE_READY" and runtime_status != bound_status:
        _issue(issues, "result.runtime.ready_requires_" + bound_status)

    evidence = copied.get("evidence")
    _exact(evidence, _EVIDENCE_KEYS, "result.evidence", issues)
    evidence_value = evidence if isinstance(evidence, Mapping) else {}
    evidence_status = evidence_value.get("status")
    if evidence_status not in {"sealed", "unknown"}:
        _issue(issues, "result.evidence.status_invalid")
    evidence_fields = ("reference", "sha256", "call_sha256", "manifest_sha256")
    if evidence_status == "sealed":
        _text(evidence_value.get("reference"), "result.evidence.reference", issues, max_len=4096)
        for field in ("sha256", "call_sha256", "manifest_sha256"):
            _digest(evidence_value.get(field), f"result.evidence.{field}", issues)
    elif any(evidence_value.get(field) is not None for field in evidence_fields):
        _issue(issues, "result.evidence.unknown_has_values")
    if status == "CANDIDATE_READY" and evidence_status != "sealed":
        _issue(issues, "result.evidence.ready_requires_sealed")
    return copied, issues


def validate_worker_result(result: Any, *, expected_call_sha256: str | None = None, expected_manifest_sha256: str | None = None) -> dict[str, Any]:
    """Validate a result and optionally bind it to call/manifest hashes."""

    copied, issues = _validate_result_value(result.to_dict() if isinstance(result, WorkerResult) else result)
    evidence = copied.get("evidence") if isinstance(copied.get("evidence"), Mapping) else {}
    if expected_call_sha256 is not None:
        if not _SHA256.fullmatch(expected_call_sha256 or ""):
            _issue(issues, "expected_call_sha256:invalid")
        elif evidence.get("call_sha256") != expected_call_sha256:
            _issue(issues, "result.evidence.call_hash_mismatch")
    if expected_manifest_sha256 is not None:
        if not _SHA256.fullmatch(expected_manifest_sha256 or ""):
            _issue(issues, "expected_manifest_sha256:invalid")
        elif evidence.get("manifest_sha256") != expected_manifest_sha256:
            _issue(issues, "result.evidence.manifest_hash_mismatch")
    schema = HOSTED_WORKER_RESULT_SCHEMA if is_hosted_result(copied) else WORKER_RESULT_SCHEMA
    return _report(valid=not issues, issues=issues, canonical=copied, schema=schema)


def require_worker_result(result: Any, **kwargs: Any) -> dict[str, Any]:
    report = validate_worker_result(result, **kwargs)
    if report["status"] != "PASS":
        raise WorkerValidationError(report["issues"], code="INVALID_WORKER_RESULT")
    return report["canonical"]


def _profile(
    profile_id: str,
    required: Sequence[str],
    tool_profiles: Sequence[str],
    *,
    max_children: int,
    max_concurrency: int,
) -> dict[str, Any]:
    return {
        "schema": CAPABILITY_PROFILE_SCHEMA,
        "profile_id": profile_id,
        "version": "profile-v1",
        "required_capabilities": list(required),
        "allowed_tool_profiles": list(tool_profiles),
        "max_child_count": max_children,
        "max_concurrency": max_concurrency,
    }


CAPABILITY_PROFILES: dict[str, dict[str, Any]] = {
    "tool-free-canary": _profile(
        "tool-free-canary",
        ("structured_output", "context", "receipt", "lifecycle", "cancellation"),
        ("none", "tool-free-canary"),
        max_children=0,
        max_concurrency=1,
    ),
    "bounded-coding": _profile(
        "bounded-coding",
        (
            "structured_output",
            "context",
            "receipt",
            "lifecycle",
            "cancellation",
            "inspect",
            "edit",
            "test",
            "single_flight",
            "hash_bound_evidence",
            "isolated_worktree",
        ),
        ("bounded-coding",),
        max_children=0,
        max_concurrency=1,
    ),
    "multi-worker": _profile(
        "multi-worker",
        (
            "structured_output",
            "context",
            "receipt",
            "lifecycle",
            "cancellation",
            "inspect",
            "edit",
            "test",
            "single_flight",
            "hash_bound_evidence",
            "isolated_worktree",
            "child_workers",
            "concurrency",
        ),
        ("bounded-coding", "multi-worker"),
        max_children=4,
        max_concurrency=4,
    ),
}
CAPABILITY_PROFILE_REGISTRY = CAPABILITY_PROFILES


def validate_capability_profile(profile: Any) -> dict[str, Any]:
    """Validate one profile object; profiles are declarative and inert."""

    issues: list[str] = []
    if not isinstance(profile, Mapping):
        return _report(valid=False, issues=("profile:not_object",), canonical={}, schema=CAPABILITY_PROFILE_SCHEMA)
    copied = _copy_mapping(profile)
    fields = {
        "schema",
        "profile_id",
        "version",
        "required_capabilities",
        "allowed_tool_profiles",
        "max_child_count",
        "max_concurrency",
    }
    _exact(copied, fields, "profile", issues)
    if copied.get("schema") != CAPABILITY_PROFILE_SCHEMA:
        _issue(issues, "profile:schema_invalid")
    _identifier(copied.get("profile_id"), "profile.profile_id", issues)
    _identifier(copied.get("version"), "profile.version", issues)
    _unique_strings(copied.get("required_capabilities"), "profile.required_capabilities", issues)
    _unique_strings(copied.get("allowed_tool_profiles"), "profile.allowed_tool_profiles", issues)
    _integer(copied.get("max_child_count"), "profile.max_child_count", issues, minimum=0)
    _integer(copied.get("max_concurrency"), "profile.max_concurrency", issues, minimum=1)
    return _report(valid=not issues, issues=issues, canonical=copied, schema=CAPABILITY_PROFILE_SCHEMA)


def evaluate_capability_compatibility(program: Any) -> dict[str, Any]:
    """Evaluate a capability program without degrading a requested profile.

    A program has one explicit requested profile and one versioned manifest.
    Missing any required capability yields ``UNSUPPORTED_CAPABILITY`` and the
    report explicitly records ``degraded: False``; the canary is never chosen
    as a substitute for bounded coding or multi-worker.
    """

    issues: list[str] = []
    if not isinstance(program, Mapping):
        return {
            "schema": CAPABILITY_PROGRAM_SCHEMA,
            "status": "FAIL",
            "outcome": "INVALID_PROGRAM",
            "issues": ["program:not_object"],
            "degraded": False,
        }
    copied = _copy_mapping(program)
    _exact(copied, _PROGRAM_KEYS, "program", issues)
    _sensitive(copied, "program", issues)
    if copied.get("schema") != CAPABILITY_PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    _identifier(copied.get("program_id"), "program.program_id", issues)
    requested = copied.get("requested_profile")
    if requested not in CAPABILITY_PROFILES:
        _issue(issues, "program.requested_profile:unknown")
    requested_caps = _unique_strings(copied.get("required_capabilities"), "program.required_capabilities", issues)
    manifest_report = validate_model_manifest(copied.get("manifest"))
    if manifest_report["status"] != "PASS":
        issues.extend(manifest_report["issues"])
    manifest = manifest_report.get("canonical") if manifest_report["status"] == "PASS" else {}
    profile = CAPABILITY_PROFILES.get(requested, {})
    profile_caps = set(profile.get("required_capabilities", []))
    available = set(manifest.get("capabilities", [])) if isinstance(manifest, Mapping) else set()
    available_profiles = set(manifest.get("allowed_tool_profiles", [])) if isinstance(manifest, Mapping) else set()
    missing = sorted((profile_caps | set(requested_caps)) - available)
    if profile and not (set(profile.get("allowed_tool_profiles", [])) & available_profiles):
        _issue(issues, "capability:tool_profile_not_allowed")
    if missing:
        _issue(issues, "capability:required_missing:" + ",".join(missing))
    compatible = not issues
    outcome = "COMPATIBLE" if compatible else (CAPABILITY_OUTCOME if manifest_report["status"] == "PASS" and requested in CAPABILITY_PROFILES else "INVALID_PROGRAM")
    return {
        "schema": CAPABILITY_PROGRAM_SCHEMA,
        "status": "PASS" if compatible else "FAIL",
        "outcome": outcome,
        "program_id": copied.get("program_id"),
        "requested_profile": requested,
        "required_capabilities": sorted(profile_caps | set(requested_caps)),
        "available_capabilities": sorted(available),
        "missing_capabilities": missing,
        "manifest_sha256": manifest_report.get("canonical_sha256"),
        "degraded": False,
        "issues": sorted(set(issues)),
    }


def capability_compatibility(program: Any) -> dict[str, Any]:
    """Pure compatibility alias retained for callers using the short name."""

    return evaluate_capability_compatibility(program)


def make_rejected_result(
    *,
    call_id: str,
    result_id: str,
    reason: str,
    status: str = "REJECTED",
) -> WorkerResult:
    """Build a structurally valid non-success result for local policy errors."""

    if status not in RESULT_STATUSES or status == "CANDIDATE_READY":
        raise ValueError("status must be a non-success WorkerResult status")
    result = WorkerResult(
        {
            "schema": WORKER_RESULT_SCHEMA,
            "result_id": result_id,
            "call_id": call_id,
            "status": status,
            "candidate": {"status": "none", "diff": None, "diff_sha256": None, "applied": False},
            "tests": {"status": "NOT_RUN", "report": None, "report_sha256": None},
            "usage": {"status": "unknown", "input_tokens": None, "output_tokens": None, "total_tokens": None},
            "timing": {"status": "unknown", "wall_time_ms": None},
            "runtime": {"status": "unknown", "logical_model_id": None, "served_name": None, "checkpoint_revision": None, "runtime_id": None},
            "evidence": {"status": "unknown", "reference": None, "sha256": None, "call_sha256": None, "manifest_sha256": None},
            "reason": reason,
        }
    )
    return result


class WorkerTransport:
    """Single required execution seam for provider-specific worker adapters.

    A handler may be supplied for a provider-free replay/fake adapter.  The
    handler is invoked at most once per idempotency key; a completed call is
    returned by value on replay, while an in-flight duplicate is rejected.
    The base transport has no handler and therefore returns ``UNAVAILABLE``.
    """

    def __init__(self, handler: Callable[[WorkerCall], Mapping[str, Any]] | None = None) -> None:
        self._handler = handler
        self._lock = threading.RLock()
        self._inflight: set[str] = set()
        self._completed: dict[str, WorkerResult] = {}
        self._sequence = 0

    def _next_result_id(self, call_id: str) -> str:
        with self._lock:
            self._sequence += 1
            return f"{call_id}:result:{self._sequence}"

    def invoke(self, call: WorkerCall | Mapping[str, Any]) -> WorkerResult:
        """Invoke exactly one validated call; no retries, fallbacks, or apply."""

        report = validate_worker_call(call)
        raw = call.to_dict() if isinstance(call, WorkerCall) else (dict(call) if isinstance(call, Mapping) else {})
        call_id = raw.get("call_id") if isinstance(raw.get("call_id"), str) else "invalid-call"
        if report["status"] != "PASS":
            return make_rejected_result(
                call_id=call_id,
                result_id=self._next_result_id(call_id),
                reason="INVALID_WORKER_CALL:" + ",".join(report["issues"]),
            )
        canonical_call = WorkerCall(report["canonical"])
        key = canonical_call["idempotency_key"]
        with self._lock:
            if key in self._completed:
                return WorkerResult(self._completed[key])
            if key in self._inflight:
                return make_rejected_result(
                    call_id=canonical_call["call_id"],
                    result_id=self._next_result_id(canonical_call["call_id"]),
                    reason="DUPLICATE_IN_FLIGHT",
                )
            self._inflight.add(key)
        try:
            if self._handler is None:
                result = make_rejected_result(
                    call_id=canonical_call["call_id"],
                    result_id=self._next_result_id(canonical_call["call_id"]),
                    reason="WORKER_UNAVAILABLE",
                    status="UNAVAILABLE",
                )
            else:
                try:
                    result = WorkerResult(self._handler(canonical_call))
                except Exception as exc:  # pragma: no cover - defensive adapter boundary
                    result = make_rejected_result(
                        call_id=canonical_call["call_id"],
                        result_id=self._next_result_id(canonical_call["call_id"]),
                        reason="WORKER_HANDLER_ERROR:" + type(exc).__name__,
                        status="UNAVAILABLE",
                    )
            result_report = validate_worker_result(result)
            if result_report["status"] != "PASS":
                result = make_rejected_result(
                    call_id=canonical_call["call_id"],
                    result_id=self._next_result_id(canonical_call["call_id"]),
                    reason="INVALID_WORKER_RESULT:" + ",".join(result_report["issues"]),
                )
            else:
                result = WorkerResult(result_report["canonical"])
            with self._lock:
                self._completed[key] = WorkerResult(result)
            return WorkerResult(result)
        finally:
            with self._lock:
                self._inflight.discard(key)


__all__ = [
    "TRANSPORT_SCHEMA",
    "WORKER_CALL_SCHEMA",
    "WORKER_RESULT_SCHEMA",
    "MODEL_MANIFEST_SCHEMA",
    "HOSTED_WORKER_RESULT_SCHEMA",
    "HOSTED_MODEL_MANIFEST_SCHEMA",
    "CAPABILITY_PROFILE_SCHEMA",
    "CAPABILITY_PROGRAM_SCHEMA",
    "VALIDATION_REPORT_SCHEMA",
    "CALL_SCHEMA",
    "RESULT_SCHEMA",
    "MANIFEST_SCHEMA",
    "PROFILE_SCHEMA",
    "RESULT_STATUSES",
    "CAPABILITY_OUTCOME",
    "CAPABILITY_PROFILES",
    "CAPABILITY_PROFILE_REGISTRY",
    "WorkerContractError",
    "WorkerValidationError",
    "WorkerCall",
    "WorkerResult",
    "WorkerTransport",
    "canonical_json",
    "canonical_bytes",
    "canonical_sha256",
    "content_sha256",
    "validate_worker_call",
    "require_worker_call",
    "validate_worker_result",
    "require_worker_result",
    "validate_model_manifest",
    "is_hosted_manifest",
    "is_hosted_result",
    "require_model_manifest",
    "validate_capability_profile",
    "evaluate_capability_compatibility",
    "capability_compatibility",
    "make_rejected_result",
]
