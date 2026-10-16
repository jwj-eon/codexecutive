#!/usr/bin/env python3
"""Closed, provider-free adapters and evidence for the Issue 30 worker seam.

This module deliberately contains no transport client, subprocess, socket, or
filesystem execution.  A replay adapter consumes JSON values supplied by a
caller and a vLLM adapter evaluates a *declarative* route observation.  The
module is therefore useful in offline tests and in the policy layer without
accidentally turning a qualification/preflight operation into a model call.

The wire values are ordinary JSON-compatible dictionaries.  Dataclasses are
provided for callers that prefer a typed ``WorkerCall``/``WorkerResult`` API,
but every public evaluator also accepts dictionaries and returns dictionaries.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Iterable, Mapping, MutableMapping, Sequence


ADAPTER_SCHEMA = "orch-dork/worker-adapter/v1"
PROGRAM_SCHEMA = "orch-dork/worker-adapter-program/v1"
ROUTE_SCHEMA = "orch-dork/worker-route/v1"
MANIFEST_SCHEMA = "orch-dork/model-manifest/v1"
CAPABILITY_SCHEMA = "orch-dork/capability-profile/v1"
EVIDENCE_SCHEMA = "orch-dork/worker-evidence/v1"
RECEIPT_SCHEMA = "orch-dork/worker-receipt/v1"
QUALIFICATION_SCHEMA = "orch-dork/worker-qualification/v1"
ACTIVATION_SCHEMA = "orch-dork/worker-activation/v1"
VERSION = "issue30-provider-free/1.0"

RESULT_STATUSES = {
    "CANDIDATE_READY",
    "REJECTED",
    "UNAVAILABLE",
    "CANCELLED",
    "TIMED_OUT",
    "DELIVERY_UNCERTAIN",
    "RECOVERY_PENDING",
}
TERMINAL_STATUSES = RESULT_STATUSES
LIFECYCLE_STATES = {
    "CREATED",
    "VALIDATING",
    "DISPATCHING",
    "STREAMING",
    "TOOL_DISPATCH",
    "COMPLETED",
    "REJECTED",
    "UNAVAILABLE",
    "CANCELLED",
    "TIMED_OUT",
    "DELIVERY_UNCERTAIN",
    "RECOVERY_PENDING",
}
CAPABILITY_PROFILES = {
    "tool-free-canary": frozenset({"structured_output", "receipt", "lifecycle", "cancellation", "context"}),
    "bounded-coding": frozenset(
        {
            "structured_output",
            "receipt",
            "lifecycle",
            "cancellation",
            "context",
            "inspect",
            "edit_patch",
            "focused_test",
        }
    ),
    "multi-worker": frozenset(
        {
            "structured_output",
            "receipt",
            "lifecycle",
            "cancellation",
            "context",
            "inspect",
            "edit_patch",
            "focused_test",
            "child_workers",
            "integrator",
        }
    ),
}
EVIDENCE_SECTIONS = (
    "call",
    "manifest",
    "capability_profile",
    "adapter",
    "effective_identity",
    "assignment",
    "base_revision",
    "patch",
    "tests",
    "lifecycle",
    "usage",
    "timing",
    "cancellation",
    "cleanup",
    "rollback",
)
FORBIDDEN = re.compile(
    r"(?:password|passwd|secret|credential|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"private[_-]?key|raw[_-]?authorization|authorization[_-]?material|private[_-]?reasoning|"
    r"chain[_-]?of[_-]?thought|session[_-]?body|copied[_-]?session|request[_-]?body|response[_-]?body)",
    re.IGNORECASE,
)
IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


def canonical_json(value: Any) -> str:
    """Return the one canonical JSON representation used for all hashes."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


# Common names in adjacent Issue 30 work are intentionally exported too.
json_sha256 = sha256_json
canonical_hash = sha256_json


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 4096


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def _digest(value: Any) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _int(value: Any, *, positive: bool = False) -> bool:
    return type(value) is int and (value > 0 if positive else value >= 0)


def _list_of_text(value: Any, path: str, issues: list[str], *, required: bool = False) -> list[str]:
    if not isinstance(value, list):
        _issue(issues, path + ":not_array")
        return []
    if required and not value:
        _issue(issues, path + ":empty")
    result = [str(item).strip() for item in value if _text(item)]
    if len(result) != len(value):
        _issue(issues, path + ":item_invalid")
    if len(result) != len(set(result)):
        _issue(issues, path + ":duplicates")
    return result


def _exact(value: Any, expected: set[str], path: str, issues: list[str]) -> None:
    if not isinstance(value, Mapping):
        _issue(issues, path + ":not_object")
        return
    for key in sorted(expected - set(value)):
        _issue(issues, path + ":missing:" + key)
    for key in sorted(set(value) - expected):
        _issue(issues, path + ":unknown:" + str(key))


def _sensitive_paths(value: Any, path: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            if FORBIDDEN.search(str(key)):
                found.append(key_path)
            found.extend(_sensitive_paths(child, key_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_sensitive_paths(child, f"{path}[{index}]"))
    return found


def _normal_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _unknown(reason: str) -> dict[str, Any]:
    return {"known": False, "reason": reason}


def _known_usage(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _unknown("usage_not_observed")
    result = dict(value)
    result["known"] = True
    return result


def _known_timing(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _unknown("timing_not_observed")
    result = dict(value)
    result["known"] = True
    return result


def _copy_json(value: Any) -> Any:
    """Copy a JSON-compatible value and reject non-JSON data deterministically."""

    return json.loads(canonical_json(value))


@dataclass(frozen=True)
class WorkerCall:
    """Immutable canonical call accepted by a transport adapter."""

    call_id: str
    assignment: Mapping[str, Any]
    lane_policy: Mapping[str, Any]
    base_revision: str
    required_capabilities: tuple[str, ...]
    authority_ref: Mapping[str, Any]
    idempotency_key: str
    budgets: Mapping[str, int]
    schema: str = "orch-dork/worker-call/v1"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WorkerCall":
        return cls(
            call_id=str(value.get("call_id", value.get("id", ""))),
            assignment=_normal_mapping(value.get("assignment")),
            lane_policy=_normal_mapping(value.get("lane_policy")),
            base_revision=str(value.get("base_revision", "")),
            required_capabilities=tuple(value.get("required_capabilities", value.get("capabilities", ())) or ()),
            authority_ref=_normal_mapping(value.get("authority_ref", value.get("authority"))),
            idempotency_key=str(value.get("idempotency_key", "")),
            budgets=_normal_mapping(value.get("budgets")),
            schema=str(value.get("schema", "orch-dork/worker-call/v1")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "call_id": self.call_id,
            "assignment": _copy_json(self.assignment),
            "lane_policy": _copy_json(self.lane_policy),
            "base_revision": self.base_revision,
            "required_capabilities": list(self.required_capabilities),
            "authority_ref": _copy_json(self.authority_ref),
            "idempotency_key": self.idempotency_key,
            "budgets": _copy_json(self.budgets),
        }


@dataclass(frozen=True)
class WorkerResult:
    status: str
    call_id: str
    reason: str
    candidate_diff: str | None
    tests: Mapping[str, Any]
    usage: Mapping[str, Any]
    timing: Mapping[str, Any]
    effective_identity: Mapping[str, Any]
    evidence_ref: Mapping[str, Any]
    lifecycle: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "orch-dork/worker-result/v1",
            "status": self.status,
            "call_id": self.call_id,
            "reason": self.reason,
            "candidate_diff": self.candidate_diff,
            "tests": _copy_json(self.tests),
            "usage": _copy_json(self.usage),
            "timing": _copy_json(self.timing),
            "effective_identity": _copy_json(self.effective_identity),
            "evidence_ref": _copy_json(self.evidence_ref),
            "lifecycle": _copy_json(self.lifecycle),
            "applied": False,
        }


class WorkerTransport:
    """The only required execution seam; concrete adapters remain local."""

    def invoke(self, call: WorkerCall | Mapping[str, Any]) -> dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError


def validate_model_manifest(manifest: Any) -> dict[str, Any]:
    """Validate a versioned manifest without accepting endpoints or secrets."""

    issues: list[str] = []
    value = manifest if isinstance(manifest, Mapping) else {}
    # The sibling transport contract uses a flattened manifest.  Accept that
    # exact shape as well as the adapter's compact nested form; both describe
    # the same immutable identity and neither admits endpoint/credential data.
    flattened = isinstance(value, Mapping) and {
        "manifest_id",
        "version",
        "checkpoint_revision",
        "weight_digest_sha256",
        "context_limit_tokens",
        "output_limit_tokens",
    }.issubset(set(value))
    if flattened:
        value = {
            "schema": value.get("schema"),
            "logical_model_id": value.get("logical_model_id"),
            "served_names": value.get("served_names"),
            "checkpoint": {
                "revision": value.get("checkpoint_revision"),
                "weight_digest": value.get("weight_digest_sha256"),
            },
            "limits": {
                "context_tokens": value.get("context_limit_tokens"),
                "output_tokens": value.get("output_limit_tokens"),
            },
            "protocols": value.get("protocols"),
            "capabilities": value.get("capabilities"),
            "quantization": value.get("quantization"),
            "runtime": value.get("runtime"),
            "allowed_tool_profiles": value.get("allowed_tool_profiles"),
        }
    expected = {
        "schema",
        "logical_model_id",
        "served_names",
        "checkpoint",
        "limits",
        "protocols",
        "capabilities",
        "quantization",
        "runtime",
        "allowed_tool_profiles",
    }
    _exact(manifest, expected, "manifest", issues)
    if value.get("schema") != MANIFEST_SCHEMA:
        _issue(issues, "manifest:schema_invalid")
    if not _identifier(value.get("logical_model_id")):
        _issue(issues, "manifest:logical_model_id_invalid")
    served = _list_of_text(value.get("served_names"), "manifest.served_names", issues, required=True)
    checkpoint = value.get("checkpoint")
    _exact(checkpoint, {"revision", "weight_digest"}, "manifest.checkpoint", issues)
    if isinstance(checkpoint, Mapping):
        revision = checkpoint.get("revision")
        digest = checkpoint.get("weight_digest")
        if not _text(revision) and not _digest(digest):
            _issue(issues, "manifest.checkpoint:revision_or_digest_required")
        if digest is not None and not _digest(digest):
            _issue(issues, "manifest.checkpoint:weight_digest_invalid")
    limits = value.get("limits")
    _exact(limits, {"context_tokens", "output_tokens"}, "manifest.limits", issues)
    if isinstance(limits, Mapping):
        for name in ("context_tokens", "output_tokens"):
            if not _int(limits.get(name), positive=True):
                _issue(issues, f"manifest.limits:{name}_invalid")
    protocols = _list_of_text(value.get("protocols"), "manifest.protocols", issues, required=True)
    capabilities = _list_of_text(value.get("capabilities"), "manifest.capabilities", issues, required=True)
    _list_of_text(value.get("allowed_tool_profiles"), "manifest.allowed_tool_profiles", issues, required=True)
    if not isinstance(value.get("quantization"), Mapping) or not value.get("quantization"):
        _issue(issues, "manifest.quantization_invalid")
    if not isinstance(value.get("runtime"), Mapping) or not value.get("runtime"):
        _issue(issues, "manifest.runtime_invalid")
    if any(str(key).lower() in {"endpoint", "url", "credential", "credentials", "token", "api_key"} for key in value):
        _issue(issues, "manifest:provider_detail_forbidden")
    sensitive = _sensitive_paths(value)
    for path in sensitive:
        _issue(issues, "manifest:sensitive_field_forbidden:" + path)
    status = "PASS" if not issues else "FAIL"
    normalized = dict(value)
    return {
        "schema": MANIFEST_SCHEMA,
        "status": status,
        "issues": sorted(issues),
        "manifest": normalized,
        "manifest_sha256": sha256_json(normalized) if status == "PASS" else None,
        "served_names": served,
        "protocols": protocols,
        "capabilities": capabilities,
    }


def validate_capability_profile(profile: Any, required_capabilities: Iterable[str] | None = None) -> dict[str, Any]:
    """Validate profile identity and required capability conformance."""

    issues: list[str] = []
    value = profile if isinstance(profile, Mapping) else {}
    name = value.get("name", value.get("profile_id"))
    # Transport v1 calls the declared set ``required_capabilities``.  It is
    # equivalent for compatibility purposes: the profile registry remains the
    # authority for what a named profile actually requires.
    declared = value.get("capabilities", value.get("required_capabilities"))
    if not _identifier(name) or name not in CAPABILITY_PROFILES:
        _issue(issues, "capability:profile_invalid")
        expected: set[str] = set()
    else:
        expected = set(CAPABILITY_PROFILES[name])
    if not isinstance(declared, list):
        _issue(issues, "capability:capabilities_not_array")
        declared_set: set[str] = set()
    else:
        declared_set = {str(item) for item in declared if _text(item)}
        if len(declared_set) != len(declared):
            _issue(issues, "capability:capabilities_invalid_or_duplicate")
    missing = sorted(expected - declared_set)
    if missing:
        _issue(issues, "UNSUPPORTED_CAPABILITY")
        for item in missing:
            _issue(issues, "capability:missing:" + item)
    required = set(required_capabilities or ())
    absent = sorted(required - declared_set)
    if absent:
        _issue(issues, "UNSUPPORTED_CAPABILITY")
        for item in absent:
            _issue(issues, "capability:required_missing:" + item)
    if value.get("schema") not in (None, CAPABILITY_SCHEMA, "orch-dork/capability-profile/v1"):
        _issue(issues, "capability:schema_invalid")
    if name == "tool-free-canary" and required:
        _issue(issues, "UNSUPPORTED_CAPABILITY")
    return {
        "schema": CAPABILITY_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "profile": name,
        "capabilities": sorted(declared_set),
        "missing": sorted(set(missing + absent)),
        "profile_sha256": sha256_json({"name": name, "capabilities": sorted(declared_set)})
        if not issues
        else None,
    }


def evaluate_jwj_lab_route(route: Any, manifest: Any | None = None) -> dict[str, Any]:
    """Evaluate a declared jwj-lab vLLM identity; never contact the route."""

    issues: list[str] = []
    value = route if isinstance(route, Mapping) else {}
    if not isinstance(route, Mapping):
        _issue(issues, "route:not_object")
    if value.get("schema") not in (None, ROUTE_SCHEMA):
        _issue(issues, "route:schema_invalid")
    if value.get("host_alias") != "jwj-lab":
        _issue(issues, "route:host_alias_invalid")
    if value.get("protocol") not in ("vllm", "vllm-openai", "openai-compatible"):
        _issue(issues, "route:protocol_invalid")
    if not _identifier(value.get("route_id")):
        _issue(issues, "route:route_id_invalid")
    served = value.get("served_names", value.get("served_models"))
    served_names = _list_of_text(served, "route.served_names", issues, required=True)
    if value.get("model_served") is False or value.get("status") in {"not_served", "unavailable"}:
        _issue(issues, "MODEL_NOT_SERVED")
    if value.get("model_served") is not True and value.get("status") not in {"served", "known"}:
        _issue(issues, "MODEL_NOT_SERVED")
    candidates = value.get("matching_routes")
    if candidates is not None and (not isinstance(candidates, list) or len(candidates) != 1):
        _issue(issues, "AMBIGUOUS_ROUTE")
    if value.get("ambiguous") is True or value.get("route_count") not in (None, 1):
        _issue(issues, "AMBIGUOUS_ROUTE")
    for key in value:
        if str(key).lower() in {"url", "endpoint", "base_url", "credential", "token", "api_key", "authorization"}:
            _issue(issues, "route:provider_detail_forbidden")
    for path in _sensitive_paths(value):
        _issue(issues, "route:sensitive_field_forbidden:" + path)
    manifest_report = None
    if manifest is not None:
        manifest_report = validate_model_manifest(manifest)
        if manifest_report["status"] != "PASS":
            issues.extend("manifest:" + item for item in manifest_report["issues"])
        elif not set(manifest_report["served_names"]).intersection(served_names):
            _issue(issues, "MODEL_NOT_SERVED")
    return {
        "schema": ROUTE_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "route_id": value.get("route_id"),
        "served_names": served_names,
        "contacted": False,
        "declarative_only": True,
        "manifest_sha256": manifest_report.get("manifest_sha256") if manifest_report else None,
    }


def _validate_call(call: Any) -> tuple[dict[str, Any], list[str]]:
    value = call.to_dict() if isinstance(call, WorkerCall) else (dict(call) if isinstance(call, Mapping) else {})
    issues: list[str] = []
    required = {
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
    _exact(value, required, "call", issues)
    if value.get("schema") not in ("orch-dork/worker-call/v1", None):
        _issue(issues, "call:schema_invalid")
    for field in ("call_id", "idempotency_key"):
        if not _identifier(value.get(field)):
            _issue(issues, "call:" + field + "_invalid")
    base_value = value.get("base_revision")
    if isinstance(base_value, Mapping):
        revision = base_value.get("revision")
        if not _text(revision):
            _issue(issues, "call:base_revision_invalid")
        value["base_revision"] = str(revision or "")
    elif not _identifier(value.get("base_revision")):
        _issue(issues, "call:base_revision_invalid")
    if not isinstance(value.get("assignment"), Mapping) or not value.get("assignment"):
        _issue(issues, "call:assignment_invalid")
    if not isinstance(value.get("lane_policy"), Mapping) or not value.get("lane_policy"):
        _issue(issues, "call:lane_policy_invalid")
    caps = _list_of_text(value.get("required_capabilities"), "call.required_capabilities", issues)
    if not isinstance(value.get("authority_ref"), Mapping) or not value.get("authority_ref"):
        _issue(issues, "call:authority_ref_invalid")
    budgets = value.get("budgets")
    budget_names = {"wall_time_ms", "generation_count", "token_count", "tool_call_count", "child_count", "concurrency"}
    _exact(budgets, budget_names, "call.budgets", issues)
    if isinstance(budgets, Mapping):
        for name in budget_names:
            if not _int(budgets.get(name), positive=name == "wall_time_ms"):
                _issue(issues, "call.budgets:" + name + "_invalid")
    for path in _sensitive_paths(value):
        _issue(issues, "call:sensitive_field_forbidden:" + path)
    return {**value, "required_capabilities": caps}, sorted(set(issues))


def _extract_route(program: Mapping[str, Any]) -> Any:
    if "route" in program:
        return program.get("route")
    routes = program.get("routes")
    if isinstance(routes, list):
        if len(routes) != 1:
            return {"ambiguous": True, "matching_routes": routes}
        return routes[0]
    return None


def _budget_usage(response: Mapping[str, Any]) -> dict[str, int | None]:
    usage = response.get("usage")
    usage = usage if isinstance(usage, Mapping) else {}
    return {
        "wall_time_ms": usage.get("wall_time_ms", response.get("wall_time_ms")),
        "generation_count": usage.get("generation_count", response.get("generation_count", 1)),
        "token_count": usage.get("token_count", usage.get("total_tokens", response.get("token_count"))),
        "tool_call_count": usage.get("tool_call_count", response.get("tool_call_count", 0)),
        "child_count": usage.get("child_count", response.get("child_count", 0)),
        "concurrency": usage.get("concurrency", response.get("concurrency", 1)),
    }


def _budget_issues(budgets: Mapping[str, Any], usage: Mapping[str, Any]) -> list[str]:
    issues: list[str] = []
    for field in ("wall_time_ms", "generation_count", "token_count", "tool_call_count", "child_count", "concurrency"):
        observed = usage.get(field)
        limit = budgets.get(field)
        if observed is not None and type(observed) is int and type(limit) is int and observed > limit:
            _issue(issues, "BUDGET_EXHAUSTED:" + field)
        elif observed is not None and type(observed) is not int:
            _issue(issues, "usage:" + field + "_invalid")
    return issues


def _result(status: str, call_id: str, reason: str, *, response: Mapping[str, Any] | None = None, lifecycle: Mapping[str, Any] | None = None, evidence_ref: Mapping[str, Any] | None = None) -> dict[str, Any]:
    response = response or {}
    candidate = response.get("candidate_diff", response.get("patch"))
    if not isinstance(candidate, str):
        candidate = None
    tests = response.get("tests", response.get("test_report"))
    tests = dict(tests) if isinstance(tests, Mapping) else {"status": "UNKNOWN", "known": False}
    identity = response.get("effective_identity", response.get("identity"))
    identity = dict(identity) if isinstance(identity, Mapping) else {}
    result = WorkerResult(
        status=status,
        call_id=call_id,
        reason=reason,
        candidate_diff=candidate,
        tests=tests,
        usage=_known_usage(response.get("usage")),
        timing=_known_timing(response.get("timing")),
        effective_identity=identity,
        evidence_ref=evidence_ref or {},
        lifecycle=lifecycle or {},
    ).to_dict()
    result["candidate_diff_sha256"] = sha256_json(candidate) if candidate is not None else None
    return result


class ReplayAdapter(WorkerTransport):
    """Deterministic fake adapter; it never retries, falls back, or contacts anything."""

    adapter_id = "provider-free-replay"

    def __init__(self, response: Mapping[str, Any] | None = None, *, responses: Sequence[Mapping[str, Any]] | None = None):
        self._response = dict(response or {})
        self._responses = [dict(item) for item in (responses or ())]
        self._idempotency_keys: set[str] = set()
        self.records: list[dict[str, Any]] = []

    def invoke(self, call: WorkerCall | Mapping[str, Any]) -> dict[str, Any]:
        value, issues = _validate_call(call)
        call_id = str(value.get("call_id", ""))
        key = value.get("idempotency_key")
        if key in self._idempotency_keys:
            issues.append("DUPLICATE_IDEMPOTENCY_KEY")
        else:
            self._idempotency_keys.add(key)
        response = self._responses.pop(0) if self._responses else dict(self._response)
        if response.get("post_dispatch_ambiguous") is True:
            status, reason = "DELIVERY_UNCERTAIN", "POST_DISPATCH_AMBIGUITY"
        elif response.get("cancel_requested") is True:
            status, reason = "CANCELLED", "CANCELLATION_REQUESTED"
        elif response.get("timed_out") is True:
            status, reason = "TIMED_OUT", "WALL_TIME_EXHAUSTED"
        elif response.get("cleanup_status") in {"uncertain", "failed"}:
            status, reason = "RECOVERY_PENDING", "CLEANUP_UNCERTAIN"
        elif issues:
            status, reason = "REJECTED", sorted(set(issues))[0]
        else:
            usage = _budget_usage(response)
            issues.extend(_budget_issues(value.get("budgets", {}), usage))
            if issues:
                status, reason = "REJECTED", sorted(set(issues))[0]
            elif response.get("status") in RESULT_STATUSES:
                status, reason = str(response["status"]), str(response.get("reason", response["status"]))
            elif response.get("model_substitution") or response.get("fallback") or response.get("retry") or response.get("resampled"):
                status, reason = "REJECTED", "IMPLICIT_RETRY_FALLBACK_OR_SUBSTITUTION"
            elif response.get("candidate_diff", response.get("patch")) is None:
                status, reason = "REJECTED", "CANDIDATE_PATCH_MISSING"
            elif response.get("applied") is True:
                status, reason = "REJECTED", "CANDIDATE_APPLICATION_FORBIDDEN"
            else:
                status, reason = "CANDIDATE_READY", "REPLAYED"
        lifecycle = {
            "state": status,
            "events": list(response.get("lifecycle", {}).get("events", [])) if isinstance(response.get("lifecycle"), Mapping) else [],
            "attempts": list(response.get("attempts", [])) if isinstance(response.get("attempts"), list) else [],
            "hosted_generations": list(response.get("hosted_generations", [])) if isinstance(response.get("hosted_generations"), list) else [],
            "tool_calls": list(response.get("tool_calls", [])) if isinstance(response.get("tool_calls"), list) else [],
            "retries": list(response.get("retries", [])) if isinstance(response.get("retries"), list) else [],
            "substitutions": list(response.get("substitutions", [])) if isinstance(response.get("substitutions"), list) else [],
        }
        result = _result(status, call_id, reason, response=response, lifecycle=lifecycle)
        self.records.append({"idempotency_key": key, "call_id": call_id, "result": result})
        return result


FakeAdapter = ReplayAdapter
ProviderFreeReplayAdapter = ReplayAdapter


class JwjLabVllmRouteAdapter(WorkerTransport):
    """Declarative route adapter.  It evaluates observations but never connects."""

    adapter_id = "jwj-lab-vllm-declarative"

    def __init__(self, route: Mapping[str, Any], manifest: Mapping[str, Any] | None = None):
        self.route = dict(route)
        self.manifest = dict(manifest) if isinstance(manifest, Mapping) else None

    def evaluate(self) -> dict[str, Any]:
        return evaluate_jwj_lab_route(self.route, self.manifest)

    def invoke(self, call: WorkerCall | Mapping[str, Any]) -> dict[str, Any]:
        route_report = self.evaluate()
        value, call_issues = _validate_call(call)
        issues = list(call_issues) + list(route_report["issues"])
        status = "UNAVAILABLE" if any(item in {"MODEL_NOT_SERVED", "AMBIGUOUS_ROUTE"} for item in issues) else "REJECTED"
        reason = sorted(set(issues))[0] if issues else "DECLARATIVE_ROUTE_NOT_EXECUTED"
        lifecycle = {"state": status, "events": [], "attempts": [], "hosted_generations": [], "tool_calls": [], "retries": [], "substitutions": []}
        return _result(status, str(value.get("call_id", "")), reason, lifecycle=lifecycle, response={"effective_identity": {"adapter_id": self.adapter_id, "route_id": self.route.get("route_id")}})


DeclarativeVllmAdapter = JwjLabVllmRouteAdapter
JwjLabVLLMAdapter = JwjLabVllmRouteAdapter


def evaluate_worker_adapter(program: Any) -> dict[str, Any]:
    """Validate adapter declaration, route availability, capabilities, and lifecycle."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    if not isinstance(program, Mapping):
        _issue(issues, "program:not_object")
    if value.get("schema") not in (None, PROGRAM_SCHEMA, ADAPTER_SCHEMA):
        _issue(issues, "program:schema_invalid")
    adapter_kind = value.get("adapter_kind", value.get("kind", value.get("adapter_id")))
    if adapter_kind in {"replay", "fake", "provider-free-replay", "provider-free"}:
        adapter_kind = "replay"
    elif adapter_kind in {"jwj-lab-vllm", "vllm", "jwj-lab-vllm-declarative"}:
        adapter_kind = "jwj-lab-vllm"
    else:
        _issue(issues, "adapter:kind_invalid")
    manifest_report = validate_model_manifest(value.get("manifest")) if value.get("manifest") is not None else {"status": "PASS", "issues": [], "manifest_sha256": None, "served_names": []}
    if manifest_report["status"] != "PASS":
        issues.extend("manifest:" + item for item in manifest_report["issues"])
    call_value = value.get("call", value.get("worker_call"))
    call, call_issues = _validate_call(call_value)
    issues.extend(call_issues)
    capability = value.get("capability_profile", value.get("capabilities"))
    cap_report = validate_capability_profile(capability, call.get("required_capabilities", []))
    issues.extend(cap_report["issues"])
    route_report = None
    if adapter_kind == "jwj-lab-vllm":
        route_report = evaluate_jwj_lab_route(_extract_route(value), value.get("manifest"))
        issues.extend(route_report["issues"])
    response = value.get("response", value.get("replay_response", {}))
    response = response if isinstance(response, Mapping) else {}
    usage = _budget_usage(response)
    issues.extend(_budget_issues(call.get("budgets", {}), usage))
    for name in ("retries", "fallbacks", "substitutions", "resampling"):
        records = value.get(name, response.get(name))
        if records:
            _issue(issues, "IMPLICIT_" + name.upper() + "_FORBIDDEN")
    lifecycle = value.get("lifecycle", response.get("lifecycle", {}))
    if lifecycle and not isinstance(lifecycle, Mapping):
        _issue(issues, "lifecycle:not_object")
    if isinstance(lifecycle, Mapping):
        events = lifecycle.get("events", [])
        if not isinstance(events, list):
            _issue(issues, "lifecycle:events_not_array")
        else:
            terminal_count = sum(1 for event in events if isinstance(event, Mapping) and str(event.get("state", event.get("type", ""))) in TERMINAL_STATUSES)
            if terminal_count > 1:
                _issue(issues, "lifecycle:multiple_terminal_states")
    status = "PASS" if not issues else "FAIL"
    disposition = "ADAPTER_READY" if status == "PASS" else "ADAPTER_REFUSED"
    return {
        "schema": ADAPTER_SCHEMA,
        "status": status,
        "disposition": disposition,
        "issues": sorted(set(issues)),
        "adapter_kind": adapter_kind,
        "adapter_id": value.get("adapter_id", adapter_kind),
        "manifest": manifest_report,
        "capability_profile": cap_report,
        "route": route_report,
        "call": call,
        "contacted": False,
        "commands_executed": 0,
        "model_calls": 0,
        "retries_allowed": 0,
        "fallbacks_allowed": 0,
        "substitutions_allowed": 0,
    }


def _evidence_payload(bundle: Mapping[str, Any]) -> dict[str, Any]:
    return {key: bundle.get(key) for key in EVIDENCE_SECTIONS}


def seal_worker_evidence(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Create a deterministic hash-bound evidence envelope.

    The caller must provide all evidence sections.  No secret-bearing value is
    silently redacted here: rejecting it makes custody failures visible.
    """

    value = dict(bundle)
    evidence_id = value.get("evidence_id", value.get("bundle_id"))
    if not _identifier(evidence_id):
        raise ValueError("evidence_id is required")
    sections = _evidence_payload(value)
    missing = [name for name, item in sections.items() if item is None]
    if missing:
        raise ValueError("incomplete evidence: " + ",".join(missing))
    sensitive = _sensitive_paths(sections)
    if sensitive:
        raise ValueError("sensitive evidence field: " + sensitive[0])
    section_hashes = {name: sha256_json(item) for name, item in sections.items()}
    envelope = {
        "schema": EVIDENCE_SCHEMA,
        "evidence_id": evidence_id,
        "sections": sections,
        "section_hashes": section_hashes,
        "bundle_sha256": sha256_json({"schema": EVIDENCE_SCHEMA, "evidence_id": evidence_id, "section_hashes": section_hashes}),
        "excluded_fields": ["secrets", "raw_authorization", "private_reasoning", "session_bodies"],
    }
    return envelope


create_worker_evidence_bundle = seal_worker_evidence
build_worker_evidence_bundle = seal_worker_evidence


def validate_worker_evidence(bundle: Any) -> dict[str, Any]:
    """Verify evidence completeness, custody exclusions, and every hash binding."""

    issues: list[str] = []
    value = bundle if isinstance(bundle, Mapping) else {}
    if value.get("schema") != EVIDENCE_SCHEMA:
        _issue(issues, "evidence:schema_invalid")
    if not _identifier(value.get("evidence_id")):
        _issue(issues, "evidence:evidence_id_invalid")
    sections = value.get("sections")
    if not isinstance(sections, Mapping):
        _issue(issues, "evidence:sections_missing")
        sections = {}
    for name in EVIDENCE_SECTIONS:
        if name not in sections:
            _issue(issues, "evidence:missing:" + name)
    unknown = sorted(set(sections) - set(EVIDENCE_SECTIONS))
    for name in unknown:
        _issue(issues, "evidence:unknown_section:" + name)
    sensitive = _sensitive_paths(sections)
    for path in sensitive:
        _issue(issues, "evidence:sensitive_field_forbidden:" + path)
    hashes = value.get("section_hashes")
    if not isinstance(hashes, Mapping):
        _issue(issues, "evidence:section_hashes_missing")
        hashes = {}
    for name in EVIDENCE_SECTIONS:
        if name not in hashes:
            _issue(issues, "evidence:hash_missing:" + name)
        elif name in sections and hashes.get(name) != sha256_json(sections[name]):
            _issue(issues, "evidence:hash_mismatch:" + name)
        elif not _digest(hashes.get(name)):
            _issue(issues, "evidence:hash_invalid:" + name)
    expected_bundle = sha256_json({"schema": EVIDENCE_SCHEMA, "evidence_id": value.get("evidence_id"), "section_hashes": dict(hashes)})
    if value.get("bundle_sha256") != expected_bundle:
        _issue(issues, "evidence:bundle_hash_mismatch")
    excluded = value.get("excluded_fields")
    if not isinstance(excluded, list) or not {"secrets", "raw_authorization", "private_reasoning", "session_bodies"}.issubset(set(excluded)):
        _issue(issues, "evidence:exclusion_declaration_incomplete")
    status = "PASS" if not issues else "FAIL"
    return {
        "schema": EVIDENCE_SCHEMA,
        "status": status,
        "verified": status == "PASS",
        "issues": sorted(set(issues)),
        "evidence_id": value.get("evidence_id"),
        "bundle_sha256": value.get("bundle_sha256") if status == "PASS" else None,
    }


verify_worker_evidence = validate_worker_evidence


def make_worker_receipt(result: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    evidence_report = validate_worker_evidence(evidence)
    payload = {"result": dict(result), "evidence_ref": {"evidence_id": evidence.get("evidence_id"), "bundle_sha256": evidence.get("bundle_sha256")}}
    return {
        "schema": RECEIPT_SCHEMA,
        "status": "PASS" if evidence_report["status"] == "PASS" else "INCONCLUSIVE",
        "payload": payload,
        "payload_sha256": sha256_json(payload),
        "evidence": evidence_report,
    }


create_worker_receipt = make_worker_receipt


def replay_worker_receipt(receipt: Any) -> dict[str, Any]:
    """Replay only sealed hashes and status; never execute a recorded action."""

    value = receipt if isinstance(receipt, Mapping) else {}
    issues: list[str] = []
    if value.get("schema") != RECEIPT_SCHEMA:
        _issue(issues, "receipt:schema_invalid")
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        _issue(issues, "receipt:payload_missing")
        payload = {}
    expected = sha256_json(payload)
    if value.get("payload_sha256") != expected:
        _issue(issues, "receipt:payload_hash_mismatch")
    evidence = value.get("evidence")
    if not isinstance(evidence, Mapping) or evidence.get("status") != "PASS":
        _issue(issues, "receipt:evidence_unverified")
    status = "PASS" if not issues else "INCONCLUSIVE"
    projection = {
        "schema": RECEIPT_SCHEMA,
        "status": status,
        "issues": sorted(set(issues)),
        "payload_sha256": value.get("payload_sha256") if status == "PASS" else None,
        "result_status": payload.get("result", {}).get("status") if isinstance(payload.get("result"), Mapping) else None,
        "contacted": False,
        "executed": False,
    }
    projection["replay_sha256"] = sha256_json(projection)
    return projection


replay_receipt = replay_worker_receipt
deterministic_receipt_replay = replay_worker_receipt


def _run_rows(value: Any) -> tuple[list[Mapping[str, Any]], list[str]]:
    if isinstance(value, list):
        rows = [row for row in value if isinstance(row, Mapping)]
        return rows, ([] if len(rows) == len(value) else ["runs:row_invalid"])
    return [], ["runs:not_array"]


def _validate_qualification_runs(rows: Sequence[Mapping[str, Any]], issues: list[str]) -> dict[str, Any]:
    seen: set[str] = set()
    public = {"qwen": 0, "luna": 0}
    hidden = {"qwen": 0, "luna": 0}
    accepted = {"qwen": 0, "luna": 0}
    for index, row in enumerate(rows):
        run_id = row.get("run_id", f"run-{index}")
        if not _identifier(run_id) or run_id in seen:
            _issue(issues, "runs:duplicate_id")
        seen.add(str(run_id))
        model = row.get("model", row.get("condition"))
        if model not in {"qwen", "luna"}:
            _issue(issues, f"runs[{index}]:model_invalid")
            continue
        for field in ("task_id", "revision", "prompt_sha256", "budgets_sha256", "tools_sha256", "evaluator_version"):
            if not _text(row.get(field)) and not _digest(row.get(field)):
                _issue(issues, f"runs[{index}]:{field}_missing")
        if row.get("evidence") is None or row.get("evidence_status") in {"missing", "incomplete"}:
            _issue(issues, "MISSING_EVIDENCE")
        score = row.get("score", row.get("public_score"))
        if type(score) is int and score >= 0:
            suite = str(row.get("suite", "public")).lower()
            if "hidden" in suite:
                hidden[model] += score
            else:
                public[model] += score
        if row.get("patch_accepted") is True:
            accepted[model] += 1
        elif row.get("patch_accepted") is False:
            _issue(issues, "INDEPENDENT_PATCH_REJECTED")
    return {"public": public, "hidden": hidden, "accepted": accepted, "run_count": len(rows)}


def evaluate_worker_qualification(program: Any) -> dict[str, Any]:
    """Evaluate the frozen paired Qwen/Luna release contract offline."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    if value.get("schema") not in (None, QUALIFICATION_SCHEMA):
        _issue(issues, "qualification:schema_invalid")
    suite_id = value.get("suite_id", value.get("qualification_id"))
    if not _identifier(suite_id):
        _issue(issues, "qualification:suite_id_invalid")
    comparison = value.get("comparison") if isinstance(value.get("comparison"), Mapping) else value
    required = ("qwen_manifest_sha256", "luna_manifest_sha256", "tasks", "revisions", "prompts", "budgets", "tools", "evaluator_versions")
    for field in required:
        if field not in comparison:
            _issue(issues, "qualification:missing:" + field)
    for field in ("qwen_manifest_sha256", "luna_manifest_sha256"):
        if not _digest(comparison.get(field)):
            _issue(issues, "qualification:" + field + "_invalid")
    for field in ("tasks", "revisions", "prompts", "budgets", "tools", "evaluator_versions"):
        if not comparison.get(field):
            _issue(issues, "qualification:" + field + "_empty")
    runs, run_issues = _run_rows(value.get("runs", comparison.get("runs", [])))
    issues.extend(run_issues)
    summary = _validate_qualification_runs(runs, issues)
    # Require the two named single-lane fixtures before considering a release.
    named = {str(row.get("task_id", "")) for row in runs}
    for task in ("RouteWeave", "ReleaseForge"):
        if not any(task.lower() in item.lower() for item in named):
            _issue(issues, "qualification:single_lane_fixture_missing:" + task)
    phases = value.get("phases", {})
    if not isinstance(phases, Mapping):
        _issue(issues, "qualification:phases_invalid")
        phases = {}
    for key in ("two_worker", "four_worker_integrator"):
        phase = phases.get(key)
        if isinstance(phase, Mapping) and phase.get("enabled") is True:
            if phase.get("status") not in {"PASS", "pass", "qualified"}:
                _issue(issues, "qualification:phase_not_qualified:" + key)
            if key == "four_worker_integrator" and not phase.get("integrator"):
                _issue(issues, "qualification:integrator_missing")
    thresholds = value.get("thresholds", {})
    if not isinstance(thresholds, Mapping):
        _issue(issues, "qualification:thresholds_invalid")
        thresholds = {}
    if thresholds and (thresholds.get("public") != "20/20" or thresholds.get("hidden") != "100/100"):
        _issue(issues, "qualification:thresholds_not_frozen")
    if summary["run_count"] and (summary["public"]["qwen"] < 20 or summary["hidden"]["qwen"] < 100):
        _issue(issues, "qualification:qwen_threshold_not_met")
    if summary["run_count"] and (summary["public"]["luna"] < 20 or summary["hidden"]["luna"] < 100):
        _issue(issues, "qualification:luna_threshold_not_met")
    regressions = value.get("regression_gates", {})
    if not isinstance(regressions, Mapping) or any(regressions.get(name) is not True for name in ("reliability", "critical_path_latency", "sol_verification_burden")):
        _issue(issues, "qualification:regression_gate_missing")
    missing_evidence = any(item == "MISSING_EVIDENCE" for item in issues)
    status = "INCONCLUSIVE" if missing_evidence or not runs else ("PASS" if not issues else "FAIL")
    return {
        "schema": QUALIFICATION_SCHEMA,
        "status": status,
        "promotable": status == "PASS",
        "issues": sorted(set(issues)),
        "suite_id": suite_id,
        "summary": summary,
        "required_thresholds": {"public": "20/20", "hidden": "100/100"},
        "initial_phase": "single_lane_repeated_RouteWeave_ReleaseForge",
        "later_phases_separately_gated": True,
        "luna_remains_default": True,
    }


def evaluate_release_activation(program: Any) -> dict[str, Any]:
    """Check release-day activation prerequisites without changing routing."""

    value = program if isinstance(program, Mapping) else {}
    issues: list[str] = []
    if value.get("schema") not in (None, ACTIVATION_SCHEMA):
        _issue(issues, "activation:schema_invalid")
    for field in ("authority_exact", "runtime_proven", "manifest_exact", "luna_default"):
        if value.get(field) is not True:
            _issue(issues, "activation:" + field + "_required")
    if type(value.get("allowlisted_lane_count")) is not int or not 0 <= value.get("allowlisted_lane_count") <= 1:
        _issue(issues, "activation:lane_allowlist_invalid")
    return {
        "schema": ACTIVATION_SCHEMA,
        "status": "PASS" if not issues else "BLOCKED",
        "issues": sorted(set(issues)),
        "activated": False,
        "luna_default": True,
        "contacted": False,
    }


def validate_worker_manifest(manifest: Any) -> dict[str, Any]:
    return validate_model_manifest(manifest)


if __name__ == "__main__":  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_file")
    parser.add_argument("--mode", choices=("adapter", "manifest", "evidence", "qualification", "activation"), default="adapter")
    args = parser.parse_args()
    value = json.loads(open(args.json_file, encoding="utf-8").read())
    fn = {
        "adapter": evaluate_worker_adapter,
        "manifest": validate_model_manifest,
        "evidence": validate_worker_evidence,
        "qualification": evaluate_worker_qualification,
        "activation": evaluate_release_activation,
    }[args.mode]
    print(json.dumps(fn(value), indent=2, sort_keys=True))
