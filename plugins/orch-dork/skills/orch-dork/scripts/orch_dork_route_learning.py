#!/usr/bin/env python3
"""Provider-free factored route evidence and deterministic advisory routing.

The evaluator is deliberately pure.  It records no state, dispatches no work,
and never changes the workflow registry or the learned sizing/stopping policy.
Its outputs are content-addressed projections for the Control Tower to inspect
or append through the existing RunEngine authority.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from types import MappingProxyType
from typing import Any, Mapping


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ImportError:  # pragma: no cover - direct-file loading.
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        previous = sys.modules.get(name)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
            raise
        return module


learned = _load_sibling("orch_dork_learned_policy")
profiles = _load_sibling("orch_dork_workflow_profiles")
model_profiles = _load_sibling("orch_dork_model_profile_registry")


EVALUATION_REQUEST_SCHEMA = "orch-dork/route-learning-evaluation-request/v1"
EVALUATION_REPORT_SCHEMA = "orch-dork/route-learning-evaluation/v1"
ROUTE_REQUEST_SCHEMA = "orch-dork/rule-route-request/v1"
BANDIT_ADVICE_SCHEMA = "orch-dork/router-bandit-advice/v1"
RUN_RECORD_REQUEST_SCHEMA = "orch-dork/factored-run-record-request/v1"
ROUTE_RECORD_SCHEMA = "orch-dork/factored-route-record/v1"
OUTCOME_RECORD_SCHEMA = "orch-dork/factored-outcome-record/v1"
FACTORED_RUN_RECORD_SCHEMA = "orch-dork/factored-run-record/v1"
FACTORED_RUN_VALIDATION_SCHEMA = "orch-dork/factored-run-validation/v1"
# Issue 186 (FR68): the v2 record adds the role and profile dimensions.  Its
# route record names the routing policy that decided the run and the role and
# resolved profile behind every node; a separate sealed role-outcome record
# attributes outcomes per role and profile, so neither dimension is folded into
# the run-level outcome fields.  v1 requests and records keep their bytes.
RUN_RECORD_REQUEST_SCHEMA_V2 = "orch-dork/factored-run-record-request/v2"
ROUTE_RECORD_SCHEMA_V2 = "orch-dork/factored-route-record/v2"
ROLE_OUTCOME_RECORD_SCHEMA = "orch-dork/factored-role-outcome-record/v1"
FACTORED_RUN_RECORD_SCHEMA_V2 = "orch-dork/factored-run-record/v2"


_MAX_CANONICAL_BYTES = 262_144
_MAX_TEXT_BYTES = 4_096
_MAX_LIST_ITEMS = 64
_MAX_COUNT = 10**12

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")

_EVALUATION_FIELDS = frozenset({"schema", "operation", "request"})
_ROUTE_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "task_features",
        "learned_policy",
        "promotion_record",
        "bandit_advice",
    }
)
_TASK_FEATURE_FIELDS = frozenset(
    {
        "task_id",
        "task_family",
        "family_known",
        "difficulty_bucket",
        "privacy_class",
        "risk_class",
        "safety_gate",
        "safety_evidence_sha256",
        "tightly_sequential",
        "parallelizable_independent_scopes",
        "objective_checks_available",
        "multiple_plausible_solutions",
        "explicit_complex_dependencies",
    }
)
_BANDIT_FIELDS = frozenset(
    {
        "schema",
        "candidate_profile_id",
        "parameter_schema",
        "parameters_sha256",
        "training_lineage_sha256s",
        "evaluation_lineage_sha256s",
        "offline_evaluation_sha256",
        "shadow_evaluation_sha256",
        "advisory_only",
        "active",
        "production_exploration",
        "advice_sha256",
    }
)
_RUN_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "terminal_stream_sha256",
        "task_features",
        "route_factors",
        "outcome_factors",
        "source_refs",
    }
)
_ROUTE_FACTOR_FIELDS = frozenset(
    {
        "task_features_sha256",
        "router_report_sha256",
        "profile_id",
        "cut_strategy",
        "lane_count",
        "executor_choices",
        "context_choice",
        "budget_choice",
        "budget_sha256",
        "verification_choice",
        "sizing_policy_ref",
        "stopping_policy_ref",
    }
)
_EXECUTOR_FIELDS = frozenset({"role", "executor_group", "model_profile"})
_CONTEXT_FIELDS = frozenset(
    {"policy_id", "input_tokens", "ingress_limit_tokens"}
)
_BUDGET_FIELDS = frozenset(
    {"token_limit", "latency_limit_ms", "cost_limit_micros"}
)
_VERIFICATION_FIELDS = frozenset({"policy_id", "required_layers"})
_OUTCOME_FACTOR_FIELDS = frozenset(
    {
        "terminal_outcome",
        "correctness",
        "verification_status",
        "verification_evidence_sha256",
        "rework_count",
        "latency_ms",
        "usage",
        "cost",
        "integration_load",
        "privacy_event_refs",
        "authority_event_refs",
        "human_disposition",
        "completed_at",
    }
)
_USAGE_FIELDS = frozenset(
    {"input_tokens", "output_tokens", "tool_calls", "model_calls", "hosted_calls"}
)
_COST_FIELDS = frozenset({"currency", "micros"})
_INTEGRATION_FIELDS = frozenset(
    {"artifact_count", "ingress_tokens", "conflict_count"}
)
_ROUTE_RECORD_FIELDS = _ROUTE_FACTOR_FIELDS | frozenset(
    {"schema", "run_id", "terminal_stream_sha256", "route_record_sha256"}
)
_OUTCOME_RECORD_FIELDS = _OUTCOME_FACTOR_FIELDS | frozenset(
    {"schema", "run_id", "terminal_stream_sha256", "outcome_record_sha256"}
)
_FACTORED_RECORD_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "terminal_stream_sha256",
        "task_features",
        "task_features_sha256",
        "route_record",
        "route_record_sha256",
        "outcome_record",
        "outcome_record_sha256",
        "source_refs",
        "advisory_only",
        "policy_mutated",
        "production_exploration",
        "authority_granted",
        "workers_permitted",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "factored_record_sha256",
    }
)

_RUN_REQUEST_FIELDS_V2 = _RUN_REQUEST_FIELDS | frozenset(
    {"role_factors", "role_outcome_factors"}
)
_ROLE_FACTOR_FIELDS = frozenset(
    {
        "registry_generation",
        "registry_sha256",
        "routing_policy_sha256",
        "assignments",
    }
)
_ROLE_ASSIGNMENT_FIELDS = frozenset(
    {"role", "profile_id", "profile_sha256", "model", "effort", "adapter", "node_ids"}
)
ROLE_OUTCOME_FACTORS = (
    "acceptance",
    "repair_passes",
    "elapsed_ms",
    "cost",
    "escalations",
    "human_disposition",
)
_ROLE_OUTCOME_FIELDS = frozenset({"role", "profile_id", *ROLE_OUTCOME_FACTORS})
# A role factor is either observed, {"status": "known", "value": ...}, or a
# typed unknown, {"status": "unknown", "reason": ...}; a missing value is
# never written as zero or success.  Each factor admits only the reasons that
# can explain its absence.
ROLE_FACTOR_UNKNOWN_REASONS = MappingProxyType(
    {
        "acceptance": (
            "not_attributable",
            "not_dispatched",
            "not_reviewed",
            "run_cancelled",
        ),
        "repair_passes": ("not_dispatched",),
        "elapsed_ms": ("not_dispatched", "not_observed"),
        "cost": ("cost_unpriced", "not_dispatched"),
        "escalations": ("not_attributable", "not_dispatched", "not_reviewed"),
        "human_disposition": ("not_attributable", "not_dispatched", "not_observed"),
    }
)
ACCEPTANCE_VALUES = ("accepted", "rejected")
_KNOWN_FACTOR_FIELDS = frozenset({"status", "value"})
_UNKNOWN_FACTOR_FIELDS = frozenset({"status", "reason"})
_ROUTE_RECORD_FIELDS_V2 = _ROUTE_RECORD_FIELDS | frozenset({"role_factors"})
_ROLE_OUTCOME_RECORD_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "terminal_stream_sha256",
        "routing_policy_sha256",
        "rows",
        "role_outcome_record_sha256",
    }
)
_FACTORED_RECORD_FIELDS_V2 = _FACTORED_RECORD_FIELDS | frozenset(
    {"role_outcome_record", "role_outcome_record_sha256"}
)


_PRIVACY_CLASSES = frozenset(
    {"local_only", "hosted_restricted", "hosted_standard"}
)
_RISK_CLASSES = frozenset({"low", "medium", "high", "critical"})
_TERMINAL_OUTCOMES = frozenset(
    {"success", "failure", "cancelled", "escalated", "partial"}
)
_CORRECTNESS = frozenset({"PASS", "FAIL", "NOT_APPLICABLE"})
_VERIFICATION_STATUSES = frozenset(
    {"PASS", "FAIL", "ESCALATED", "UNKNOWN", "NOT_APPLICABLE"}
)
_HUMAN_DISPOSITIONS = frozenset(
    {"accepted", "accepted_with_edits", "rejected", "not_required"}
)


class RouteLearningError(ValueError):
    """A bounded route-learning contract could not be canonicalized."""


def _canonical(value: Any) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > _MAX_CANONICAL_BYTES:
        raise RouteLearningError("canonical_bytes_exceeded")
    return raw


def json_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    result = deepcopy(dict(value))
    result.pop(field, None)
    result[field] = json_sha256(result)
    return result


def _seal_valid(value: Any, field: str) -> bool:
    if not isinstance(value, Mapping) or not _sha(value.get(field)):
        return False
    core = dict(value)
    digest = core.pop(field)
    try:
        return digest == json_sha256(core)
    except (RouteLearningError, TypeError, ValueError, OverflowError):
        return False


def _issue(issues: list[str], code: str) -> None:
    if code not in issues:
        issues.append(code)


def _closed(
    value: Any, fields: frozenset[str], label: str, issues: list[str]
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _issue(issues, label + ":contract_invalid")
        return {}
    return deepcopy(dict(value))


def _sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _count(value: Any, *, minimum: int = 0, maximum: int = _MAX_COUNT) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _sha_list(
    value: Any, label: str, issues: list[str], *, minimum: int = 0
) -> list[str]:
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= _MAX_LIST_ITEMS
        or any(not _sha(item) for item in value)
        or len(value) != len(set(value))
    ):
        _issue(issues, label + ":invalid")
        return []
    return sorted(value)


def _source_refs(value: Any, issues: list[str]) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= _MAX_LIST_ITEMS
        or any(
            not isinstance(item, str)
            or not item
            or len(item.encode("utf-8")) > _MAX_TEXT_BYTES
            for item in value
        )
        or len(value) != len(set(value))
    ):
        _issue(issues, "run_record:source_refs_invalid")
        return []
    return sorted(value)


def _valid_instant(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo == timezone.utc


def _validate_task_features(value: Any, issues: list[str]) -> dict[str, Any]:
    task = _closed(value, _TASK_FEATURE_FIELDS, "task_features", issues)
    if not task:
        return {}
    for field in ("task_id", "task_family"):
        if not _identifier(task.get(field)):
            _issue(issues, "task_features:" + field + "_invalid")
    if type(task.get("family_known")) is not bool:
        _issue(issues, "task_features:family_known_invalid")
    if task.get("difficulty_bucket") not in learned.DIFFICULTY_BUCKETS:
        _issue(issues, "task_features:difficulty_invalid")
    if task.get("privacy_class") not in _PRIVACY_CLASSES:
        _issue(issues, "task_features:privacy_invalid")
    if task.get("risk_class") not in _RISK_CLASSES:
        _issue(issues, "task_features:risk_invalid")
    if task.get("safety_gate") not in {"PASS", "REFUSE"}:
        _issue(issues, "task_features:safety_gate_invalid")
    if not _sha(task.get("safety_evidence_sha256")):
        _issue(issues, "task_features:safety_evidence_invalid")
    for field in (
        "tightly_sequential",
        "parallelizable_independent_scopes",
        "objective_checks_available",
        "multiple_plausible_solutions",
        "explicit_complex_dependencies",
    ):
        if type(task.get(field)) is not bool:
            _issue(issues, "task_features:" + field + "_invalid")
    return task


def _bandit_result(
    disposition: str,
    *,
    candidate_profile_id: str | None = None,
    advice_sha256: str | None = None,
    reason_codes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "disposition": disposition,
        "candidate_profile_id": candidate_profile_id,
        "advice_sha256": advice_sha256,
        "reason_codes": list(reason_codes or []),
        "applied": False,
    }


def validate_bandit_advice(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    advice = _closed(value, _BANDIT_FIELDS, "bandit", issues)
    if not advice:
        return {
            "status": "FAIL",
            "disposition": "REFUSED_INVALID_ADVICE",
            "issues": sorted(issues),
            "candidate_profile_id": None,
            "advice_sha256": None,
        }
    if advice.get("schema") != BANDIT_ADVICE_SCHEMA:
        _issue(issues, "bandit:schema_invalid")
    if not _identifier(advice.get("candidate_profile_id")):
        _issue(issues, "bandit:profile_id_invalid")
    try:
        registered = profiles.profile(advice.get("candidate_profile_id"))
    except (profiles.WorkflowProfileError, TypeError, ValueError):
        return {
            "status": "FAIL",
            "disposition": "REFUSED_UNREGISTERED_ACTION",
            "issues": ["bandit:profile_unregistered"],
            "candidate_profile_id": None,
            "advice_sha256": advice.get("advice_sha256") if _sha(advice.get("advice_sha256")) else None,
        }
    if advice.get("parameter_schema") != registered["parameter_schema"]:
        _issue(issues, "bandit:parameter_schema_mismatch")
    for field in (
        "parameters_sha256",
        "offline_evaluation_sha256",
        "shadow_evaluation_sha256",
    ):
        if not _sha(advice.get(field)):
            _issue(issues, "bandit:" + field + "_invalid")
    training = _sha_list(
        advice.get("training_lineage_sha256s"),
        "bandit:training_lineages",
        issues,
        minimum=1,
    )
    evaluation = _sha_list(
        advice.get("evaluation_lineage_sha256s"),
        "bandit:evaluation_lineages",
        issues,
        minimum=1,
    )
    if set(training) & set(evaluation):
        return {
            "status": "FAIL",
            "disposition": "REFUSED_LINEAGE_LEAKAGE",
            "issues": ["bandit:lineage_not_disjoint"],
            "candidate_profile_id": registered["profile_id"],
            "advice_sha256": advice.get("advice_sha256") if _sha(advice.get("advice_sha256")) else None,
        }
    if (
        advice.get("advisory_only") is not True
        or advice.get("active") is not False
        or advice.get("production_exploration") is not False
    ):
        return {
            "status": "FAIL",
            "disposition": "REFUSED_PRODUCTION_EXPLORATION",
            "issues": ["bandit:inactive_contract_required"],
            "candidate_profile_id": registered["profile_id"],
            "advice_sha256": advice.get("advice_sha256") if _sha(advice.get("advice_sha256")) else None,
        }
    if not _seal_valid(advice, "advice_sha256"):
        _issue(issues, "bandit:seal_invalid")
    return {
        "status": "PASS" if not issues else "FAIL",
        "disposition": "ACCEPTED_INACTIVE" if not issues else "REFUSED_INVALID_ADVICE",
        "issues": sorted(issues),
        "candidate_profile_id": registered["profile_id"],
        "advice_sha256": advice.get("advice_sha256") if not issues else None,
    }


def _evaluate_bandit(value: Any) -> dict[str, Any]:
    if value is None:
        return _bandit_result("NOT_SUBMITTED")
    report = validate_bandit_advice(value)
    return _bandit_result(
        report["disposition"],
        candidate_profile_id=report.get("candidate_profile_id"),
        advice_sha256=report.get("advice_sha256"),
        reason_codes=report.get("issues", []),
    )


def _standing_advice(source: str = "standing_defaults") -> dict[str, Any]:
    return {
        "source": source,
        "standing_defaults_id": learned.STANDING_DEFAULTS_ID,
        "policy_sha256": None,
        "promotion_record_sha256": None,
        "inference_sha256": None,
        "sizer_recommendation": None,
        "stopping_signal": None,
        "advisory_only": True,
        "split_gate_required": True,
        "deepening_gate_required": True,
        "workers_permitted": False,
        "authority_granted": False,
    }


def _learned_advice(
    task: Mapping[str, Any],
    policy: Any,
    promotion: Any,
    issues: list[str],
) -> dict[str, Any]:
    if policy is None and promotion is None:
        return _standing_advice()
    if policy is None or promotion is None:
        _issue(issues, "learned:policy_promotion_pair_required")
        return _standing_advice("invalid_evidence")
    policy_validation = learned.validate_learned_policy(policy)
    if policy_validation.get("status") != "PASS":
        _issue(issues, "learned:policy_invalid")
    promotion_validation = learned.validate_promotion_record(promotion)
    if promotion_validation.get("status") != "PASS":
        _issue(issues, "learned:promotion_invalid")
    if issues:
        return _standing_advice("invalid_evidence")
    if promotion.get("candidate_policy_sha256") != policy.get("policy_sha256"):
        _issue(issues, "learned:promotion_policy_mismatch")
        return _standing_advice("invalid_evidence")
    assignments = promotion.get("family_classifier", {}).get("assignments", {})
    if assignments.get(task["task_family"]) != "candidate":
        advice = _standing_advice("standing_defaults_after_promotion")
        advice["promotion_record_sha256"] = promotion["record_sha256"]
        return advice
    inference = learned.evaluate_learned_policy(
        {
            "schema": learned.INFERENCE_PROGRAM_SCHEMA,
            "policy": policy,
            "task": {
                "task_id": task["task_id"],
                "task_family": task["task_family"],
                "difficulty_bucket": task["difficulty_bucket"],
            },
        }
    )
    if inference.get("status") != "PASS":
        _issue(issues, "learned:inference_invalid")
        return _standing_advice("invalid_evidence")
    if (
        inference.get("advisory_only") is not True
        or inference.get("split_gate_required") is not True
        or inference.get("deepening_gate_required") is not True
        or inference.get("workers_permitted") is not False
        or inference.get("authority_granted") is not False
    ):
        _issue(issues, "learned:inference_authority_invalid")
        return _standing_advice("invalid_evidence")
    return {
        "source": "promoted_policy",
        "standing_defaults_id": learned.STANDING_DEFAULTS_ID,
        "policy_sha256": policy["policy_sha256"],
        "promotion_record_sha256": promotion["record_sha256"],
        "inference_sha256": json_sha256(inference),
        "sizer_recommendation": deepcopy(inference.get("sizer_recommendation")),
        "stopping_signal": deepcopy(inference.get("stopping_signal")),
        "advisory_only": True,
        "split_gate_required": True,
        "deepening_gate_required": True,
        "workers_permitted": False,
        "authority_granted": False,
    }


def _rule(task: Mapping[str, Any]) -> tuple[str, str]:
    if task["family_known"] is False:
        return "direct/v1", "unknown_family_safe_default"
    if task["explicit_complex_dependencies"]:
        return "finite_dag/v1", "explicit_complex_dependencies"
    if task["tightly_sequential"]:
        return "direct/v1", "tightly_sequential"
    if task["objective_checks_available"]:
        return "execute_verify_repair/v1", "objective_checks"
    if task["multiple_plausible_solutions"]:
        return "best_of_n/v1", "multiple_plausible_solutions"
    if task["parallelizable_independent_scopes"]:
        return "parallel_join/v1", "parallel_independent_scopes"
    return "direct/v1", "safe_default"


def _route(request: Any) -> tuple[str, str, list[str], Any, Any]:
    issues: list[str] = []
    value = _closed(request, _ROUTE_REQUEST_FIELDS, "route_request", issues)
    if not value:
        return "FAIL", "INVALID_ENVELOPE", issues, None, _bandit_result("NOT_EVALUATED_INVALID_ENVELOPE")
    if value.get("schema") != ROUTE_REQUEST_SCHEMA:
        _issue(issues, "route_request:schema_invalid")
    task = _validate_task_features(value.get("task_features"), issues)
    if issues:
        return "FAIL", "INVALID_EVIDENCE", issues, None, _bandit_result("NOT_EVALUATED_INVALID_EVIDENCE")
    if task["safety_gate"] == "REFUSE":
        return (
            "PASS",
            "REFUSED_SAFETY",
            [],
            None,
            _bandit_result("NOT_EVALUATED_SAFETY_PRECEDENCE"),
        )
    advice = _learned_advice(
        task, value.get("learned_policy"), value.get("promotion_record"), issues
    )
    if issues:
        return "FAIL", "INVALID_EVIDENCE", issues, None, _bandit_result("NOT_EVALUATED_INVALID_EVIDENCE")
    bandit = _evaluate_bandit(value.get("bandit_advice"))
    profile_id, rule_id = _rule(task)
    registered = profiles.profile(profile_id)
    route = {
        "task_features_sha256": json_sha256(task),
        "profile_id": profile_id,
        "profile_sha256": registered["profile_sha256"],
        "rule_id": rule_id,
        "sizing_stopping_advice": advice,
        "advisory_only": True,
        "dispatch_permitted": False,
        "authority_granted": False,
    }
    return "PASS", "ROUTE_SELECTED", [], route, bandit


def _validate_route_factors(
    value: Any,
    task: Mapping[str, Any],
    issues: list[str],
) -> dict[str, Any]:
    route = _closed(value, _ROUTE_FACTOR_FIELDS, "route", issues)
    if not route:
        return {}
    if route.get("task_features_sha256") != json_sha256(task):
        _issue(issues, "route:task_features_mismatch")
    if not _sha(route.get("router_report_sha256")):
        _issue(issues, "route:router_report_invalid")
    try:
        profiles.profile(route.get("profile_id"))
    except (profiles.WorkflowProfileError, TypeError, ValueError):
        _issue(issues, "route:profile_unregistered")
    if not _identifier(route.get("cut_strategy")):
        _issue(issues, "route:cut_strategy_invalid")
    lane_count = route.get("lane_count")
    if not _count(lane_count, minimum=1, maximum=100):
        _issue(issues, "route:lane_count_invalid")
    elif (
        route.get("profile_id") == "direct/v1" and lane_count != 1
    ) or (
        # One execution plus each declared repair node: the Control Tower's
        # route counts every declared node, and a workflow declares at most
        # two repairs, so a run that declares repairs is still recordable.
        route.get("profile_id") == "execute_verify_repair/v1"
        and not 1 <= lane_count <= 1 + profiles.MAX_DECLARED_REPAIRS
    ) or (
        route.get("profile_id") in {"parallel_join/v1", "best_of_n/v1"}
        and lane_count < 2
    ):
        _issue(issues, "route:lane_count_profile_mismatch")
    executors = route.get("executor_choices")
    normalized_executors: list[dict[str, Any]] = []
    if not isinstance(executors, list) or not 1 <= len(executors) <= _MAX_LIST_ITEMS:
        _issue(issues, "route:executor_choices_invalid")
    else:
        for raw in executors:
            item = _closed(raw, _EXECUTOR_FIELDS, "route:executor", issues)
            if item and all(_identifier(item.get(field)) for field in _EXECUTOR_FIELDS):
                normalized_executors.append(item)
            elif item:
                _issue(issues, "route:executor_value_invalid")
        identities = [
            (item["role"], item["executor_group"], item["model_profile"])
            for item in normalized_executors
        ]
        if len(identities) != len(set(identities)):
            _issue(issues, "route:executor_duplicate")
        route["executor_choices"] = sorted(
            normalized_executors,
            key=lambda item: (
                item["role"], item["executor_group"], item["model_profile"]
            ),
        )
    context = _closed(route.get("context_choice"), _CONTEXT_FIELDS, "route:context", issues)
    if context:
        if not _identifier(context.get("policy_id")):
            _issue(issues, "route:context_policy_invalid")
        if not _count(context.get("input_tokens")) or not _count(
            context.get("ingress_limit_tokens")
        ):
            _issue(issues, "route:context_count_invalid")
        elif context["input_tokens"] > context["ingress_limit_tokens"]:
            _issue(issues, "route:context_limit_exceeded")
    budget = _closed(route.get("budget_choice"), _BUDGET_FIELDS, "route:budget", issues)
    if budget and any(not _count(budget.get(field)) for field in _BUDGET_FIELDS):
        _issue(issues, "route:budget_value_invalid")
    if not _sha(route.get("budget_sha256")):
        _issue(issues, "route:budget_sha256_invalid")
    verification = _closed(
        route.get("verification_choice"),
        _VERIFICATION_FIELDS,
        "route:verification",
        issues,
    )
    if verification:
        if not _identifier(verification.get("policy_id")):
            _issue(issues, "route:verification_policy_invalid")
        layers = verification.get("required_layers")
        if (
            not isinstance(layers, list)
            or not layers
            or len(layers) > len(profiles.VERIFICATION_LAYERS)
            or any(item not in profiles.VERIFICATION_LAYERS for item in layers)
            or len(layers) != len(set(layers))
        ):
            _issue(issues, "route:verification_layers_invalid")
        else:
            route["verification_choice"]["required_layers"] = [
                layer for layer in profiles.VERIFICATION_LAYERS if layer in layers
            ]
    for field in ("sizing_policy_ref", "stopping_policy_ref"):
        if not _identifier(route.get(field)):
            _issue(issues, "route:" + field + "_invalid")
    return route


def _validate_outcome_factors(value: Any, issues: list[str]) -> dict[str, Any]:
    outcome = _closed(value, _OUTCOME_FACTOR_FIELDS, "outcome", issues)
    if not outcome:
        return {}
    if outcome.get("terminal_outcome") not in _TERMINAL_OUTCOMES:
        _issue(issues, "outcome:terminal_outcome_invalid")
    if outcome.get("correctness") not in _CORRECTNESS:
        _issue(issues, "outcome:correctness_invalid")
    if outcome.get("verification_status") not in _VERIFICATION_STATUSES:
        _issue(issues, "outcome:verification_status_invalid")
    if not _sha(outcome.get("verification_evidence_sha256")):
        _issue(issues, "outcome:verification_invalid")
    for field in ("rework_count", "latency_ms"):
        if not _count(outcome.get(field)):
            _issue(issues, "outcome:" + field + "_invalid")
    usage = _closed(outcome.get("usage"), _USAGE_FIELDS, "outcome:usage", issues)
    if usage and any(not _count(usage.get(field)) for field in _USAGE_FIELDS):
        _issue(issues, "outcome:usage_value_invalid")
    cost = _closed(outcome.get("cost"), _COST_FIELDS, "outcome:cost", issues)
    if cost:
        if cost.get("currency") != "USD" or not _count(cost.get("micros")):
            _issue(issues, "outcome:cost_value_invalid")
    integration = _closed(
        outcome.get("integration_load"),
        _INTEGRATION_FIELDS,
        "outcome:integration",
        issues,
    )
    if integration and any(
        not _count(integration.get(field)) for field in _INTEGRATION_FIELDS
    ):
        _issue(issues, "outcome:integration_value_invalid")
    outcome["privacy_event_refs"] = _sha_list(
        outcome.get("privacy_event_refs"), "outcome:privacy_event_refs", issues
    )
    outcome["authority_event_refs"] = _sha_list(
        outcome.get("authority_event_refs"), "outcome:authority_event_refs", issues
    )
    if outcome.get("human_disposition") not in _HUMAN_DISPOSITIONS:
        _issue(issues, "outcome:human_disposition_invalid")
    if not _valid_instant(outcome.get("completed_at")):
        _issue(issues, "outcome:completed_at_invalid")
    return outcome


def known_factor(value: Any) -> dict[str, Any]:
    """An observed role factor."""

    return {"status": "known", "value": deepcopy(value)}


def unknown_factor(reason: str) -> dict[str, str]:
    """A role factor that was not observed, with the reason it is missing."""

    return {"status": "unknown", "reason": reason}


def _validate_role_factors(value: Any, issues: list[str]) -> dict[str, Any]:
    """The routing choice per role and profile: one row per role and profile.

    Rows are in canonical (role, profile_id) order, each profile names one
    role, and no node appears in two rows.  Whether the rows cover every
    node of the run's routing policy is the Control Tower's check, which
    holds the policy.
    """

    factors = _closed(value, _ROLE_FACTOR_FIELDS, "role_factors", issues)
    if not factors:
        return {}
    if not _identifier(factors.get("registry_generation")):
        _issue(issues, "role_factors:registry_generation_invalid")
    for field in ("registry_sha256", "routing_policy_sha256"):
        if not _sha(factors.get(field)):
            _issue(issues, "role_factors:" + field + "_invalid")
    assignments = factors.get("assignments")
    if not isinstance(assignments, list) or not 1 <= len(assignments) <= _MAX_LIST_ITEMS:
        _issue(issues, "role_factors:assignments_invalid")
        factors["assignments"] = []
        return factors
    keys: list[tuple[str, str]] = []
    nodes: list[str] = []
    for raw in assignments:
        item = _closed(raw, _ROLE_ASSIGNMENT_FIELDS, "role_factors:assignment", issues)
        if not item:
            continue
        role = item.get("role")
        profile_id = item.get("profile_id")
        if role not in model_profiles.ROLES:
            _issue(issues, "role_factors:role_unknown")
        if not _identifier(profile_id):
            _issue(issues, "role_factors:profile_id_invalid")
        if not _sha(item.get("profile_sha256")):
            _issue(issues, "role_factors:profile_sha256_invalid")
        for field in ("model", "effort"):
            if item.get(field) is not None and not _identifier(item.get(field)):
                _issue(issues, "role_factors:" + field + "_invalid")
        if item.get("adapter") not in model_profiles.ADAPTERS:
            _issue(issues, "role_factors:adapter_invalid")
        node_ids = item.get("node_ids")
        if (
            not isinstance(node_ids, list)
            or not 1 <= len(node_ids) <= _MAX_LIST_ITEMS
            or any(not _identifier(node) for node in node_ids)
            or node_ids != sorted(set(node_ids))
        ):
            _issue(issues, "role_factors:node_ids_invalid")
        else:
            nodes.extend(node_ids)
        if isinstance(role, str) and isinstance(profile_id, str):
            keys.append((role, profile_id))
    if len(keys) == len(assignments) and keys != sorted(set(keys)):
        _issue(issues, "role_factors:assignments_not_canonical")
    profile_ids = [profile_id for _role, profile_id in keys]
    if len(profile_ids) != len(set(profile_ids)):
        _issue(issues, "role_factors:profile_duplicate")
    if len(nodes) != len(set(nodes)):
        _issue(issues, "role_factors:node_duplicate")
    return factors


def _validate_role_factor(factor: str, value: Any, issues: list[str]) -> None:
    if (
        isinstance(value, Mapping)
        and set(value) == _UNKNOWN_FACTOR_FIELDS
        and value.get("status") == "unknown"
    ):
        if value.get("reason") not in ROLE_FACTOR_UNKNOWN_REASONS[factor]:
            _issue(issues, "role_outcome:" + factor + "_reason_invalid")
        return
    if (
        not isinstance(value, Mapping)
        or set(value) != _KNOWN_FACTOR_FIELDS
        or value.get("status") != "known"
    ):
        _issue(issues, "role_outcome:" + factor + "_untyped")
        return
    observed = value.get("value")
    if factor == "acceptance":
        valid = observed in ACCEPTANCE_VALUES
    elif factor == "human_disposition":
        valid = observed in _HUMAN_DISPOSITIONS
    elif factor == "cost":
        valid = (
            isinstance(observed, Mapping)
            and set(observed) == _COST_FIELDS
            and observed.get("currency") == "USD"
            and _count(observed.get("micros"))
        )
    else:
        valid = _count(observed)
    if not valid:
        _issue(issues, "role_outcome:" + factor + "_value_invalid")


def _validate_role_outcomes(
    value: Any, assignments: Any, issues: list[str]
) -> list[dict[str, Any]]:
    """One outcome row per role-factor row, in the same order, every factor typed."""

    expected = (
        [
            (item.get("role"), item.get("profile_id"))
            for item in assignments
            if isinstance(item, Mapping)
        ]
        if isinstance(assignments, list)
        else []
    )
    if not isinstance(value, list) or not expected or len(value) != len(expected):
        _issue(issues, "role_outcome:rows_mismatch")
        return []
    rows: list[dict[str, Any]] = []
    for raw, key in zip(value, expected):
        row = _closed(raw, _ROLE_OUTCOME_FIELDS, "role_outcome:row", issues)
        if not row:
            continue
        if (row.get("role"), row.get("profile_id")) != key:
            _issue(issues, "role_outcome:rows_mismatch")
        for factor in ROLE_OUTCOME_FACTORS:
            _validate_role_factor(factor, row.get(factor), issues)
        rows.append(row)
    return rows


def validate_role_attribution(role_factors: Any, role_outcome_factors: Any) -> dict[str, Any]:
    """Validate the shared role grammar without requiring route measurements.

    The project watcher can observe roles and their outcomes without knowing
    the older route record's context limits or task difficulty. This validates
    only that attribution; it grants no authority and certifies no provenance.
    """

    issues: list[str] = []
    factors = _validate_role_factors(role_factors, issues)
    rows = _validate_role_outcomes(role_outcome_factors, factors.get("assignments"), issues)
    return {
        "schema": "orch-dork/role-attribution-validation/v1",
        "status": "FAIL" if issues else "PASS",
        "issues": sorted(set(issues)),
        "role_factors": factors if not issues else None,
        "role_outcome_factors": rows if not issues else None,
    }


def _validate_role_outcome_record(
    record: Mapping[str, Any],
    role_factors: Mapping[str, Any],
    issues: list[str],
) -> None:
    role_record = _closed(
        record.get("role_outcome_record"),
        _ROLE_OUTCOME_RECORD_FIELDS,
        "role_outcome_record",
        issues,
    )
    if not role_record:
        return
    if role_record.get("schema") != ROLE_OUTCOME_RECORD_SCHEMA:
        _issue(issues, "role_outcome_record:schema_invalid")
    if role_record.get("run_id") != record.get("run_id") or role_record.get(
        "terminal_stream_sha256"
    ) != record.get("terminal_stream_sha256"):
        _issue(issues, "role_outcome_record:run_binding_mismatch")
    if role_record.get("routing_policy_sha256") != role_factors.get(
        "routing_policy_sha256"
    ):
        _issue(issues, "role_outcome_record:routing_policy_mismatch")
    _validate_role_outcomes(
        role_record.get("rows"), role_factors.get("assignments"), issues
    )
    if not _seal_valid(role_record, "role_outcome_record_sha256"):
        _issue(issues, "role_outcome_record:seal_invalid")
    if record.get("role_outcome_record_sha256") != role_record.get(
        "role_outcome_record_sha256"
    ):
        _issue(issues, "factored_record:role_outcome_digest_mismatch")


def _record_run(request: Any) -> tuple[str, str, list[str], Any]:
    issues: list[str] = []
    version_two = (
        isinstance(request, Mapping)
        and request.get("schema") == RUN_RECORD_REQUEST_SCHEMA_V2
    )
    value = _closed(
        request,
        _RUN_REQUEST_FIELDS_V2 if version_two else _RUN_REQUEST_FIELDS,
        "run_record",
        issues,
    )
    if not value:
        return "FAIL", "INVALID_ENVELOPE", issues, None
    if not version_two and value.get("schema") != RUN_RECORD_REQUEST_SCHEMA:
        _issue(issues, "run_record:schema_invalid")
    if not _identifier(value.get("run_id")):
        _issue(issues, "run_record:run_id_invalid")
    if not _sha(value.get("terminal_stream_sha256")):
        _issue(issues, "run_record:terminal_stream_invalid")
    task = _validate_task_features(value.get("task_features"), issues)
    route = _validate_route_factors(value.get("route_factors"), task, issues) if task else {}
    outcome = _validate_outcome_factors(value.get("outcome_factors"), issues)
    refs = _source_refs(value.get("source_refs"), issues)
    role_factors: dict[str, Any] = {}
    role_rows: list[dict[str, Any]] = []
    if version_two:
        role_factors = _validate_role_factors(value.get("role_factors"), issues)
        role_rows = _validate_role_outcomes(
            value.get("role_outcome_factors"),
            role_factors.get("assignments"),
            issues,
        )
    if issues:
        return "FAIL", "INVALID_EVIDENCE", sorted(issues), None
    route_core = {
        "schema": ROUTE_RECORD_SCHEMA_V2 if version_two else ROUTE_RECORD_SCHEMA,
        "run_id": value["run_id"],
        "terminal_stream_sha256": value["terminal_stream_sha256"],
        **route,
    }
    if version_two:
        route_core["role_factors"] = role_factors
    route_record = _seal(route_core, "route_record_sha256")
    outcome_record = _seal(
        {
            "schema": OUTCOME_RECORD_SCHEMA,
            "run_id": value["run_id"],
            "terminal_stream_sha256": value["terminal_stream_sha256"],
            **outcome,
        },
        "outcome_record_sha256",
    )
    factored_core = {
        "schema": (
            FACTORED_RUN_RECORD_SCHEMA_V2 if version_two else FACTORED_RUN_RECORD_SCHEMA
        ),
        "run_id": value["run_id"],
        "terminal_stream_sha256": value["terminal_stream_sha256"],
        "task_features": task,
        "task_features_sha256": json_sha256(task),
        "route_record": route_record,
        "route_record_sha256": route_record["route_record_sha256"],
        "outcome_record": outcome_record,
        "outcome_record_sha256": outcome_record["outcome_record_sha256"],
        "source_refs": refs,
        "advisory_only": True,
        "policy_mutated": False,
        "production_exploration": False,
        "authority_granted": False,
        "workers_permitted": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    if version_two:
        role_record = _seal(
            {
                "schema": ROLE_OUTCOME_RECORD_SCHEMA,
                "run_id": value["run_id"],
                "terminal_stream_sha256": value["terminal_stream_sha256"],
                "routing_policy_sha256": role_factors["routing_policy_sha256"],
                "rows": role_rows,
            },
            "role_outcome_record_sha256",
        )
        factored_core["role_outcome_record"] = role_record
        factored_core["role_outcome_record_sha256"] = role_record[
            "role_outcome_record_sha256"
        ]
    factored = _seal(factored_core, "factored_record_sha256")
    return "PASS", "RUN_EVIDENCE_RECORDED", [], factored


def validate_factored_record(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    version_two = (
        isinstance(value, Mapping)
        and value.get("schema") == FACTORED_RUN_RECORD_SCHEMA_V2
    )
    record = _closed(
        value,
        _FACTORED_RECORD_FIELDS_V2 if version_two else _FACTORED_RECORD_FIELDS,
        "factored_record",
        issues,
    )
    if record:
        if not version_two and record.get("schema") != FACTORED_RUN_RECORD_SCHEMA:
            _issue(issues, "factored_record:schema_invalid")
        if not _identifier(record.get("run_id")):
            _issue(issues, "factored_record:run_id_invalid")
        if not _sha(record.get("terminal_stream_sha256")):
            _issue(issues, "factored_record:terminal_stream_invalid")
        task = _validate_task_features(record.get("task_features"), issues)
        if task and record.get("task_features_sha256") != json_sha256(task):
            _issue(issues, "factored_record:task_features_mismatch")
        route = _closed(
            record.get("route_record"),
            _ROUTE_RECORD_FIELDS_V2 if version_two else _ROUTE_RECORD_FIELDS,
            "route_record",
            issues,
        )
        role_factors: dict[str, Any] = {}
        if route:
            route_factors = {
                key: route[key] for key in _ROUTE_FACTOR_FIELDS if key in route
            }
            if task:
                _validate_route_factors(route_factors, task, issues)
            expected_route_schema = (
                ROUTE_RECORD_SCHEMA_V2 if version_two else ROUTE_RECORD_SCHEMA
            )
            if route.get("schema") != expected_route_schema:
                _issue(issues, "route_record:schema_invalid")
            if version_two:
                role_factors = _validate_role_factors(route.get("role_factors"), issues)
            if route.get("run_id") != record.get("run_id") or route.get(
                "terminal_stream_sha256"
            ) != record.get("terminal_stream_sha256"):
                _issue(issues, "route_record:run_binding_mismatch")
            if not _seal_valid(route, "route_record_sha256"):
                _issue(issues, "route_record:seal_invalid")
            if record.get("route_record_sha256") != route.get(
                "route_record_sha256"
            ):
                _issue(issues, "factored_record:route_digest_mismatch")
        outcome = _closed(
            record.get("outcome_record"),
            _OUTCOME_RECORD_FIELDS,
            "outcome_record",
            issues,
        )
        if outcome:
            outcome_factors = {
                key: outcome[key] for key in _OUTCOME_FACTOR_FIELDS if key in outcome
            }
            _validate_outcome_factors(outcome_factors, issues)
            if outcome.get("schema") != OUTCOME_RECORD_SCHEMA:
                _issue(issues, "outcome_record:schema_invalid")
            if outcome.get("run_id") != record.get("run_id") or outcome.get(
                "terminal_stream_sha256"
            ) != record.get("terminal_stream_sha256"):
                _issue(issues, "outcome_record:run_binding_mismatch")
            if not _seal_valid(outcome, "outcome_record_sha256"):
                _issue(issues, "outcome_record:seal_invalid")
            if record.get("outcome_record_sha256") != outcome.get(
                "outcome_record_sha256"
            ):
                _issue(issues, "factored_record:outcome_digest_mismatch")
        if version_two:
            _validate_role_outcome_record(record, role_factors, issues)
        _source_refs(record.get("source_refs"), issues)
        for field, expected in (
            ("advisory_only", True),
            ("policy_mutated", False),
            ("production_exploration", False),
            ("authority_granted", False),
            ("workers_permitted", False),
            ("provider_free", True),
            ("model_calls", 0),
            ("hosted_calls", 0),
        ):
            if record.get(field) != expected or type(record.get(field)) is not type(expected):
                _issue(issues, "factored_record:" + field + "_invalid")
        if not _seal_valid(record, "factored_record_sha256"):
            _issue(issues, "factored_record:seal_invalid")
    return {
        "schema": FACTORED_RUN_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(issues),
        "factored_record_sha256": record.get("factored_record_sha256") if record and not issues else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _report(
    *,
    status: str,
    decision: str,
    issues: list[str],
    operation: str | None,
    route: Any = None,
    run_evidence: Any = None,
    bandit: Any = None,
) -> dict[str, Any]:
    return _seal(
        {
            "schema": EVALUATION_REPORT_SCHEMA,
            "status": status,
            "decision": decision,
            "issues": sorted(set(issues)),
            "operation": operation,
            "route": deepcopy(route),
            "run_evidence": deepcopy(run_evidence),
            "bandit": deepcopy(bandit) if bandit is not None else _bandit_result("NOT_APPLICABLE"),
            "advisory_only": True,
            "policy_mutated": False,
            "production_exploration": False,
            "split_gate_required": True,
            "deepening_gate_required": True,
            "authority_granted": False,
            "workers_permitted": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        },
        "report_sha256",
    )


def evaluate(program: Any) -> dict[str, Any]:
    """Evaluate one closed routing or terminal evidence request."""

    try:
        _canonical(program)
    except (RouteLearningError, TypeError, ValueError, OverflowError):
        return _report(
            status="FAIL",
            decision="INVALID_ENVELOPE",
            issues=["input:hostile_or_noncanonical"],
            operation=None,
        )
    issues: list[str] = []
    value = _closed(program, _EVALUATION_FIELDS, "evaluation", issues)
    if not value:
        return _report(
            status="FAIL",
            decision="INVALID_ENVELOPE",
            issues=issues,
            operation=None,
        )
    if value.get("schema") != EVALUATION_REQUEST_SCHEMA:
        _issue(issues, "evaluation:schema_invalid")
    operation = value.get("operation")
    if operation not in {"route", "record_run"}:
        _issue(issues, "evaluation:operation_invalid")
    if issues:
        return _report(
            status="FAIL",
            decision="INVALID_ENVELOPE",
            issues=issues,
            operation=operation if isinstance(operation, str) else None,
        )
    if operation == "route":
        status, decision, route_issues, route, bandit = _route(value.get("request"))
        return _report(
            status=status,
            decision=decision,
            issues=route_issues,
            operation=operation,
            route=route,
            bandit=bandit,
        )
    status, decision, record_issues, evidence = _record_run(value.get("request"))
    return _report(
        status=status,
        decision=decision,
        issues=record_issues,
        operation=operation,
        run_evidence=evidence,
    )


__all__ = [
    "BANDIT_ADVICE_SCHEMA",
    "EVALUATION_REQUEST_SCHEMA",
    "EVALUATION_REPORT_SCHEMA",
    "ACCEPTANCE_VALUES",
    "FACTORED_RUN_RECORD_SCHEMA",
    "FACTORED_RUN_RECORD_SCHEMA_V2",
    "OUTCOME_RECORD_SCHEMA",
    "ROLE_FACTOR_UNKNOWN_REASONS",
    "ROLE_OUTCOME_FACTORS",
    "ROLE_OUTCOME_RECORD_SCHEMA",
    "ROUTE_RECORD_SCHEMA",
    "ROUTE_RECORD_SCHEMA_V2",
    "ROUTE_REQUEST_SCHEMA",
    "RUN_RECORD_REQUEST_SCHEMA",
    "RUN_RECORD_REQUEST_SCHEMA_V2",
    "evaluate",
    "json_sha256",
    "known_factor",
    "unknown_factor",
    "validate_bandit_advice",
    "validate_factored_record",
    "validate_role_attribution",
]
