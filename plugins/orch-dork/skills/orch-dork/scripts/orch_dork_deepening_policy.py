#!/usr/bin/env python3
"""Closed, provider-free economic gate for runtime decomposition proposals.

The policy consumes an already typed decomposition proposal, the remaining
resources visible to root, and sealed Issue 104 measurements.  It records an
ACCEPT, DENY, or DEFER decision without applying a plan revision, scheduling a
worker, granting authority, or inventing a recursion-depth limit.  Dependency
depth is retained only as decision evidence; every proposed child remains an
ordinary node whose delegated scope can only stay equal or narrow.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ImportError:  # pragma: no cover - direct-file loading.
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


decomposition = _load_sibling("orch_dork_decomposition")
governor = _load_sibling("orch_dork_efficiency_governor")
ownership = _load_sibling("orch_dork_ownership")
trace = _load_sibling("orch_dork_trace")
hostile = _load_sibling("orch_dork_hostile_input")

PROFILE = hostile.PROFILE
HostileInputError = hostile.HostileInputError
canonicalize_bounded_json = hostile.canonicalize_bounded_json

PROGRAM_SCHEMA = "orch-dork/deepening-policy-program/v1"
REPORT_SCHEMA = "orch-dork/deepening-policy-report/v1"
DECISION_SCHEMA = "orch-dork/deepening-policy-decision/v1"
DECISION_VALIDATION_SCHEMA = "orch-dork/deepening-policy-decision-validation/v1"
POLICY_VERSION = "deepening-policy/v1"

DECISIONS = frozenset({"ACCEPT", "DENY", "DEFER"})
CAPACITY_STATUSES = frozenset({"available", "unavailable", "unknown"})
CRITICAL_PATH_POSITIONS = frozenset(
    {"on_critical_path", "off_critical_path", "unknown"}
)

_PROGRAM_FIELDS = frozenset(
    {
        "schema",
        "decision_id",
        "proposal",
        "parent_plan",
        "marginal_value",
        "resources",
        "authorization_context",
        "measurement_records",
        "gate_constants",
    }
)
_MARGINAL_FIELDS = frozenset(
    {
        "verified_coverage_gain_count",
        "critical_path_reduction_bps",
        "capability_diversity_gain_count",
        "coordination_cost_bps",
        "shared_state_risk_bps",
    }
)
_RESOURCE_FIELDS = frozenset(
    {"remaining_budget", "capacity", "critical_path"}
)
_BUDGET_FIELDS = frozenset(
    {"executor_tokens", "child_tokens", "wall_clock_minutes"}
)
_CAPACITY_FIELDS = frozenset(
    {"status", "available_slots", "evidence_sha256"}
)
_CRITICAL_PATH_FIELDS = frozenset(
    {
        "position",
        "dependency_depth",
        "remaining_predecessors",
        "remaining_successors",
    }
)
_AUTHORIZATION_FIELDS = frozenset(
    {
        "root_actor_id",
        "decision_actor_id",
        "parent_node_id",
        "parent_authorization_profile_ref",
        "parent_read_set",
        "parent_write_set",
        "parent_tools",
        "workers_can_spawn",
    }
)
_GATE_FIELDS = frozenset(
    {
        "minimum_verified_coverage_gain_count",
        "minimum_critical_path_net_bps",
        "minimum_capability_diversity_gain_count",
        "maximum_coordination_cost_bps",
        "maximum_shared_state_risk_bps",
        "minimum_budget_reserve_bps",
        "minimum_available_capacity_slots",
        "maximum_decision_latency_ms",
        "maximum_replan_round_trip_ms",
        "maximum_integration_wall_time_ms",
    }
)
_BASIS_FIELDS = frozenset(
    {
        "marginal_value",
        "budget",
        "capacity",
        "critical_path_position",
        "measurements",
        "authorization_preservation",
    }
)
_DECISION_FIELDS = frozenset(
    {
        "schema",
        "policy_version",
        "decision_id",
        "program_sha256",
        "proposal_sha256",
        "parent_plan_sha256",
        "decision",
        "reason_codes",
        "gate_constants",
        "basis",
        "economic_gate",
        "workers_can_spawn",
        "authority_granted",
        "capacity_ceiling_changed",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "record_sha256",
    }
)
_ECONOMIC_GATE_FIELDS = frozenset(
    {
        "outcome",
        "evaluated_dimensions",
        "depth_limit_consulted",
        "economic_gate_only",
    }
)
_MARGINAL_BASIS_FIELDS = frozenset(
    {
        "verified_coverage_gain",
        "critical_path_reduction",
        "capability_diversity_gain",
        "coordination_cost",
        "shared_state_risk",
        "positive_benefit_dimensions",
        "passed",
    }
)
_BUDGET_BASIS_FIELDS = frozenset(
    {
        "requested",
        "remaining",
        "reserve_bps",
        "minimum_reserve_bps",
        "sufficient",
        "reserve_passed",
        "passed",
    }
)
_CAPACITY_BASIS_FIELDS = frozenset(
    {"status", "available_slots", "minimum_available_slots", "evidence_sha256", "passed"}
)
_CRITICAL_BASIS_FIELDS = frozenset(
    {
        "position",
        "dependency_depth",
        "remaining_predecessors",
        "remaining_successors",
        "independent_non_path_benefit",
        "passed",
    }
)
_MEASUREMENT_BASIS_FIELDS = frozenset(
    {
        "record_sha256s",
        "decision_latency",
        "replan_round_trip",
        "integration_wall_time",
        "complete",
        "passed",
    }
)
_METRIC_BASIS_FIELDS = frozenset(
    {"status", "record_count", "maximum_observed_ms", "maximum_allowed_ms", "passed"}
)
_AUTHORIZATION_BASIS_FIELDS = frozenset(
    {
        "status",
        "dependency_depth",
        "root_actor_is_decider",
        "parent_node_bound",
        "authorization_profile_bound",
        "parent_spawn_disabled",
        "ownership_disjoint",
        "children",
    }
)
_AUTHORIZATION_CHILD_FIELDS = frozenset(
    {
        "node_id",
        "ordinary_node",
        "authority_inherited",
        "workers_can_spawn",
        "read_scope_narrowed",
        "write_scope_narrowed",
        "tool_scope_narrowed",
    }
)

_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


def _canonical(value: Any) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return canonicalize_bounded_json(raw, profile=PROFILE, batch=False)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _reason(reasons: list[str], value: str) -> None:
    if value not in reasons:
        reasons.append(value)


def _closed(
    value: Any,
    fields: frozenset[str],
    label: str,
    issues: list[str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":type_invalid")
        return {}
    result = dict(value)
    for field in sorted(fields - set(result)):
        _issue(issues, label + ":missing_field:" + field)
    for field in sorted(set(result) - fields):
        _issue(issues, label + ":unknown_field:" + str(field))
    return result


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _bounded_int(value: Any, *, maximum: int | None = None) -> bool:
    return (
        type(value) is int
        and value >= 0
        and (maximum is None or value <= maximum)
    )


def _text_list(value: Any, label: str, issues: list[str]) -> list[str]:
    if not isinstance(value, list) or len(value) > PROFILE.max_array_items:
        _issue(issues, label + ":array_invalid")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if (
            not isinstance(item, str)
            or not item.strip()
            or len(item.encode("utf-8")) > PROFILE.max_string_bytes
        ):
            _issue(issues, f"{label}[{index}]:value_invalid")
        else:
            result.append(item)
    if len(result) != len(set(result)):
        _issue(issues, label + ":duplicate")
    return result


def _validate_gate_constants(value: Any, issues: list[str]) -> dict[str, int]:
    gates = _closed(value, _GATE_FIELDS, "gate_constants", issues)
    for field in sorted(_GATE_FIELDS):
        maximum = 10_000 if field.endswith("_bps") else None
        if not _bounded_int(gates.get(field), maximum=maximum):
            _issue(issues, "gate_constants:" + field + "_invalid")
    if gates.get("minimum_available_capacity_slots") == 0:
        _issue(issues, "gate_constants:minimum_available_capacity_slots_zero")
    for field in (
        "maximum_decision_latency_ms",
        "maximum_replan_round_trip_ms",
        "maximum_integration_wall_time_ms",
    ):
        if gates.get(field) == 0:
            _issue(issues, "gate_constants:" + field + "_zero")
    return {
        field: int(gates[field])
        for field in sorted(_GATE_FIELDS)
        if _bounded_int(gates.get(field))
    }


def _malformed_report(
    issues: Sequence[str], program_sha256: str | None
) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "policy_version": POLICY_VERSION,
        "status": "FAIL",
        "decision": "DENY",
        "decision_record": None,
        "reason_codes": ["contract_invalid"],
        "issues": sorted(set(str(item) for item in issues)),
        "program_sha256": program_sha256,
        "proposal_sha256": None,
        "workers_can_spawn": False,
        "workers_permitted": False,
        "authority_granted": False,
        "capacity_ceiling_changed": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _normalize_resources(
    values: Sequence[str], label: str, reasons: list[str]
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for value in values:
        try:
            normalized.append(ownership.normalize_resource(value))
        except ownership.OwnershipError:
            _reason(reasons, label)
    return normalized


def _all_contained(
    child_values: Sequence[str],
    parent_scopes: Sequence[Mapping[str, Any]],
    label: str,
    reasons: list[str],
) -> bool:
    normalized = _normalize_resources(child_values, label, reasons)
    if len(normalized) != len(child_values):
        return False
    return all(
        any(ownership.resource_contains(scope, value) for scope in parent_scopes)
        for value in normalized
    )


def _authorization_basis(
    proposal: Mapping[str, Any],
    context: Mapping[str, Any],
    dependency_depth: int,
    reasons: list[str],
) -> dict[str, Any]:
    root_actor_is_decider = (
        context["root_actor_id"] == context["decision_actor_id"]
    )
    parent_node_bound = context["parent_node_id"] == proposal.get("parent_node_id")
    profile = proposal.get("root_spec", {}).get("authorization_profile_ref")
    authorization_profile_bound = (
        context["parent_authorization_profile_ref"] == profile
    )
    parent_spawn_disabled = context["workers_can_spawn"] is False
    if not root_actor_is_decider:
        _reason(reasons, "authorization_decider_not_root")
    if not parent_node_bound:
        _reason(reasons, "authorization_parent_node_mismatch")
    if not authorization_profile_bound:
        _reason(reasons, "authorization_profile_mismatch")
    if not parent_spawn_disabled:
        _reason(reasons, "parent_spawn_authority_invalid")

    parent_reads = _normalize_resources(
        context["parent_read_set"], "authorization_scope_broadened", reasons
    )
    parent_writes = _normalize_resources(
        context["parent_write_set"], "authorization_scope_broadened", reasons
    )
    parent_tools = set(context["parent_tools"])
    children: list[dict[str, Any]] = []
    child_write_sets: list[list[dict[str, Any]]] = []
    for child in proposal.get("children", []):
        child_id = str(child.get("proposed_id"))
        reads = list(child.get("read_set", []))
        writes = list(child.get("expected_write_set", []))
        tools = list(child.get("tools", []))
        read_narrowed = _all_contained(
            reads, parent_reads, "authorization_scope_broadened", reasons
        )
        write_narrowed = _all_contained(
            writes, parent_writes, "authorization_scope_broadened", reasons
        )
        tool_narrowed = set(tools) <= parent_tools
        if not read_narrowed or not write_narrowed:
            _reason(reasons, "authorization_scope_broadened")
        if not tool_narrowed:
            _reason(reasons, "authorization_tool_broadened")
        child_write_sets.append(
            _normalize_resources(
                writes, "authorization_scope_broadened", reasons
            )
        )
        children.append(
            {
                "node_id": child_id,
                "ordinary_node": True,
                "authority_inherited": False,
                "workers_can_spawn": False,
                "read_scope_narrowed": read_narrowed,
                "write_scope_narrowed": write_narrowed,
                "tool_scope_narrowed": tool_narrowed,
            }
        )

    ownership_disjoint = True
    for left_index, left in enumerate(child_write_sets):
        for right in child_write_sets[left_index + 1 :]:
            if any(
                ownership.resources_intersect(a, b)
                for a in left
                for b in right
            ):
                ownership_disjoint = False
    if not ownership_disjoint:
        _reason(reasons, "authorization_ownership_overlap")

    passed = all(
        (
            root_actor_is_decider,
            parent_node_bound,
            authorization_profile_bound,
            parent_spawn_disabled,
            ownership_disjoint,
            all(
                child["read_scope_narrowed"]
                and child["write_scope_narrowed"]
                and child["tool_scope_narrowed"]
                for child in children
            ),
        )
    )
    return {
        "status": "PASS" if passed else "FAIL",
        "dependency_depth": dependency_depth,
        "root_actor_is_decider": root_actor_is_decider,
        "parent_node_bound": parent_node_bound,
        "authorization_profile_bound": authorization_profile_bound,
        "parent_spawn_disabled": parent_spawn_disabled,
        "ownership_disjoint": ownership_disjoint,
        "children": children,
    }


def _marginal_basis(
    values: Mapping[str, int], gates: Mapping[str, int], reasons: list[str]
) -> dict[str, Any]:
    coverage = values["verified_coverage_gain_count"]
    critical = values["critical_path_reduction_bps"]
    capability = values["capability_diversity_gain_count"]
    coordination = values["coordination_cost_bps"]
    shared_risk = values["shared_state_risk_bps"]
    critical_net = critical - coordination - shared_risk
    coverage_positive = (
        coverage > 0
        and coverage >= gates["minimum_verified_coverage_gain_count"]
    )
    critical_positive = (
        critical_net > 0
        and critical_net >= gates["minimum_critical_path_net_bps"]
    )
    capability_positive = (
        capability > 0
        and capability >= gates["minimum_capability_diversity_gain_count"]
    )
    coordination_passed = coordination <= gates["maximum_coordination_cost_bps"]
    shared_risk_passed = shared_risk <= gates["maximum_shared_state_risk_bps"]
    positive_dimensions: list[str] = []
    if critical_positive:
        positive_dimensions.append("critical_path_reduction")
    if coverage_positive:
        positive_dimensions.append("verified_coverage_gain")
    if capability_positive:
        positive_dimensions.append("capability_diversity_gain")
    if not positive_dimensions:
        _reason(reasons, "marginal_value_not_positive")
    if not coordination_passed:
        _reason(reasons, "coordination_cost_exceeds_gate")
    if not shared_risk_passed:
        _reason(reasons, "shared_state_risk_exceeds_gate")
    passed = bool(positive_dimensions) and coordination_passed and shared_risk_passed
    return {
        "verified_coverage_gain": {
            "observed_count": coverage,
            "minimum_count": gates["minimum_verified_coverage_gain_count"],
            "positive": coverage_positive,
        },
        "critical_path_reduction": {
            "observed_bps": critical,
            "combined_cost_and_risk_bps": coordination + shared_risk,
            "net_bps": critical_net,
            "minimum_net_bps": gates["minimum_critical_path_net_bps"],
            "positive": critical_positive,
        },
        "capability_diversity_gain": {
            "observed_count": capability,
            "minimum_count": gates["minimum_capability_diversity_gain_count"],
            "positive": capability_positive,
        },
        "coordination_cost": {
            "observed_bps": coordination,
            "maximum_bps": gates["maximum_coordination_cost_bps"],
            "passed": coordination_passed,
        },
        "shared_state_risk": {
            "observed_bps": shared_risk,
            "maximum_bps": gates["maximum_shared_state_risk_bps"],
            "passed": shared_risk_passed,
        },
        "positive_benefit_dimensions": positive_dimensions,
        "passed": passed,
    }


def _budget_basis(
    requested: Mapping[str, int],
    remaining: Mapping[str, int],
    minimum_reserve_bps: int,
    reasons: list[str],
) -> dict[str, Any]:
    reserves: dict[str, int] = {}
    enough = True
    for field in sorted(_BUDGET_FIELDS):
        available = remaining[field]
        needed = requested[field]
        if needed > available:
            enough = False
        reserves[field] = (
            max(0, (available - needed) * 10_000 // available)
            if available > 0
            else 0
        )
    reserve_passed = all(
        value >= minimum_reserve_bps for value in reserves.values()
    )
    if not enough:
        _reason(reasons, "remaining_budget_insufficient")
    if enough and not reserve_passed:
        _reason(reasons, "remaining_budget_reserve_below_gate")
    return {
        "requested": {field: requested[field] for field in sorted(_BUDGET_FIELDS)},
        "remaining": {field: remaining[field] for field in sorted(_BUDGET_FIELDS)},
        "reserve_bps": reserves,
        "minimum_reserve_bps": minimum_reserve_bps,
        "sufficient": enough,
        "reserve_passed": reserve_passed,
        "passed": enough and reserve_passed,
    }


def _metric_basis(
    values: Sequence[Mapping[str, Any]], maximum_ms: int
) -> dict[str, Any]:
    observed = [
        int(item["value_ms"])
        for item in values
        if item.get("status") == "observed" and type(item.get("value_ms")) is int
    ]
    unknown = any(item.get("status") == "unknown" for item in values)
    complete = bool(observed) and not unknown
    maximum_observed = max(observed) if observed else None
    return {
        "status": "observed" if complete else "unknown",
        "record_count": len(values),
        "maximum_observed_ms": maximum_observed,
        "maximum_allowed_ms": maximum_ms,
        "passed": complete and maximum_observed is not None and maximum_observed <= maximum_ms,
    }


def _measurement_basis(
    records: Sequence[Mapping[str, Any]],
    gates: Mapping[str, int],
    reasons: list[str],
) -> dict[str, Any]:
    decisions = [
        item for item in records if item.get("schema") == trace.DEEPENING_DECISION_SCHEMA
    ]
    integrations = [
        item
        for item in records
        if item.get("schema") == trace.DEEPENING_INTEGRATION_SCHEMA
    ]
    decision_hashes = {item.get("record_sha256") for item in decisions}
    accepted = [
        item
        for item in decisions
        if item.get("decision", {}).get("outcome") == "accepted"
    ]
    accepted_key_list = [
        (item.get("run_id"), item.get("proposal_sha256")) for item in accepted
    ]
    accepted_keys = {
        key: item for key, item in zip(accepted_key_list, accepted)
    }
    linked_integrations: list[Mapping[str, Any]] = []
    linked_keys: list[tuple[Any, Any]] = []
    for item in integrations:
        key = (item.get("run_id"), item.get("proposal_sha256"))
        decision = accepted_keys.get(key)
        if (
            decision is not None
            and item.get("decision_record_sha256") in decision_hashes
            and item.get("decision_record_sha256") == decision.get("record_sha256")
        ):
            linked_integrations.append(item)
            linked_keys.append(key)

    decision_latency = _metric_basis(
        [item.get("decision_latency", {}) for item in decisions],
        gates["maximum_decision_latency_ms"],
    )
    replan_round_trip = _metric_basis(
        [item.get("replan_round_trip", {}) for item in accepted],
        gates["maximum_replan_round_trip_ms"],
    )
    integration_wall_time = _metric_basis(
        [item.get("integration_cost", {}).get("join_wall_time", {}) for item in linked_integrations],
        gates["maximum_integration_wall_time_ms"],
    )
    complete = (
        bool(decisions)
        and bool(accepted)
        and len(set(accepted_key_list)) == len(accepted_key_list)
        and len(linked_integrations) == len(integrations) == len(accepted)
        and sorted(linked_keys) == sorted(accepted_key_list)
        and all(
            metric["status"] == "observed"
            for metric in (
                decision_latency,
                replan_round_trip,
                integration_wall_time,
            )
        )
    )
    if not complete:
        _reason(reasons, "measurement_evidence_incomplete")
    if (
        decision_latency["status"] == "observed"
        and not decision_latency["passed"]
    ):
        _reason(reasons, "historical_decision_latency_exceeds_gate")
    if (
        replan_round_trip["status"] == "observed"
        and not replan_round_trip["passed"]
    ):
        _reason(reasons, "historical_replan_cost_exceeds_gate")
    if (
        integration_wall_time["status"] == "observed"
        and not integration_wall_time["passed"]
    ):
        _reason(reasons, "historical_integration_cost_exceeds_gate")
    passed = complete and all(
        metric["passed"]
        for metric in (decision_latency, replan_round_trip, integration_wall_time)
    )
    return {
        "record_sha256s": [str(item["record_sha256"]) for item in records],
        "decision_latency": decision_latency,
        "replan_round_trip": replan_round_trip,
        "integration_wall_time": integration_wall_time,
        "complete": complete,
        "passed": passed,
    }


def _seal_decision(core: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(core)
    return {**value, "record_sha256": _sha256(value)}


def _validate_decision_basis(value: Any, issues: list[str]) -> None:
    basis = _closed(value, _BASIS_FIELDS, "decision_record.basis", issues)

    marginal = _closed(
        basis.get("marginal_value"),
        _MARGINAL_BASIS_FIELDS,
        "decision_record.basis.marginal_value",
        issues,
    )
    nested_marginal = {
        "verified_coverage_gain": frozenset({"observed_count", "minimum_count", "positive"}),
        "critical_path_reduction": frozenset(
            {"observed_bps", "combined_cost_and_risk_bps", "net_bps", "minimum_net_bps", "positive"}
        ),
        "capability_diversity_gain": frozenset({"observed_count", "minimum_count", "positive"}),
        "coordination_cost": frozenset({"observed_bps", "maximum_bps", "passed"}),
        "shared_state_risk": frozenset({"observed_bps", "maximum_bps", "passed"}),
    }
    for name, fields in nested_marginal.items():
        row = _closed(
            marginal.get(name), fields, "decision_record.basis.marginal_value." + name, issues
        )
        for field, item in row.items():
            if field in {"positive", "passed"}:
                if type(item) is not bool:
                    _issue(issues, "decision_record.basis.marginal_value:" + name + "_boolean_invalid")
            elif type(item) is not int:
                _issue(issues, "decision_record.basis.marginal_value:" + name + "_number_invalid")
    positive = marginal.get("positive_benefit_dimensions")
    allowed_positive = {
        "critical_path_reduction",
        "verified_coverage_gain",
        "capability_diversity_gain",
    }
    if (
        not isinstance(positive, list)
        or any(item not in allowed_positive for item in positive)
        or len(positive) != len(set(positive))
    ):
        _issue(issues, "decision_record.basis.marginal_value:positive_dimensions_invalid")
    if type(marginal.get("passed")) is not bool:
        _issue(issues, "decision_record.basis.marginal_value:passed_invalid")

    budget = _closed(
        basis.get("budget"), _BUDGET_BASIS_FIELDS, "decision_record.basis.budget", issues
    )
    for name in ("requested", "remaining", "reserve_bps"):
        row = _closed(
            budget.get(name), _BUDGET_FIELDS, "decision_record.basis.budget." + name, issues
        )
        if any(type(item) is not int or item < 0 for item in row.values()):
            _issue(issues, "decision_record.basis.budget:" + name + "_invalid")
    if type(budget.get("minimum_reserve_bps")) is not int:
        _issue(issues, "decision_record.basis.budget:minimum_reserve_invalid")
    for field in ("sufficient", "reserve_passed", "passed"):
        if type(budget.get(field)) is not bool:
            _issue(issues, "decision_record.basis.budget:" + field + "_invalid")

    capacity = _closed(
        basis.get("capacity"),
        _CAPACITY_BASIS_FIELDS,
        "decision_record.basis.capacity",
        issues,
    )
    if capacity.get("status") not in CAPACITY_STATUSES:
        _issue(issues, "decision_record.basis.capacity:status_invalid")
    if capacity.get("available_slots") is not None and not _bounded_int(capacity.get("available_slots")):
        _issue(issues, "decision_record.basis.capacity:available_slots_invalid")
    if not _bounded_int(capacity.get("minimum_available_slots")):
        _issue(issues, "decision_record.basis.capacity:minimum_slots_invalid")
    if not _digest(capacity.get("evidence_sha256")):
        _issue(issues, "decision_record.basis.capacity:evidence_sha256_invalid")
    if capacity.get("passed") is not None and type(capacity.get("passed")) is not bool:
        _issue(issues, "decision_record.basis.capacity:passed_invalid")

    critical = _closed(
        basis.get("critical_path_position"),
        _CRITICAL_BASIS_FIELDS,
        "decision_record.basis.critical_path_position",
        issues,
    )
    if critical.get("position") not in CRITICAL_PATH_POSITIONS:
        _issue(issues, "decision_record.basis.critical_path_position:position_invalid")
    for field in ("dependency_depth", "remaining_predecessors", "remaining_successors"):
        if not _bounded_int(critical.get(field)):
            _issue(issues, "decision_record.basis.critical_path_position:" + field + "_invalid")
    if type(critical.get("independent_non_path_benefit")) is not bool:
        _issue(issues, "decision_record.basis.critical_path_position:benefit_invalid")
    if critical.get("passed") is not None and type(critical.get("passed")) is not bool:
        _issue(issues, "decision_record.basis.critical_path_position:passed_invalid")

    measurements = _closed(
        basis.get("measurements"),
        _MEASUREMENT_BASIS_FIELDS,
        "decision_record.basis.measurements",
        issues,
    )
    hashes = measurements.get("record_sha256s")
    if (
        not isinstance(hashes, list)
        or any(not _digest(item) for item in hashes)
        or len(hashes) != len(set(hashes))
    ):
        _issue(issues, "decision_record.basis.measurements:record_sha256s_invalid")
    for name in ("decision_latency", "replan_round_trip", "integration_wall_time"):
        metric = _closed(
            measurements.get(name),
            _METRIC_BASIS_FIELDS,
            "decision_record.basis.measurements." + name,
            issues,
        )
        if metric.get("status") not in {"observed", "unknown"}:
            _issue(issues, "decision_record.basis.measurements:" + name + "_status_invalid")
        if not _bounded_int(metric.get("record_count")):
            _issue(issues, "decision_record.basis.measurements:" + name + "_count_invalid")
        if metric.get("maximum_observed_ms") is not None and not _bounded_int(metric.get("maximum_observed_ms")):
            _issue(issues, "decision_record.basis.measurements:" + name + "_observed_invalid")
        if not _bounded_int(metric.get("maximum_allowed_ms")):
            _issue(issues, "decision_record.basis.measurements:" + name + "_maximum_invalid")
        if type(metric.get("passed")) is not bool:
            _issue(issues, "decision_record.basis.measurements:" + name + "_passed_invalid")
    for field in ("complete", "passed"):
        if type(measurements.get(field)) is not bool:
            _issue(issues, "decision_record.basis.measurements:" + field + "_invalid")

    authorization = _closed(
        basis.get("authorization_preservation"),
        _AUTHORIZATION_BASIS_FIELDS,
        "decision_record.basis.authorization_preservation",
        issues,
    )
    if authorization.get("status") not in {"PASS", "FAIL"}:
        _issue(issues, "decision_record.basis.authorization_preservation:status_invalid")
    if not _bounded_int(authorization.get("dependency_depth")):
        _issue(issues, "decision_record.basis.authorization_preservation:depth_invalid")
    for field in (
        "root_actor_is_decider",
        "parent_node_bound",
        "authorization_profile_bound",
        "parent_spawn_disabled",
        "ownership_disjoint",
    ):
        if type(authorization.get(field)) is not bool:
            _issue(issues, "decision_record.basis.authorization_preservation:" + field + "_invalid")
    children = authorization.get("children")
    if not isinstance(children, list):
        _issue(issues, "decision_record.basis.authorization_preservation:children_invalid")
        children = []
    for index, child_value in enumerate(children):
        child = _closed(
            child_value,
            _AUTHORIZATION_CHILD_FIELDS,
            f"decision_record.basis.authorization_preservation.children[{index}]",
            issues,
        )
        if not _identifier(child.get("node_id")):
            _issue(issues, "decision_record.basis.authorization_preservation:child_id_invalid")
        for field in _AUTHORIZATION_CHILD_FIELDS - {"node_id"}:
            if type(child.get(field)) is not bool:
                _issue(issues, "decision_record.basis.authorization_preservation:child_boolean_invalid")


def evaluate_deepening_policy(program: Any) -> dict[str, Any]:
    """Evaluate one decomposition proposal at the recorded economic gate."""

    try:
        program_sha256 = _sha256(program)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        return _malformed_report(["program:hostile_or_noncanonical"], None)

    issues: list[str] = []
    value = _closed(program, _PROGRAM_FIELDS, "program", issues)
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    if not _identifier(value.get("decision_id")):
        _issue(issues, "program:decision_id_invalid")

    proposal = value.get("proposal")
    parent_plan = value.get("parent_plan")
    proposal_report = decomposition.validate_decomposition_proposal(
        proposal, parent_plan=parent_plan
    )
    if proposal_report.get("status") != "PASS":
        _issue(issues, "proposal:invalid")
    parent_plan_report = governor.validate_logical_plan(parent_plan)
    if parent_plan_report.get("status") != "PASS":
        _issue(issues, "parent_plan:invalid")

    marginal_raw = _closed(
        value.get("marginal_value"), _MARGINAL_FIELDS, "marginal_value", issues
    )
    marginal: dict[str, int] = {}
    for field in sorted(_MARGINAL_FIELDS):
        maximum = 10_000 if field.endswith("_bps") else PROFILE.max_nodes
        if not _bounded_int(marginal_raw.get(field), maximum=maximum):
            _issue(issues, "marginal_value:" + field + "_invalid")
        else:
            marginal[field] = int(marginal_raw[field])

    resources = _closed(value.get("resources"), _RESOURCE_FIELDS, "resources", issues)
    remaining_raw = _closed(
        resources.get("remaining_budget"),
        _BUDGET_FIELDS,
        "resources.remaining_budget",
        issues,
    )
    remaining: dict[str, int] = {}
    for field in sorted(_BUDGET_FIELDS):
        if not _bounded_int(remaining_raw.get(field)):
            _issue(issues, "resources.remaining_budget:" + field + "_invalid")
        else:
            remaining[field] = int(remaining_raw[field])

    capacity = _closed(
        resources.get("capacity"),
        _CAPACITY_FIELDS,
        "resources.capacity",
        issues,
    )
    if capacity.get("status") not in CAPACITY_STATUSES:
        _issue(issues, "resources.capacity:status_invalid")
    available_slots = capacity.get("available_slots")
    if capacity.get("status") == "unknown":
        if available_slots is not None:
            _issue(issues, "resources.capacity:unknown_slots_present")
    elif not _bounded_int(available_slots):
        _issue(issues, "resources.capacity:available_slots_invalid")
    if not _digest(capacity.get("evidence_sha256")):
        _issue(issues, "resources.capacity:evidence_sha256_invalid")

    critical = _closed(
        resources.get("critical_path"),
        _CRITICAL_PATH_FIELDS,
        "resources.critical_path",
        issues,
    )
    if critical.get("position") not in CRITICAL_PATH_POSITIONS:
        _issue(issues, "resources.critical_path:position_invalid")
    for field in (
        "dependency_depth",
        "remaining_predecessors",
        "remaining_successors",
    ):
        if not _bounded_int(critical.get(field)):
            _issue(issues, "resources.critical_path:" + field + "_invalid")

    authorization = _closed(
        value.get("authorization_context"),
        _AUTHORIZATION_FIELDS,
        "authorization_context",
        issues,
    )
    for field in (
        "root_actor_id",
        "decision_actor_id",
        "parent_node_id",
        "parent_authorization_profile_ref",
    ):
        if not _identifier(authorization.get(field)):
            _issue(issues, "authorization_context:" + field + "_invalid")
    for field in ("parent_read_set", "parent_write_set", "parent_tools"):
        authorization[field] = _text_list(
            authorization.get(field), "authorization_context." + field, issues
        )
    if type(authorization.get("workers_can_spawn")) is not bool:
        _issue(issues, "authorization_context:workers_can_spawn_invalid")

    gates = _validate_gate_constants(value.get("gate_constants"), issues)
    measurements_raw = value.get("measurement_records")
    measurements: list[Mapping[str, Any]] = []
    if not isinstance(measurements_raw, list) or len(measurements_raw) > PROFILE.max_array_items:
        _issue(issues, "measurement_records:array_invalid")
    else:
        measurement_hashes: list[str] = []
        for record in measurements_raw:
            validation = trace.validate_deepening_measurement_record(record)
            if validation.get("status") != "PASS":
                _issue(issues, "measurement_records:invalid")
            elif isinstance(record, Mapping):
                measurements.append(record)
                measurement_hashes.append(str(record.get("record_sha256")))
        if len(measurement_hashes) != len(set(measurement_hashes)):
            _issue(issues, "measurement_records:duplicate")

    requested_raw = proposal.get("budget") if isinstance(proposal, Mapping) else None
    requested: dict[str, int] = {}
    if isinstance(requested_raw, Mapping):
        for field in sorted(_BUDGET_FIELDS):
            if _bounded_int(requested_raw.get(field)):
                requested[field] = int(requested_raw[field])
            else:
                _issue(issues, "proposal:budget_invalid")
    else:
        _issue(issues, "proposal:budget_invalid")

    if issues:
        return _malformed_report(issues, program_sha256)

    assert isinstance(proposal, Mapping)
    reasons: list[str] = []
    marginal_basis = _marginal_basis(marginal, gates, reasons)
    budget_basis = _budget_basis(
        requested,
        remaining,
        gates["minimum_budget_reserve_bps"],
        reasons,
    )

    capacity_status = str(capacity["status"])
    capacity_passed: bool | None
    if capacity_status == "unknown":
        capacity_passed = None
        _reason(reasons, "capacity_unknown")
    elif capacity_status == "unavailable":
        capacity_passed = False
        _reason(reasons, "capacity_unavailable")
    else:
        capacity_passed = int(available_slots) >= gates["minimum_available_capacity_slots"]
        if not capacity_passed:
            _reason(reasons, "capacity_below_gate")
    capacity_basis = {
        "status": capacity_status,
        "available_slots": available_slots,
        "minimum_available_slots": gates["minimum_available_capacity_slots"],
        "evidence_sha256": capacity["evidence_sha256"],
        "passed": capacity_passed,
    }

    position = str(critical["position"])
    independent_benefit = bool(
        marginal_basis["verified_coverage_gain"]["positive"]
        or marginal_basis["capability_diversity_gain"]["positive"]
    )
    if position == "unknown":
        critical_passed: bool | None = None
        _reason(reasons, "critical_path_position_unknown")
    elif position == "off_critical_path" and not independent_benefit:
        critical_passed = False
        _reason(reasons, "off_critical_path_no_independent_benefit")
    else:
        critical_passed = True
    critical_basis = {
        "position": position,
        "dependency_depth": int(critical["dependency_depth"]),
        "remaining_predecessors": int(critical["remaining_predecessors"]),
        "remaining_successors": int(critical["remaining_successors"]),
        "independent_non_path_benefit": independent_benefit,
        "passed": critical_passed,
    }

    measurement_basis = _measurement_basis(measurements, gates, reasons)
    authorization_basis = _authorization_basis(
        proposal, authorization, int(critical["dependency_depth"]), reasons
    )
    basis = {
        "marginal_value": marginal_basis,
        "budget": budget_basis,
        "capacity": capacity_basis,
        "critical_path_position": critical_basis,
        "measurements": measurement_basis,
        "authorization_preservation": authorization_basis,
    }

    denial_reasons = {
        "marginal_value_not_positive",
        "coordination_cost_exceeds_gate",
        "shared_state_risk_exceeds_gate",
        "remaining_budget_insufficient",
        "remaining_budget_reserve_below_gate",
        "capacity_unavailable",
        "capacity_below_gate",
        "off_critical_path_no_independent_benefit",
        "historical_decision_latency_exceeds_gate",
        "historical_replan_cost_exceeds_gate",
        "historical_integration_cost_exceeds_gate",
        "authorization_decider_not_root",
        "authorization_parent_node_mismatch",
        "authorization_profile_mismatch",
        "parent_spawn_authority_invalid",
        "authorization_scope_broadened",
        "authorization_tool_broadened",
        "authorization_ownership_overlap",
    }
    defer_reasons = {
        "capacity_unknown",
        "critical_path_position_unknown",
        "measurement_evidence_incomplete",
    }
    if denial_reasons & set(reasons):
        decision = "DENY"
        outcome = "stopped"
    elif defer_reasons & set(reasons):
        decision = "DEFER"
        outcome = "deferred"
    else:
        decision = "ACCEPT"
        outcome = "cleared"
        _reason(reasons, "economic_gate_cleared")

    decision_core = {
        "schema": DECISION_SCHEMA,
        "policy_version": POLICY_VERSION,
        "decision_id": value["decision_id"],
        "program_sha256": program_sha256,
        "proposal_sha256": proposal_report["proposal_sha256"],
        "parent_plan_sha256": _sha256(parent_plan),
        "decision": decision,
        "reason_codes": sorted(reasons),
        "gate_constants": {field: gates[field] for field in sorted(_GATE_FIELDS)},
        "basis": basis,
        "economic_gate": {
            "outcome": outcome,
            "evaluated_dimensions": [
                "marginal_value",
                "budget",
                "capacity",
                "critical_path_position",
                "measurements",
                "authorization_preservation",
            ],
            "depth_limit_consulted": False,
            "economic_gate_only": True,
        },
        "workers_can_spawn": False,
        "authority_granted": False,
        "capacity_ceiling_changed": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    decision_record = _seal_decision(decision_core)
    return {
        "schema": REPORT_SCHEMA,
        "policy_version": POLICY_VERSION,
        "status": "PASS",
        "decision": decision,
        "decision_record": decision_record,
        "reason_codes": list(decision_record["reason_codes"]),
        "issues": [],
        "program_sha256": program_sha256,
        "proposal_sha256": proposal_report["proposal_sha256"],
        "workers_can_spawn": False,
        "workers_permitted": False,
        "authority_granted": False,
        "capacity_ceiling_changed": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def validate_deepening_policy_decision(record: Any) -> dict[str, Any]:
    """Validate the closed shape and deterministic seal of one decision."""

    issues: list[str] = []
    try:
        _canonical(record)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        issues.append("decision_record:hostile_or_noncanonical")
        record = {}
    value = _closed(record, _DECISION_FIELDS, "decision_record", issues)
    if value.get("schema") != DECISION_SCHEMA:
        _issue(issues, "decision_record:schema_invalid")
    if value.get("policy_version") != POLICY_VERSION:
        _issue(issues, "decision_record:policy_version_invalid")
    if not _identifier(value.get("decision_id")):
        _issue(issues, "decision_record:decision_id_invalid")
    for field in ("program_sha256", "proposal_sha256", "parent_plan_sha256"):
        if not _digest(value.get(field)):
            _issue(issues, "decision_record:" + field + "_invalid")
    if value.get("decision") not in DECISIONS:
        _issue(issues, "decision_record:decision_invalid")
    reasons = value.get("reason_codes")
    if (
        not isinstance(reasons, list)
        or not reasons
        or any(not _identifier(item) for item in reasons)
        or reasons != sorted(set(reasons))
    ):
        _issue(issues, "decision_record:reason_codes_invalid")
    _validate_gate_constants(value.get("gate_constants"), issues)
    _validate_decision_basis(value.get("basis"), issues)
    economic = _closed(
        value.get("economic_gate"),
        _ECONOMIC_GATE_FIELDS,
        "decision_record.economic_gate",
        issues,
    )
    expected_outcome = {
        "ACCEPT": "cleared",
        "DENY": "stopped",
        "DEFER": "deferred",
    }.get(value.get("decision"))
    if economic.get("outcome") != expected_outcome:
        _issue(issues, "decision_record:economic_outcome_mismatch")
    if economic.get("evaluated_dimensions") != [
        "marginal_value",
        "budget",
        "capacity",
        "critical_path_position",
        "measurements",
        "authorization_preservation",
    ]:
        _issue(issues, "decision_record:evaluated_dimensions_invalid")
    if economic.get("depth_limit_consulted") is not False:
        _issue(issues, "decision_record:depth_limit_consulted")
    if economic.get("economic_gate_only") is not True:
        _issue(issues, "decision_record:economic_gate_not_exclusive")
    for field, expected in (
        ("workers_can_spawn", False),
        ("authority_granted", False),
        ("capacity_ceiling_changed", False),
        ("provider_free", True),
        ("model_calls", 0),
        ("hosted_calls", 0),
    ):
        if value.get(field) != expected or type(value.get(field)) is not type(expected):
            _issue(issues, "decision_record:" + field + "_invalid")
    recorded_sha = value.get("record_sha256")
    core = dict(value)
    core.pop("record_sha256", None)
    try:
        if not _digest(recorded_sha) or recorded_sha != _sha256(core):
            _issue(issues, "decision_record:seal_mismatch")
    except (HostileInputError, TypeError, ValueError, OverflowError):
        _issue(issues, "decision_record:seal_mismatch")
    return {
        "schema": DECISION_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "record_sha256": recorded_sha if not issues else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def append_deepening_policy_decision(
    program: Any, ledger_path: str | Path
) -> dict[str, Any]:
    """Evaluate and append one valid policy decision to the trace ledger."""

    report = evaluate_deepening_policy(program)
    if report.get("status") != "PASS" or not isinstance(
        report.get("decision_record"), Mapping
    ):
        return report
    receipt = trace.append_trace_record(ledger_path, report["decision_record"])
    return {**report, "chain_receipt": receipt}


__all__ = [
    "DECISION_SCHEMA",
    "DECISION_VALIDATION_SCHEMA",
    "POLICY_VERSION",
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "append_deepening_policy_decision",
    "evaluate_deepening_policy",
    "validate_deepening_policy_decision",
]
