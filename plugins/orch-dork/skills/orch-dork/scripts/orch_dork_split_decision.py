#!/usr/bin/env python3
"""Deterministic split decisioning and execution-profile selection.

This policy answers one question before a logical plan is frozen: does the
proposed decomposition create independently verifiable value after its
coordination and shared-state costs are considered?  It is deliberately not a
scheduler, capacity observer, planner, or authority grant.  Accepted new
orchestration selects ``finite_dag/v1`` unless a caller explicitly asks for
the bounded dependency-free compatibility choreography.
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


try:
    from orch_dork_hostile_input import (
        PROFILE,
        HostileInputError,
        canonicalize_bounded_json,
    )
except ImportError:  # pragma: no cover - isolated direct-file loading.
    _hostile_path = Path(__file__).resolve().with_name("orch_dork_hostile_input.py")
    _hostile_spec = importlib.util.spec_from_file_location(
        "orch_dork_hostile_input", _hostile_path
    )
    if _hostile_spec is None or _hostile_spec.loader is None:
        raise
    _hostile = importlib.util.module_from_spec(_hostile_spec)
    sys.modules.setdefault("orch_dork_hostile_input", _hostile)
    _hostile_spec.loader.exec_module(_hostile)
    PROFILE = _hostile.PROFILE
    HostileInputError = _hostile.HostileInputError
    canonicalize_bounded_json = _hostile.canonicalize_bounded_json


PROGRAM_SCHEMA = "orch-dork/split-decision-program/v1"
REPORT_SCHEMA = "orch-dork/split-decision/v1"
POLICY_VERSION = "split-decision-policy/v1"

DEFAULT_ORCHESTRATION_PROFILE = "finite_dag/v1"
COMPATIBILITY_PROFILE = "first_completed_worker/v1"
ATOMIC_PROFILE = "single_worker/v1"
SOFT_WORKER_CAP = 4

OPERATIONS = frozenset({"initial_split", "expand_split"})
REQUESTED_PROFILES = frozenset(
    {"default", DEFAULT_ORCHESTRATION_PROFILE, COMPATIBILITY_PROFILE}
)
SCALE_BASES = frozenset(
    {
        "ordinary",
        "deterministic_shards",
        "distinct_evidence_channels",
        "heterogeneous_capabilities",
    }
)
EXPANSION_TRIGGERS = frozenset(
    {
        "uncovered_criterion",
        "unresolved_conflict",
        "failed_verification",
        "new_evidence_channel",
    }
)
DECISIONS = frozenset(
    {"KEEP_ATOMIC", "SPLIT", "EXPAND", "STOP_EXPANSION", "REVIEW_REQUIRED", "REFUSE"}
)

_PROGRAM_FIELDS = frozenset(
    {
        "schema",
        "decision_id",
        "operation",
        "requested_profile",
        "current_worker_count",
        "acceptance_units",
        "candidates",
        "join",
        "shared_mutable_resources",
        "strict_serial_dependencies",
        "marginal_value",
        "scale_basis",
        "expansion_evidence",
    }
)
_ACCEPTANCE_FIELDS = frozenset(
    {"id", "independently_verifiable", "evidence_locator"}
)
_CANDIDATE_FIELDS = frozenset(
    {
        "id",
        "acceptance_unit_ids",
        "owned_resources",
        "depends_on",
        "input_contract",
        "output_contract",
        "verification",
        "partition_key",
        "evidence_channel",
        "capability_channel",
        "capability_evidence_sha256",
    }
)
_JOIN_FIELDS = frozenset({"owner", "strategy", "verification"})
_SERIAL_FIELDS = frozenset({"source", "target", "reason"})
_VALUE_FIELDS = frozenset(
    {
        "verified_coverage_gain_count",
        "critical_path_reduction_bps",
        "capability_diversity_gain_count",
        "coordination_cost_bps",
        "shared_state_risk_bps",
    }
)
_EXPANSION_FIELDS = frozenset(
    {"trigger", "novel_claim_ids", "novel_source_ids", "novel_output_ids"}
)
_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
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


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _reason(reasons: list[str], value: str) -> None:
    if value not in reasons:
        reasons.append(value)


def _all_distinct_present(values: Sequence[str | None], expected: int) -> bool:
    return (
        len(values) == expected
        and all(values)
        and len(set(values)) == expected
    )


def _closed(
    value: Any, fields: frozenset[str], label: str, issues: list[str]
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, f"{label}:type_invalid")
        return {}
    result = dict(value)
    for field in sorted(fields - set(result)):
        _issue(issues, f"{label}:missing_field:{field}")
    for field in sorted(set(result) - fields):
        _issue(issues, f"{label}:unknown_field:{field}")
    return result


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value.encode("utf-8")) <= PROFILE.max_string_bytes
    )


def _bounded_int(value: Any, *, maximum: int | None = None) -> bool:
    return (
        type(value) is int
        and value >= 0
        and (maximum is None or value <= maximum)
    )


def _string_list(
    value: Any,
    label: str,
    issues: list[str],
    *,
    identifiers: bool = False,
) -> list[str]:
    if not isinstance(value, list) or len(value) > PROFILE.max_array_items:
        _issue(issues, f"{label}:array_invalid")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        valid = _identifier(item) if identifiers else _text(item)
        if not valid:
            _issue(issues, f"{label}[{index}]:value_invalid")
            continue
        result.append(str(item))
    if len(result) != len(set(result)):
        _issue(issues, f"{label}:duplicate")
    return result


def _has_cycle(dependencies: Mapping[str, Sequence[str]]) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for predecessor in dependencies.get(node, ()):
            if visit(predecessor):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in dependencies)


def _malformed_report(issues: list[str], program_digest: str | None) -> dict[str, Any]:
    core = {
        "schema": REPORT_SCHEMA,
        "policy_version": POLICY_VERSION,
        "status": "FAIL",
        "decision": "REFUSE",
        "split_approved": False,
        "plan_required": False,
        "execution_profile": None,
        "profile_source": None,
        "default_orchestration_profile": DEFAULT_ORCHESTRATION_PROFILE,
        "compatibility_profile": COMPATIBILITY_PROFILE,
        "soft_worker_cap": SOFT_WORKER_CAP,
        "proposed_worker_count": None,
        "structural_gate": None,
        "marginal_value": None,
        "expansion_disposition": "REFUSED",
        "reason_codes": ["contract_invalid"],
        "issues": sorted(set(issues)),
        "program_sha256": program_digest,
        "workers_permitted": False,
        "authority_granted": False,
        "capacity_consulted": False,
        "capacity_ceiling_changed": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "decision_sha256": _sha(core)}


def evaluate_split_decision(program: Any) -> dict[str, Any]:
    """Evaluate one initial or expansion split without scheduling workers."""

    issues: list[str] = []
    reasons: list[str] = []
    try:
        program_digest = _sha(program)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        return _malformed_report(["program:hostile_or_noncanonical"], None)

    value = _closed(program, _PROGRAM_FIELDS, "program", issues)
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    if not _identifier(value.get("decision_id")):
        _issue(issues, "program:decision_id_invalid")
    operation = value.get("operation")
    if operation not in OPERATIONS:
        _issue(issues, "program:operation_invalid")
    requested_profile = value.get("requested_profile")
    if requested_profile not in REQUESTED_PROFILES:
        _issue(issues, "program:requested_profile_invalid")
    current_worker_count = value.get("current_worker_count")
    if not _bounded_int(current_worker_count):
        _issue(issues, "program:current_worker_count_invalid")
        current_worker_count = 0
    elif operation == "initial_split" and current_worker_count != 0:
        _issue(issues, "program:initial_worker_count_not_zero")
    elif operation == "expand_split" and current_worker_count < 1:
        _issue(issues, "program:expansion_worker_count_invalid")

    acceptance_raw = value.get("acceptance_units")
    if not isinstance(acceptance_raw, list) or not acceptance_raw or len(
        acceptance_raw
    ) > PROFILE.max_array_items:
        _issue(issues, "acceptance_units:array_invalid")
        acceptance_raw = []
    acceptance_ids: list[str] = []
    independently_verifiable = True
    for index, raw in enumerate(acceptance_raw):
        row = _closed(raw, _ACCEPTANCE_FIELDS, f"acceptance_units[{index}]", issues)
        unit_id = row.get("id")
        if not _identifier(unit_id) or unit_id in acceptance_ids:
            _issue(issues, f"acceptance_units[{index}]:id_invalid_or_duplicate")
        else:
            acceptance_ids.append(str(unit_id))
        independent = row.get("independently_verifiable")
        if not isinstance(independent, bool):
            _issue(issues, f"acceptance_units[{index}]:independence_invalid")
            independently_verifiable = False
        elif not independent:
            independently_verifiable = False
        if not _text(row.get("evidence_locator")):
            _issue(issues, f"acceptance_units[{index}]:evidence_locator_invalid")

    candidates_raw = value.get("candidates")
    if not isinstance(candidates_raw, list) or len(candidates_raw) > PROFILE.max_array_items:
        _issue(issues, "candidates:array_invalid")
        candidates_raw = []
    candidate_ids: list[str] = []
    dependencies: dict[str, list[str]] = {}
    coverage: set[str] = set()
    resource_owner: dict[str, str] = {}
    ownership_disjoint = True
    contracts_complete = True
    partitions: list[str | None] = []
    evidence_channels: list[str | None] = []
    capability_channels: list[str | None] = []
    capability_evidence: list[str | None] = []
    for index, raw in enumerate(candidates_raw):
        label = f"candidates[{index}]"
        row = _closed(raw, _CANDIDATE_FIELDS, label, issues)
        candidate_id = row.get("id")
        if not _identifier(candidate_id) or candidate_id in candidate_ids:
            _issue(issues, f"{label}:id_invalid_or_duplicate")
            candidate_key = f"<invalid-{index}>"
        else:
            candidate_key = str(candidate_id)
            candidate_ids.append(candidate_key)
        unit_ids = _string_list(
            row.get("acceptance_unit_ids"),
            f"{label}.acceptance_unit_ids",
            issues,
            identifiers=True,
        )
        if not unit_ids:
            contracts_complete = False
        for unit_id in unit_ids:
            if unit_id not in acceptance_ids:
                _issue(issues, f"{label}:acceptance_unit_unknown")
            else:
                coverage.add(unit_id)
        resources = _string_list(row.get("owned_resources"), f"{label}.owned_resources", issues)
        if not resources:
            ownership_disjoint = False
        for resource in resources:
            prior = resource_owner.get(resource)
            if prior is not None and prior != candidate_key:
                ownership_disjoint = False
            else:
                resource_owner[resource] = candidate_key
        predecessors = _string_list(
            row.get("depends_on"), f"{label}.depends_on", issues, identifiers=True
        )
        dependencies[candidate_key] = predecessors
        verification = _string_list(row.get("verification"), f"{label}.verification", issues)
        if not (
            _text(row.get("input_contract"))
            and _text(row.get("output_contract"))
            and verification
        ):
            contracts_complete = False
        partition = row.get("partition_key")
        if partition is not None and not _identifier(partition):
            _issue(issues, f"{label}:partition_key_invalid")
            partition = None
        evidence_channel = row.get("evidence_channel")
        if not _identifier(evidence_channel):
            _issue(issues, f"{label}:evidence_channel_invalid")
            evidence_channel = None
        capability_channel = row.get("capability_channel")
        if not _identifier(capability_channel):
            _issue(issues, f"{label}:capability_channel_invalid")
            capability_channel = None
        capability_evidence_sha256 = row.get("capability_evidence_sha256")
        if capability_evidence_sha256 is not None and not (
            isinstance(capability_evidence_sha256, str)
            and _SHA256.fullmatch(capability_evidence_sha256)
        ):
            _issue(issues, f"{label}:capability_evidence_sha256_invalid")
            capability_evidence_sha256 = None
        partitions.append(partition)
        evidence_channels.append(evidence_channel)
        capability_channels.append(capability_channel)
        capability_evidence.append(capability_evidence_sha256)

    known_candidates = set(candidate_ids)
    for candidate_id, predecessors in dependencies.items():
        for predecessor in predecessors:
            if predecessor not in known_candidates:
                _issue(issues, "candidates:dependency_unknown")
            if predecessor == candidate_id:
                _issue(issues, "candidates:self_dependency")
    dependency_cycle = _has_cycle(dependencies)

    join_value = value.get("join")
    join_defined = isinstance(join_value, Mapping)
    join_strategy = None
    if join_value is not None:
        join = _closed(join_value, _JOIN_FIELDS, "join", issues)
        join_strategy = join.get("strategy")
        verification = _string_list(join.get("verification"), "join.verification", issues)
        if join.get("owner") != "sol" or join_strategy not in {
            "dependency_ordered",
            "first_completed_worker",
        } or not verification:
            join_defined = False

    shared_resources = _string_list(
        value.get("shared_mutable_resources"), "shared_mutable_resources", issues
    )
    serial_raw = value.get("strict_serial_dependencies")
    if not isinstance(serial_raw, list) or len(serial_raw) > PROFILE.max_array_items:
        _issue(issues, "strict_serial_dependencies:array_invalid")
        serial_raw = []
    strict_serial_count = 0
    for index, raw in enumerate(serial_raw):
        row = _closed(raw, _SERIAL_FIELDS, f"strict_serial_dependencies[{index}]", issues)
        source = row.get("source")
        target = row.get("target")
        if source not in known_candidates or target not in known_candidates or source == target:
            _issue(issues, f"strict_serial_dependencies[{index}]:edge_invalid")
        if not _text(row.get("reason")):
            _issue(issues, f"strict_serial_dependencies[{index}]:reason_invalid")
        strict_serial_count += 1

    marginal = _closed(value.get("marginal_value"), _VALUE_FIELDS, "marginal_value", issues)
    for field in (
        "critical_path_reduction_bps",
        "coordination_cost_bps",
        "shared_state_risk_bps",
    ):
        if not _bounded_int(marginal.get(field), maximum=10_000):
            _issue(issues, f"marginal_value:{field}_invalid")
    for field in (
        "verified_coverage_gain_count",
        "capability_diversity_gain_count",
    ):
        if not _bounded_int(marginal.get(field), maximum=PROFILE.max_nodes):
            _issue(issues, f"marginal_value:{field}_invalid")
    if _bounded_int(marginal.get("verified_coverage_gain_count")) and marginal.get(
        "verified_coverage_gain_count", 0
    ) > len(acceptance_ids):
        _issue(issues, "marginal_value:coverage_gain_exceeds_acceptance")

    scale_basis = value.get("scale_basis")
    if scale_basis not in SCALE_BASES:
        _issue(issues, "program:scale_basis_invalid")
    expansion = _closed(
        value.get("expansion_evidence"),
        _EXPANSION_FIELDS,
        "expansion_evidence",
        issues,
    )
    trigger = expansion.get("trigger")
    if trigger is not None and trigger not in EXPANSION_TRIGGERS:
        _issue(issues, "expansion_evidence:trigger_invalid")
    novelty = 0
    for field in ("novel_claim_ids", "novel_source_ids", "novel_output_ids"):
        novelty += len(
            _string_list(
                expansion.get(field), f"expansion_evidence.{field}", issues, identifiers=True
            )
        )

    if issues:
        return _malformed_report(issues, program_digest)

    total_worker_count = int(current_worker_count) + len(candidates_raw)
    at_least_two = total_worker_count >= 2 and len(candidates_raw) >= 1
    coverage_complete = bool(acceptance_ids) and coverage == set(acceptance_ids)
    acyclic = not dependency_cycle
    no_shared_state = not shared_resources
    no_strict_serial = strict_serial_count == 0
    expected_join_strategy = (
        "first_completed_worker"
        if requested_profile == COMPATIBILITY_PROFILE
        else "dependency_ordered"
    )
    join_matches_profile = join_defined and join_strategy == expected_join_strategy

    structural = {
        "at_least_two_workers": at_least_two,
        "acceptance_independently_verifiable": independently_verifiable,
        "acceptance_coverage_complete": coverage_complete,
        "candidate_contracts_complete": contracts_complete,
        "candidate_ownership_disjoint": ownership_disjoint,
        "dependency_graph_acyclic": acyclic,
        "join_defined": join_defined,
        "join_matches_profile": join_matches_profile,
        "no_shared_mutable_state": no_shared_state,
        "no_strict_serial_coupling": no_strict_serial,
    }
    structural["passed"] = all(structural.values())

    if not at_least_two:
        _reason(reasons, "candidate_count_below_two")
    if not independently_verifiable:
        _reason(reasons, "acceptance_not_independently_verifiable")
    if not coverage_complete:
        _reason(reasons, "acceptance_coverage_incomplete")
    if not contracts_complete:
        _reason(reasons, "candidate_contract_incomplete")
    if not ownership_disjoint:
        _reason(reasons, "candidate_ownership_overlap")
    if not acyclic:
        _reason(reasons, "dependency_cycle")
    if not join_defined:
        _reason(reasons, "join_not_defined")
    elif not join_matches_profile:
        _reason(reasons, "join_strategy_profile_mismatch")
    if not no_shared_state:
        _reason(reasons, "shared_mutable_state")
    if not no_strict_serial:
        _reason(reasons, "strict_serial_coupling")

    coverage_gain = int(marginal["verified_coverage_gain_count"])
    critical_path = int(marginal["critical_path_reduction_bps"])
    capability_gain = int(marginal["capability_diversity_gain_count"])
    coordination_cost = int(marginal["coordination_cost_bps"])
    shared_state_risk = int(marginal["shared_state_risk_bps"])
    critical_path_net_positive = critical_path > coordination_cost + shared_state_risk
    marginal_positive = (
        coverage_gain > 0 or capability_gain > 0 or critical_path_net_positive
    )
    if not marginal_positive:
        _reason(reasons, "marginal_value_not_positive")
    marginal_report = {
        "verified_coverage_gain_count": coverage_gain,
        "critical_path_reduction_bps": critical_path,
        "capability_diversity_gain_count": capability_gain,
        "coordination_cost_bps": coordination_cost,
        "shared_state_risk_bps": shared_state_risk,
        "critical_path_net_positive": critical_path_net_positive,
        "positive": marginal_positive,
    }

    scale_evidence_valid = total_worker_count <= SOFT_WORKER_CAP
    if total_worker_count > SOFT_WORKER_CAP:
        if scale_basis == "deterministic_shards":
            scale_evidence_valid = _all_distinct_present(partitions, len(candidates_raw))
        elif scale_basis == "distinct_evidence_channels":
            scale_evidence_valid = _all_distinct_present(
                evidence_channels, len(candidates_raw)
            )
        elif scale_basis == "heterogeneous_capabilities":
            distinct_capabilities = len(
                {item for item in capability_channels if item}
            )
            scale_evidence_valid = (
                distinct_capabilities >= 2
                and capability_gain == distinct_capabilities
                and _all_distinct_present(
                    capability_evidence, len(candidates_raw)
                )
            )
        if not scale_evidence_valid:
            _reason(reasons, "soft_cap_requires_scaling_evidence")

    compatibility_invalid = False
    if requested_profile == COMPATIBILITY_PROFILE:
        if operation == "expand_split":
            compatibility_invalid = True
            _reason(reasons, "compatibility_profile_expansion_unsupported")
        if not 2 <= total_worker_count <= SOFT_WORKER_CAP:
            compatibility_invalid = True
            _reason(reasons, "compatibility_profile_worker_count_invalid")
        if any(dependencies.values()):
            compatibility_invalid = True
            _reason(reasons, "compatibility_profile_dependencies_present")

    expansion_disposition = "NOT_REQUESTED"
    expansion_invalid = False
    expansion_redundant = False
    if operation == "expand_split":
        if trigger is None:
            expansion_invalid = True
            expansion_disposition = "REFUSED"
            _reason(reasons, "expansion_trigger_required")
        elif novelty == 0:
            expansion_redundant = True
            expansion_disposition = "STOP_REDUNDANT"
            _reason(reasons, "expansion_redundant")
        else:
            expansion_disposition = "APPROVE"
    elif trigger is not None or novelty:
        expansion_invalid = True
        expansion_disposition = "REFUSED"
        _reason(reasons, "initial_split_has_expansion_evidence")

    if compatibility_invalid or expansion_invalid:
        decision = "REFUSE"
    elif expansion_redundant:
        decision = "STOP_EXPANSION"
    elif not structural["passed"] or not marginal_positive:
        decision = "KEEP_ATOMIC"
    elif not scale_evidence_valid:
        decision = "REVIEW_REQUIRED"
    elif operation == "expand_split":
        decision = "EXPAND"
    else:
        decision = "SPLIT"

    if decision == "KEEP_ATOMIC":
        execution_profile = ATOMIC_PROFILE
        profile_source = "atomic_policy"
    elif decision in {"SPLIT", "EXPAND", "STOP_EXPANSION"}:
        if requested_profile == COMPATIBILITY_PROFILE:
            execution_profile = COMPATIBILITY_PROFILE
            profile_source = "explicit_compatibility"
        elif requested_profile == DEFAULT_ORCHESTRATION_PROFILE:
            execution_profile = DEFAULT_ORCHESTRATION_PROFILE
            profile_source = "explicit"
        else:
            execution_profile = DEFAULT_ORCHESTRATION_PROFILE
            profile_source = "policy_default"
    else:
        execution_profile = None
        profile_source = None

    core = {
        "schema": REPORT_SCHEMA,
        "policy_version": POLICY_VERSION,
        "status": "PASS",
        "decision": decision,
        "split_approved": decision in {"SPLIT", "EXPAND"},
        "plan_required": decision in {"SPLIT", "EXPAND"},
        "execution_profile": execution_profile,
        "profile_source": profile_source,
        "default_orchestration_profile": DEFAULT_ORCHESTRATION_PROFILE,
        "compatibility_profile": COMPATIBILITY_PROFILE,
        "soft_worker_cap": SOFT_WORKER_CAP,
        "proposed_worker_count": total_worker_count,
        "structural_gate": structural,
        "marginal_value": marginal_report,
        "expansion_disposition": expansion_disposition,
        "reason_codes": sorted(reasons),
        "issues": [],
        "program_sha256": program_digest,
        "workers_permitted": False,
        "authority_granted": False,
        "capacity_consulted": False,
        "capacity_ceiling_changed": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "decision_sha256": _sha(core)}


__all__ = [
    "ATOMIC_PROFILE",
    "COMPATIBILITY_PROFILE",
    "DECISIONS",
    "DEFAULT_ORCHESTRATION_PROFILE",
    "EXPANSION_TRIGGERS",
    "OPERATIONS",
    "POLICY_VERSION",
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "REQUESTED_PROFILES",
    "SCALE_BASES",
    "SOFT_WORKER_CAP",
    "evaluate_split_decision",
]
