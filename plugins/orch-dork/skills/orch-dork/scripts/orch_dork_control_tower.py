#!/usr/bin/env python3
"""Provider-free Control Tower over the canonical Orch Dork run kernel.

This module owns the single public program/report seam introduced by Issue
144.  It composes existing contracts and emits decisions; it never contacts a
model, executes a tool, reads credentials, mutates a repository, or treats an
intent as observed work.
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
import threading
from typing import Any, Callable, Mapping


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ImportError:
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


contracts = _load_sibling("orch_dork_adaptive_contracts")
governor = _load_sibling("orch_dork_efficiency_governor")
run_store = _load_sibling("orch_dork_run_store")
run_engine = _load_sibling("orch_dork_run_engine")
worker_transport = _load_sibling("orch_dork_worker_transport")
observer_receipt = _load_sibling("orch_dork_observer_receipt")
topology_closure = _load_sibling("orch_dork_topology_closure")
artifact_ledger = _load_sibling("orch_dork_artifact_ledger")
# Publish the one shared lane maximum before the scheduler imports it.
lane_capacity = _load_sibling("orch_dork_shared_capacity")
control_scheduler = _load_sibling("orch_dork_control_scheduler")
workflow_profiles = _load_sibling("orch_dork_workflow_profiles")
model_profiles = _load_sibling("orch_dork_model_profile_registry")
# The node profiles every provider-free plan this module builds names: the
# registry's default implementer for delegated nodes and its default reviewer
# for root labor (Issue 185).  Read once from the sealed registry.
_IMPLEMENTER_PROFILE = model_profiles.default_profile("implementer")["profile_id"]
_ROOT_LABOR_PROFILE = model_profiles.default_profile("reviewer")
# Every join, comparator and root-labor node this module builds runs on the
# root, so the reviewer default must stay a root-labor profile; a default
# that moved elsewhere would be named here, not discovered as an invalid plan.
if _ROOT_LABOR_PROFILE["model_binding"] != "root_executes":
    raise RuntimeError("control_tower_root_labor_profile_invalid")
_ROOT_LABOR_PROFILE = _ROOT_LABOR_PROFILE["profile_id"]


def _learning_evaluators():
    """Load the optional Issue 148 projections only at their inspect seam."""

    return (
        _load_sibling("orch_dork_route_learning"),
        _load_sibling("orch_dork_strategy_cards"),
    )


def _optimization_evaluator(kind: str):
    """Load exactly one optional Issue 149 projection at its inspect seam."""

    module = (
        "orch_dork_topology_lab"
        if kind == "topology"
        else "orch_dork_champion_challenger"
    )
    return _load_sibling(module)


def _worker_timing_key(key: Any) -> bool:
    """Whether a deliverable key carries one worker's timing receipt."""

    return isinstance(key, str) and (
        key == "worker_timing" or key.startswith("worker_timing:")
    )


PROGRAM_SCHEMA = "orch-dork/control-tower-program/v1"
REPORT_SCHEMA = "orch-dork/control-tower-report/v1"
PROGRAM_SCHEMA_V2 = "orch-dork/control-tower-program/v2"
REPORT_SCHEMA_V2 = "orch-dork/control-tower-report/v2"
TASK_BRIEF_SCHEMA = "orch-dork/task-brief/v1"
ROUTE_SCHEMA = "orch-dork/factored-route-recommendation/v1"
PROFILE_SCHEMA = "orch-dork/workflow-profile/v1"
COMPILATION_SCHEMA = "orch-dork/workflow-compilation-receipt/v1"
PREPARATION_SCHEMA = "orch-dork/control-preparation/v1"
PLANNING_REQUIREMENT_SCHEMA = "orch-dork/planning-requirement/v1"
PLANNING_SUBMISSION_SCHEMA = "orch-dork/planning-submission/v1"
ADVANCE_SCHEMA = "orch-dork/control-advance/v1"
DECISION_SCHEMA = "orch-dork/control-decision/v1"
INTENT_SCHEMA = "orch-dork/control-intent/v1"
INSPECTION_QUERY_SCHEMA = "orch-dork/control-inspection-query/v1"
INSPECTION_SCHEMA = "orch-dork/control-inspection/v1"
CLEANUP_OBSERVATION_SCHEMA = "orch-dork/cleanup-observation/v1"
LANE_CLEANUP_PAYLOAD_SCHEMA = lane_capacity.LANE_CLEANUP_PAYLOAD_SCHEMA
JOIN_RESULT_SCHEMA = "orch-dork/join-result/v1"
COMPARISON_RESULT_SCHEMA = "orch-dork/comparison-result/v1"
ENQUEUE_SCHEMA = "orch-dork/control-enqueue/v1"
SCHEDULE_SCHEMA = "orch-dork/control-schedule/v1"
SCHEDULER_INSPECTION_QUERY_SCHEMA = (
    "orch-dork/control-scheduler-inspection-query/v1"
)
SCHEDULER_INSPECTION_SCHEMA = "orch-dork/control-scheduler-inspection/v1"
LEARNING_INSPECTION_QUERY_SCHEMA = (
    "orch-dork/control-learning-inspection-query/v1"
)
LEARNING_INSPECTION_SCHEMA = "orch-dork/control-learning-inspection/v1"
OPTIMIZATION_INSPECTION_QUERY_SCHEMA = (
    "orch-dork/control-optimization-inspection-query/v1"
)
OPTIMIZATION_INSPECTION_SCHEMA = (
    "orch-dork/control-optimization-inspection/v1"
)
SCHEDULER_CURSOR_SCHEMA = "orch-dork/control-scheduler-cursor/v1"
SCHEDULER_DECISION_SCHEMA = "orch-dork/control-scheduler-decision/v1"
SCHEDULER_CAPACITY_SCHEMA = control_scheduler.CAPACITY_SCHEMA
POLICY_GENERATION = "control-tower-policy/v1"
LANE_LEDGER_SCHEMA = lane_capacity.AUTHORITY_STATE_SCHEMA
LANE_RESERVATION_SCHEMA = lane_capacity.CONTROL_RESERVATION_SCHEMA
LANE_DELTA_SCHEMA = lane_capacity.CONTROL_DELTA_SCHEMA

_LANE_LEDGER_RUN_ID = "ct-laneledgerv2"
_MULTI_LANE_PROFILES = frozenset(
    {"parallel_join/v1", "best_of_n/v1", "finite_dag/v1"}
)
_SINGLE_LANE_PROFILES = frozenset(
    {"direct/v1", "execute_verify_repair/v1"}
)
_LANE_PROFILES = _MULTI_LANE_PROFILES | _SINGLE_LANE_PROFILES

OPERATIONS = frozenset({"prepare", "advance", "inspect"})
PRIVACY_CLASSES = frozenset({"local_only", "hosted_restricted", "hosted_standard"})
RISK_CLASSES = frozenset({"low", "medium", "high", "critical"})

_PROGRAM_FIELDS = frozenset({"schema", "program_id", "operation", "payload"})
_TASK_FIELDS = frozenset(
    {
        "schema",
        "task_id",
        "ticket_id",
        "project_ref",
        "objective",
        "deliverables",
        "constraints",
        "non_goals",
        "acceptance_checks",
        "input_refs",
        "privacy_class",
        "risk_class",
        "budgets",
        "requested_external_effects",
        "required_human_approvals",
        "routing_hints",
    }
)
_PROJECT_FIELDS = frozenset({"project_id", "project_ground_sha256"})
_DELIVERABLE_FIELDS = frozenset({"id", "description", "media_type"})
_ACCEPTANCE_FIELDS = frozenset({"id", "description", "required"})
_BUDGET_FIELDS = frozenset(
    {
        "context_tokens",
        "output_tokens",
        "handoff_tokens",
        "tool_calls",
        "retries",
        "cost_microusd",
        "wall_time_ms",
        "turns",
        "nodes",
    }
)
_ROUTING_FIELDS = frozenset({"requested_profile", "executor_group"})
_PLANNING_REQUIREMENT_FIELDS = frozenset(
    {
        "schema",
        "task_brief_sha256",
        "planner_executor_group",
        "context_manifest",
        "output_contract",
        "privacy_class",
        "budget",
        "authority_class",
        "issued_at_ms",
        "expires_at_ms",
        "requirement_sha256",
    }
)
_PLANNING_SUBMISSION_FIELDS = frozenset(
    {"schema", "planning_requirement", "proposal", "submission_sha256"}
)
_PARALLEL_SUBMISSION_FIELDS = frozenset(
    {
        "schema",
        "topology_id",
        "information_units",
        "producers",
        "relations",
        "relays",
        "join",
        "criteria",
        "artifacts",
        "unknowns",
        "submission_sha256",
    }
)
_START_FIELDS = frozenset({"schema", "kind", "preparation"})
_ENQUEUE_FIELDS = frozenset({"schema", "kind", "preparation"})
_SCHEDULE_FIELDS = frozenset(
    {"schema", "kind", "prior_scheduler_cursor", "max_dispatches"}
)
_SCHEDULER_STATE_EXCEPTIONS = (
    KeyError,
    TypeError,
    ValueError,
    run_engine.NotFoundError,
    run_engine.RunKernelError,
    control_scheduler.SchedulerContractError,
)
_OBSERVE_FIELDS = frozenset(
    {"schema", "kind", "run_id", "prior_cursor", "observation"}
)
_CANCEL_FIELDS = frozenset({"schema", "kind", "run_id", "prior_cursor", "reason"})
_OBSERVATION_FIELDS = frozenset({"kind", "intent", "result"})
_CLEANUP_FIELDS = frozenset(
    {"schema", "status", "owned_descendants", "observer_receipts"}
)
_JOIN_RESULT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "input_artifact_refs",
        "consumed_artifact_refs",
        "unused_artifact_refs",
        "output_body",
        "criterion_ids",
        "conflicts",
        "evidence_sha256",
    }
)
_COMPARISON_RESULT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "blinded_candidate_labels",
        "selected_labels",
        "output_body",
        "criterion_ids",
        "direct_baseline_evidence_sha256",
        "evidence_sha256",
        "comparison_sha256",
    }
)
_PREPARATION_FIELDS = frozenset(
    {
        "schema",
        "preparation_status",
        "task_brief_sha256",
        "policy_generation",
        "project_ground_sha256",
        "privacy_class",
        "risk_class",
        "expires_at_ms",
        "result",
        "preparation_sha256",
    }
)
_READY_FIELDS = frozenset(
    {
        "task_brief",
        "planning_submission",
        "workflow_submission",
        "topology_closure",
        "project_ref",
        "budgets",
        "route",
        "profile",
        "compilation",
        "task_spec",
        "task_specs",
        "logical_plan",
        "routing_policy",
        "executor_capability",
        "authority_requirements",
        "reservation_requirements",
    }
)
# "routing_policy" (Issue 183) is the sealed registry resolution that names the
# role and capability profile behind every node of the frozen logical plan.  It
# is recomputed at advance, so a preparation cannot carry a policy that does
# not match its plan.
_ROUTE_RECORD_FIELDS = frozenset(
    {
        "schema",
        "profile_id",
        "worker_count",
        "cut",
        "executor_groups",
        "context_policy",
        "budget_sha256",
        "verification_depth",
        "evidence",
        "confidence_bps",
        "route_sha256",
    }
)
_PROFILE_RECORD_FIELDS = frozenset(
    {
        "schema",
        "profile_id",
        "version",
        "compiler_id",
        "parameter_schema",
        "applicability_rules",
        "topology_invariants",
        "repair_limit",
        "required_verification",
        "output_plan_schema",
        "profile_sha256",
    }
)
_COMPILATION_FIELDS = frozenset(
    {
        "schema",
        "task_brief_sha256",
        "route_sha256",
        "profile_sha256",
        "compiler_id",
        "logical_plan_sha256",
        "planning_submission_sha256",
        "workflow_submission_sha256",
        "topology_closure",
        "compilation_sha256",
    }
)
_CAPABILITY_FIELDS = frozenset(
    {
        "schema",
        "executor_group",
        "runtime_identity",
        "task_kinds",
        "privacy_classes",
        "tools",
        "provider",
        "side_effects",
        "retries",
        "fallbacks",
        "replacements",
        "max_concurrency",
        "context_limit_tokens",
        "output_limit_tokens",
        "resources",
        "timeout",
        "cleanup",
        "observable_evidence",
        "capability_sha256",
    }
)
_RUNTIME_IDENTITY_FIELDS = frozenset(
    {
        "schema",
        "logical_model_id",
        "runtime_id",
        "provider",
        "structured_output",
    }
)
_RESERVATION_FIELDS = frozenset(
    {"logical_nodes", "live_sessions", "hosted_calls", "retries", "fallbacks", "replacements"}
)
_INTENT_FIELDS = frozenset(
    {
        "schema",
        "kind",
        "task_id",
        "run_id",
        "preparation_sha256",
        "plan_revision",
        "node_id",
        "context_sha256",
        "executor_group",
        "runtime_identity_sha256",
        "authority_sha256",
        "reservation_sha256",
        "idempotency_key",
        "not_before_ms",
        "expires_at_ms",
        "payload",
        "intent_sha256",
    }
)
_INTENT_PAYLOAD_FIELDS = {
    "dispatch": frozenset(
        {
            "worker_call",
            "worker_call_sha256",
            "model_manifest",
            "model_manifest_sha256",
            "independence_group",
            "observed_executions",
        }
    ),
    "verification": frozenset(
        {
            "task_spec",
            "handoff_receipt",
            "artifact_refs",
            "review_contract",
            "observed_executions",
        }
    ),
    "integration": frozenset(
        {
            "task_spec",
            "topology_closure_sha256",
            "input_artifact_refs",
            "producer_handoff_receipts",
            "required_producer_ids",
            "ingress_bytes",
            "ingress_limit_bytes",
            "observed_executions",
        }
    ),
    "comparison": frozenset(
        {
            "task_spec",
            "blinded_candidates",
            "comparator_independence_group",
            "selection_mode",
            "allowed_outcomes",
            "direct_baseline",
            "observed_executions",
        }
    ),
    "cleanup": frozenset({"owned_process_group", "observed_executions"}),
}
_INSPECTION_QUERY_FIELDS = frozenset(
    {"schema", "run_id", "after_seq", "max_events", "max_artifacts"}
)
_SCHEDULER_INSPECTION_QUERY_FIELDS = frozenset({"schema", "max_runs"})
_LEARNING_INSPECTION_QUERY_FIELDS = frozenset({"schema", "kind", "request"})
_OPTIMIZATION_INSPECTION_QUERY_FIELDS = frozenset(
    {"schema", "kind", "request"}
)
_TERMINAL_LEARNING_FIELDS = frozenset(
    {"run_id", "route_program", "strategy_program"}
)
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
# The lane ledger's own refusal names (``lane_ledger_*``), as raised from
# _lane_ledger_state; anything else that escapes reconstruction is reported
# only as the generic read failure.
_LEDGER_REFUSAL = re.compile(r"\Alane_ledger_[a-z_]{1,80}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


def _canonical(value: Any) -> bytes:
    return contracts.canonical_bytes(value)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _hash_row_sequence(rows: list[Mapping[str, Any]]) -> str:
    """Hash an arbitrarily long ordered projection without a batch envelope."""

    digest = _sha256({"row_count": len(rows)})
    for index, row in enumerate(rows):
        digest = _sha256(
            {"index": index, "previous_sha256": digest, "row": row}
        )
    return digest


def _issue(issues: list[str], code: str) -> None:
    if code not in issues:
        issues.append(code)


def _exact(value: Any, fields: frozenset[str], path: str, issues: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, path + ":not_object")
        return {}
    if set(value) != fields:
        if fields - set(value):
            _issue(issues, path + ":missing_fields")
        if set(value) - fields:
            _issue(issues, path + ":unknown_fields")
    return value


def _identifier(value: Any, path: str, issues: list[str]) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _issue(issues, path + ":invalid")
        return ""
    return value


def _text(value: Any, path: str, issues: list[str]) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 4096:
        _issue(issues, path + ":invalid")
        return ""
    return value.strip()


def _text_list(value: Any, path: str, issues: list[str]) -> list[str]:
    if not isinstance(value, list) or len(value) > 256:
        _issue(issues, path + ":invalid")
        return []
    result = [_text(item, path + ":item", issues) for item in value]
    result = [item for item in result if item]
    if len(result) != len(set(result)):
        _issue(issues, path + ":duplicates")
    return sorted(set(result))


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    core = deepcopy(dict(value))
    core.pop(field, None)
    return {**core, field: _sha256(core)}


def _seal_valid(value: Any, field: str) -> bool:
    if not isinstance(value, Mapping) or set(value) - {field} == set(value):
        return False
    digest = value.get(field)
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        return False
    core = dict(value)
    core.pop(field, None)
    return digest == _sha256(core)


def _intent_valid(value: Any, kind: str) -> bool:
    if (
        not isinstance(value, Mapping)
        or set(value) != _INTENT_FIELDS
        or value.get("schema") != INTENT_SCHEMA
        or value.get("kind") != kind
        or not _seal_valid(value, "intent_sha256")
    ):
        return False
    payload = value.get("payload")
    return isinstance(payload, Mapping) and set(payload) == _INTENT_PAYLOAD_FIELDS[kind]


def _lane_reservation(intent: Mapping[str, Any]) -> dict[str, Any]:
    return lane_capacity.control_reservation(
        run_id=intent["run_id"],
        node_id=intent["node_id"],
        intent_sha256=intent["intent_sha256"],
    )


def _lane_reservation_valid(value: Any) -> bool:
    return lane_capacity.validate_control_reservation(value)


def _lane_key(value: Mapping[str, Any]) -> tuple[str, str]:
    return str(value["run_id"]), str(value["node_id"])


def _lane_identity(run_id: str, node_id: str) -> str:
    return run_id + ":" + node_id


def _lane_cleanup_payload(
    *,
    lane_id: str,
    run_id: str,
    route: str,
    terminal_state: str,
    cleanup_status: str,
    owned_descendants: int,
    terminal_evidence_sha256: str,
) -> dict[str, Any]:
    return lane_capacity.cleanup_observer_payload(
        lane_id=lane_id,
        run_id=run_id,
        route=route,
        terminal_state=terminal_state,
        cleanup_status=cleanup_status,
        owned_descendants=owned_descendants,
        terminal_evidence_sha256=terminal_evidence_sha256,
    )


def _verified_lane_cleanup(
    envelope: Any,
    *,
    expected_payload: Mapping[str, Any],
    trust_store: Any,
    replay_guard: Any,
    evaluation_time: Any,
) -> dict[str, Any] | None:
    if evaluation_time is None:
        return None
    report = observer_receipt.verify_signed_receipt(
        envelope,
        expected_kind="lane-cleanup-observation",
        expected_payload=expected_payload,
        evaluation_time=evaluation_time,
        trust_store=trust_store,
        replay_guard=replay_guard,
    )
    if report.get("status") != "PASS":
        return None
    digest = report.get("signed_receipt_sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        return None
    return report


def _worker_result_release(
    raw_result: Any,
    *,
    run_id: str,
    intent: Any,
    cleanup_trust_store: Any,
    cleanup_replay_guard: Any,
    cleanup_evaluation_time: Any,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if not isinstance(raw_result, Mapping) or not isinstance(intent, Mapping):
        return None, None
    result = dict(raw_result)
    cleanup_envelope = result.pop("lane_cleanup_receipt", None)
    node_id = intent.get("node_id")
    payload = intent.get("payload")
    result_report = worker_transport.validate_worker_result(
        result,
        expected_call_sha256=(
            payload.get("worker_call_sha256")
            if isinstance(payload, Mapping)
            else None
        ),
        expected_manifest_sha256=(
            payload.get("model_manifest_sha256")
            if isinstance(payload, Mapping)
            else None
        ),
    )
    if (
        not isinstance(node_id, str)
        or result_report.get("status") != "PASS"
    ):
        return None, None
    terminal_state = {
        "CANDIDATE_READY": "completed",
        "REJECTED": "failed",
        "UNAVAILABLE": "failed",
        "TIMED_OUT": "failed",
        "CANCELLED": "cancelled",
    }.get(result.get("status"))
    if terminal_state is None:
        return None, None
    terminal_evidence_sha256 = (
        result.get("evidence", {}).get("sha256")
        if result.get("evidence", {}).get("status") == "sealed"
        else worker_transport.canonical_sha256(result)
    )
    cleanup_payload = _lane_cleanup_payload(
        lane_id=_lane_identity(run_id, node_id),
        run_id=run_id,
        route=lane_capacity.CONTROL_TOWER_ROUTE,
        terminal_state=terminal_state,
        cleanup_status="complete",
        owned_descendants=0,
        terminal_evidence_sha256=terminal_evidence_sha256,
    )
    cleanup_report = _verified_lane_cleanup(
        cleanup_envelope,
        expected_payload=cleanup_payload,
        trust_store=cleanup_trust_store,
        replay_guard=cleanup_replay_guard,
        evaluation_time=cleanup_evaluation_time,
    )
    if cleanup_report is None:
        return None, None
    receipt = lane_capacity.release(
        {
            "lane_id": _lane_identity(run_id, node_id),
            "run_id": run_id,
            "route": lane_capacity.CONTROL_TOWER_ROUTE,
            "state": terminal_state,
            "cleanup_status": "complete",
            "terminal_evidence_sha256": terminal_evidence_sha256,
            "cleanup_evidence_sha256": cleanup_report[
                "signed_receipt_sha256"
            ],
            "cleanup_observer_receipt": cleanup_envelope,
        },
        cleanup_payload["owned_descendants"],
    )
    if not lane_capacity.validate_release_receipt(
        receipt,
        lane_id=_lane_identity(run_id, node_id),
        run_id=run_id,
        route=lane_capacity.CONTROL_TOWER_ROUTE,
        terminal_state=terminal_state,
    ):
        return None, None
    return result, receipt


def _cancellation_requested(events: list[Mapping[str, Any]]) -> bool:
    return any(
        json.loads(event["payload"]).get("cancellation", {}).get("status")
        == "requested"
        for event in events
        if event["kind"] == run_engine.KIND_APPLIED
    )


def _cleanup_observation(events: list[Mapping[str, Any]]) -> dict[str, Any] | None:
    observations = []
    for event in events:
        if event["kind"] != run_engine.KIND_APPLIED:
            continue
        cleanup = json.loads(event["payload"]).get("cleanup")
        if cleanup is not None:
            if not isinstance(cleanup, Mapping):
                raise ValueError("cleanup_observation_invalid")
            observations.append(dict(cleanup))
    if len(observations) > 1:
        raise ValueError("cleanup_observation_duplicated")
    return observations[0] if observations else None


def _validate_task_brief(value: Any) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    task = _exact(value, _TASK_FIELDS, "task_brief", issues)
    if task.get("schema") != TASK_BRIEF_SCHEMA:
        _issue(issues, "task_brief:schema_invalid")
    task_id = _identifier(task.get("task_id"), "task_brief:task_id", issues)
    ticket_id = _identifier(task.get("ticket_id"), "task_brief:ticket_id", issues)

    project = _exact(task.get("project_ref"), _PROJECT_FIELDS, "task_brief:project_ref", issues)
    project_id = _identifier(project.get("project_id"), "task_brief:project_id", issues)
    project_digest = project.get("project_ground_sha256")
    if not isinstance(project_digest, str) or _SHA256.fullmatch(project_digest) is None:
        _issue(issues, "task_brief:project_ground_sha256_invalid")
        project_digest = ""

    deliverables: list[dict[str, Any]] = []
    raw_deliverables = task.get("deliverables")
    if not isinstance(raw_deliverables, list) or not raw_deliverables or len(raw_deliverables) > 32:
        _issue(issues, "task_brief:deliverables_invalid")
    else:
        seen: set[str] = set()
        for raw in raw_deliverables:
            item = _exact(raw, _DELIVERABLE_FIELDS, "task_brief:deliverable", issues)
            deliverable_id = _identifier(item.get("id"), "task_brief:deliverable_id", issues)
            if deliverable_id in seen:
                _issue(issues, "task_brief:deliverables_duplicate")
            seen.add(deliverable_id)
            media_type = _text(item.get("media_type"), "task_brief:media_type", issues).lower()
            if "/" not in media_type:
                _issue(issues, "task_brief:media_type_invalid")
            deliverables.append(
                {
                    "id": deliverable_id,
                    "description": _text(item.get("description"), "task_brief:deliverable_description", issues),
                    "media_type": media_type,
                }
            )
    deliverables.sort(key=lambda item: item["id"])

    acceptance: list[dict[str, Any]] = []
    raw_acceptance = task.get("acceptance_checks")
    if not isinstance(raw_acceptance, list) or not raw_acceptance or len(raw_acceptance) > 64:
        _issue(issues, "task_brief:acceptance_checks_invalid")
    else:
        seen_acceptance: set[str] = set()
        for raw in raw_acceptance:
            item = _exact(raw, _ACCEPTANCE_FIELDS, "task_brief:acceptance_check", issues)
            check_id = _identifier(item.get("id"), "task_brief:acceptance_id", issues)
            if check_id in seen_acceptance:
                _issue(issues, "task_brief:acceptance_duplicate")
            seen_acceptance.add(check_id)
            required = item.get("required")
            if type(required) is not bool:
                _issue(issues, "task_brief:acceptance_required_invalid")
                required = False
            acceptance.append(
                {
                    "id": check_id,
                    "description": _text(item.get("description"), "task_brief:acceptance_description", issues),
                    "required": required,
                }
            )
    acceptance.sort(key=lambda item: item["id"])

    refs: list[dict[str, Any]] = []
    raw_refs = task.get("input_refs")
    if not isinstance(raw_refs, list) or len(raw_refs) > 256:
        _issue(issues, "task_brief:input_refs_invalid")
    else:
        for raw in raw_refs:
            report = contracts.validate_artifact_ref(raw)
            if report.get("status") != "PASS":
                _issue(issues, "task_brief:input_ref_invalid")
            else:
                refs.append(report["normalized"])
    refs.sort(key=lambda item: (item["uri"], item["sha256"]))

    budgets_value = _exact(task.get("budgets"), _BUDGET_FIELDS, "task_brief:budgets", issues)
    budgets: dict[str, int] = {}
    for field in sorted(_BUDGET_FIELDS):
        number = budgets_value.get(field)
        minimum = 0 if field in {"cost_microusd", "retries", "tool_calls"} else 1
        if type(number) is not int or number < minimum:
            _issue(issues, "task_brief:budget_invalid")
            number = 0
        budgets[field] = number
    if budgets.get("retries") != 0:
        _issue(issues, "task_brief:retry_not_zero")

    privacy = task.get("privacy_class")
    if privacy not in PRIVACY_CLASSES:
        _issue(issues, "task_brief:privacy_invalid")
    risk = task.get("risk_class")
    if risk not in RISK_CLASSES:
        _issue(issues, "task_brief:risk_invalid")

    routing = _exact(task.get("routing_hints"), _ROUTING_FIELDS, "task_brief:routing_hints", issues)
    requested_profile = _identifier(
        routing.get("requested_profile"), "task_brief:requested_profile", issues
    )
    executor_group = _identifier(
        routing.get("executor_group"), "task_brief:executor_group", issues
    )

    normalized = {
        "schema": TASK_BRIEF_SCHEMA,
        "task_id": task_id,
        "ticket_id": ticket_id,
        "project_ref": {
            "project_id": project_id,
            "project_ground_sha256": project_digest,
        },
        "objective": _text(task.get("objective"), "task_brief:objective", issues),
        "deliverables": deliverables,
        "constraints": _text_list(task.get("constraints"), "task_brief:constraints", issues),
        "non_goals": _text_list(task.get("non_goals"), "task_brief:non_goals", issues),
        "acceptance_checks": acceptance,
        "input_refs": refs,
        "privacy_class": privacy,
        "risk_class": risk,
        "budgets": budgets,
        "requested_external_effects": _text_list(
            task.get("requested_external_effects"), "task_brief:external_effects", issues
        ),
        "required_human_approvals": _text_list(
            task.get("required_human_approvals"), "task_brief:human_approvals", issues
        ),
        "routing_hints": {
            "requested_profile": requested_profile,
            "executor_group": executor_group,
        },
    }
    try:
        _canonical(normalized)
    except (TypeError, ValueError, OverflowError):
        _issue(issues, "task_brief:hostile_or_non_json_input")
    return normalized, sorted(set(issues))


def _planning_requirement(
    task: Mapping[str, Any], task_digest: str, issued_at_ms: int
) -> dict[str, Any]:
    return _seal(
        {
            "schema": PLANNING_REQUIREMENT_SCHEMA,
            "task_brief_sha256": task_digest,
            "planner_executor_group": "strong-planner",
            "context_manifest": {
                "schema": "orch-dork/context-manifest/v1",
                "required_refs": task["input_refs"],
                "optional_refs": [],
                "forbidden_context": ["conversation_history", "private_reasoning"],
                "purpose": "Propose one typed finite_dag/v1 plan.",
            },
            "output_contract": governor.LOGICAL_PLAN_SCHEMA,
            "privacy_class": task["privacy_class"],
            "budget": {
                "context_tokens": task["budgets"]["context_tokens"],
                "output_tokens": task["budgets"]["output_tokens"],
                "turns": 1,
            },
            "authority_class": "provider_free_planning",
            "issued_at_ms": issued_at_ms,
            "expires_at_ms": issued_at_ms + task["budgets"]["wall_time_ms"],
        },
        "requirement_sha256",
    )


def _refused_preparation(
    task: Mapping[str, Any],
    task_digest: str,
    now_ms: int,
    reason_codes: list[str],
    *,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "reason_codes": sorted(set(reason_codes)),
        "intents": [],
    }
    if isinstance(details, Mapping):
        result.update(deepcopy(dict(details)))
    return _seal(
        {
            "schema": PREPARATION_SCHEMA,
            "preparation_status": "REFUSED",
            "task_brief_sha256": task_digest,
            "policy_generation": POLICY_GENERATION,
            "project_ground_sha256": task["project_ref"]["project_ground_sha256"],
            "privacy_class": task["privacy_class"],
            "risk_class": task["risk_class"],
            "expires_at_ms": now_ms + task["budgets"]["wall_time_ms"],
            "result": result,
        },
        "preparation_sha256",
    )


def _validate_planning_submission(
    value: Any,
    *,
    task: Mapping[str, Any],
    task_digest: str,
    now_ms: int,
    root_model: str,
    allow_general: bool = False,
) -> tuple[dict[str, Any] | None, list[str]]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _PLANNING_SUBMISSION_FIELDS
        or value.get("schema") != PLANNING_SUBMISSION_SCHEMA
        or not _seal_valid(value, "submission_sha256")
    ):
        return None, ["prepare:planning_submission_invalid"]

    requirement = value.get("planning_requirement")
    if (
        not isinstance(requirement, Mapping)
        or set(requirement) != _PLANNING_REQUIREMENT_FIELDS
        or requirement.get("schema") != PLANNING_REQUIREMENT_SCHEMA
        or not _seal_valid(requirement, "requirement_sha256")
    ):
        return None, ["prepare:planning_submission_invalid"]
    issued_at_ms = requirement.get("issued_at_ms")
    expires_at_ms = requirement.get("expires_at_ms")
    if (
        type(issued_at_ms) is not int
        or type(expires_at_ms) is not int
        or issued_at_ms < 0
        or expires_at_ms < issued_at_ms
    ):
        return None, ["prepare:planning_submission_invalid"]
    if now_ms < issued_at_ms or now_ms > expires_at_ms:
        return None, ["prepare:planning_requirement_expired"]
    if requirement != _planning_requirement(task, task_digest, issued_at_ms):
        return None, ["prepare:planning_requirement_mismatch"]

    proposal_report = governor.validate_logical_plan(value.get("proposal"))
    if proposal_report.get("status") != "PASS":
        return None, ["prepare:planning_proposal_invalid"]
    proposal = proposal_report["canonical_plan"]
    if allow_general:
        workers = proposal.get("workers", [])
        worker_ids = [worker.get("id") for worker in workers]
        execution = proposal.get("execution", {})
        authority = proposal.get("authority", {})
        integration = proposal.get("integration", {})
        planner = proposal.get("planner", {})
        if (
            proposal != value.get("proposal")
            or proposal.get("finite") is not True
            or type(proposal.get("logical_worker_count")) is not int
            or not 2
            <= proposal["logical_worker_count"]
            <= task["budgets"]["nodes"]
            or proposal["logical_worker_count"] != len(workers)
            or proposal.get("revision") != 1
            or proposal.get("predecessor_plan_sha256") is not None
            or proposal.get("objective") != task["objective"]
            or planner.get("role") != "sol"
            or planner.get("root_thread_id") != task["task_id"]
            or planner.get("model") != root_model
            or execution.get("profile") != "finite_dag/v1"
            or execution.get("workers_can_spawn") is not False
            or execution.get("retries_allowed") != 0
            or execution.get("fallbacks_allowed") != 0
            or execution.get("replacements_allowed") != 0
            or integration.get("strategy") != "dependency_ordered"
            or integration.get("release_required") is not False
            or integration.get("final_verification")
            != [check["id"] for check in task["acceptance_checks"]]
            or authority.get("authority_id")
            != "provider-free-control-tower"
            or authority.get("scope") != "provider_free"
            or authority.get("status") != "granted"
            or authority.get("authorized_worker_ids") != worker_ids
            or any(worker.get("optional") is not False for worker in workers)
            or proposal.get("acceptance_criteria")
            != [check["description"] for check in task["acceptance_checks"]]
        ):
            return None, ["prepare:planning_proposal_outside_envelope"]
        return deepcopy(dict(value)), []
    if proposal.get("logical_worker_count") != 1:
        return None, ["prepare:planned_topology_deferred"]
    if proposal != _logical_plan(task, root_model):
        return None, ["prepare:planning_proposal_mismatch"]
    return deepcopy(dict(value)), []


def _executor_capability(
    executor_group: str,
    task: Mapping[str, Any],
    *,
    max_concurrency: int = 1,
) -> dict[str, Any]:
    return _seal(
        {
            "schema": "orch-dork/executor-capability/v1",
            "executor_group": executor_group,
            "runtime_identity": {
                "schema": "orch-dork/executor-runtime-identity/v1",
                "logical_model_id": governor.worker_model(),
                "runtime_id": "provider-free-fake/v1",
                "provider": "provider-free",
                "structured_output": "closed-json/v1",
            },
            "task_kinds": ["execute"],
            "privacy_classes": ["local_only"],
            "tools": [],
            "provider": "provider-free",
            "side_effects": [],
            "retries": 0,
            "fallbacks": 0,
            "replacements": 0,
            "max_concurrency": max_concurrency,
            "context_limit_tokens": task["budgets"]["context_tokens"],
            "output_limit_tokens": task["budgets"]["output_tokens"],
            "resources": {
                "gpu_memory_mib": 0,
                "process_slots": 1,
                "integration_slots": 1,
            },
            "timeout": {
                "wall_time_ms": task["budgets"]["wall_time_ms"],
                "cleanup_grace_ms": min(5000, task["budgets"]["wall_time_ms"]),
            },
            "cleanup": {
                "supported": True,
                "owned_process_group": True,
                "terminal_evidence": ["complete", "unknown"],
            },
            "observable_evidence": [
                "worker-result/v1",
                "cleanup-observation/v1",
            ],
        },
        "capability_sha256",
    )


def _plan_routing_policy(logical_plan: Any) -> dict[str, Any] | None:
    """The sealed routing policy the registry resolves for one logical plan."""

    return governor.validate_logical_plan(logical_plan).get("routing_policy")


def _task_spec(task: Mapping[str, Any], executor_group: str) -> dict[str, Any]:
    deliverable = task["deliverables"][0]
    raw = {
        "schema": contracts.TASK_SPEC_SCHEMA,
        "id": task["task_id"] + ":executor",
        "kind": "execute",
        "goal": task["objective"],
        "rationale": "Execute one admitted direct/v1 node.",
        "non_goals": task["non_goals"],
        "dependencies": [],
        "input_refs": task["input_refs"],
        "read_scope": [],
        "write_scope": [],
        "deliverable": {
            "schema": "orch-dork/direct-result/v1",
            "media_type": deliverable["media_type"],
            "description": deliverable["description"],
        },
        "acceptance_checks": task["acceptance_checks"],
        "executor": executor_group,
        "model_profile": _IMPLEMENTER_PROFILE,
        "allowed_tools": [],
        "risk": {"level": task["risk_class"], "reasons": task["constraints"]},
        "budgets": {
            "context_tokens": task["budgets"]["context_tokens"],
            "output_tokens": task["budgets"]["output_tokens"],
            "handoff_tokens": task["budgets"]["handoff_tokens"],
            "tool_calls": task["budgets"]["tool_calls"],
            "retries": task["budgets"]["retries"],
        },
        "may_request_decomposition": False,
        "failure_policy": {
            "on_blocked": "stop",
            "on_failed": "stop",
            "on_budget_exhausted": "stop",
        },
    }
    return contracts.seal_task_spec(raw)


def _logical_plan(task: Mapping[str, Any], root_model: str) -> dict[str, Any]:
    worker_id = task["task_id"] + ":executor"
    deliverable = "result/" + task["deliverables"][0]["id"]
    plan = {
        "schema": governor.LOGICAL_PLAN_SCHEMA,
        "plan_id": task["task_id"] + "-direct-v1",
        "revision": 1,
        "predecessor_plan_sha256": None,
        "planner": {
            "role": "sol",
            "root_thread_id": task["task_id"],
            "model": root_model,
        },
        "objective": task["objective"],
        "finite": True,
        "logical_worker_count": 1,
        "workers": [
            {
                "id": worker_id,
                "executor": "subagent",
                "justification": "Execute one coherent bounded direct task.",
                "objective": task["objective"],
                "deliverables": [deliverable],
                "owned_resources": ["result"],
                "excluded_resources": [],
                "dependencies": [],
                "verification": [check["id"] for check in task["acceptance_checks"]],
                "optional": False,
                "model_profile": _IMPLEMENTER_PROFILE,
                "context_budget_tokens": task["budgets"]["context_tokens"],
            }
        ],
        "execution": {
            "profile": "finite_dag/v1",
            "capacity_source": "runtime_inventory",
            "worker_model": governor.worker_model(),
            "worker_effort": governor.worker_effort(),
            "context_policy": "none",
            "workers_can_spawn": False,
            "retries_allowed": 0,
            "fallbacks_allowed": 0,
            "replacements_allowed": 0,
        },
        "integration": {
            "strategy": "dependency_ordered",
            "release_required": False,
            "final_verification": [check["id"] for check in task["acceptance_checks"]],
        },
        "authority": {
            "authority_id": "provider-free-control-tower",
            "scope": "provider_free",
            "status": "granted",
            "authorized_worker_ids": [worker_id],
        },
        "protected_resources": [],
        "acceptance_criteria": [check["description"] for check in task["acceptance_checks"]],
    }
    plan = governor.bind_routing_policy(plan)
    report = governor.validate_logical_plan(plan)
    if report.get("status") != "PASS":
        raise ValueError("logical_plan_invalid")
    return plan


def _direct_preparation(
    task: Mapping[str, Any],
    task_digest: str,
    now_ms: int,
    *,
    root_model: str,
    planning_submission: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    planning_submission_sha256 = (
        planning_submission["submission_sha256"]
        if isinstance(planning_submission, Mapping)
        else None
    )
    direct_topology = _seal(
        {
            "schema": "orch-dork/topology-closure-not-applicable/v1",
            "status": "NOT_APPLICABLE",
            "reason": "single_node",
        },
        "closure_sha256",
    )
    executor_group = task["routing_hints"]["executor_group"]
    capability = _executor_capability(executor_group, task)
    task_spec = _task_spec(task, executor_group)
    logical_plan = _logical_plan(task, root_model)
    route_evidence = ["caller_requested_direct", "single_coherent_task"]
    if planning_submission_sha256 is not None:
        route_evidence = [
            "single_coherent_task",
            "validated_atomic_planning_submission",
        ]
    route = _seal(
        {
            "schema": ROUTE_SCHEMA,
            "profile_id": "direct/v1",
            "worker_count": 1,
            "cut": "atomic",
            "executor_groups": [executor_group],
            "context_policy": "bounded_refs",
            "budget_sha256": _sha256(task["budgets"]),
            "verification_depth": "final",
            "evidence": route_evidence,
            "confidence_bps": 10000,
        },
        "route_sha256",
    )
    profile = workflow_profiles.profile("direct/v1")
    compilation = _seal(
        {
            "schema": COMPILATION_SCHEMA,
            "task_brief_sha256": task_digest,
            "route_sha256": route["route_sha256"],
            "profile_sha256": profile["profile_sha256"],
            "compiler_id": profile["compiler_id"],
            "logical_plan_sha256": _sha256(logical_plan),
            "planning_submission_sha256": planning_submission_sha256,
            "workflow_submission_sha256": None,
            "topology_closure": direct_topology["closure_sha256"],
        },
        "compilation_sha256",
    )
    ready = {
        "task_brief": deepcopy(dict(task)),
        "planning_submission": (
            deepcopy(dict(planning_submission))
            if isinstance(planning_submission, Mapping)
            else None
        ),
        "workflow_submission": None,
        "topology_closure": direct_topology,
        "project_ref": task["project_ref"],
        "budgets": task["budgets"],
        "route": route,
        "profile": profile,
        "compilation": compilation,
        "task_spec": task_spec,
        "task_specs": [task_spec],
        "logical_plan": logical_plan,
        "routing_policy": _plan_routing_policy(logical_plan),
        "executor_capability": capability,
        "authority_requirements": [],
        "reservation_requirements": {
            "logical_nodes": 1,
            "live_sessions": 1,
            "hosted_calls": 0,
            "retries": 0,
            "fallbacks": 0,
            "replacements": 0,
        },
    }
    return _seal(
        {
            "schema": PREPARATION_SCHEMA,
            "preparation_status": "READY_TO_FREEZE",
            "task_brief_sha256": task_digest,
            "policy_generation": POLICY_GENERATION,
            "project_ground_sha256": task["project_ref"]["project_ground_sha256"],
            "privacy_class": task["privacy_class"],
            "risk_class": task["risk_class"],
            "expires_at_ms": now_ms + task["budgets"]["wall_time_ms"],
            "result": ready,
        },
        "preparation_sha256",
    )


def _profile_topology_closure(
    profile_id: str,
    logical_plan: Mapping[str, Any],
    workflow_submission: Mapping[str, Any],
) -> dict[str, Any]:
    """Seal a compiler-worked closure for one registry-bounded topology.

    These profiles have no caller-defined graph grammar: their complete node
    and edge sets are derived by the registered compiler.  The general
    finite-DAG path still uses the full Topology Closure evaluator.
    """

    workers = sorted(logical_plan["workers"], key=lambda worker: worker["id"])
    return _seal(
        {
            "schema": "orch-dork/profile-topology-closure/v1",
            "status": "PASS",
            "profile_id": profile_id,
            "logical_plan_sha256": _sha256(logical_plan),
            "workflow_submission_sha256": workflow_submission[
                "submission_sha256"
            ],
            "nodes": [worker["id"] for worker in workers] + ["reviewer"],
            "dependencies": [
                {
                    "node_id": worker["id"],
                    "depends_on": sorted(worker["dependencies"]),
                }
                for worker in workers
            ],
            "criterion_owners": [
                {
                    "criterion_id": check_id,
                    "producer_node_ids": [workers[-1]["id"]],
                    "verifier_node_ids": ["reviewer"],
                }
                for check_id in logical_plan["integration"]["final_verification"]
            ],
            "typed_unknowns": [],
            "invariants": workflow_profiles.profile(profile_id)[
                "topology_invariants"
            ],
        },
        "closure_sha256",
    )


def _profile_plan(
    task: Mapping[str, Any],
    *,
    profile_id: str,
    workers: list[dict[str, Any]],
    plan_suffix: str,
    root_model: str,
) -> dict[str, Any]:
    worker_ids = [worker["id"] for worker in workers]
    plan = {
        "schema": governor.LOGICAL_PLAN_SCHEMA,
        "plan_id": task["task_id"] + "-" + plan_suffix,
        "revision": 1,
        "predecessor_plan_sha256": None,
        "planner": {
            "role": "sol",
            "root_thread_id": task["task_id"],
            "model": root_model,
        },
        "objective": task["objective"],
        "finite": True,
        "logical_worker_count": len(workers),
        "workers": workers,
        "execution": {
            "profile": "finite_dag/v1",
            "capacity_source": "runtime_inventory",
            "worker_model": governor.worker_model(),
            "worker_effort": governor.worker_effort(),
            "context_policy": "none",
            "workers_can_spawn": False,
            "retries_allowed": 0,
            "fallbacks_allowed": 0,
            "replacements_allowed": 0,
        },
        "integration": {
            "strategy": "dependency_ordered",
            "release_required": False,
            "final_verification": [
                check["id"] for check in task["acceptance_checks"]
            ],
        },
        "authority": {
            "authority_id": "provider-free-control-tower",
            "scope": "provider_free",
            "status": "granted",
            "authorized_worker_ids": worker_ids,
        },
        "protected_resources": [],
        "acceptance_criteria": [
            check["description"] for check in task["acceptance_checks"]
        ],
    }
    plan = governor.bind_routing_policy(plan)
    report = governor.validate_logical_plan(plan)
    if report.get("status") != "PASS":
        raise ValueError(profile_id + "_logical_plan_invalid")
    return report["canonical_plan"]


def _execute_repair_task_specs(
    task: Mapping[str, Any], max_repairs: int
) -> list[dict[str, Any]]:
    executor = _task_spec(task, task["routing_hints"]["executor_group"])
    specs = [executor]
    previous = executor["id"]
    deliverable = task["deliverables"][0]
    for sequence in range(1, max_repairs + 1):
        node_id = task["task_id"] + ":repair-" + str(sequence)
        specs.append(
            contracts.seal_task_spec(
                {
                    "schema": contracts.TASK_SPEC_SCHEMA,
                    "id": node_id,
                    "kind": "execute",
                    "goal": "Repair only explicitly failed acceptance checks.",
                    "rationale": "Execute one separately admitted bounded Repair node.",
                    "non_goals": task["non_goals"]
                    + [
                        "Retry or resample the failed response",
                        "Widen tools, scope, privacy, authority, or acceptance",
                    ],
                    "dependencies": [previous],
                    "input_refs": task["input_refs"],
                    "read_scope": [],
                    "write_scope": [],
                    "deliverable": {
                        "schema": "orch-dork/repair-result/v1",
                        "media_type": deliverable["media_type"],
                        "description": deliverable["description"],
                    },
                    "acceptance_checks": task["acceptance_checks"],
                    "executor": task["routing_hints"]["executor_group"],
                    "model_profile": _IMPLEMENTER_PROFILE,
                    "allowed_tools": [],
                    "risk": {
                        "level": task["risk_class"],
                        "reasons": task["constraints"],
                    },
                    "budgets": {
                        "context_tokens": max(
                            1,
                            task["budgets"]["context_tokens"]
                            // (max_repairs + 1),
                        ),
                        "output_tokens": max(
                            1,
                            task["budgets"]["output_tokens"]
                            // (max_repairs + 1),
                        ),
                        "handoff_tokens": task["budgets"]["handoff_tokens"],
                        "tool_calls": task["budgets"]["tool_calls"],
                        "retries": 0,
                    },
                    "may_request_decomposition": False,
                    "failure_policy": {
                        "on_blocked": "stop",
                        "on_failed": "stop",
                        "on_budget_exhausted": "stop",
                    },
                }
            )
        )
        previous = node_id
    return specs


def _execute_repair_preparation(
    task: Mapping[str, Any],
    task_digest: str,
    now_ms: int,
    workflow_submission: Mapping[str, Any],
    *,
    root_model: str,
) -> dict[str, Any]:
    report = workflow_profiles.validate_workflow_submission(
        "execute_verify_repair/v1", workflow_submission
    )
    if report["status"] != "PASS":
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            ["prepare:" + issue for issue in report["issues"]],
        )
    submission = report["normalized"]
    max_repairs = submission["max_repairs"]
    task_specs = _execute_repair_task_specs(task, max_repairs)
    context_budget = max(
        1, task["budgets"]["context_tokens"] // (max_repairs + 1)
    )
    workers = []
    for index, task_spec in enumerate(task_specs):
        worker_deliverable = (
            "result/"
            + task["deliverables"][0]["id"]
            + ("" if index == 0 else "-repair-" + str(index))
        )
        workers.append(
            {
                "id": task_spec["id"],
                "executor": "subagent",
                "justification": (
                    "Execute the original bounded task."
                    if index == 0
                    else "Execute one declared Repair node only after an exact REPAIR disposition."
                ),
                "objective": task_spec["goal"],
                "deliverables": [worker_deliverable],
                "owned_resources": [worker_deliverable],
                "excluded_resources": [],
                "dependencies": task_spec["dependencies"],
                "verification": [
                    check["id"] for check in task["acceptance_checks"]
                ],
                "optional": index > 0,
                "model_profile": _IMPLEMENTER_PROFILE,
                "context_budget_tokens": context_budget,
            }
        )
    try:
        logical_plan = _profile_plan(
            task,
            profile_id="execute_verify_repair/v1",
            workers=workers,
            plan_suffix="execute-verify-repair-v1",
            root_model=root_model,
        )
    except ValueError:
        return _refused_preparation(
            task, task_digest, now_ms, ["prepare:logical_plan_invalid"]
        )
    closure = _profile_topology_closure(
        "execute_verify_repair/v1", logical_plan, submission
    )
    executor_group = task["routing_hints"]["executor_group"]
    capability = _executor_capability(executor_group, task)
    route = _seal(
        {
            "schema": ROUTE_SCHEMA,
            "profile_id": "execute_verify_repair/v1",
            "worker_count": len(task_specs),
            "cut": "serial_declared_repair",
            "executor_groups": [executor_group],
            "context_policy": "fresh_per_revision",
            "budget_sha256": _sha256(task["budgets"]),
            "verification_depth": "layered_each_revision",
            "evidence": [
                "caller_requested_execute_verify_repair",
                submission["submission_sha256"],
            ],
            "confidence_bps": 10000,
        },
        "route_sha256",
    )
    profile = workflow_profiles.profile("execute_verify_repair/v1")
    compilation = _seal(
        {
            "schema": COMPILATION_SCHEMA,
            "task_brief_sha256": task_digest,
            "route_sha256": route["route_sha256"],
            "profile_sha256": profile["profile_sha256"],
            "compiler_id": profile["compiler_id"],
            "logical_plan_sha256": _sha256(logical_plan),
            "planning_submission_sha256": None,
            "workflow_submission_sha256": submission["submission_sha256"],
            "topology_closure": closure["closure_sha256"],
        },
        "compilation_sha256",
    )
    ready = {
        "task_brief": deepcopy(dict(task)),
        "planning_submission": None,
        "workflow_submission": submission,
        "topology_closure": closure,
        "project_ref": task["project_ref"],
        "budgets": task["budgets"],
        "route": route,
        "profile": profile,
        "compilation": compilation,
        "task_spec": task_specs[0],
        "task_specs": task_specs,
        "logical_plan": logical_plan,
        "routing_policy": _plan_routing_policy(logical_plan),
        "executor_capability": capability,
        "authority_requirements": task["required_human_approvals"],
        "reservation_requirements": {
            "logical_nodes": len(task_specs),
            "live_sessions": 1,
            "hosted_calls": 0,
            "retries": 0,
            "fallbacks": 0,
            "replacements": 0,
        },
    }
    return _seal(
        {
            "schema": PREPARATION_SCHEMA,
            "preparation_status": "READY_TO_FREEZE",
            "task_brief_sha256": task_digest,
            "policy_generation": POLICY_GENERATION,
            "project_ground_sha256": task["project_ref"][
                "project_ground_sha256"
            ],
            "privacy_class": task["privacy_class"],
            "risk_class": task["risk_class"],
            "expires_at_ms": now_ms + task["budgets"]["wall_time_ms"],
            "result": ready,
        },
        "preparation_sha256",
    )


def _best_of_n_task_specs(
    task: Mapping[str, Any], candidate_count: int
) -> list[dict[str, Any]]:
    specs = []
    context_budget = max(1, task["budgets"]["context_tokens"] // candidate_count)
    output_budget = max(1, task["budgets"]["output_tokens"] // candidate_count)
    for index in range(1, candidate_count + 1):
        node_id = "candidate-" + str(index).zfill(3)
        specs.append(
            contracts.seal_task_spec(
                {
                    "schema": contracts.TASK_SPEC_SCHEMA,
                    "id": node_id,
                    "kind": "execute",
                    "goal": task["objective"],
                    "rationale": "Produce one independent budget-matched candidate.",
                    "non_goals": task["non_goals"]
                    + ["Inspect peer candidates or completion order"],
                    "dependencies": [],
                    "input_refs": task["input_refs"],
                    "read_scope": [],
                    "write_scope": [],
                    "deliverable": {
                        "schema": "orch-dork/best-of-n-candidate/v1",
                        "media_type": task["deliverables"][0]["media_type"],
                        "description": "One blinded candidate",
                    },
                    "acceptance_checks": task["acceptance_checks"],
                    "executor": task["routing_hints"]["executor_group"],
                    "model_profile": _IMPLEMENTER_PROFILE,
                    "allowed_tools": [],
                    "risk": {
                        "level": task["risk_class"],
                        "reasons": task["constraints"],
                    },
                    "budgets": {
                        "context_tokens": context_budget,
                        "output_tokens": output_budget,
                        "handoff_tokens": task["budgets"]["handoff_tokens"],
                        "tool_calls": task["budgets"]["tool_calls"],
                        "retries": 0,
                    },
                    "may_request_decomposition": False,
                    "failure_policy": {
                        "on_blocked": "stop",
                        "on_failed": "stop",
                        "on_budget_exhausted": "stop",
                    },
                }
            )
        )
    specs.append(
        contracts.seal_task_spec(
            {
                "schema": contracts.TASK_SPEC_SCHEMA,
                "id": "comparator",
                "kind": "join",
                "goal": "Compare blinded candidates against the declared direct baseline.",
                "rationale": "Select, synthesize, tie, or escalate without candidate identity leakage.",
                "non_goals": task["non_goals"]
                + ["Infer candidate identity", "Grant promotion authority"],
                # Candidate identities are deliberately absent from the
                # comparator-facing TaskSpec. Runtime release is gated by
                # the all-candidates-applied event, while the comparator sees
                # only opaque option labels and content-addressed artifacts.
                "dependencies": [],
                "input_refs": [],
                "read_scope": [],
                "write_scope": [],
                "deliverable": {
                    "schema": "orch-dork/best-of-n-result/v1",
                    "media_type": task["deliverables"][0]["media_type"],
                    "description": task["deliverables"][0]["description"],
                },
                "acceptance_checks": task["acceptance_checks"],
                "executor": "blinded-comparator",
                "model_profile": _ROOT_LABOR_PROFILE,
                "allowed_tools": [],
                "risk": {
                    "level": task["risk_class"],
                    "reasons": task["constraints"],
                },
                "budgets": {
                    "context_tokens": max(1, task["budgets"]["context_tokens"] // 2),
                    "output_tokens": task["budgets"]["output_tokens"],
                    "handoff_tokens": task["budgets"]["handoff_tokens"],
                    "tool_calls": 1,
                    "retries": 0,
                },
                "may_request_decomposition": False,
                "failure_policy": {
                    "on_blocked": "stop",
                    "on_failed": "stop",
                    "on_budget_exhausted": "stop",
                },
            }
        )
    )
    return specs


def _best_of_n_preparation(
    task: Mapping[str, Any],
    task_digest: str,
    now_ms: int,
    workflow_submission: Mapping[str, Any],
    *,
    root_model: str,
) -> dict[str, Any]:
    report = workflow_profiles.validate_workflow_submission(
        "best_of_n/v1", workflow_submission
    )
    if report["status"] != "PASS":
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            ["prepare:" + issue for issue in report["issues"]],
        )
    submission = report["normalized"]
    count = submission["candidate_count"]
    task_specs = _best_of_n_task_specs(task, count)
    context_budget = max(1, task["budgets"]["context_tokens"] // count)
    workers = [
        {
            "id": task_spec["id"],
            "executor": "subagent",
            "justification": "Produce one independent budget-matched candidate.",
            "objective": task["objective"],
            "deliverables": ["result/" + task_spec["id"]],
            "owned_resources": ["result/" + task_spec["id"]],
            "excluded_resources": [],
            "dependencies": [],
            "verification": [check["id"] for check in task["acceptance_checks"]],
            "optional": False,
            "model_profile": _IMPLEMENTER_PROFILE,
            "context_budget_tokens": context_budget,
        }
        for task_spec in task_specs[:-1]
    ]
    workers.append(
        {
            "id": "comparator",
            "executor": "sol",
            "justification": "Blindly compare every candidate against the direct baseline.",
            "objective": task["objective"],
            "deliverables": ["result/" + task["deliverables"][0]["id"]],
            "owned_resources": ["result/" + task["deliverables"][0]["id"]],
            "excluded_resources": [],
            "dependencies": [task_spec["id"] for task_spec in task_specs[:-1]],
            "verification": [check["id"] for check in task["acceptance_checks"]],
            "optional": False,
            "model_profile": _ROOT_LABOR_PROFILE,
            "context_budget_tokens": max(1, task["budgets"]["context_tokens"] // 2),
        }
    )
    try:
        logical_plan = _profile_plan(
            task,
            profile_id="best_of_n/v1",
            workers=workers,
            plan_suffix="best-of-n-v1",
            root_model=root_model,
        )
    except ValueError:
        return _refused_preparation(
            task, task_digest, now_ms, ["prepare:logical_plan_invalid"]
        )
    closure = _profile_topology_closure("best_of_n/v1", logical_plan, submission)
    capability = _executor_capability(
        task["routing_hints"]["executor_group"], task, max_concurrency=count
    )
    route = _seal(
        {
            "schema": ROUTE_SCHEMA,
            "profile_id": "best_of_n/v1",
            "worker_count": count,
            "cut": "blinded_best_of_" + str(count),
            "executor_groups": [task["routing_hints"]["executor_group"]],
            "context_policy": "candidate_isolation",
            "budget_sha256": _sha256(task["budgets"]),
            "verification_depth": "comparison_and_layered_final",
            "evidence": [
                "budget_matched_candidates",
                submission["direct_baseline"]["evidence_sha256"],
            ],
            "confidence_bps": 10000,
        },
        "route_sha256",
    )
    profile = workflow_profiles.profile("best_of_n/v1")
    compilation = _seal(
        {
            "schema": COMPILATION_SCHEMA,
            "task_brief_sha256": task_digest,
            "route_sha256": route["route_sha256"],
            "profile_sha256": profile["profile_sha256"],
            "compiler_id": profile["compiler_id"],
            "logical_plan_sha256": _sha256(logical_plan),
            "planning_submission_sha256": None,
            "workflow_submission_sha256": submission["submission_sha256"],
            "topology_closure": closure["closure_sha256"],
        },
        "compilation_sha256",
    )
    ready = {
        "task_brief": deepcopy(dict(task)),
        "planning_submission": None,
        "workflow_submission": submission,
        "topology_closure": closure,
        "project_ref": task["project_ref"],
        "budgets": task["budgets"],
        "route": route,
        "profile": profile,
        "compilation": compilation,
        "task_spec": task_specs[-1],
        "task_specs": task_specs,
        "logical_plan": logical_plan,
        "routing_policy": _plan_routing_policy(logical_plan),
        "executor_capability": capability,
        "authority_requirements": task["required_human_approvals"],
        "reservation_requirements": {
            "logical_nodes": count + 1,
            "live_sessions": count,
            "hosted_calls": 0,
            "retries": 0,
            "fallbacks": 0,
            "replacements": 0,
        },
    }
    return _seal(
        {
            "schema": PREPARATION_SCHEMA,
            "preparation_status": "READY_TO_FREEZE",
            "task_brief_sha256": task_digest,
            "policy_generation": POLICY_GENERATION,
            "project_ground_sha256": task["project_ref"][
                "project_ground_sha256"
            ],
            "privacy_class": task["privacy_class"],
            "risk_class": task["risk_class"],
            "expires_at_ms": now_ms + task["budgets"]["wall_time_ms"],
            "result": ready,
        },
        "preparation_sha256",
    )


def _finite_dag_preparation(
    task: Mapping[str, Any],
    task_digest: str,
    now_ms: int,
    workflow_submission: Mapping[str, Any],
    *,
    root_model: str,
) -> dict[str, Any]:
    profile_report = workflow_profiles.validate_workflow_submission(
        "finite_dag/v1", workflow_submission
    )
    if profile_report["status"] != "PASS":
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            ["prepare:" + issue for issue in profile_report["issues"]],
        )
    submission = profile_report["normalized"]
    planning, planning_issues = _validate_planning_submission(
        submission["planning_submission"],
        task=task,
        task_digest=task_digest,
        now_ms=now_ms,
        root_model=root_model,
        allow_general=True,
    )
    if planning_issues or planning is None:
        return _refused_preparation(
            task, task_digest, now_ms, planning_issues
        )
    topology = submission["topology_submission"]
    if (
        not isinstance(topology, Mapping)
        or set(topology) != _PARALLEL_SUBMISSION_FIELDS
        or topology.get("schema") != topology_closure.SUBMISSION_SCHEMA
        or not _seal_valid(topology, "submission_sha256")
    ):
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            ["prepare:topology_submission_invalid"],
        )
    logical_plan = planning["proposal"]
    producer_ids = sorted(
        producer["node_id"] for producer in topology["producers"]
    )
    integration_node_id = submission["integration_node_id"]
    if (
        integration_node_id != topology["join"]["node_id"]
        or sorted(worker["id"] for worker in logical_plan["workers"])
        != sorted(producer_ids + [integration_node_id])
    ):
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            ["prepare:planner_topology_mismatch"],
        )
    expected_dependencies: dict[str, set[str]] = {
        producer_id: set() for producer_id in producer_ids
    }
    for relay in topology["relays"]:
        manifest = relay.get("manifest", {})
        consumer = manifest.get("consumer_node")
        producer = manifest.get("producer_node")
        if consumer in expected_dependencies and producer in producer_ids:
            expected_dependencies[consumer].add(producer)
    expected_dependencies[integration_node_id] = set(
        topology["join"]["input_producer_ids"]
    )
    if any(
        set(worker["dependencies"])
        != expected_dependencies.get(worker["id"], set())
        for worker in logical_plan["workers"]
    ):
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            ["prepare:planner_dependency_mismatch"],
        )
    try:
        task_specs = _parallel_task_specs(task, topology, logical_plan)
    except (KeyError, TypeError, ValueError, contracts.ContractValidationError):
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            ["prepare:planner_task_specs_invalid"],
        )
    semantic_plan_sha256 = _sha256(
        {
            "information_units": topology["information_units"],
            "relations": topology["relations"],
            "criteria": topology["criteria"],
        }
    )
    closure = topology_closure.evaluate_topology_closure(
        {
            "schema": topology_closure.PROGRAM_SCHEMA,
            "task_brief_sha256": task_digest,
            "acceptance_checks": task["acceptance_checks"],
            "project_ground_sha256": task["project_ref"][
                "project_ground_sha256"
            ],
            "privacy_class": task["privacy_class"],
            "profile_id": "finite_dag/v1",
            "semantic_plan_sha256": semantic_plan_sha256,
            "compiler_input_sha256": _sha256(logical_plan),
            "logical_plan": logical_plan,
            "admitted_input_refs": task["input_refs"],
            "submission": topology,
        }
    )
    if closure.get("status") != "PASS":
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            list(closure.get("issues", []))
            + (["topology:review_required"] if closure.get("status") == "REVIEW_REQUIRED" else []),
            details={"topology_closure": closure},
        )
    capability = _executor_capability(
        task["routing_hints"]["executor_group"],
        task,
        max_concurrency=min(
            len(producer_ids), lane_capacity.MAX_CONCURRENT_LANES
        ),
    )
    route = _seal(
        {
            "schema": ROUTE_SCHEMA,
            "profile_id": "finite_dag/v1",
            "worker_count": len(producer_ids),
            "cut": topology["topology_id"],
            "executor_groups": [task["routing_hints"]["executor_group"]],
            "context_policy": "planner_bound_topology_closure",
            "budget_sha256": _sha256(task["budgets"]),
            "verification_depth": "node_and_layered_final",
            "evidence": [
                "requirement_bound_planner_proposal",
                planning["submission_sha256"],
                closure["closure_sha256"],
            ],
            "confidence_bps": 10000,
        },
        "route_sha256",
    )
    profile = workflow_profiles.profile("finite_dag/v1")
    compilation = _seal(
        {
            "schema": COMPILATION_SCHEMA,
            "task_brief_sha256": task_digest,
            "route_sha256": route["route_sha256"],
            "profile_sha256": profile["profile_sha256"],
            "compiler_id": profile["compiler_id"],
            "logical_plan_sha256": _sha256(logical_plan),
            "planning_submission_sha256": planning["submission_sha256"],
            "workflow_submission_sha256": submission["submission_sha256"],
            "topology_closure": closure["closure_sha256"],
        },
        "compilation_sha256",
    )
    join_spec = next(
        task_spec
        for task_spec in task_specs
        if task_spec["id"] == integration_node_id
    )
    ready = {
        "task_brief": deepcopy(dict(task)),
        "planning_submission": planning,
        "workflow_submission": submission,
        "topology_closure": closure,
        "project_ref": task["project_ref"],
        "budgets": task["budgets"],
        "route": route,
        "profile": profile,
        "compilation": compilation,
        "task_spec": join_spec,
        "task_specs": task_specs,
        "logical_plan": logical_plan,
        "routing_policy": _plan_routing_policy(logical_plan),
        "executor_capability": capability,
        "authority_requirements": task["required_human_approvals"],
        "reservation_requirements": {
            "logical_nodes": logical_plan["logical_worker_count"],
            "live_sessions": min(
                len(producer_ids), lane_capacity.MAX_CONCURRENT_LANES
            ),
            "hosted_calls": 0,
            "retries": 0,
            "fallbacks": 0,
            "replacements": 0,
        },
    }
    return _seal(
        {
            "schema": PREPARATION_SCHEMA,
            "preparation_status": "READY_TO_FREEZE",
            "task_brief_sha256": task_digest,
            "policy_generation": POLICY_GENERATION,
            "project_ground_sha256": task["project_ref"][
                "project_ground_sha256"
            ],
            "privacy_class": task["privacy_class"],
            "risk_class": task["risk_class"],
            "expires_at_ms": now_ms + task["budgets"]["wall_time_ms"],
            "result": ready,
        },
        "preparation_sha256",
    )


def _parallel_logical_plan(
    task: Mapping[str, Any], submission: Mapping[str, Any], root_model: str
) -> dict[str, Any]:
    producers = sorted(submission["producers"], key=lambda row: row["node_id"])
    join = submission["join"]
    relay_dependencies: dict[str, set[str]] = {
        producer["node_id"]: set() for producer in producers
    }
    for relay_record in submission["relays"]:
        manifest = relay_record["manifest"]
        relay_dependencies.setdefault(manifest["consumer_node"], set()).add(
            manifest["producer_node"]
        )
    context_budget = max(1, task["budgets"]["context_tokens"] // len(producers))
    workers = []
    for producer in producers:
        output = "result/" + producer["output_artifact_id"]
        workers.append(
            {
                "id": producer["node_id"],
                "executor": "subagent",
                "justification": "Produce one partition under admitted Topology Closure.",
                "objective": task["objective"],
                "deliverables": [output],
                "owned_resources": [output],
                "excluded_resources": [],
                "dependencies": sorted(relay_dependencies.get(producer["node_id"], set())),
                "verification": [check["id"] for check in task["acceptance_checks"]],
                "optional": False,
                "model_profile": _IMPLEMENTER_PROFILE,
                "context_budget_tokens": context_budget,
            }
        )
    join_output = "result/" + join["output_artifact_id"]
    workers.append(
        {
            "id": join["node_id"],
            "executor": "sol",
            "justification": "Join every declared producer artifact and discharge owned criteria.",
            "objective": task["objective"],
            "deliverables": [join_output],
            "owned_resources": [join_output],
            "excluded_resources": [],
            "dependencies": sorted(join["input_producer_ids"]),
            "verification": [check["id"] for check in task["acceptance_checks"]],
            "optional": False,
            "model_profile": _ROOT_LABOR_PROFILE,
            "context_budget_tokens": max(1, task["budgets"]["context_tokens"] // 2),
        }
    )
    worker_ids = [worker["id"] for worker in workers]
    plan = {
        "schema": governor.LOGICAL_PLAN_SCHEMA,
        "plan_id": task["task_id"] + "-parallel-join-v1",
        "revision": 1,
        "predecessor_plan_sha256": None,
        "planner": {
            "role": "sol",
            "root_thread_id": task["task_id"],
            "model": root_model,
        },
        "objective": task["objective"],
        "finite": True,
        "logical_worker_count": len(workers),
        "workers": workers,
        "execution": {
            "profile": "finite_dag/v1",
            "capacity_source": "runtime_inventory",
            "worker_model": governor.worker_model(),
            "worker_effort": governor.worker_effort(),
            "context_policy": "none",
            "workers_can_spawn": False,
            "retries_allowed": 0,
            "fallbacks_allowed": 0,
            "replacements_allowed": 0,
        },
        "integration": {
            "strategy": "dependency_ordered",
            "release_required": False,
            "final_verification": [check["id"] for check in task["acceptance_checks"]],
        },
        "authority": {
            "authority_id": "provider-free-control-tower",
            "scope": "provider_free",
            "status": "granted",
            "authorized_worker_ids": worker_ids,
        },
        "protected_resources": [],
        "acceptance_criteria": [
            check["description"] for check in task["acceptance_checks"]
        ],
    }
    plan = governor.bind_routing_policy(plan)
    report = governor.validate_logical_plan(plan)
    if report.get("status") != "PASS":
        raise ValueError("parallel_logical_plan_invalid")
    return report["canonical_plan"]


def _parallel_task_specs(
    task: Mapping[str, Any],
    submission: Mapping[str, Any],
    logical_plan: Mapping[str, Any],
) -> list[dict[str, Any]]:
    units = {
        unit["unit_id"]: unit["source_ref"] for unit in submission["information_units"]
    }
    plan_workers = {worker["id"]: worker for worker in logical_plan["workers"]}
    specs: list[dict[str, Any]] = []
    producers = sorted(submission["producers"], key=lambda row: row["node_id"])
    for producer in producers:
        refs = [units[unit_id] for unit_id in producer["unit_ids"]]
        for relay_record in submission["relays"]:
            manifest = relay_record["manifest"]
            if manifest["consumer_node"] != producer["node_id"]:
                continue
            for required in manifest["required_inputs"]:
                matches = [
                    ref
                    for ref in task["input_refs"]
                    if ref["uri"] == required["artifact_ref"]
                    and ref["sha256"] == required["sha256"]
                ]
                refs.extend(matches)
        refs = sorted(
            {(ref["uri"], ref["sha256"]): ref for ref in refs}.values(),
            key=lambda ref: (ref["uri"], ref["sha256"]),
        )
        worker = plan_workers[producer["node_id"]]
        specs.append(
            contracts.seal_task_spec(
                {
                    "schema": contracts.TASK_SPEC_SCHEMA,
                    "id": producer["node_id"],
                    "kind": "execute",
                    "goal": task["objective"],
                    "rationale": "Execute one Topology-Closure-proven producer partition.",
                    "non_goals": task["non_goals"],
                    "dependencies": worker["dependencies"],
                    "input_refs": refs,
                    "read_scope": [],
                    "write_scope": [],
                    "deliverable": {
                        "schema": "orch-dork/parallel-producer-result/v1",
                        "media_type": "application/json",
                        "description": "Bound output from " + producer["node_id"],
                    },
                    "acceptance_checks": task["acceptance_checks"],
                    "executor": task["routing_hints"]["executor_group"],
                    "model_profile": _IMPLEMENTER_PROFILE,
                    "allowed_tools": [],
                    "risk": {"level": task["risk_class"], "reasons": task["constraints"]},
                    "budgets": {
                        "context_tokens": worker["context_budget_tokens"],
                        "output_tokens": max(
                            1, task["budgets"]["output_tokens"] // len(producers)
                        ),
                        "handoff_tokens": task["budgets"]["handoff_tokens"],
                        "tool_calls": task["budgets"]["tool_calls"],
                        "retries": 0,
                    },
                    "may_request_decomposition": False,
                    "failure_policy": {
                        "on_blocked": "stop",
                        "on_failed": "stop",
                        "on_budget_exhausted": "stop",
                    },
                }
            )
        )
    join = submission["join"]
    join_worker = plan_workers[join["node_id"]]
    deliverable = task["deliverables"][0]
    specs.append(
        contracts.seal_task_spec(
            {
                "schema": contracts.TASK_SPEC_SCHEMA,
                "id": join["node_id"],
                "kind": "join",
                "goal": task["objective"],
                "rationale": "Consume every producer artifact and discharge the declared join criteria.",
                "non_goals": task["non_goals"],
                "dependencies": join_worker["dependencies"],
                "input_refs": [],
                "read_scope": [],
                "write_scope": [],
                "deliverable": {
                    "schema": "orch-dork/parallel-join-result/v1",
                    "media_type": deliverable["media_type"],
                    "description": deliverable["description"],
                },
                "acceptance_checks": task["acceptance_checks"],
                "executor": "deterministic-join",
                "model_profile": _ROOT_LABOR_PROFILE,
                "allowed_tools": [],
                "risk": {"level": task["risk_class"], "reasons": task["constraints"]},
                "budgets": {
                    "context_tokens": join_worker["context_budget_tokens"],
                    "output_tokens": task["budgets"]["output_tokens"],
                    "handoff_tokens": task["budgets"]["handoff_tokens"],
                    "tool_calls": 1,
                    "retries": 0,
                },
                "may_request_decomposition": False,
                "failure_policy": {
                    "on_blocked": "stop",
                    "on_failed": "stop",
                    "on_budget_exhausted": "stop",
                },
            }
        )
    )
    return specs


def _parallel_preparation(
    task: Mapping[str, Any],
    task_digest: str,
    now_ms: int,
    workflow_submission: Any,
    *,
    root_model: str,
) -> dict[str, Any]:
    if (
        not isinstance(workflow_submission, Mapping)
        or set(workflow_submission) != _PARALLEL_SUBMISSION_FIELDS
        or workflow_submission.get("schema") != topology_closure.SUBMISSION_SCHEMA
        or not _seal_valid(workflow_submission, "submission_sha256")
    ):
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            ["prepare:workflow_submission_invalid"],
        )
    try:
        logical_plan = _parallel_logical_plan(task, workflow_submission, root_model)
    except (KeyError, TypeError, ValueError):
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            ["prepare:workflow_submission_invalid"],
        )
    if logical_plan["logical_worker_count"] > task["budgets"]["nodes"]:
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            ["prepare:node_budget_exceeded"],
        )
    try:
        task_specs = _parallel_task_specs(task, workflow_submission, logical_plan)
    except (KeyError, TypeError, ValueError, contracts.ContractValidationError):
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            ["prepare:workflow_submission_invalid"],
        )
    semantic_plan_sha256 = _sha256(
        {
            "information_units": workflow_submission["information_units"],
            "relations": workflow_submission["relations"],
            "criteria": workflow_submission["criteria"],
        }
    )
    closure = topology_closure.evaluate_topology_closure(
        {
            "schema": topology_closure.PROGRAM_SCHEMA,
            "task_brief_sha256": task_digest,
            "acceptance_checks": task["acceptance_checks"],
            "project_ground_sha256": task["project_ref"]["project_ground_sha256"],
            "privacy_class": task["privacy_class"],
            "profile_id": "parallel_join/v1",
            "semantic_plan_sha256": semantic_plan_sha256,
            "compiler_input_sha256": _sha256(logical_plan),
            "logical_plan": logical_plan,
            "admitted_input_refs": task["input_refs"],
            "submission": workflow_submission,
        }
    )
    if closure["status"] != "PASS":
        reasons = list(closure["issues"])
        if closure["status"] == "REVIEW_REQUIRED":
            reasons.append("topology:review_required")
        return _refused_preparation(
            task,
            task_digest,
            now_ms,
            reasons,
            details={"topology_closure": closure},
        )

    capability = _executor_capability(
        task["routing_hints"]["executor_group"],
        task,
        max_concurrency=min(
            len(workflow_submission["producers"]),
            lane_capacity.MAX_CONCURRENT_LANES,
        ),
    )
    route = _seal(
        {
            "schema": ROUTE_SCHEMA,
            "profile_id": "parallel_join/v1",
            "worker_count": len(workflow_submission["producers"]),
            "cut": workflow_submission["topology_id"],
            "executor_groups": [task["routing_hints"]["executor_group"]],
            "context_policy": "topology_closure",
            "budget_sha256": _sha256(task["budgets"]),
            "verification_depth": "join_and_final",
            "evidence": ["topology_closure_pass", closure["closure_sha256"]],
            "confidence_bps": 10000,
        },
        "route_sha256",
    )
    profile = workflow_profiles.profile("parallel_join/v1")
    compilation = _seal(
        {
            "schema": COMPILATION_SCHEMA,
            "task_brief_sha256": task_digest,
            "route_sha256": route["route_sha256"],
            "profile_sha256": profile["profile_sha256"],
            "compiler_id": profile["compiler_id"],
            "logical_plan_sha256": _sha256(logical_plan),
            "planning_submission_sha256": None,
            "workflow_submission_sha256": workflow_submission["submission_sha256"],
            "topology_closure": closure["closure_sha256"],
        },
        "compilation_sha256",
    )
    ready = {
        "task_brief": deepcopy(dict(task)),
        "planning_submission": None,
        "workflow_submission": deepcopy(dict(workflow_submission)),
        "topology_closure": closure,
        "project_ref": task["project_ref"],
        "budgets": task["budgets"],
        "route": route,
        "profile": profile,
        "compilation": compilation,
        "task_spec": task_specs[-1],
        "task_specs": task_specs,
        "logical_plan": logical_plan,
        "routing_policy": _plan_routing_policy(logical_plan),
        "executor_capability": capability,
        "authority_requirements": [],
        "reservation_requirements": {
            "logical_nodes": len(logical_plan["workers"]),
            "live_sessions": min(
                len(workflow_submission["producers"]),
                lane_capacity.MAX_CONCURRENT_LANES,
            ),
            "hosted_calls": 0,
            "retries": 0,
            "fallbacks": 0,
            "replacements": 0,
        },
    }
    return _seal(
        {
            "schema": PREPARATION_SCHEMA,
            "preparation_status": "READY_TO_FREEZE",
            "task_brief_sha256": task_digest,
            "policy_generation": POLICY_GENERATION,
            "project_ground_sha256": task["project_ref"]["project_ground_sha256"],
            "privacy_class": task["privacy_class"],
            "risk_class": task["risk_class"],
            "expires_at_ms": now_ms + task["budgets"]["wall_time_ms"],
            "result": ready,
        },
        "preparation_sha256",
    )


def _worker_manifest(capability: Mapping[str, Any], task: Mapping[str, Any]) -> dict[str, Any]:
    runtime = capability["runtime_identity"]
    manifest = {
        "schema": worker_transport.MODEL_MANIFEST_SCHEMA,
        "manifest_id": task["task_id"] + "-fake-manifest",
        "version": "manifest-v1",
        "logical_model_id": runtime["logical_model_id"],
        "served_names": ["provider-free-fake"],
        "checkpoint_revision": "provider-free-fixture-v1",
        "weight_digest_sha256": capability["capability_sha256"],
        "context_limit_tokens": task["budgets"]["context_tokens"],
        "output_limit_tokens": task["budgets"]["output_tokens"],
        "protocols": ["worker-json-v1"],
        "capabilities": ["structured_output", "receipt", "cancellation"],
        "quantization": {"scheme": "none", "bits": 1},
        "runtime": {"name": "provider-free-fake", "version": "v1"},
        "allowed_tool_profiles": ["none"],
    }
    report = worker_transport.validate_model_manifest(manifest)
    if report.get("status") != "PASS":
        raise ValueError("model_manifest_invalid")
    return report["canonical"]


def _bound_executor_capability(
    control: Mapping[str, Any],
) -> dict[str, Any] | None:
    capability = control.get("executor_capability")
    if (
        not isinstance(capability, Mapping)
        or set(capability) != _CAPABILITY_FIELDS
        or not _seal_valid(capability, "capability_sha256")
        or capability.get("capability_sha256")
        != control.get("capability_sha256")
    ):
        return None
    return deepcopy(dict(capability))


def _worker_result_exceeds_budget(
    result: Mapping[str, Any],
    task_spec: Mapping[str, Any],
    capability: Mapping[str, Any],
) -> bool:
    """Require exact observed usage inside every bound worker dimension."""

    budgets = task_spec.get("budgets")
    usage = result.get("usage")
    timing = result.get("timing")
    candidate = result.get("candidate")
    timeout = capability.get("timeout")
    if not all(
        isinstance(value, Mapping)
        for value in (budgets, usage, timing, candidate, timeout)
    ):
        return True
    if usage.get("status") != "exact" or timing.get("status") != "exact":
        return True
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    total_tokens = usage.get("total_tokens")
    wall_time_ms = timing.get("wall_time_ms")
    limits = (
        budgets.get("context_tokens"),
        budgets.get("output_tokens"),
        capability.get("context_limit_tokens"),
        capability.get("output_limit_tokens"),
        timeout.get("wall_time_ms"),
    )
    if any(type(value) is not int or value < 0 for value in limits):
        return True
    context_budget, output_budget, context_limit, output_limit, wall_limit = limits
    if (
        type(input_tokens) is not int
        or type(output_tokens) is not int
        or type(total_tokens) is not int
        or type(wall_time_ms) is not int
        or input_tokens > min(context_budget, context_limit)
        or output_tokens > min(output_budget, output_limit)
        or total_tokens > context_budget + output_budget
        or wall_time_ms > wall_limit
    ):
        return True
    body = candidate.get("diff")
    return (
        not isinstance(body, str)
        or len(body.encode("utf-8")) > output_budget * 4
    )


def _worker_call(
    task: Mapping[str, Any],
    task_spec: Mapping[str, Any],
    preparation: Mapping[str, Any],
    *,
    profile_id: str = "direct/v1",
    call_suffix: str | None = None,
    input_sha256: str | None = None,
) -> dict[str, Any]:
    suffix = call_suffix if call_suffix is not None else "1"
    idempotency_key = preparation["preparation_sha256"] + ":dispatch"
    if call_suffix is not None:
        idempotency_key += ":" + call_suffix
    call = {
        "schema": worker_transport.WORKER_CALL_SCHEMA,
        "call_id": task["task_id"] + "-call-" + suffix,
        "assignment": {
            "assignment_id": task_spec["id"],
            "lane_id": task_spec["id"],
            "objective": task_spec["goal"],
            "input_sha256": (
                input_sha256
                if input_sha256 is not None
                else preparation["task_brief_sha256"]
            ),
            "source_pointer": "control-preparation:" + preparation["preparation_sha256"],
        },
        "lane_policy": {
            "policy_id": "control-tower-" + profile_id.removesuffix("/v1"),
            "policy_revision": POLICY_GENERATION,
            "policy_sha256": _sha256({"policy_generation": POLICY_GENERATION}),
            "registry_ref": "workflow-profile:" + profile_id,
        },
        "base_revision": {
            "repository_id": task["project_ref"]["project_id"],
            "revision": task["project_ref"]["project_ground_sha256"],
            "tree_sha256": task["project_ref"]["project_ground_sha256"],
            "source_pointer": "project-ground:" + task["project_ref"]["project_ground_sha256"],
        },
        "required_capabilities": ["structured_output", "receipt", "cancellation"],
        "authority_ref": {
            "authority_id": "provider-free-control-tower",
            "grant_id": "provider-free-no-effect",
            "scope_sha256": _sha256(
                {
                    "task_brief_sha256": preparation["task_brief_sha256"],
                    "external_effects": [],
                }
            ),
        },
        "idempotency_key": idempotency_key,
        "budgets": {
            "wall_time_ms": task["budgets"]["wall_time_ms"],
            "generation_count": 1,
            "token_count": task["budgets"]["context_tokens"] + task["budgets"]["output_tokens"],
            "tool_call_count": task_spec["budgets"]["tool_calls"],
            "child_count": 0,
            "concurrency": 1,
        },
    }
    report = worker_transport.validate_worker_call(call)
    if report.get("status") != "PASS":
        raise ValueError("worker_call_invalid")
    return report["canonical"]


def _dispatch_intent(
    *,
    task_id: str,
    run_id: str,
    preparation: Mapping[str, Any],
    task_spec: Mapping[str, Any],
    logical_plan: Mapping[str, Any],
    ready: Mapping[str, Any],
    capability: Mapping[str, Any],
    call: Mapping[str, Any],
    call_sha256: str,
    manifest: Mapping[str, Any],
    manifest_sha256: str,
    now_ms: int,
    plan_revision: int | None = None,
    independence_group: str | None = None,
) -> dict[str, Any]:
    bound_independence_group = (
        independence_group
        if independence_group is not None
        else ready["route"]["executor_groups"][0] + ":default"
    )
    return _seal(
        {
            "schema": INTENT_SCHEMA,
            "kind": "dispatch",
            "task_id": task_id,
            "run_id": run_id,
            "preparation_sha256": preparation["preparation_sha256"],
            "plan_revision": (
                logical_plan["revision"]
                if plan_revision is None
                else plan_revision
            ),
            "node_id": task_spec["id"],
            "context_sha256": _sha256(task_spec["input_refs"]),
            "executor_group": ready["route"]["executor_groups"][0],
            "runtime_identity_sha256": _sha256(
                {
                    "runtime_identity": capability["runtime_identity"],
                    "independence_group": bound_independence_group,
                }
            ),
            "authority_sha256": call["authority_ref"]["scope_sha256"],
            "reservation_sha256": _sha256(ready["reservation_requirements"]),
            "idempotency_key": call["idempotency_key"],
            "not_before_ms": now_ms,
            "expires_at_ms": preparation["expires_at_ms"],
            "payload": {
                "worker_call": call,
                "worker_call_sha256": call_sha256,
                "model_manifest": manifest,
                "model_manifest_sha256": manifest_sha256,
                "independence_group": bound_independence_group,
                "observed_executions": 0,
            },
        },
        "intent_sha256",
    )


def _verification_intent(
    *,
    dispatch_intent: Mapping[str, Any],
    control: Mapping[str, Any],
    task_spec: Mapping[str, Any],
    handoff: Mapping[str, Any],
    now_ms: int,
    completed_repairs: int = 0,
) -> dict[str, Any]:
    review_contract = _seal(
        {
            "schema": "orch-dork/control-review-contract/v1",
            "profile_id": control["profile_id"],
            "repair_limit": control.get("repair_limit", 0),
            "completed_repairs": completed_repairs,
            "acceptance_sha256": _sha256(task_spec["acceptance_checks"]),
            "scope_sha256": control["review_scope_sha256"],
            "required_human_approvals": control.get(
                "authority_requirements", []
            ),
            "independent_review_required": (
                control["profile_id"] in {"best_of_n/v1", "finite_dag/v1"}
                or control.get("task_brief", {}).get("risk_class")
                in {"high", "critical"}
            ),
            "verification_layers": list(workflow_profiles.VERIFICATION_LAYERS),
        },
        "contract_sha256",
    )
    return _seal(
        {
            "schema": INTENT_SCHEMA,
            "kind": "verification",
            "task_id": dispatch_intent["task_id"],
            "run_id": dispatch_intent["run_id"],
            "preparation_sha256": control["preparation_sha256"],
            "plan_revision": dispatch_intent["plan_revision"],
            "node_id": "reviewer",
            "context_sha256": handoff["handoff_sha256"],
            "executor_group": "deterministic-verifier",
            "runtime_identity_sha256": _sha256(
                {"runtime_id": "deterministic-verifier/v1"}
            ),
            "authority_sha256": dispatch_intent["authority_sha256"],
            "reservation_sha256": _sha256(
                {"verification": 1, "model_calls": 0, "hosted_calls": 0}
            ),
            "idempotency_key": handoff["handoff_sha256"] + ":verify",
            "not_before_ms": now_ms,
            "expires_at_ms": control["expires_at_ms"],
            "payload": {
                "task_spec": task_spec,
                "handoff_receipt": handoff,
                "artifact_refs": handoff["artifact_refs"],
                "review_contract": review_contract,
                "observed_executions": 0,
            },
        },
        "intent_sha256",
    )


def _integration_intent(
    *,
    dispatch_intent: Mapping[str, Any],
    control: Mapping[str, Any],
    task_spec: Mapping[str, Any],
    producer_handoffs: list[Mapping[str, Any]],
    now_ms: int,
) -> dict[str, Any]:
    handoffs = sorted(
        (deepcopy(dict(handoff)) for handoff in producer_handoffs),
        key=lambda handoff: handoff["task_spec_sha256"],
    )
    artifact_refs = sorted(
        {
            (ref["uri"], ref["sha256"]): ref
            for handoff in handoffs
            for ref in handoff["artifact_refs"]
        }.values(),
        key=lambda ref: (ref["uri"], ref["sha256"]),
    )
    required_producers = sorted(control["dispatch_intents"])
    context_sha256 = _sha256(
        {
            "artifact_refs": artifact_refs,
            "handoff_sha256s": [handoff["handoff_sha256"] for handoff in handoffs],
        }
    )
    ingress_bytes = _integration_ingress_bytes(artifact_refs, handoffs)
    ingress_limit_bytes = task_spec["budgets"]["context_tokens"] * 4
    return _seal(
        {
            "schema": INTENT_SCHEMA,
            "kind": "integration",
            "task_id": dispatch_intent["task_id"],
            "run_id": dispatch_intent["run_id"],
            "preparation_sha256": control["preparation_sha256"],
            "plan_revision": dispatch_intent["plan_revision"],
            "node_id": task_spec["id"],
            "context_sha256": context_sha256,
            "executor_group": "deterministic-join",
            "runtime_identity_sha256": _sha256(
                {"runtime_id": "deterministic-join/v1"}
            ),
            "authority_sha256": dispatch_intent["authority_sha256"],
            "reservation_sha256": _sha256(
                {"integration": 1, "model_calls": 0, "hosted_calls": 0}
            ),
            "idempotency_key": context_sha256 + ":join",
            "not_before_ms": now_ms,
            "expires_at_ms": control["expires_at_ms"],
            "payload": {
                "task_spec": task_spec,
                "topology_closure_sha256": control["topology_closure"][
                    "closure_sha256"
                ],
                "input_artifact_refs": artifact_refs,
                "producer_handoff_receipts": handoffs,
                "required_producer_ids": required_producers,
                "ingress_bytes": ingress_bytes,
                "ingress_limit_bytes": ingress_limit_bytes,
                "observed_executions": 0,
            },
        },
        "intent_sha256",
    )


def _comparison_intent(
    *,
    dispatch_intent: Mapping[str, Any],
    control: Mapping[str, Any],
    task_spec: Mapping[str, Any],
    candidate_handoffs: list[Mapping[str, Any]],
    now_ms: int,
) -> dict[str, Any]:
    artifacts = []
    for handoff in candidate_handoffs:
        if len(handoff.get("artifact_refs", [])) != 1:
            raise ValueError("comparison_candidate_artifact_invalid")
        artifacts.append(deepcopy(dict(handoff["artifact_refs"][0])))
    artifacts.sort(key=lambda ref: (ref["sha256"], ref["uri"]))
    blinded = [
        {"label": "option-" + str(index).zfill(3), "artifact_ref": ref}
        for index, ref in enumerate(artifacts, start=1)
    ]
    submission = control["workflow_submission"]
    return _seal(
        {
            "schema": INTENT_SCHEMA,
            "kind": "comparison",
            "task_id": dispatch_intent["task_id"],
            "run_id": dispatch_intent["run_id"],
            "preparation_sha256": control["preparation_sha256"],
            "plan_revision": control["plan_revision"],
            "node_id": task_spec["id"],
            "context_sha256": _sha256(
                {
                    "blinded_candidates": blinded,
                    "direct_baseline": submission["direct_baseline"],
                }
            ),
            "executor_group": "blinded-comparator",
            "runtime_identity_sha256": _sha256(
                {
                    "runtime_id": "blinded-comparator/v1",
                    "independence_group": submission[
                        "comparator_independence_group"
                    ],
                }
            ),
            "authority_sha256": dispatch_intent["authority_sha256"],
            "reservation_sha256": _sha256(
                {
                    "integration_slots": 1,
                    "model_calls": 0,
                    "hosted_calls": 0,
                }
            ),
            "idempotency_key": control["preparation_sha256"]
            + ":comparison",
            "not_before_ms": now_ms,
            "expires_at_ms": control["expires_at_ms"],
            "payload": {
                "task_spec": task_spec,
                "blinded_candidates": blinded,
                "comparator_independence_group": submission[
                    "comparator_independence_group"
                ],
                "selection_mode": submission["selection_mode"],
                "allowed_outcomes": [
                    "winner",
                    "synthesis",
                    "tie",
                    "escalate",
                ],
                "direct_baseline": submission["direct_baseline"],
                "observed_executions": 0,
            },
        },
        "intent_sha256",
    )


def _integration_ingress_bytes(
    artifact_refs: list[Mapping[str, Any]],
    producer_handoffs: list[Mapping[str, Any]],
) -> int:
    artifact_bytes = sum(ref["size_bytes"] for ref in artifact_refs)
    envelope_bytes = len(
        _canonical(
            {
                "artifact_refs": artifact_refs,
                "producer_handoff_receipts": producer_handoffs,
            }
        )
    )
    return artifact_bytes + envelope_bytes


def _cleanup_intent(
    *,
    control: Mapping[str, Any],
    run_id: str,
    context_sha256: str,
    requested_at_ms: int,
    prior_seq: int,
) -> dict[str, Any]:
    return _seal(
        {
            "schema": INTENT_SCHEMA,
            "kind": "cleanup",
            "task_id": control["task_id"],
            "run_id": run_id,
            "preparation_sha256": control["preparation_sha256"],
            "plan_revision": control["plan_revision"],
            "node_id": "owned-cleanup",
            "context_sha256": context_sha256,
            "executor_group": "owned-adapter-cleanup",
            "runtime_identity_sha256": _sha256({"runtime_id": "owned-cleanup/v1"}),
            "authority_sha256": control["cleanup_authority_sha256"],
            "reservation_sha256": _sha256({"cleanup": 1, "replacements": 0}),
            "idempotency_key": run_id + ":cleanup:" + str(prior_seq),
            "not_before_ms": requested_at_ms,
            "expires_at_ms": requested_at_ms + control["cleanup_grace_ms"],
            "payload": {"owned_process_group": run_id, "observed_executions": 0},
        },
        "intent_sha256",
    )


def _task_from_ready(preparation: Mapping[str, Any]) -> dict[str, Any]:
    ready = preparation["result"]
    if isinstance(ready.get("task_brief"), Mapping):
        return deepcopy(dict(ready["task_brief"]))
    task_spec = ready["task_spec"]
    logical_plan = ready["logical_plan"]
    task_id = logical_plan["planner"]["root_thread_id"]
    deliverable = task_spec["deliverable"]
    return {
        "task_id": task_id,
        "project_ref": ready["project_ref"],
        "budgets": ready["budgets"],
        "deliverables": [
            {
                "id": logical_plan["workers"][0]["deliverables"][0].split("/", 1)[-1],
                "description": deliverable["description"],
                "media_type": deliverable["media_type"],
            }
        ],
    }


def _preparation_ready(
    value: Any, now_ms: int, *, root_model: str
) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    preparation = value if isinstance(value, Mapping) else {}
    if not isinstance(value, Mapping) or set(value) != _PREPARATION_FIELDS:
        _issue(issues, "advance:preparation_contract_invalid")
    if not _seal_valid(preparation, "preparation_sha256"):
        _issue(issues, "advance:preparation_seal_invalid")
    if preparation.get("schema") != PREPARATION_SCHEMA:
        _issue(issues, "advance:preparation_schema_invalid")
    if preparation.get("preparation_status") != "READY_TO_FREEZE":
        _issue(issues, "advance:preparation_not_ready")
    if preparation.get("policy_generation") != POLICY_GENERATION:
        _issue(issues, "advance:policy_generation_drift")
    expires = preparation.get("expires_at_ms")
    if type(expires) is not int or expires < now_ms:
        _issue(issues, "advance:preparation_expired")
    ready = preparation.get("result") if isinstance(preparation.get("result"), Mapping) else {}
    if not isinstance(ready, Mapping) or set(ready) != _READY_FIELDS:
        _issue(issues, "advance:ready_contract_invalid")
    elif ready["routing_policy"] != _plan_routing_policy(ready.get("logical_plan")):
        _issue(issues, "advance:routing_policy_mismatch")
    route = ready.get("route")
    profile = ready.get("profile")
    compilation = ready.get("compilation")
    capability = ready.get("executor_capability")
    if not isinstance(route, Mapping) or set(route) != _ROUTE_RECORD_FIELDS:
        _issue(issues, "advance:route_contract_invalid")
    if not isinstance(profile, Mapping) or set(profile) != _PROFILE_RECORD_FIELDS:
        _issue(issues, "advance:profile_contract_invalid")
    if not isinstance(compilation, Mapping) or set(compilation) != _COMPILATION_FIELDS:
        _issue(issues, "advance:compilation_contract_invalid")
    if not isinstance(capability, Mapping) or set(capability) != _CAPABILITY_FIELDS:
        _issue(issues, "advance:capability_contract_invalid")
    runtime_identity = capability.get("runtime_identity") if isinstance(capability, Mapping) else None
    if not isinstance(runtime_identity, Mapping) or set(runtime_identity) != _RUNTIME_IDENTITY_FIELDS:
        _issue(issues, "advance:runtime_identity_contract_invalid")
    reservations = ready.get("reservation_requirements")
    if not isinstance(reservations, Mapping) or set(reservations) != _RESERVATION_FIELDS:
        _issue(issues, "advance:reservation_contract_invalid")
    if not isinstance(ready.get("authority_requirements"), list):
        _issue(issues, "advance:authority_requirements_invalid")
    if not isinstance(ready.get("project_ref"), Mapping) or set(ready["project_ref"]) != _PROJECT_FIELDS:
        _issue(issues, "advance:project_ref_contract_invalid")
    if not isinstance(ready.get("budgets"), Mapping) or set(ready["budgets"]) != _BUDGET_FIELDS:
        _issue(issues, "advance:budget_contract_invalid")
    for record, field, code in (
        (route, "route_sha256", "advance:route_seal_invalid"),
        (profile, "profile_sha256", "advance:profile_seal_invalid"),
        (compilation, "compilation_sha256", "advance:compilation_seal_invalid"),
        (capability, "capability_sha256", "advance:capability_seal_invalid"),
    ):
        if not _seal_valid(record, field):
            _issue(issues, code)
    if contracts.validate_task_spec(ready.get("task_spec")).get("status") != "PASS":
        _issue(issues, "advance:task_spec_invalid")
    task_specs = ready.get("task_specs")
    node_budget = (
        ready.get("budgets", {}).get("nodes")
        if isinstance(ready.get("budgets"), Mapping)
        else None
    )
    if (
        not isinstance(task_specs, list)
        or not task_specs
        or type(node_budget) is not int
        or len(task_specs) > node_budget
    ):
        _issue(issues, "advance:task_specs_invalid")
    else:
        task_spec_ids = []
        for task_spec in task_specs:
            task_report = contracts.validate_task_spec(task_spec)
            if task_report.get("status") != "PASS":
                _issue(issues, "advance:task_specs_invalid")
            elif isinstance(task_spec, Mapping):
                task_spec_ids.append(task_spec.get("id"))
        if len(task_spec_ids) != len(set(task_spec_ids)):
            _issue(issues, "advance:task_specs_duplicate")
        if ready.get("task_spec") not in task_specs:
            _issue(issues, "advance:primary_task_spec_unbound")
    if governor.validate_logical_plan(ready.get("logical_plan")).get("status") != "PASS":
        _issue(issues, "advance:logical_plan_invalid")
    closure = ready.get("topology_closure")
    if not isinstance(closure, Mapping) or not _seal_valid(closure, "closure_sha256"):
        _issue(issues, "advance:topology_closure_invalid")
    if isinstance(compilation, Mapping):
        if compilation.get("route_sha256") != (route or {}).get("route_sha256"):
            _issue(issues, "advance:compilation_route_mismatch")
        if compilation.get("profile_sha256") != (profile or {}).get("profile_sha256"):
            _issue(issues, "advance:compilation_profile_mismatch")
        if compilation.get("logical_plan_sha256") != _sha256(ready.get("logical_plan")):
            _issue(issues, "advance:compilation_plan_mismatch")
        if compilation.get("topology_closure") != (
            closure.get("closure_sha256") if isinstance(closure, Mapping) else None
        ):
            _issue(issues, "advance:compilation_topology_mismatch")

    task, task_issues = _validate_task_brief(ready.get("task_brief"))
    if task_issues:
        _issue(issues, "advance:bound_task_brief_invalid")
    else:
        task_digest = _sha256(task)
        if preparation.get("task_brief_sha256") != task_digest:
            _issue(issues, "advance:task_brief_binding_mismatch")
        requested_profile = task["routing_hints"]["requested_profile"]
        planning_submission = ready.get("planning_submission")
        workflow_submission = ready.get("workflow_submission")
        submission_valid = True
        workflow_profiles_with_parameters = {
            "parallel_join/v1",
            "execute_verify_repair/v1",
            "best_of_n/v1",
        }
        if (
            requested_profile == "finite_dag/v1"
            and isinstance(route, Mapping)
            and route.get("profile_id") == "finite_dag/v1"
        ):
            if (
                not isinstance(planning_submission, Mapping)
                or not isinstance(workflow_submission, Mapping)
                or workflow_submission.get("planning_submission")
                != planning_submission
            ):
                _issue(issues, "advance:preparation_identity_drift")
                submission_valid = False
            else:
                _, submission_issues = _validate_planning_submission(
                    planning_submission,
                    task=task,
                    task_digest=task_digest,
                    now_ms=now_ms,
                    root_model=root_model,
                    allow_general=True,
                )
                if submission_issues:
                    _issue(issues, "advance:planning_submission_invalid")
                    submission_valid = False
        elif requested_profile in workflow_profiles_with_parameters:
            if planning_submission is not None or not isinstance(
                workflow_submission, Mapping
            ):
                _issue(issues, "advance:preparation_identity_drift")
                submission_valid = False
        else:
            if workflow_submission is not None:
                _issue(issues, "advance:preparation_identity_drift")
                submission_valid = False
            if requested_profile == "direct/v1" and planning_submission is not None:
                _issue(issues, "advance:preparation_identity_drift")
                submission_valid = False
            elif requested_profile == "finite_dag/v1" and planning_submission is None:
                _issue(issues, "advance:preparation_identity_drift")
                submission_valid = False
            elif planning_submission is not None:
                _, submission_issues = _validate_planning_submission(
                    planning_submission,
                    task=task,
                    task_digest=task_digest,
                    now_ms=now_ms,
                    root_model=root_model,
                )
                if submission_issues:
                    _issue(issues, "advance:planning_submission_invalid")
                    submission_valid = False

        if type(expires) is int and submission_valid:
            issued_at_ms = expires - task["budgets"]["wall_time_ms"]
            if issued_at_ms < 0:
                _issue(issues, "advance:preparation_expired")
            else:
                if requested_profile == "parallel_join/v1":
                    expected = _parallel_preparation(
                        task,
                        task_digest,
                        issued_at_ms,
                        workflow_submission,
                        root_model=root_model,
                    )
                elif requested_profile == "execute_verify_repair/v1":
                    expected = _execute_repair_preparation(
                        task,
                        task_digest,
                        issued_at_ms,
                        workflow_submission,
                        root_model=root_model,
                    )
                elif requested_profile == "best_of_n/v1":
                    expected = _best_of_n_preparation(
                        task,
                        task_digest,
                        issued_at_ms,
                        workflow_submission,
                        root_model=root_model,
                    )
                elif (
                    requested_profile == "finite_dag/v1"
                    and isinstance(route, Mapping)
                    and route.get("profile_id") == "finite_dag/v1"
                ):
                    expected = _finite_dag_preparation(
                        task,
                        task_digest,
                        issued_at_ms,
                        workflow_submission,
                        root_model=root_model,
                    )
                else:
                    expected = _direct_preparation(
                        task,
                        task_digest,
                        issued_at_ms,
                        root_model=root_model,
                        planning_submission=(
                            planning_submission
                            if isinstance(planning_submission, Mapping)
                            else None
                        ),
                    )
                if expected != preparation:
                    _issue(issues, "advance:preparation_identity_drift")
    return dict(preparation), sorted(set(issues))


def _cursor(run_id: str, events: list[Mapping[str, Any]], state: Mapping[str, Any]) -> dict[str, Any]:
    last = events[-1]
    return {
        "run_id": run_id,
        "seq": last["seq"],
        "event_hash": last["event_hash"],
        "stream_sha256": state["stream_sha256"],
    }


def _genesis_cursor(run_id: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "seq": 0,
        "event_hash": run_store.GENESIS_PREV_HASH,
        "stream_sha256": run_store.GENESIS_PREV_HASH,
    }


def _stored_plan_core(plan: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(plan)
    value.pop("plan_sha256", None)
    return run_engine.plan_core(value)


def _prestart_refusal(
    payload: Mapping[str, Any], reason_codes: list[str]
) -> dict[str, Any]:
    accepted_input_sha256 = _sha256(payload)
    run_id = "ct-refused-" + accepted_input_sha256[:24]
    cursor = _genesis_cursor(run_id)
    return _seal(
        {
            "schema": DECISION_SCHEMA,
            "decision_status": "REFUSED",
            "prior_cursor": cursor,
            "accepted_input_sha256": accepted_input_sha256,
            "resulting_cursor": cursor,
            "state_sha256": None,
            "reason_codes": sorted(set(reason_codes)),
            "intents": [],
            "budget_settlement": {"reserved": False},
            "authority_settlement": {"consumed": False},
        },
        "decision_sha256",
    )


InMemoryArtifactLedger = artifact_ledger.InMemoryArtifactLedger
FilesystemArtifactLedger = artifact_ledger.FilesystemArtifactLedger


class ControlTower:
    """Deep public seam; adapters are injected at construction time."""

    def __init__(
        self,
        *,
        store: Any = None,
        artifacts: Any = None,
        scheduler_capacity: Mapping[str, Any] | None = None,
        clock_ms: Callable[[], int] | None = None,
        frontier_store: Any = None,
        frontier_run_resolver: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        cleanup_observer_trust_store: Any = None,
        cleanup_observer_replay_guard: Any = None,
        cleanup_observer_evaluation_time: Any = None,
        root_model: str | None = None,
    ) -> None:
        # The root every plan this tower prepares names as its planner.  A
        # caller that observed the live route injects the observed root; a
        # provider-free caller plans under the registry's default
        # orchestrator.  Either way the root must be admitted, a registered
        # orchestrator or a model with an onboarded profile, never a literal
        # and never an environment value (Issue 185, ADR 0012).
        resolved_root = (
            root_model if root_model is not None else model_profiles.default_root_model()
        )
        if not model_profiles.root_admitted(resolved_root):
            raise ValueError("control_tower_root_model_not_onboarded")
        self.root_model = resolved_root
        self.store = store if store is not None else run_store.InMemoryRunStore()
        if getattr(self.store, "durable", False) and not getattr(
            artifacts, "durable", False
        ):
            raise ValueError("durable_run_store_requires_durable_artifacts")
        self.engine = run_engine.RunEngine(self.store)
        self.artifacts = artifacts if artifacts is not None else InMemoryArtifactLedger()
        self.scheduler_capacity = (
            control_scheduler.validate_capacity(scheduler_capacity)
            if scheduler_capacity is not None
            else None
        )
        self._scheduler_lock = threading.Lock()
        self._lane_lock = threading.Lock()
        self._lane_ledger_cache: dict[str, Any] | None = None
        self.clock_ms = clock_ms if clock_ms is not None else (lambda: 0)
        self._frontier_store = frontier_store
        self._frontier_run_resolver = frontier_run_resolver
        self._frontier_controller = None
        self._cleanup_observer_trust_store = cleanup_observer_trust_store
        self._cleanup_observer_replay_guard = cleanup_observer_replay_guard
        self._cleanup_observer_evaluation_time = (
            cleanup_observer_evaluation_time
            if cleanup_observer_evaluation_time is not None
            else lambda: datetime.now(timezone.utc)
        )

    def _mission_authority(self, repository):
        """Load ``orch_dork_mission_authority`` and bind one authority handle.

        The three public wrappers share this private accessor so the
        sibling module name and the ``MissionAuthority(self, repository)``
        construction have a single definition. Each wrapper owns one
        terminal method on the same handle and the original command
        shapes are preserved.
        """
        module = _load_sibling("orch_dork_mission_authority")
        return module.MissionAuthority(self, repository)

    def initialize_mission_authority(self, repository):
        """Explicitly create typed history for a host-resolved common directory."""
        return self._mission_authority(repository).initialize()

    def read_mission_authority(self, repository):
        """Read existing typed history without creating canonical state."""
        return self._mission_authority(repository).read()

    def transition_mission(self, repository, transition):
        """Accept a closed mission fact through the canonical run store."""
        return self._mission_authority(repository).transition(transition)

    def _cleanup_observer_now(self) -> str | None:
        value = self._cleanup_observer_evaluation_time
        if callable(value):
            value = value()
        return lane_capacity._evaluation_time_text(value)

    def _observer_authority_configured(self) -> bool:
        """Whether a signed lane-release receipt can be verified at all.

        The receipt verifier takes the trust store and replay guard injected
        at construction and otherwise falls back to the two observer
        authority environment variables.  When neither source names them,
        every release receipt in the ledger fails verification and the
        ledger reads as corrupt (``lane_ledger_authority_invalid``).  Naming
        the missing dependency first keeps that failure honest.  The rule is
        the verifier's own (``observer_receipt.host_authority_configured``),
        read from the same process environment the verifier will read.
        """

        return observer_receipt.host_authority_configured(
            trust_store=self._cleanup_observer_trust_store,
            replay_guard=self._cleanup_observer_replay_guard,
        )

    @staticmethod
    def _delta_carries_release_receipts(authority_delta: Any) -> bool:
        receipts = (
            authority_delta.get("release_receipts")
            if isinstance(authority_delta, Mapping)
            else None
        )
        return isinstance(receipts, list) and bool(receipts)

    def _frontier(self):
        if self._frontier_controller is None:
            module = _load_sibling("orch_dork_frontier_campaign")
            self._frontier_controller = module.FrontierCampaignController(
                store=self._frontier_store,
                clock_ms=self.clock_ms,
                run_resolver=(
                    self._frontier_run_resolver
                    if self._frontier_run_resolver is not None
                    else self._resolve_frontier_run
                ),
            )
        return self._frontier_controller

    def _resolve_frontier_run(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Resolve one exact campaign observation from canonical RunEngine state."""

        expected_fields = {
            "campaign_id",
            "fixture_sha256",
            "role",
            "profile_id",
            "task_brief_sha256",
            "qwen_identity_sha256",
            "tool_policy_sha256",
            "run_ref",
        }
        if not isinstance(request, Mapping) or set(request) != expected_fields:
            return {"status": "FAIL", "issues": ["run:request_invalid"]}
        run_ref = request.get("run_ref")
        if (
            not isinstance(run_ref, Mapping)
            or set(run_ref) != {"schema", "run_id", "stream_sha256"}
            or run_ref.get("schema") != "orch-dork/frontier-run-ref/v2"
            or not isinstance(run_ref.get("run_id"), str)
            or not isinstance(run_ref.get("stream_sha256"), str)
        ):
            return {"status": "FAIL", "issues": ["run:ref_invalid"]}
        try:
            events = list(self.engine.events(run_ref["run_id"], 0))
            plan = json.loads(events[0]["payload"])["plan"]
            state = self.engine.reduce(plan, events)
            origin = plan["origin"]
            if isinstance(origin.get("frontier_binding"), Mapping):
                binding = dict(origin["frontier_binding"])
            else:
                raise KeyError("frontier binding absent")
        except (
            IndexError,
            KeyError,
            TypeError,
            ValueError,
            run_engine.NotFoundError,
            run_engine.RunKernelError,
        ):
            return {"status": "FAIL", "issues": ["run:unresolvable"]}
        expected = {field: request[field] for field in expected_fields - {"run_ref"}}
        if (
            binding != expected
            or not state.get("terminal")
            or state.get("terminal_kind") != "completed"
            or state.get("stream_sha256") != run_ref["stream_sha256"]
        ):
            return {"status": "FAIL", "issues": ["run:binding_invalid"]}
        return {
            "status": "PASS",
            "issues": [],
            "run_id": run_ref["run_id"],
            "stream_sha256": state["stream_sha256"],
            "event_count": len(events),
        }

    def prepare(self, payload: Any) -> tuple[dict[str, Any] | None, list[str]]:
        if not isinstance(payload, Mapping) or set(payload) not in (
            {"task_brief"},
            {"task_brief", "planning_submission"},
            {"task_brief", "workflow_submission"},
        ):
            return None, ["prepare:payload_invalid"]
        task, issues = _validate_task_brief(payload.get("task_brief"))
        if issues:
            return None, issues

        task_digest = _sha256(task)
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["prepare:clock_invalid"]

        requested_profile = task["routing_hints"]["requested_profile"]
        executor_group = task["routing_hints"]["executor_group"]
        try:
            workflow_profiles.profile(requested_profile)
        except workflow_profiles.WorkflowProfileError:
            return _refused_preparation(
                task,
                task_digest,
                now_ms,
                ["prepare:profile_unregistered"],
            ), []
        workflow_submission = payload.get("workflow_submission")
        if workflow_submission is not None:
            if (
                task["privacy_class"] != "local_only"
                or task["requested_external_effects"]
                or (
                    task["required_human_approvals"]
                    and requested_profile == "parallel_join/v1"
                )
                or requested_profile
                not in {
                    "parallel_join/v1",
                    "execute_verify_repair/v1",
                    "best_of_n/v1",
                    "finite_dag/v1",
                }
                or executor_group != "fake-local"
            ):
                return _refused_preparation(
                    task,
                    task_digest,
                    now_ms,
                    ["prepare:workflow_submission_inapplicable"],
                ), []
            if requested_profile == "parallel_join/v1":
                return _parallel_preparation(
                    task, task_digest, now_ms, workflow_submission,
                    root_model=self.root_model,
                ), []
            if requested_profile == "execute_verify_repair/v1":
                return _execute_repair_preparation(
                    task, task_digest, now_ms, workflow_submission,
                    root_model=self.root_model,
                ), []
            if requested_profile == "best_of_n/v1":
                return _best_of_n_preparation(
                    task, task_digest, now_ms, workflow_submission,
                    root_model=self.root_model,
                ), []
            return _finite_dag_preparation(
                task, task_digest, now_ms, workflow_submission,
                root_model=self.root_model,
            ), []
        if requested_profile in {
            "parallel_join/v1",
            "execute_verify_repair/v1",
            "best_of_n/v1",
        }:
            return _refused_preparation(
                task,
                task_digest,
                now_ms,
                ["prepare:workflow_submission_required"],
            ), []
        planning_applicable = (
            task["privacy_class"] == "local_only"
            and not task["requested_external_effects"]
            and requested_profile == "finite_dag/v1"
            and executor_group == "fake-local"
        )
        submission = payload.get("planning_submission")
        if submission is not None:
            if not planning_applicable:
                return _refused_preparation(
                    task,
                    task_digest,
                    now_ms,
                    ["prepare:planning_submission_inapplicable"],
                ), []
            accepted_submission, submission_issues = _validate_planning_submission(
                submission,
                task=task,
                task_digest=task_digest,
                now_ms=now_ms,
                root_model=self.root_model,
            )
            if submission_issues:
                return _refused_preparation(
                    task, task_digest, now_ms, submission_issues
                ), []
            return _direct_preparation(
                task,
                task_digest,
                now_ms,
                root_model=self.root_model,
                planning_submission=accepted_submission,
            ), []

        if planning_applicable:
            requirement = _planning_requirement(task, task_digest, now_ms)
            planning = _seal(
                {
                    "schema": PREPARATION_SCHEMA,
                    "preparation_status": "PLANNING_REQUIRED",
                    "task_brief_sha256": task_digest,
                    "policy_generation": POLICY_GENERATION,
                    "project_ground_sha256": task["project_ref"]["project_ground_sha256"],
                    "privacy_class": task["privacy_class"],
                    "risk_class": task["risk_class"],
                    "expires_at_ms": now_ms + task["budgets"]["wall_time_ms"],
                    "result": {"planning_requirement": requirement},
                },
                "preparation_sha256",
            )
            return planning, []
        if (
            task["privacy_class"] != "local_only"
            or task["requested_external_effects"]
            or task["required_human_approvals"]
            or requested_profile != "direct/v1"
            or executor_group != "fake-local"
        ):
            return _refused_preparation(
                task,
                task_digest,
                now_ms,
                ["prepare:direct_profile_inapplicable"],
            ), []

        return _direct_preparation(
            task, task_digest, now_ms, root_model=self.root_model
        ), []

    def advance(self, payload: Any) -> tuple[dict[str, Any] | None, list[str]]:
        if isinstance(payload, Mapping) and payload.get("kind") == "enqueue":
            return self._enqueue(payload)
        if isinstance(payload, Mapping) and payload.get("kind") == "schedule":
            return self._schedule(payload)
        if isinstance(payload, Mapping) and payload.get("kind") == "observe":
            return self._observe(payload)
        if isinstance(payload, Mapping) and payload.get("kind") == "cancel":
            return self._cancel(payload)
        value = _exact(payload, _START_FIELDS, "advance", [])
        if not isinstance(payload, Mapping) or set(payload) != _START_FIELDS:
            return None, ["advance:payload_invalid"]
        if value.get("schema") != ADVANCE_SCHEMA or value.get("kind") != "start":
            return None, ["advance:start_invalid"]
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        preparation, issues = _preparation_ready(
            value.get("preparation"), now_ms, root_model=self.root_model
        )
        if issues:
            return _prestart_refusal(value, issues), []

        ready = preparation["result"]
        if ready["route"]["profile_id"] in {
            "parallel_join/v1",
            "best_of_n/v1",
            "finite_dag/v1",
        }:
            return self._start_parallel(value, preparation, now_ms)
        return self._start_direct(value, preparation, now_ms, queued=False)

    @staticmethod
    def _lane_ledger_run_id() -> str:
        return _LANE_LEDGER_RUN_ID

    def _lane_ledger_plan(self) -> dict[str, Any]:
        return run_engine.make_plan(
            run_id=self._lane_ledger_run_id(),
            name="Control Tower global lane reservation ledger",
            expected_roles=("ledger",),
            deliverable=False,
            actors=(
                run_engine.actor(
                    kind="observer",
                    model="deterministic-lane-ledger/v1",
                    actor_key="ledger",
                    intent="reserve:global-control-tower-lanes/v1",
                ),
            ),
            origin={
                "control_tower": {
                    "schema": LANE_LEDGER_SCHEMA,
                    "capacity": lane_capacity.MAX_CONCURRENT_LANES,
                    "provider_free": True,
                    "policy_generation": POLICY_GENERATION,
                }
            },
        )

    def _ensure_lane_ledger_run(self) -> tuple[bool, list[str]]:
        run_id = self._lane_ledger_run_id()
        expected = run_engine.plan_core(self._lane_ledger_plan())
        if not self.store.exists(run_id):
            try:
                self.engine.start(expected)
            except (run_engine.MalformedInputError, run_engine.ProtocolError):
                if not self.store.exists(run_id):
                    return False, ["advance:lane_ledger_initialization_conflict"]
        try:
            events = list(self.engine.events(run_id, 0))
            observed = _stored_plan_core(
                json.loads(events[0]["payload"])["plan"]
            )
        except (
            IndexError,
            KeyError,
            TypeError,
            ValueError,
            run_engine.NotFoundError,
            run_engine.RunKernelError,
        ):
            return False, ["advance:lane_ledger_invalid"]
        if observed != expected:
            return False, ["advance:lane_ledger_drift"]
        return True, []

    def _lane_ledger_state(
        self,
    ) -> tuple[
        list[dict[str, Any]],
        dict[tuple[str, str], dict[str, Any]],
        dict[str, Any],
    ]:
        events = list(self.engine.events(self._lane_ledger_run_id(), 0))
        cache = self._lane_ledger_cache
        cache_is_prefix = (
            isinstance(cache, Mapping)
            and type(cache.get("event_count")) is int
            and 0 < cache["event_count"] <= len(events)
            and events[cache["event_count"] - 1]["event_hash"]
            == cache.get("last_event_hash")
        )
        if cache_is_prefix:
            deltas = deepcopy(cache["deltas"])
            authority_state = deepcopy(cache["authority_state"])
            unverified_events = events[cache["event_count"] :]
        else:
            deltas = []
            authority_state = lane_capacity.empty_authority_state(
                "control-tower-shared-capacity/v1"
            )
            unverified_events = events
        verified_release_receipts = (
            [list(rows) for rows in cache["release_receipts"]]
            if cache_is_prefix
            else []
        )
        for event in unverified_events:
            if event["kind"] != run_engine.KIND_APPLIED:
                continue
            facts = json.loads(event["payload"])
            if not isinstance(facts, Mapping) or facts.get("roles") != ["ledger"]:
                raise ValueError("lane_ledger_roles_invalid")
            deliverables = facts.get("deliverables", {})
            evidence = facts.get("evidence", {})
            if not isinstance(deliverables, Mapping):
                raise ValueError("lane_ledger_delta_missing")
            if not isinstance(evidence, Mapping):
                raise ValueError("lane_ledger_authority_evidence_invalid")
            raw = deliverables.get("lane_delta")
            raw_authority = deliverables.get("authority_delta")
            if not isinstance(raw, str):
                raise ValueError("lane_ledger_delta_missing")
            if not isinstance(raw_authority, str):
                raise ValueError("lane_ledger_authority_missing")
            delta = json.loads(raw)
            authority_delta = json.loads(raw_authority)
            if not isinstance(delta, Mapping):
                raise ValueError("lane_ledger_delta_invalid")
            released, reserved = delta.get('released'), delta.get('reserved')
            if not isinstance(released, list) or not isinstance(reserved, list):
                raise ValueError('lane_ledger_records_invalid')
            if not all(lane_capacity.validate_control_reservation(row)
                       for row in released + reserved):
                raise ValueError('lane_ledger_reservation_invalid')
            if delta.get("released") != sorted(
                delta.get("released", []), key=_lane_key
            ) or delta.get("reserved") != sorted(
                delta.get("reserved", []), key=_lane_key
            ):
                raise ValueError("lane_ledger_order_invalid")
            deltas.append(dict(delta))
            if self._delta_carries_release_receipts(
                authority_delta
            ) and not self._observer_authority_configured():
                raise ValueError("lane_ledger_observer_authority_unconfigured")
            applied_authority = lane_capacity.apply_authority_delta(
                authority_state,
                authority_delta,
                observer_trust_store=self._cleanup_observer_trust_store,
                observer_replay_guard=self._cleanup_observer_replay_guard,
            )
            if applied_authority.get("status") != "APPLIED":
                raise ValueError("lane_ledger_authority_invalid")
            if evidence.get("lane_ledger") != authority_delta.get(
                "delta_sha256"
            ):
                raise ValueError("lane_ledger_authority_evidence_invalid")
            # Persist the release_receipts row only after the
            # ``apply_authority_delta`` typed validator accepts the
            # delta. ``apply_authority_delta`` already performs the
            # ``isinstance(delta, Mapping)`` shape check that prevents
            # a non-object authority_delta from reaching the indexed
            # ``authority_delta.get("release_receipts", ...)`` access
            # below, so the cache is the projection of authoritative
            # rows rather than a hand-authored copy of the raw event
            # payload.
            verified_release_receipts.append(
                [
                    dict(receipt)
                    for receipt in authority_delta.get("release_receipts", [])
                ]
            )
            successor = applied_authority["state"]
            transition = applied_authority["transition"]
            successor_validation = lane_capacity.validate_authority_state(
                successor
            )
            successor_bindings = successor_validation["ledger"]["bindings"]
            reserved_control_ids = {
                _lane_identity(*_lane_key(record))
                for record in delta["reserved"]
            }
            released_control_ids = {
                _lane_identity(*_lane_key(record))
                for record in delta["released"]
            }
            new_control_ids = {
                entry["lane_id"]
                for entry in transition["new_identity_entries"]
                if entry["route"] == lane_capacity.CONTROL_TOWER_ROUTE
            }
            added_control_ids = {
                lane_id
                for lane_id in transition["added_active_lane_ids"]
                if successor_bindings[lane_id]["route"]
                == lane_capacity.CONTROL_TOWER_ROUTE
            }
            removed_control_ids = {
                lane_id
                for lane_id in transition["removed_active_lane_ids"]
                if successor_bindings[lane_id]["route"]
                == lane_capacity.CONTROL_TOWER_ROUTE
            }
            if (
                new_control_ids != reserved_control_ids
                or added_control_ids != reserved_control_ids
                or removed_control_ids != released_control_ids
            ):
                raise ValueError("lane_ledger_authority_delta_mismatch")
            authority_state = dict(successor)
        reduced = lane_capacity.reduce_control_deltas(deltas)
        if reduced.get("status") != "RESOLVED":
            raise ValueError("lane_ledger_shared_contract_invalid")
        authority = lane_capacity.validate_authority_state(authority_state)
        control_active = {
            _lane_identity(run_id, node_id)
            for run_id, node_id in reduced["active"]
        }
        authority_control_active = {
            lane_id
            for lane_id in authority["active_lane_ids"]
            if authority["ledger"]["bindings"][lane_id]["route"]
            == lane_capacity.CONTROL_TOWER_ROUTE
        }
        if control_active != authority_control_active:
            raise ValueError("lane_ledger_authority_drift")
        self._lane_ledger_cache = {
            "event_count": len(events),
            "last_event_hash": events[-1]["event_hash"],
            "deltas": deepcopy(deltas),
            "authority_state": deepcopy(authority_state),
            "release_receipts": [
                list(rows) for rows in verified_release_receipts
            ],
        }
        return events, reduced["active"], authority_state

    def read_shared_capacity_authority(self) -> dict[str, Any]:
        """Read the one persisted authority state used by every lane route."""
        ready, issues = self._ensure_lane_ledger_run()
        if not ready:
            return {
                "schema": lane_capacity.AUTHORITY_READ_SCHEMA,
                "status": "UNKNOWN",
                "store_id": self._lane_ledger_run_id(),
                "continuity_verified": False,
                "state": None,
                "state_sha256": None,
                "reason_codes": issues,
            }
        try:
            _events, _active, authority_state = self._lane_ledger_state()
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError) as error:
            reason_codes = ["lane_ledger:authority_read_failed"]
            if type(error) is ValueError and _LEDGER_REFUSAL.fullmatch(
                str(error)
            ):
                # The ledger's own named refusal travels with the generic
                # read failure so a reader can tell a missing observer
                # authority from a corrupt ledger; the ledger's
                # ``lane_ledger_<reason>`` becomes ``lane_ledger:<reason>``
                # in the read report's own namespace.
                reason_codes.append(
                    "lane_ledger:" + str(error)[len("lane_ledger_"):]
                )
            return {
                "schema": lane_capacity.AUTHORITY_READ_SCHEMA,
                "status": "UNKNOWN",
                "store_id": self._lane_ledger_run_id(),
                "continuity_verified": False,
                "state": None,
                "state_sha256": None,
                "reason_codes": reason_codes,
            }
        return lane_capacity.authority_read_report(
            authority_state,
            store_id=self._lane_ledger_run_id(),
        )

    def commit_shared_capacity_authority(
        self,
        successor: Any,
        *,
        release_receipts: Any = (),
        observer_evaluation_time: Any = None,
    ) -> dict[str, Any]:
        """CAS one native/Qwen authority transition into the same lane stream.

        ``observer_evaluation_time`` is optional so a caller that already
        captured a single observer time at the operation boundary can
        thread it through both the release validator and the commit
        build; the default keeps the existing one-call discipline that
        rebuilds ``self._cleanup_observer_now()`` at commit time.
        """
        ready, issues = self._ensure_lane_ledger_run()
        if not ready:
            return {"status": "UNKNOWN", "reason_codes": issues}
        if observer_evaluation_time is None:
            observer_evaluation_time = self._cleanup_observer_now()
        with self._lane_lock:
            try:
                events, _active, current = self._lane_ledger_state()
                built = lane_capacity.build_authority_delta(
                    current,
                    successor,
                    release_receipts=release_receipts,
                    observer_trust_store=self._cleanup_observer_trust_store,
                    observer_replay_guard=self._cleanup_observer_replay_guard,
                    observer_evaluation_time=observer_evaluation_time,
                )
                if built.get("status") != "BUILT":
                    return {
                        "status": "REFUSE",
                        "reason_codes": built.get(
                            "reason_codes",
                            ["lane_ledger:authority_cas_mismatch"],
                        ),
                    }
                transition = built["transition"]
                authority_delta = built["delta"]
                successor_authority = lane_capacity.validate_authority_state(
                    successor
                )
                changed_lane_ids = set(
                    transition["added_active_lane_ids"]
                    + transition["removed_active_lane_ids"]
                )
                changed_lane_ids.update(
                    entry["lane_id"]
                    for entry in transition["new_identity_entries"]
                )
                if any(
                    successor_authority["ledger"]["bindings"][lane_id][
                        "route"
                    ]
                    == lane_capacity.CONTROL_TOWER_ROUTE
                    for lane_id in changed_lane_ids
                ):
                    return {
                        "status": "REFUSE",
                        "reason_codes": [
                            "lane_ledger:external_control_transition_forbidden"
                        ],
                    }
                delta = lane_capacity.control_delta(released=[], reserved=[])
                self.engine.apply(
                    self._lane_ledger_run_id(),
                    "ledger",
                    roles=("ledger",),
                    status="SUCCESS",
                    deliverables={
                        "lane_delta": json.dumps(
                            delta, sort_keys=True, separators=(",", ":")
                        ),
                        "authority_delta": json.dumps(
                            authority_delta,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    },
                    evidence={
                        "lane_ledger": authority_delta["delta_sha256"]
                    },
                    expected_seq=events[-1]["seq"],
                    expected_prev_hash=events[-1]["event_hash"],
                )
            except run_store.StaleSeqError:
                return {
                    "status": "REFUSE",
                    "reason_codes": ["lane_ledger:authority_cas_conflict"],
                }
            except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
                return {
                    "status": "UNKNOWN",
                    "reason_codes": ["lane_ledger:authority_commit_failed"],
                }
        return {
            "status": "COMMITTED",
            "state_sha256": successor["state_sha256"],
            "reason_codes": [],
        }

    def _committed_release_matches(self, release_receipt: Mapping[str, Any]) -> bool:
        """Find the exact original receipt in the verified lane projection.

        Reads ``verified_release_receipts`` from the lane ledger cache
        populated by ``_lane_ledger_state``. The projection only stores
        rows whose ``authority_delta`` passed ``apply_authority_delta``
        with status ``APPLIED`` so each retained row carries a sealed
        ``receipt_sha256`` over its canonical JSON. Identity of a
        sealed record is decided by that digest; container equality
        is not used so a legitimately committed release cannot be
        refused for a JSON round-trip artifact introduced when the
        raw payload persisted through the lane ledger event. The
        ``lane_id`` selector stays narrow so an unrelated retained
        receipt of the same digest does not match. Falls back to
        populating the cache if the caller has not yet projected
        the ledger.
        """
        if not isinstance(release_receipt, Mapping):
            return False
        cache = self._lane_ledger_cache
        if not (
            isinstance(cache, Mapping)
            and isinstance(cache.get("release_receipts"), list)
        ):
            self._lane_ledger_state()
            cache = self._lane_ledger_cache
        presented = release_receipt.get("receipt_sha256")
        if not (
            isinstance(presented, str)
            and presented
        ):
            return False
        presented_lane = release_receipt.get("lane_id")
        for retained_receipts in reversed(cache["release_receipts"]):
            for retained in retained_receipts:
                if not isinstance(retained, Mapping):
                    continue
                if retained.get("lane_id") != presented_lane:
                    continue
                retained_digest = retained.get("receipt_sha256")
                if (
                    isinstance(retained_digest, str)
                    and retained_digest == presented
                ):
                    return True
        return False

    def _classify_retained_release(
        self, receipt: Any, observed: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Classify one candidate release receipt against verified history.

        Returns an explicit status record so the public read and the
        release path no longer branch on a None sentinel for an active
        lane. Each caller decides what the STILL_ACTIVE record means:
        ``read_shared_capacity_release`` projects it to UNKNOWN to keep
        the public read refusing to remove capacity, while
        ``release_shared_capacity_lane`` proceeds with the signed CAS
        release for exactly the active receipt presented.
        """
        if observed["status"] != "VERIFIED":
            return {"status": "UNKNOWN", "reason_codes": observed["reason_codes"]}
        # The public validator owns the closed-string type policy at its
        # creation boundary. This caller only needs Mapping to safely
        # forward the four expected values via .get so any unhashable
        # list, dict, bool or missing key falls through to REFUSE without
        # repeating the same isinstance checks here.
        if not isinstance(receipt, Mapping):
            return {"status": "REFUSE", "reason_codes": ["release:receipt_invalid"]}
        if not lane_capacity.validate_release_receipt(
            receipt,
            lane_id=receipt.get("lane_id"),
            run_id=receipt.get("run_id"),
            route=receipt.get("route"),
            terminal_state=receipt.get("terminal_state"),
        ):
            return {"status": "REFUSE", "reason_codes": ["release:receipt_invalid"]}
        lane_id = receipt["lane_id"]
        if lane_id in observed["state"]["active_lane_ids"]:
            return {"status": "STILL_ACTIVE", "reason_codes": []}
        if not self._committed_release_matches(receipt):
            return {
                "status": "REFUSE",
                "reason_codes": ["release:original_receipt_unavailable"],
            }
        return {
            "status": "RELEASED",
            "state_changed": False,
            "idempotent_replay": True,
            "state_sha256": observed["state_sha256"],
            "receipt_sha256": receipt["receipt_sha256"],
            "reason_codes": [],
        }

    def read_shared_capacity_release(self, release_receipt: Any) -> dict[str, Any]:
        """Read the exact already committed release; never remove capacity."""
        try:
            observed = self.read_shared_capacity_authority()
            classified = self._classify_retained_release(release_receipt, observed)
            if classified["status"] == "STILL_ACTIVE":
                return {
                    "status": "UNKNOWN",
                    "reason_codes": ["release:lane_still_active"],
                }
            return classified
        except (KeyError, TypeError, ValueError, run_store.StoreError, run_engine.RunKernelError):
            return {"status": "UNKNOWN", "reason_codes": ["lane_ledger:release_readback_failed"]}

    def release_shared_capacity_lane(self, release_receipt: Any) -> dict[str, Any]:
        """Commit one signed cleanup release, retaining the original identity.

        The observer trust, replay registry and evaluation time are this
        tower's existing host authority. The caller cannot substitute them.
        Root mission settlement records its intent separately before this
        operation, so a crash between streams retains the original claim
        and resumes this exact receipt. This method creates no mission
        completion, target-write permission or tracker proposal.
        """
        if (not self.store.durable or
                not callable(getattr(self.store, "authorization_guard", None))):
            return {"status": "REFUSE", "reason_codes": [
                "lane_ledger:durable_release_guard_unavailable"]}
        try:
            # The existing commit owns its lane/store locks and requires the
            # exact predecessor digest. A concurrent change refuses its CAS;
            # wrapping it in another lane lock would deadlock this host.
            observed = self.read_shared_capacity_authority()
            # An inactive lane is read against its original signed fact and
            # recorded evaluation time, never a fresh grant or alternate receipt.
            classified = self._classify_retained_release(release_receipt, observed)
            if classified["status"] in ("UNKNOWN", "REFUSE", "RELEASED"):
                return classified
            # STILL_ACTIVE: only the active receipt proceeds to a fresh,
            # exact-CAS, signed release; the host never accepts an
            # alternate receipt or a lost-trust cleanup, and the public
            # read path above kept this same lane as UNKNOWN until now.
            # Capture a single observer time at this boundary so both
            # the release validator and the commit build read the same
            # snapshot, matching the captured-time discipline already
            # used by ``_rebalance_lane_reservations``. Two calls to
            # ``self._cleanup_observer_now()`` would admit a freshness
            # drift between the validator and the commit on a busy
            # host or near a validity-window edge.
            observer_evaluation_time = self._cleanup_observer_now()
            released = lane_capacity.release_authority_lane(
                observed["state"], release_receipt,
                observer_trust_store=self._cleanup_observer_trust_store,
                observer_replay_guard=self._cleanup_observer_replay_guard,
                observer_evaluation_time=observer_evaluation_time)
            if released["status"] != "RELEASED":
                return released
            if released["state_changed"]:
                committed = self.commit_shared_capacity_authority(
                    released["state"], release_receipts=[release_receipt],
                    observer_evaluation_time=observer_evaluation_time)
                if committed["status"] != "COMMITTED":
                    return committed
            return {"status": "RELEASED", "state_changed": released["state_changed"],
                    "idempotent_replay": released["idempotent_replay"],
                    "state_sha256": released["state"]["state_sha256"], "reason_codes": []}
        except run_store.StoreError:
            return {"status": "REFUSE", "reason_codes": [
                "lane_ledger:durable_release_guard_unavailable"]}
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return {"status": "UNKNOWN", "reason_codes": [
                "lane_ledger:release_readback_failed"]}

    def _lane_run_snapshots(
        self,
    ) -> dict[str, dict[str, Any]]:
        snapshots: dict[str, dict[str, Any]] = {}
        for run_id in self.store.run_ids():
            if run_id in {
                self._lane_ledger_run_id(),
                self._scheduler_run_id(),
            }:
                continue
            events = list(self.engine.events(run_id, 0))
            if not events:
                continue
            started = json.loads(events[0]["payload"])
            plan = started.get("plan", {})
            control = plan.get("origin", {}).get("control_tower", {})
            profile_id = control.get("profile_id")
            if profile_id not in _LANE_PROFILES:
                continue
            if profile_id in _MULTI_LANE_PROFILES:
                dispatch_intents = control.get("dispatch_intents")
                task_specs = control.get("task_specs")
                if not isinstance(dispatch_intents, Mapping) or not isinstance(
                    task_specs, Mapping
                ):
                    raise ValueError("lane_run_control_invalid")
                automatic_dispatch = True
            else:
                direct_intent = control.get("dispatch_intent")
                direct_spec = control.get("task_spec")
                if not _intent_valid(direct_intent, "dispatch") or not isinstance(
                    direct_spec, Mapping
                ):
                    raise ValueError("lane_run_control_invalid")
                dispatch_intents = {direct_intent["node_id"]: direct_intent}
                task_specs = {direct_intent["node_id"]: direct_spec}
                for event in events:
                    if event["kind"] != run_engine.KIND_APPLIED:
                        continue
                    deliverables = json.loads(event["payload"]).get(
                        "deliverables", {}
                    )
                    raw_intent = deliverables.get("repair_intent")
                    raw_spec = deliverables.get("repair_task_spec")
                    if raw_intent is None and raw_spec is None:
                        continue
                    if not isinstance(raw_intent, str) or not isinstance(
                        raw_spec, str
                    ):
                        raise ValueError("lane_repair_claim_invalid")
                    repair_intent = json.loads(raw_intent)
                    repair_spec = json.loads(raw_spec)
                    if (
                        not _intent_valid(repair_intent, "dispatch")
                        or repair_intent.get("run_id") != run_id
                        or not isinstance(repair_spec, Mapping)
                        or repair_spec.get("id") != repair_intent.get("node_id")
                    ):
                        raise ValueError("lane_repair_claim_invalid")
                    dispatch_intents[repair_intent["node_id"]] = repair_intent
                    task_specs[repair_intent["node_id"]] = repair_spec
                automatic_dispatch = control.get("scheduling_mode") == "immediate"
            canonical_intents: dict[str, dict[str, Any]] = {}
            for node_id, intent in dispatch_intents.items():
                if (
                    not isinstance(node_id, str)
                    or not _intent_valid(intent, "dispatch")
                    or intent.get("run_id") != run_id
                    or intent.get("node_id") != node_id
                ):
                    raise ValueError("lane_run_intent_invalid")
                canonical_intents[node_id] = dict(intent)
            applied: set[str] = set()
            released: set[str] = set()
            release_receipts: dict[str, dict[str, Any]] = {}
            release_evaluation_times: dict[str, str] = {}
            for event in events:
                if event["kind"] != run_engine.KIND_APPLIED:
                    continue
                facts = json.loads(event["payload"])
                roles = facts.get("roles", [])
                deliverables = facts.get("deliverables", {})
                applied.update(
                    role for role in roles if role in canonical_intents
                )
                if (
                    profile_id in _SINGLE_LANE_PROFILES
                    and "executor" in roles
                    and "worker_usage" in deliverables
                ):
                    applied.add(control["dispatch_intent"]["node_id"])
                repair_sequence = deliverables.get("repair_sequence")
                if isinstance(repair_sequence, str):
                    matching_repairs = [
                        node_id
                        for node_id in canonical_intents
                        if node_id.endswith("repair-" + repair_sequence)
                    ]
                    if len(matching_repairs) != 1:
                        raise ValueError("lane_repair_result_invalid")
                    applied.add(matching_repairs[0])
                for node_id, intent in canonical_intents.items():
                    raw_receipt = deliverables.get(
                        "lane_release_receipt:" + node_id
                    )
                    if raw_receipt is None:
                        continue
                    if not isinstance(raw_receipt, str):
                        raise ValueError("lane_release_receipt_invalid")
                    evaluation_time = deliverables.get(
                        "lane_release_evaluation_time:" + node_id
                    )
                    if (
                        not isinstance(evaluation_time, str)
                        or lane_capacity._evaluation_time_text(evaluation_time)
                        != evaluation_time
                    ):
                        raise ValueError("lane_release_evaluation_time_invalid")
                    receipt = json.loads(raw_receipt)
                    worker_terminal_status = deliverables.get(
                        "worker_terminal_status:" + node_id
                    )
                    terminal_state = {
                        None: "completed",
                        "REJECTED": "failed",
                        "UNAVAILABLE": "failed",
                        "TIMED_OUT": "failed",
                        "CANCELLED": "cancelled",
                    }.get(worker_terminal_status)
                    if terminal_state is None:
                        raise ValueError("lane_release_terminal_state_invalid")
                    if not lane_capacity.validate_release_receipt(
                        receipt,
                        lane_id=_lane_identity(run_id, node_id),
                        run_id=run_id,
                        route=lane_capacity.CONTROL_TOWER_ROUTE,
                        terminal_state=terminal_state,
                    ):
                        raise ValueError("lane_release_receipt_invalid")
                    released.add(node_id)
                    release_receipts[node_id] = dict(receipt)
                    release_evaluation_times[node_id] = evaluation_time
            state = self.engine.reduce(_stored_plan_core(plan), events)
            cleanup = _cleanup_observation(events)
            snapshots[run_id] = {
                "applied": applied,
                "released": released,
                "release_receipts": release_receipts,
                "release_evaluation_times": release_evaluation_times,
                "automatic_dispatch": automatic_dispatch,
                "cancellation_pending": _cancellation_requested(events)
                and not state["terminal"],
                "cancelled": _cancellation_requested(events),
                "cleanup_safe": (
                    cleanup is not None
                    and cleanup.get("status") == "complete"
                    and cleanup.get("owned_descendants") == 0
                ),
                "cleanup_evidence_sha256": (
                    cleanup.get("evidence_sha256")
                    if cleanup is not None
                    else None
                ),
                "cleanup_evidence_sha256_by_lane": (
                    cleanup.get("evidence_sha256_by_lane")
                    if cleanup is not None
                    else None
                ),
                "cleanup_observer_receipts": (
                    cleanup.get("observer_receipts")
                    if cleanup is not None
                    else None
                ),
                "cleanup_observer_evaluation_times": (
                    cleanup.get("observer_evaluation_times")
                    if cleanup is not None
                    else None
                ),
                "dispatch_intents": canonical_intents,
                "expires_at_ms": control.get("expires_at_ms"),
                "root_thread_id": control.get("task_id"),
                "plan_revision": control.get("plan_revision"),
                "plan_sha256": control.get("logical_plan_sha256"),
                "task_node_budget": control.get("task_node_budget"),
                "task_specs": task_specs,
                "terminal": state["terminal"],
                "terminal_evidence_sha256": (
                    cleanup.get("terminal_evidence_sha256")
                    if cleanup is not None
                    else state["stream_sha256"]
                ),
            }
        return snapshots

    def _lane_reservation_active(self, run_id: str, node_id: str) -> bool:
        ready, issues = self._ensure_lane_ledger_run()
        if not ready:
            raise ValueError(issues[0])
        _, active, _authority_state = self._lane_ledger_state()
        record = active.get((run_id, node_id))
        if record is None:
            return False
        snapshot = self._lane_run_snapshots().get(run_id)
        intent = (
            snapshot.get("dispatch_intents", {}).get(node_id)
            if snapshot is not None
            else None
        )
        if intent is None or record != _lane_reservation(intent):
            raise ValueError("lane_ledger_binding_invalid")
        return True

    def _authority_transitions_for_delta(
        self,
        authority_state: Mapping[str, Any],
        snapshots: Mapping[str, Mapping[str, Any]],
        *,
        released: list[Mapping[str, Any]],
        reserved: list[Mapping[str, Any]],
    ) -> tuple[
        dict[str, Any] | None,
        list[dict[str, Any]],
        dict[str, str],
    ]:
        base_state = dict(authority_state)
        state = dict(authority_state)
        transitions: list[dict[str, Any]] = []
        release_receipts: list[dict[str, Any]] = []
        release_evaluation_times: dict[str, str] = {}

        required_runs = sorted(
            {str(record["run_id"]) for record in released + reserved}
        )
        authority = lane_capacity.validate_authority_state(state)
        for run_id in required_runs:
            snapshot = snapshots.get(run_id)
            if snapshot is None:
                raise ValueError("lane_authority_run_missing")
            if run_id not in authority["runs"]:
                registered = lane_capacity.register_run_authority(
                    state,
                    run_id=run_id,
                    root_thread_id=snapshot.get("root_thread_id"),
                    task_node_budget=snapshot.get("task_node_budget"),
                    plan_sha256=snapshot.get("plan_sha256"),
                )
                if registered.get("status") != "REGISTERED":
                    raise ValueError("lane_authority_registration_failed")
                state = registered["state"]
                transitions.append(state)
                authority = lane_capacity.validate_authority_state(state)
            current = authority["runs"][run_id]["plan_revisions"][-1]
            if current != {
                "revision": snapshot.get("plan_revision"),
                "plan_sha256": snapshot.get("plan_sha256"),
            }:
                raise ValueError("lane_authority_plan_mismatch")

        for record in released:
            run_id, node_id = _lane_key(record)
            snapshot = snapshots[run_id]
            lane_id = _lane_identity(run_id, node_id)
            receipt = snapshot["release_receipts"].get(node_id)
            evaluation_time = snapshot["release_evaluation_times"].get(
                node_id
            )
            if receipt is None and snapshot["terminal"] and snapshot["cleanup_safe"]:
                receipt = lane_capacity.release(
                    {
                        "lane_id": lane_id,
                        "run_id": run_id,
                        "route": lane_capacity.CONTROL_TOWER_ROUTE,
                        "state": (
                            "cancelled" if snapshot["cancelled"] else "completed"
                        ),
                        "cleanup_status": "complete",
                        "terminal_evidence_sha256": snapshot[
                            "terminal_evidence_sha256"
                        ],
                        "cleanup_evidence_sha256": snapshot[
                            "cleanup_evidence_sha256_by_lane"
                        ][lane_id],
                        "cleanup_observer_receipt": snapshot[
                            "cleanup_observer_receipts"
                        ][lane_id],
                    },
                    0,
                )
                evaluation_time = snapshot[
                    "cleanup_observer_evaluation_times"
                ][lane_id]
            if not isinstance(evaluation_time, str):
                raise ValueError("lane_authority_release_time_missing")
            released_state = lane_capacity.release_authority_lane(
                state,
                receipt,
                observer_trust_store=self._cleanup_observer_trust_store,
                observer_replay_guard=self._cleanup_observer_replay_guard,
                observer_evaluation_time=evaluation_time,
            )
            if released_state.get("status") != "RELEASED":
                raise ValueError("lane_authority_release_failed")
            state = released_state["state"]
            transitions.append(state)
            release_receipts.append(dict(receipt))
            release_evaluation_times[lane_id] = evaluation_time

        for record in reserved:
            run_id, node_id = _lane_key(record)
            snapshot = snapshots[run_id]
            reserved_state = lane_capacity.reserve_authority_lane(
                state,
                lane_id=_lane_identity(run_id, node_id),
                run_id=run_id,
                route=lane_capacity.CONTROL_TOWER_ROUTE,
                plan_revision=snapshot["plan_revision"],
                plan_sha256=snapshot["plan_sha256"],
            )
            if reserved_state.get("status") != "RESERVED":
                raise ValueError("lane_authority_reservation_failed")
            state = reserved_state["state"]
            transitions.append(state)
        if not transitions:
            return None, [], {}
        return (
            lane_capacity.collapse_authority_transition(
                base_state,
                state,
                release_receipts=release_receipts,
                observer_trust_store=self._cleanup_observer_trust_store,
                observer_replay_guard=self._cleanup_observer_replay_guard,
                observer_evaluation_time=release_evaluation_times,
            ),
            release_receipts,
            release_evaluation_times,
        )

    def _rebalance_lane_reservations(
        self,
        now_ms: int,
        *,
        requested_intents: list[Mapping[str, Any]] | None = None,
    ) -> tuple[list[dict[str, Any]], int, int]:
        ready, issues = self._ensure_lane_ledger_run()
        if not ready:
            raise ValueError(issues[0])
        with self._lane_lock:
            for _attempt in range(128):
                events, active, authority_state = self._lane_ledger_state()
                snapshots = self._lane_run_snapshots()
                released: list[dict[str, Any]] = []
                for key, record in sorted(active.items()):
                    snapshot = snapshots.get(key[0])
                    if snapshot is None:
                        raise ValueError("lane_ledger_run_missing")
                    intent = snapshot["dispatch_intents"].get(key[1])
                    if intent is None or record != _lane_reservation(intent):
                        raise ValueError("lane_ledger_binding_invalid")
                    if key[1] in snapshot["released"] or (
                        snapshot["terminal"] and snapshot["cleanup_safe"]
                    ):
                        released.append(record)

                occupied = {
                    key: record
                    for key, record in active.items()
                    if record not in released
                }
                authority = lane_capacity.validate_authority_state(
                    authority_state
                )
                if authority.get("status") != "RESOLVED":
                    raise ValueError("lane_authority_invalid")
                available = max(
                    0,
                    lane_capacity.MAX_CONCURRENT_LANES
                    - (
                        len(authority["active_lane_ids"])
                        - len(released)
                    ),
                )
                candidates: list[dict[str, Any]] = []
                adopted: list[dict[str, Any]] = []
                if requested_intents is not None:
                    for requested in requested_intents:
                        run_id = requested.get("run_id")
                        node_id = requested.get("node_id")
                        snapshot = snapshots.get(str(run_id))
                        bound = (
                            snapshot.get("dispatch_intents", {}).get(node_id)
                            if snapshot is not None
                            else None
                        )
                        if (
                            not _intent_valid(requested, "dispatch")
                            or bound != requested
                            or snapshot["terminal"]
                            or snapshot["cancellation_pending"]
                            or node_id in snapshot["applied"]
                        ):
                            raise ValueError("lane_requested_intent_invalid")
                        if (run_id, node_id) in occupied:
                            if occupied[(run_id, node_id)] != _lane_reservation(
                                requested
                            ):
                                raise ValueError("lane_requested_binding_invalid")
                            adopted.append(dict(requested))
                            continue
                        candidates.append(dict(requested))
                else:
                    for run_id, snapshot in sorted(snapshots.items()):
                        if (
                            not snapshot["automatic_dispatch"]
                            or snapshot["terminal"]
                            or snapshot["cancellation_pending"]
                            or type(snapshot["expires_at_ms"]) is not int
                            or now_ms > snapshot["expires_at_ms"]
                        ):
                            continue
                        for node_id, intent in sorted(
                            snapshot["dispatch_intents"].items()
                        ):
                            if (
                                node_id in snapshot["applied"]
                                or (run_id, node_id) in occupied
                            ):
                                continue
                            task_spec = snapshot["task_specs"].get(node_id)
                            dependencies = (
                                task_spec.get("dependencies")
                                if isinstance(task_spec, Mapping)
                                else None
                            )
                            if not isinstance(dependencies, list):
                                raise ValueError("lane_task_spec_invalid")
                            if set(dependencies) <= snapshot["applied"]:
                                candidates.append(intent)
                newly_selected = candidates[:available]
                selected_keys = {
                    (intent["run_id"], intent["node_id"])
                    for intent in adopted + newly_selected
                }
                if requested_intents is not None:
                    selected = [
                        dict(intent)
                        for intent in requested_intents
                        if (intent["run_id"], intent["node_id"])
                        in selected_keys
                    ]
                else:
                    selected = newly_selected
                reserved = sorted(
                    (_lane_reservation(intent) for intent in newly_selected),
                    key=_lane_key,
                )
                released.sort(key=_lane_key)
                if not released and not reserved:
                    return selected, 0, 0
                delta = lane_capacity.control_delta(
                    released=released,
                    reserved=reserved,
                )
                (
                    authority_successor,
                    authority_release_receipts,
                    authority_release_evaluation_times,
                ) = self._authority_transitions_for_delta(
                    authority_state,
                    snapshots,
                    released=released,
                    reserved=reserved,
                )
                if authority_successor is None:
                    raise ValueError("lane_authority_transition_missing")
                built_authority = lane_capacity.build_authority_delta(
                    authority_state,
                    authority_successor,
                    release_receipts=authority_release_receipts,
                    observer_trust_store=self._cleanup_observer_trust_store,
                    observer_replay_guard=self._cleanup_observer_replay_guard,
                    observer_evaluation_time=(
                        authority_release_evaluation_times
                    ),
                )
                if built_authority.get("status") != "BUILT":
                    raise ValueError("lane_authority_delta_invalid")
                authority_delta = built_authority["delta"]
                try:
                    self.engine.apply(
                        self._lane_ledger_run_id(),
                        "ledger",
                        roles=("ledger",),
                        status="SUCCESS",
                        deliverables={
                            "lane_delta": json.dumps(
                                delta,
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                            "authority_delta": json.dumps(
                                authority_delta,
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                        },
                        evidence={
                            "lane_ledger": authority_delta[
                                "delta_sha256"
                            ]
                        },
                        expected_seq=events[-1]["seq"],
                        expected_prev_hash=events[-1]["event_hash"],
                    )
                except run_store.StaleSeqError:
                    continue
                return [dict(intent) for intent in selected], len(released), len(
                    reserved
                )
        raise ValueError("lane_ledger_cas_exhausted")

    @staticmethod
    def _scheduler_run_id() -> str:
        return "ct-scheduler"

    def _scheduler_capacity_vector(self) -> dict[str, Any]:
        if self.scheduler_capacity is None:
            raise control_scheduler.SchedulerContractError(
                "scheduler_not_configured"
            )
        return control_scheduler.capacity_vector(self.scheduler_capacity)

    def _scheduler_plan(self) -> dict[str, Any]:
        capacity = self._scheduler_capacity_vector()
        return run_engine.make_plan(
            run_id=self._scheduler_run_id(),
            name="Control Tower global scheduler",
            expected_roles=("scheduler",),
            deliverable=False,
            actors=(
                run_engine.actor(
                    kind="observer",
                    model="deterministic-scheduler/v1",
                    actor_key="scheduler",
                    intent="reserve:control-tower/v1",
                ),
            ),
            origin={
                "control_scheduler": {
                    "capacity": capacity,
                    "capacity_sha256": self.scheduler_capacity[
                        "capacity_sha256"
                    ],
                    "policy_generation": POLICY_GENERATION,
                }
            },
        )

    def _ensure_scheduler_run(self) -> tuple[bool, list[str]]:
        if self.scheduler_capacity is None:
            return False, ["schedule:not_configured"]
        run_id = self._scheduler_run_id()
        expected = run_engine.plan_core(self._scheduler_plan())
        if not self.store.exists(run_id):
            try:
                self.engine.start(expected)
            except (run_engine.MalformedInputError, run_engine.ProtocolError):
                if not self.store.exists(run_id):
                    return False, ["schedule:initialization_conflict"]
        try:
            events = list(self.engine.events(run_id, 0))
            observed = _stored_plan_core(
                json.loads(events[0]["payload"])["plan"]
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            run_engine.NotFoundError,
            run_engine.RunKernelError,
        ):
            return False, ["schedule:state_invalid"]
        if observed != expected:
            return False, ["schedule:capacity_drift"]
        return True, []

    def _enqueue(
        self, payload: Any
    ) -> tuple[dict[str, Any] | None, list[str]]:
        if not isinstance(payload, Mapping) or set(payload) != _ENQUEUE_FIELDS:
            return None, ["advance:enqueue_payload_invalid"]
        if payload.get("schema") != ENQUEUE_SCHEMA or payload.get("kind") != "enqueue":
            return None, ["advance:enqueue_invalid"]
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        preparation, issues = _preparation_ready(
            payload.get("preparation"), now_ms, root_model=self.root_model
        )
        if issues:
            return _prestart_refusal(payload, issues), []
        if preparation["result"]["route"]["profile_id"] != "direct/v1":
            return _prestart_refusal(
                payload, ["advance:scheduler_direct_only"]
            ), []
        ready, scheduler_issues = self._ensure_scheduler_run()
        if not ready:
            return _prestart_refusal(payload, scheduler_issues), []
        return self._start_direct(payload, preparation, now_ms, queued=True)

    def _scheduler_reservations(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for event in self.engine.events(self._scheduler_run_id(), 0):
            if event["kind"] != run_engine.KIND_APPLIED:
                continue
            facts = json.loads(event["payload"])
            raw = facts.get("deliverables", {}).get("reservations")
            if not isinstance(raw, str):
                continue
            decoded = json.loads(raw)
            if not isinstance(decoded, list):
                raise ValueError("scheduler_reservations_invalid")
            for record in decoded:
                try:
                    canonical = control_scheduler.validate_reservation(record)
                except control_scheduler.SchedulerContractError:
                    raise ValueError("scheduler_reservation_invalid")
                if canonical["capacity_sha256"] != self.scheduler_capacity[
                    "capacity_sha256"
                ]:
                    raise ValueError("scheduler_reservation_capacity_mismatch")
                records.append(canonical)
        run_ids = [record["run_id"] for record in records]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("scheduler_duplicate_reservation")
        return records

    def _scheduled_runs(self, now_ms: int) -> dict[str, Any]:
        reservations = self._scheduler_reservations()
        reservation_by_run = {record["run_id"]: record for record in reservations}
        queued = []
        active = []
        completed = []
        terminated = []
        cancellation_pending = []
        cleanup_unknown = []
        expired = []
        snapshots = []
        for run_id in self.store.run_ids():
            if run_id == self._scheduler_run_id():
                continue
            events = list(self.engine.events(run_id, 0))
            if not events:
                continue
            started = json.loads(events[0]["payload"])
            plan = started.get("plan", {})
            control = plan.get("origin", {}).get("control_tower", {})
            if control.get("scheduling_mode") != "queued":
                continue
            state = self.engine.reduce(_stored_plan_core(plan), events)
            terminal_kind = events[-1]["kind"] if state["terminal"] else None
            cancellation = _cancellation_requested(events)
            cleanup = _cleanup_observation(events)
            reservation = reservation_by_run.get(run_id)
            if reservation is not None:
                dispatch_intent = control.get("dispatch_intent")
                if (
                    not isinstance(dispatch_intent, Mapping)
                    or reservation.get("intent_sha256")
                    != dispatch_intent.get("intent_sha256")
                    or reservation.get("expires_at_ms")
                    != dispatch_intent.get("expires_at_ms")
                    or reservation.get("resources")
                    != control.get("scheduler_resources")
                ):
                    raise ValueError("scheduler_reservation_binding_mismatch")
            snapshot = {
                "run_id": run_id,
                "seq": events[-1]["seq"],
                "stream_sha256": state["stream_sha256"],
                "terminal_kind": terminal_kind,
                "cancellation_pending": cancellation and not state["terminal"],
                "cleanup_status": cleanup.get("status") if cleanup else None,
                "reservation_sha256": (
                    reservation.get("reservation_sha256")
                    if reservation is not None
                    else None
                ),
            }
            snapshots.append(snapshot)
            if terminal_kind == run_engine.KIND_COMPLETED:
                completed.append(run_id)
                continue
            if terminal_kind == run_engine.KIND_TERMINATED:
                terminated.append(run_id)
                cleanup_safe = (
                    cleanup is not None
                    and cleanup.get("status") == "complete"
                    and cleanup.get("owned_descendants") == 0
                )
                if reservation is not None and not cleanup_safe:
                    active.append(reservation)
                    cleanup_unknown.append(run_id)
                continue
            if cancellation:
                cancellation_pending.append(run_id)
                if reservation is not None:
                    active.append(reservation)
                continue
            if reservation is not None:
                active.append(reservation)
                continue
            if now_ms > control.get("expires_at_ms", -1):
                expired.append(run_id)
                continue
            queued.append(
                {
                    "run_id": run_id,
                    "dispatch_count": 0,
                    "resources": control.get("scheduler_resources"),
                    "intent": control.get("dispatch_intent"),
                }
            )
        known_queued = {row["run_id"] for row in queued}
        known = (
            known_queued
            | {row["run_id"] for row in active}
            | set(completed)
            | set(terminated)
            | set(cancellation_pending)
            | set(cleanup_unknown)
            | set(expired)
        )
        unknown_reservations = sorted(set(reservation_by_run) - known)
        if unknown_reservations:
            raise ValueError("scheduler_reservation_run_unknown")
        snapshots.sort(key=lambda row: row["run_id"])
        return {
            "queued": sorted(queued, key=lambda row: row["run_id"]),
            "active": sorted(active, key=lambda row: row["run_id"]),
            "completed": sorted(completed),
            "terminated": sorted(terminated),
            "cancellation_pending": sorted(cancellation_pending),
            "cleanup_unknown": sorted(cleanup_unknown),
            "expired": sorted(expired),
            "reservations": reservations,
            "snapshots": snapshots,
        }

    def _scheduler_cursor(
        self, state: Mapping[str, Any]
    ) -> dict[str, Any]:
        events = list(self.engine.events(self._scheduler_run_id(), 0))
        scheduler_plan = json.loads(events[0]["payload"])["plan"]
        scheduler_state = self.engine.reduce(
            _stored_plan_core(scheduler_plan), events
        )
        core = {
            "schema": SCHEDULER_CURSOR_SCHEMA,
            "scheduler_run_id": self._scheduler_run_id(),
            "seq": events[-1]["seq"],
            "event_hash": events[-1]["event_hash"],
            "stream_sha256": scheduler_state["stream_sha256"],
            "snapshot_sha256": _hash_row_sequence(state["snapshots"]),
            "capacity_sha256": self.scheduler_capacity["capacity_sha256"],
        }
        return {**core, "cursor_sha256": _sha256(core)}

    def _scheduler_view(self, now_ms: int, *, max_runs: int) -> dict[str, Any]:
        state = self._scheduled_runs(now_ms)
        usage = control_scheduler.zero_resources()
        for record in state["active"]:
            usage = control_scheduler.add_resources(usage, record["resources"])
        capacity = self._scheduler_capacity_vector()
        run_lists = {
            key: state[key][:max_runs]
            for key in (
                "completed",
                "terminated",
                "cancellation_pending",
                "cleanup_unknown",
                "expired",
            )
        }
        queued_ids = [row["run_id"] for row in state["queued"]]
        active_ids = [row["run_id"] for row in state["active"]]
        feasibility = control_scheduler.choose(
            capacity=self.scheduler_capacity,
            active=state["active"],
            candidates=state["queued"],
            max_dispatches=control_scheduler.MAX_CONCURRENT_LANES,
        )
        oversized_ids = feasibility["oversized_run_ids"]
        core = {
            "schema": SCHEDULER_INSPECTION_SCHEMA,
            "scheduler_cursor": self._scheduler_cursor(state),
            "capacity": capacity,
            "resource_usage": {
                field: usage[field] for field in control_scheduler.RESOURCE_FIELDS
            },
            "queued_run_ids": queued_ids[:max_runs],
            "active_run_ids": active_ids[:max_runs],
            **{key + "_run_ids": value for key, value in run_lists.items()},
            "oversized_run_ids": oversized_ids[:max_runs],
            "counts": {
                "queued": len(queued_ids),
                "active": len(active_ids),
                "completed": len(state["completed"]),
                "terminated": len(state["terminated"]),
                "cancellation_pending": len(state["cancellation_pending"]),
                "cleanup_unknown": len(state["cleanup_unknown"]),
                "expired": len(state["expired"]),
                "reservation_records": len(state["reservations"]),
            },
            "counters": {"retries": 0, "fallbacks": 0, "replacements": 0},
            "truncated": len(oversized_ids) > max_runs or any(
                len(state[key]) > max_runs
                for key in (
                    "queued",
                    "active",
                    "completed",
                    "terminated",
                    "cancellation_pending",
                    "cleanup_unknown",
                    "expired",
                )
            ),
            "run_state_authoritative": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
        return {**core, "inspection_sha256": _sha256(core)}

    def _schedule(
        self, payload: Any
    ) -> tuple[dict[str, Any] | None, list[str]]:
        if not isinstance(payload, Mapping) or set(payload) != _SCHEDULE_FIELDS:
            return None, ["schedule:payload_invalid"]
        if payload.get("schema") != SCHEDULE_SCHEMA or payload.get("kind") != "schedule":
            return None, ["schedule:program_invalid"]
        prior = payload.get("prior_scheduler_cursor")
        if not _seal_valid(prior, "cursor_sha256"):
            return None, ["schedule:cursor_invalid"]
        max_dispatches = payload.get("max_dispatches")
        if (
            type(max_dispatches) is not int
            or not 1 <= max_dispatches <= control_scheduler.MAX_CONCURRENT_LANES
        ):
            return None, ["schedule:max_dispatches_invalid"]
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["schedule:clock_invalid"]
        ready, issues = self._ensure_scheduler_run()
        if not ready:
            return _prestart_refusal(payload, issues), []
        with self._scheduler_lock:
            try:
                current_state = self._scheduled_runs(now_ms)
                current_cursor = self._scheduler_cursor(current_state)
            except _SCHEDULER_STATE_EXCEPTIONS:
                return None, ["schedule:state_invalid"]
            if prior != current_cursor:
                return self._scheduler_refusal(
                    payload,
                    current_cursor,
                    current_state,
                    ["schedule:stale_cursor"],
                ), []
            try:
                choice = control_scheduler.choose(
                    capacity=self.scheduler_capacity,
                    active=current_state["active"],
                    candidates=current_state["queued"],
                    max_dispatches=max_dispatches,
                )
            except control_scheduler.SchedulerContractError:
                return self._scheduler_refusal(
                    payload,
                    current_cursor,
                    current_state,
                    ["schedule:capacity_invalid"],
                ), []
            selected = choice["selected"]
            if not selected:
                return self._scheduler_decision(
                    payload,
                    current_cursor,
                    current_cursor,
                    "NOOP",
                    ["schedule:no_feasible_ready_run"],
                    [],
                    [],
                    choice["resource_usage"],
                    choice["oversized_run_ids"],
                ), []
            try:
                lane_intents, _released_lanes, _reserved_lanes = (
                    self._rebalance_lane_reservations(
                        now_ms,
                        requested_intents=[
                            candidate["intent"] for candidate in selected
                        ],
                    )
                )
            except run_store.StaleSeqError:
                return self._scheduler_refusal(
                    payload,
                    current_cursor,
                    current_state,
                    ["schedule:cas_conflict"],
                ), []
            except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
                return self._scheduler_refusal(
                    payload,
                    current_cursor,
                    current_state,
                    ["schedule:lane_ledger_invalid"],
                ), []
            if not lane_intents:
                usage = control_scheduler.zero_resources()
                for record in current_state["active"]:
                    usage = control_scheduler.add_resources(
                        usage, record["resources"]
                    )
                return self._scheduler_decision(
                    payload,
                    current_cursor,
                    current_cursor,
                    "NOOP",
                    ["schedule:global_lane_capacity_exhausted"],
                    [],
                    [],
                    usage,
                    choice["oversized_run_ids"],
                ), []
            choice = control_scheduler.choose(
                capacity=self.scheduler_capacity,
                active=current_state["active"],
                candidates=current_state["queued"],
                max_dispatches=len(lane_intents),
            )
            selected = choice["selected"]
            if [candidate["intent"] for candidate in selected] != lane_intents:
                return self._scheduler_refusal(
                    payload,
                    current_cursor,
                    current_state,
                    [
                        "schedule:lane_selection_drift",
                        "schedule:lane_reservation_retained_for_recovery",
                    ],
                ), []
            reservations = []
            for candidate in selected:
                core = {
                    "schema": control_scheduler.RESERVATION_SCHEMA,
                    "reservation_id": _sha256(
                        {
                            "run_id": candidate["run_id"],
                            "intent_sha256": candidate["intent"]["intent_sha256"],
                            "scheduler_cursor_sha256": current_cursor[
                                "cursor_sha256"
                            ],
                        }
                    ),
                    "run_id": candidate["run_id"],
                    "resources": candidate["resources"],
                    "intent_sha256": candidate["intent"]["intent_sha256"],
                    "issued_at_ms": now_ms,
                    "expires_at_ms": candidate["intent"]["expires_at_ms"],
                    "capacity_sha256": self.scheduler_capacity[
                        "capacity_sha256"
                    ],
                }
                reservations.append(
                    {**core, "reservation_sha256": _sha256(core)}
                )
            try:
                self.engine.apply(
                    self._scheduler_run_id(),
                    "scheduler",
                    roles=("scheduler",),
                    status="SUCCESS",
                    deliverables={
                        "reservations": json.dumps(
                            reservations,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    },
                    evidence={
                        "scheduler": _sha256(
                            [
                                reservation["reservation_sha256"]
                                for reservation in reservations
                            ]
                        )
                    },
                    expected_seq=current_cursor["seq"],
                    expected_prev_hash=current_cursor["event_hash"],
                )
            except (
                run_engine.MalformedInputError,
                run_engine.ProtocolError,
                run_store.StaleSeqError,
            ):
                try:
                    refreshed_state = self._scheduled_runs(now_ms)
                    refreshed_cursor = self._scheduler_cursor(refreshed_state)
                except _SCHEDULER_STATE_EXCEPTIONS:
                    refreshed_state = current_state
                    refreshed_cursor = current_cursor
                return self._scheduler_refusal(
                    payload,
                    refreshed_cursor,
                    refreshed_state,
                    [
                        "schedule:cas_conflict",
                        "schedule:lane_reservation_retained_for_recovery",
                    ],
                ), []
            resulting_state = self._scheduled_runs(now_ms)
            resulting_cursor = self._scheduler_cursor(resulting_state)
            return self._scheduler_decision(
                payload,
                current_cursor,
                resulting_cursor,
                "ADVANCED",
                ["schedule:reservations_committed"],
                reservations,
                [candidate["intent"] for candidate in selected],
                choice["resource_usage"],
                choice["oversized_run_ids"],
            ), []

    def _scheduler_decision(
        self,
        payload: Mapping[str, Any],
        prior_cursor: Mapping[str, Any],
        resulting_cursor: Mapping[str, Any],
        status: str,
        reason_codes: list[str],
        reservations: list[Mapping[str, Any]],
        intents: list[Mapping[str, Any]],
        usage: Mapping[str, Any],
        oversized: list[str],
    ) -> dict[str, Any]:
        core = {
            "schema": SCHEDULER_DECISION_SCHEMA,
            "decision_status": status,
            "prior_scheduler_cursor": deepcopy(dict(prior_cursor)),
            "accepted_input_sha256": _sha256(payload),
            "resulting_scheduler_cursor": deepcopy(dict(resulting_cursor)),
            "reason_codes": sorted(set(reason_codes)),
            "reservations": deepcopy([dict(item) for item in reservations]),
            "intents": deepcopy([dict(item) for item in intents]),
            "resource_usage": {
                field: usage[field] for field in control_scheduler.RESOURCE_FIELDS
            },
            "oversized_run_ids": sorted(oversized),
            "counters": {"retries": 0, "fallbacks": 0, "replacements": 0},
        }
        return {**core, "decision_sha256": _sha256(core)}

    def _scheduler_refusal(
        self,
        payload: Mapping[str, Any],
        cursor: Mapping[str, Any],
        state: Mapping[str, Any],
        reasons: list[str],
    ) -> dict[str, Any]:
        usage = control_scheduler.zero_resources()
        for record in state.get("active", []):
            usage = control_scheduler.add_resources(usage, record["resources"])
        return self._scheduler_decision(
            payload,
            cursor,
            cursor,
            "REFUSED",
            reasons,
            [],
            [],
            usage,
            [],
        )

    def _start_direct(
        self,
        value: Mapping[str, Any],
        preparation: Mapping[str, Any],
        now_ms: int,
        *,
        queued: bool,
    ) -> tuple[dict[str, Any], list[str]]:
        ready = preparation["result"]
        task_spec = ready["task_spec"]
        logical_plan = ready["logical_plan"]
        task = _task_from_ready(preparation)
        capability = ready["executor_capability"]
        profile_id = ready["route"]["profile_id"]
        manifest = _worker_manifest(capability, task)
        call = _worker_call(
            task, task_spec, preparation, profile_id=profile_id
        )
        call_report = worker_transport.validate_worker_call(call)
        manifest_report = worker_transport.validate_model_manifest(manifest)
        task_id = logical_plan["planner"]["root_thread_id"]
        run_id = "ct-" + preparation["preparation_sha256"][:24]
        intent = _dispatch_intent(
            task_id=task_id,
            run_id=run_id,
            preparation=preparation,
            task_spec=task_spec,
            logical_plan=logical_plan,
            ready=ready,
            capability=capability,
            call=call,
            call_sha256=call_report["canonical_sha256"],
            manifest=manifest,
            manifest_sha256=manifest_report["canonical_sha256"],
            now_ms=now_ms,
        )
        review_scope_sha256 = _sha256(
            {
                "task_brief_sha256": preparation["task_brief_sha256"],
                "profile_sha256": ready["profile"]["profile_sha256"],
                "privacy_class": preparation["privacy_class"],
                "project_ground_sha256": preparation[
                    "project_ground_sha256"
                ],
                "authority_sha256": intent["authority_sha256"],
                "read_scope": task_spec["read_scope"],
                "write_scope": task_spec["write_scope"],
                "allowed_tools": task_spec["allowed_tools"],
                "required_human_approvals": ready[
                    "authority_requirements"
                ],
            }
        )
        run_plan = run_engine.make_plan(
            run_id=run_id,
            name=logical_plan["objective"],
            expected_roles=("executor", "reviewer"),
            deliverable=True,
            actors=(
                run_engine.actor(
                    kind="executor",
                    model=capability["runtime_identity"]["logical_model_id"],
                    actor_key="executor",
                    intent="execute:" + profile_id,
                ),
                run_engine.actor(
                    kind="reviewer",
                    model="deterministic-verifier/v1",
                    actor_key="reviewer",
                    intent="verify:" + profile_id,
                ),
            ),
            origin={
                "control_tower": {
                    "task_id": task_id,
                    "plan_revision": logical_plan["revision"],
                    "preparation_sha256": preparation["preparation_sha256"],
                    "privacy_class": preparation["privacy_class"],
                    "policy_generation": POLICY_GENERATION,
                    "profile_sha256": ready["profile"]["profile_sha256"],
                    "compilation_sha256": ready["compilation"]["compilation_sha256"],
                    "task_spec": task_spec,
                    "task_specs": {
                        spec["id"]: spec for spec in ready["task_specs"]
                    },
                    "task_brief": ready["task_brief"],
                    "workflow_submission": ready["workflow_submission"],
                    "logical_plan": logical_plan,
                    "route": ready["route"],
                    "reservation_requirements": ready[
                        "reservation_requirements"
                    ],
                    "task_node_budget": ready["budgets"]["nodes"],
                    "authority_requirements": ready[
                        "authority_requirements"
                    ],
                    "logical_plan_sha256": _sha256(logical_plan),
                    "executor_capability": capability,
                    "capability_sha256": capability["capability_sha256"],
                    "worker_call": call,
                    "worker_call_sha256": call_report["canonical_sha256"],
                    "cleanup_authority_sha256": intent["authority_sha256"],
                    "model_manifest": manifest,
                    "model_manifest_sha256": manifest_report["canonical_sha256"],
                    "dispatch_intent": intent,
                    "profile_id": profile_id,
                    "repair_limit": (
                        ready["workflow_submission"]["max_repairs"]
                        if profile_id == "execute_verify_repair/v1"
                        else ready["profile"]["repair_limit"]
                    ),
                    "review_scope_sha256": review_scope_sha256,
                    "scheduling_mode": "queued" if queued else "immediate",
                    "scheduler_resources": control_scheduler.reservation_resources(
                        task,
                        capability,
                    ),
                    "cleanup_grace_ms": capability["timeout"][
                        "cleanup_grace_ms"
                    ],
                    "expires_at_ms": preparation["expires_at_ms"],
                }
            },
        )
        if not queued:
            ledger_ready, ledger_issues = self._ensure_lane_ledger_run()
            if not ledger_ready:
                return _prestart_refusal(value, ledger_issues), []
        try:
            self.engine.start(run_plan)
        except (run_engine.MalformedInputError, run_engine.ProtocolError):
            refusal = _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "REFUSED",
                    "prior_cursor": _genesis_cursor(run_id),
                    "accepted_input_sha256": _sha256(value),
                    "resulting_cursor": _genesis_cursor(run_id),
                    "state_sha256": None,
                    "reason_codes": ["advance:run_already_started"],
                    "intents": [],
                    "budget_settlement": {"reserved": False},
                    "authority_settlement": {"consumed": False},
                },
                "decision_sha256",
            )
            return refusal, []

        events = list(self.engine.events(run_id))
        state = self.engine.reduce(run_engine.plan_core(run_plan), events)
        dispatch_intents: list[dict[str, Any]] = []
        reserved_lanes = 0
        if not queued:
            try:
                dispatch_intents, _released_lanes, reserved_lanes = (
                    self._rebalance_lane_reservations(now_ms)
                )
            except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
                return self._state_refusal(
                    value,
                    _cursor(run_id, events, state),
                    state,
                    ["advance:lane_ledger_invalid"],
                )
        decision = _seal(
            {
                "schema": DECISION_SCHEMA,
                "decision_status": "QUEUED" if queued else "ADVANCED",
                "prior_cursor": _genesis_cursor(run_id),
                "accepted_input_sha256": _sha256(value),
                "resulting_cursor": _cursor(run_id, events, state),
                "state_sha256": _sha256(dict(state)),
                "reason_codes": [
                    "advance:queued" if queued else "advance:started"
                ],
                "intents": dispatch_intents,
                "budget_settlement": {
                    "reserved": bool(dispatch_intents),
                    "reserved_lanes": reserved_lanes,
                    "reservation_sha256": (
                        None if queued else intent["reservation_sha256"]
                    ),
                    "lane_reservation_sha256": (
                        None
                        if queued
                        else _sha256(
                            [
                                _lane_reservation(emitted)[
                                    "reservation_sha256"
                                ]
                                for emitted in dispatch_intents
                            ]
                        )
                    ),
                },
                "authority_settlement": {
                    "consumed": False,
                    "scope_sha256": intent["authority_sha256"],
                },
            },
            "decision_sha256",
        )
        return decision, []

    def _start_parallel(
        self,
        value: Mapping[str, Any],
        preparation: Mapping[str, Any],
        now_ms: int,
    ) -> tuple[dict[str, Any], list[str]]:
        ready = preparation["result"]
        logical_plan = ready["logical_plan"]
        task = _task_from_ready(preparation)
        capability = ready["executor_capability"]
        profile_id = ready["route"]["profile_id"]
        manifest = _worker_manifest(capability, task)
        manifest_report = worker_transport.validate_model_manifest(manifest)
        task_specs = {
            task_spec["id"]: task_spec for task_spec in ready["task_specs"]
        }
        producer_specs = sorted(
            (
                task_spec
                for task_spec in ready["task_specs"]
                if task_spec["kind"] == "execute"
            ),
            key=lambda task_spec: task_spec["id"],
        )
        task_id = logical_plan["planner"]["root_thread_id"]
        run_id = "ct-" + preparation["preparation_sha256"][:24]
        calls: dict[str, dict[str, Any]] = {}
        call_hashes: dict[str, str] = {}
        all_intents: list[dict[str, Any]] = []
        if profile_id == "best_of_n/v1":
            independence_groups = dict(
                zip(
                    [task_spec["id"] for task_spec in producer_specs],
                    ready["workflow_submission"][
                        "candidate_independence_groups"
                    ],
                )
            )
        else:
            independence_groups = {
                task_spec["id"]: profile_id + ":" + task_spec["id"]
                for task_spec in producer_specs
            }
        for task_spec in producer_specs:
            call = _worker_call(
                task,
                task_spec,
                preparation,
                profile_id=profile_id,
                call_suffix=task_spec["id"],
            )
            call_report = worker_transport.validate_worker_call(call)
            intent = _dispatch_intent(
                task_id=task_id,
                run_id=run_id,
                preparation=preparation,
                task_spec=task_spec,
                logical_plan=logical_plan,
                ready=ready,
                capability=capability,
                call=call,
                call_sha256=call_report["canonical_sha256"],
                manifest=manifest,
                manifest_sha256=manifest_report["canonical_sha256"],
                now_ms=now_ms,
                independence_group=independence_groups[task_spec["id"]],
            )
            calls[task_spec["id"]] = call
            call_hashes[task_spec["id"]] = call_report["canonical_sha256"]
            all_intents.append(intent)

        producer_ids = [task_spec["id"] for task_spec in producer_specs]
        join_spec = next(
            task_spec for task_spec in ready["task_specs"] if task_spec["kind"] == "join"
        )
        expected_roles = tuple(producer_ids + ["integrator", "reviewer"])
        actors = [
            run_engine.actor(
                kind="executor",
                model=capability["runtime_identity"]["logical_model_id"],
                actor_key=producer_id,
                intent="execute:" + profile_id + ":" + producer_id,
            )
            for producer_id in producer_ids
        ]
        actors.extend(
            [
                run_engine.actor(
                    kind="integrator",
                    model="deterministic-join/v1",
                    actor_key=join_spec["id"],
                    intent="join:" + profile_id,
                ),
                run_engine.actor(
                    kind="reviewer",
                    model="deterministic-verifier/v1",
                    actor_key="reviewer",
                    intent="verify:" + profile_id,
                ),
            ]
        )
        control = {
            "task_id": task_id,
            "profile_id": profile_id,
            "plan_revision": logical_plan["revision"],
            "preparation_sha256": preparation["preparation_sha256"],
            "privacy_class": preparation["privacy_class"],
            "policy_generation": POLICY_GENERATION,
            "profile_sha256": ready["profile"]["profile_sha256"],
            "compilation_sha256": ready["compilation"]["compilation_sha256"],
            "task_spec": join_spec,
            "task_specs": task_specs,
            "task_brief": ready["task_brief"],
            "logical_plan": logical_plan,
            "route": ready["route"],
            "reservation_requirements": ready["reservation_requirements"],
            "task_node_budget": ready["budgets"]["nodes"],
            "authority_requirements": ready["authority_requirements"],
            "logical_plan_sha256": _sha256(logical_plan),
            "executor_capability": capability,
            "capability_sha256": capability["capability_sha256"],
            "worker_calls": calls,
            "worker_call_hashes": call_hashes,
            "cleanup_authority_sha256": all_intents[0]["authority_sha256"],
            "model_manifest": manifest,
            "model_manifest_sha256": manifest_report["canonical_sha256"],
            "dispatch_intents": {
                intent["node_id"]: intent for intent in all_intents
            },
            "initial_dispatch_node_ids": [],
            "topology_closure": ready["topology_closure"],
            "profile_submission": ready["workflow_submission"],
            "workflow_submission": (
                ready["workflow_submission"]["topology_submission"]
                if profile_id == "finite_dag/v1"
                else ready["workflow_submission"]
            ),
            "repair_limit": ready["profile"]["repair_limit"],
            "review_scope_sha256": _sha256(
                {
                    "task_brief_sha256": preparation["task_brief_sha256"],
                    "profile_sha256": ready["profile"]["profile_sha256"],
                    "privacy_class": preparation["privacy_class"],
                    "project_ground_sha256": preparation[
                        "project_ground_sha256"
                    ],
                    "authority_sha256": all_intents[0]["authority_sha256"],
                    "read_scope": join_spec["read_scope"],
                    "write_scope": join_spec["write_scope"],
                    "allowed_tools": join_spec["allowed_tools"],
                    "required_human_approvals": ready[
                        "authority_requirements"
                    ],
                }
            ),
            "cleanup_grace_ms": capability["timeout"]["cleanup_grace_ms"],
            "expires_at_ms": preparation["expires_at_ms"],
        }
        run_plan = run_engine.make_plan(
            run_id=run_id,
            name=logical_plan["objective"],
            expected_roles=expected_roles,
            deliverable=True,
            actors=tuple(actors),
            origin={"control_tower": control},
        )
        ledger_ready, ledger_issues = self._ensure_lane_ledger_run()
        if not ledger_ready:
            return _prestart_refusal(value, ledger_issues), []
        try:
            self.engine.start(run_plan)
        except (run_engine.MalformedInputError, run_engine.ProtocolError):
            return _prestart_refusal(value, ["advance:run_already_started"]), []
        events = list(self.engine.events(run_id))
        state = self.engine.reduce(run_engine.plan_core(run_plan), events)
        try:
            intents, _released_lanes, reserved_lanes = (
                self._rebalance_lane_reservations(now_ms)
            )
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return self._state_refusal(
                value,
                _cursor(run_id, events, state),
                state,
                ["advance:lane_ledger_invalid"],
            )
        decision = _seal(
            {
                "schema": DECISION_SCHEMA,
                "decision_status": "ADVANCED",
                "prior_cursor": _genesis_cursor(run_id),
                "accepted_input_sha256": _sha256(value),
                "resulting_cursor": _cursor(run_id, events, state),
                "state_sha256": _sha256(dict(state)),
                "reason_codes": [
                    "advance:best_candidates_ready"
                    if profile_id == "best_of_n/v1"
                    else "advance:parallel_producers_ready"
                ],
                "intents": intents,
                "budget_settlement": {
                    "reserved": bool(intents),
                    "reserved_lanes": reserved_lanes,
                    "reservation_sha256": _sha256(
                        ready["reservation_requirements"]
                    ),
                    "lane_reservation_sha256": _sha256(
                        [
                            _lane_reservation(intent)[
                                "reservation_sha256"
                            ]
                            for intent in intents
                        ]
                    ),
                },
                "authority_settlement": {
                    "consumed": False,
                    "scope_sha256": (
                        intents[0]["authority_sha256"] if intents else None
                    ),
                },
            },
            "decision_sha256",
        )
        return decision, []

    def _cancel(self, payload: Any) -> tuple[dict[str, Any] | None, list[str]]:
        if not isinstance(payload, Mapping) or set(payload) != _CANCEL_FIELDS:
            return None, ["advance:cancel_payload_invalid"]
        reason = payload.get("reason")
        if (
            payload.get("schema") != ADVANCE_SCHEMA
            or reason not in {"user_requested", "deadline_expired"}
        ):
            return None, ["advance:cancel_invalid"]
        run_id = payload.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            return None, ["advance:run_id_invalid"]
        try:
            events = list(self.engine.events(run_id, 0))
        except run_engine.NotFoundError:
            return None, ["advance:run_not_found"]
        plan = json.loads(events[0]["payload"])["plan"]
        state = self.engine.reduce(plan, events)
        current_cursor = _cursor(run_id, events, state)
        if payload.get("prior_cursor") != current_cursor:
            return self._cursor_refusal(payload, current_cursor, state)
        if state["terminal"]:
            return self._post_terminal_refusal(payload, current_cursor, state)
        if _cancellation_requested(events):
            return self._state_refusal(
                payload, current_cursor, state, ["advance:cancellation_pending"]
            )
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        control = plan.get("origin", {}).get("control_tower", {})
        if reason == "deadline_expired" and now_ms <= control.get(
            "expires_at_ms", now_ms
        ):
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:deadline_not_expired"],
            )
        try:
            self.engine.append_event(
                run_id,
                run_engine.KIND_APPLIED,
                "kernel",
                {
                    "roles": [],
                    "status": "CANCEL_REQUESTED",
                    "deliverables": {},
                    "evidence": {},
                    "cancellation": {
                        "status": "requested",
                        "reason": reason,
                        "requested_at_ms": now_ms,
                        "prior_seq": current_cursor["seq"],
                    },
                },
                expected_seq=current_cursor["seq"],
                expected_prev_hash=current_cursor["event_hash"],
            )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        current_events = list(self.engine.events(run_id, 0))
        current_state = self.engine.reduce(plan, current_events)
        cleanup_intent = _cleanup_intent(
            control=control,
            run_id=run_id,
            context_sha256=current_state["stream_sha256"],
            requested_at_ms=now_ms,
            prior_seq=current_cursor["seq"],
        )
        decision = _seal(
            {
                "schema": DECISION_SCHEMA,
                "decision_status": "CANCELLATION_PENDING",
                "prior_cursor": current_cursor,
                "accepted_input_sha256": _sha256(payload),
                "resulting_cursor": _cursor(run_id, current_events, current_state),
                "state_sha256": _sha256(dict(current_state)),
                "reason_codes": [
                    "advance:timeout_requested"
                    if reason == "deadline_expired"
                    else "advance:cancellation_requested"
                ],
                "intents": [cleanup_intent],
                "budget_settlement": {"reserved": True},
                "authority_settlement": {"consumed": False},
            },
            "decision_sha256",
        )
        return decision, []

    def _state_refusal(
        self,
        payload: Mapping[str, Any],
        cursor: Mapping[str, Any],
        state: Mapping[str, Any],
        reason_codes: list[str],
    ) -> tuple[dict[str, Any], list[str]]:
        return (
            _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "REFUSED",
                    "prior_cursor": cursor,
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": cursor,
                    "state_sha256": _sha256(dict(state)),
                    "reason_codes": sorted(set(reason_codes)),
                    "intents": [],
                    "budget_settlement": {"reserved": False},
                    "authority_settlement": {"consumed": False},
                },
                "decision_sha256",
            ),
            [],
        )

    def _cas_refusal(
        self,
        payload: Mapping[str, Any],
        run_id: str,
    ) -> tuple[dict[str, Any], list[str]]:
        """Return the canonical state won by another cursor-bound writer."""
        events = list(self.engine.events(run_id, 0))
        plan = json.loads(events[0]["payload"])["plan"]
        state = self.engine.reduce(plan, events)
        cursor = _cursor(run_id, events, state)
        return (
            _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "REFUSED",
                    "prior_cursor": deepcopy(dict(payload["prior_cursor"])),
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": cursor,
                    "state_sha256": _sha256(dict(state)),
                    "reason_codes": ["advance:cas_conflict"],
                    "intents": [],
                    "budget_settlement": {"reserved": False},
                    "authority_settlement": {"consumed": False},
                },
                "decision_sha256",
            ),
            [],
        )

    def _cursor_refusal(
        self,
        payload: Mapping[str, Any],
        cursor: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        return (
            _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "REFUSED",
                    "prior_cursor": cursor,
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": cursor,
                    "state_sha256": _sha256(dict(state)),
                    "reason_codes": ["advance:stale_cursor"],
                    "intents": [],
                    "budget_settlement": {"reserved": False},
                    "authority_settlement": {"consumed": False},
                },
                "decision_sha256",
            ),
            [],
        )

    def _post_terminal_refusal(
        self,
        payload: Mapping[str, Any],
        cursor: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        return (
            _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "REFUSED",
                    "prior_cursor": cursor,
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": cursor,
                    "state_sha256": _sha256(dict(state)),
                    "reason_codes": ["advance:post_terminal"],
                    "intents": [],
                    "budget_settlement": {"reserved": False, "settled": True},
                    "authority_settlement": {"consumed": False, "settled": True},
                },
                "decision_sha256",
            ),
            [],
        )

    def _observe_terminal_worker_result(
        self,
        payload: Mapping[str, Any],
        *,
        run_id: str,
        events: list[Mapping[str, Any]],
        plan: Mapping[str, Any],
        state: Mapping[str, Any],
        current_cursor: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        intent = observation.get("intent")
        result = observation.get("result")
        if not _intent_valid(intent, "dispatch") or not isinstance(
            result, Mapping
        ):
            return None, ["advance:terminal_worker_result_invalid"]
        terminal_state = {
            "REJECTED": "failed",
            "UNAVAILABLE": "failed",
            "TIMED_OUT": "failed",
            "CANCELLED": "cancelled",
        }.get(result.get("status"))
        if terminal_state is None:
            return None, ["advance:worker_result_not_terminal"]
        control = plan.get("origin", {}).get("control_tower", {})
        node_id = str(intent.get("node_id"))
        bound = control.get("dispatch_intent")
        if bound != intent:
            bound = control.get("dispatch_intents", {}).get(node_id)
        if bound != intent:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:dispatch_binding_mismatch"],
            )
        try:
            lane_reserved = self._lane_reservation_active(run_id, node_id)
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["advance:lane_ledger_invalid"]
        if not lane_reserved:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:dispatch_lane_unreserved"],
            )
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        if now_ms < intent["not_before_ms"] or now_ms > intent["expires_at_ms"]:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:dispatch_intent_expired"],
            )
        receipt = observation.get("lane_release_receipt")
        if not lane_capacity.validate_release_receipt(
            receipt,
            lane_id=_lane_identity(run_id, node_id),
            run_id=run_id,
            route=lane_capacity.CONTROL_TOWER_ROUTE,
            terminal_state=terminal_state,
        ):
            return None, ["advance:lane_release_receipt_invalid"]
        deliverables = {
            "lane_release_receipt:" + node_id: json.dumps(
                receipt, sort_keys=True, separators=(",", ":")
            ),
            "lane_release_evaluation_time:" + node_id: observation[
                "lane_release_evaluation_time"
            ],
            "worker_terminal_status:" + node_id: str(result["status"]),
            "worker_usage:" + node_id: json.dumps(
                result["usage"], sort_keys=True, separators=(",", ":")
            ),
            "worker_timing:" + node_id: json.dumps(
                result["timing"], sort_keys=True, separators=(",", ":")
            ),
            "worker_runtime:" + node_id: json.dumps(
                result["runtime"], sort_keys=True, separators=(",", ":")
            ),
        }
        started = json.loads(events[0]["payload"])
        assignments = started.get("assignments", {})
        actor_assignment = assignments.get(node_id)
        actor_role = node_id
        if not isinstance(actor_assignment, Mapping):
            actor_assignment = assignments.get("executor")
            actor_role = "executor"
        actor_key = (
            actor_assignment.get("actor_key")
            if isinstance(actor_assignment, Mapping)
            else None
        )
        if not isinstance(actor_key, str):
            return None, ["advance:terminal_worker_actor_unbound"]
        try:
            self.engine.apply(
                run_id,
                actor_key,
                roles=(actor_role,),
                status="ERROR",
                deliverables=deliverables,
                evidence={
                    "worker_result:" + node_id: (
                        worker_transport.canonical_sha256(result)
                    )
                },
                expected_seq=current_cursor["seq"],
                expected_prev_hash=current_cursor["event_hash"],
            )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        except (run_engine.MalformedInputError, run_engine.ProtocolError):
            return None, ["advance:terminal_worker_fact_rejected"]

        failed_events = list(self.engine.events(run_id, 0))
        failed_state = self.engine.reduce(plan, failed_events)
        failed_cursor = _cursor(run_id, failed_events, failed_state)
        try:
            _ledger_events, active_lanes, _authority_state = (
                self._lane_ledger_state()
            )
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["advance:lane_ledger_invalid"]
        other_active = [
            key
            for key in active_lanes
            if key[0] == run_id and key[1] != node_id
        ]

        if other_active:
            cancellation, cancellation_issues = self._cancel(
                {
                    "schema": ADVANCE_SCHEMA,
                    "kind": "cancel",
                    "run_id": run_id,
                    "prior_cursor": failed_cursor,
                    "reason": "user_requested",
                }
            )
            if cancellation is None or cancellation_issues:
                return cancellation, cancellation_issues
            dispatch_intents, released_lanes, reserved_lanes = (
                self._rebalance_lane_reservations(now_ms)
            )
            return (
                _seal(
                    {
                        "schema": DECISION_SCHEMA,
                        "decision_status": "CANCELLATION_PENDING",
                        "prior_cursor": current_cursor,
                        "accepted_input_sha256": _sha256(payload),
                        "resulting_cursor": cancellation["resulting_cursor"],
                        "state_sha256": cancellation["state_sha256"],
                        "reason_codes": [
                            "advance:worker_"
                            + ("cancelled" if terminal_state == "cancelled" else "failed")
                            + "_cleanup_pending"
                        ],
                        "intents": [
                            *cancellation["intents"],
                            *dispatch_intents,
                        ],
                        "budget_settlement": {
                            "reserved": True,
                            "released_lanes": released_lanes,
                            "reserved_lanes": reserved_lanes,
                        },
                        "authority_settlement": {"consumed": False},
                    },
                    "decision_sha256",
                ),
                [],
            )

        try:
            if terminal_state == "cancelled":
                self.engine.cancel(
                    run_id,
                    note="worker reported cancellation",
                    expected_seq=failed_cursor["seq"],
                    expected_prev_hash=failed_cursor["event_hash"],
                )
            else:
                integrator = started.get("assignments", {}).get("integrator")
                actor_key = (
                    integrator.get("actor_key")
                    if isinstance(integrator, Mapping)
                    else "kernel"
                )
                self.engine.complete(
                    run_id,
                    actor_key,
                    "ERROR",
                    note="worker reported terminal failure",
                    expected_seq=failed_cursor["seq"],
                    expected_prev_hash=failed_cursor["event_hash"],
                )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        except (run_engine.MalformedInputError, run_engine.ProtocolError):
            return None, ["advance:terminal_worker_transition_rejected"]
        dispatch_intents, released_lanes, reserved_lanes = (
            self._rebalance_lane_reservations(now_ms)
        )
        final_events = list(self.engine.events(run_id, 0))
        final_state = self.engine.reduce(plan, final_events)
        return (
            _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "TERMINATED",
                    "prior_cursor": current_cursor,
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": _cursor(
                        run_id, final_events, final_state
                    ),
                    "state_sha256": _sha256(dict(final_state)),
                    "reason_codes": [
                        "advance:worker_"
                        + ("cancelled" if terminal_state == "cancelled" else "failed")
                    ],
                    "intents": dispatch_intents,
                    "budget_settlement": {
                        "reserved": bool(dispatch_intents),
                        "settled": True,
                        "released_lanes": released_lanes,
                        "reserved_lanes": reserved_lanes,
                    },
                    "authority_settlement": {
                        "consumed": False,
                        "settled": True,
                    },
                },
                "decision_sha256",
            ),
            [],
        )

    def _observe(self, payload: Any) -> tuple[dict[str, Any] | None, list[str]]:
        if not isinstance(payload, Mapping) or set(payload) != _OBSERVE_FIELDS:
            return None, ["advance:payload_invalid"]
        if payload.get("schema") != ADVANCE_SCHEMA:
            return None, ["advance:schema_invalid"]
        run_id = payload.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            return None, ["advance:run_id_invalid"]
        try:
            events = list(self.engine.events(run_id, 0))
        except run_engine.NotFoundError:
            return None, ["advance:run_not_found"]
        started = json.loads(events[0]["payload"])
        plan = started["plan"]
        state = self.engine.reduce(plan, events)
        current_cursor = _cursor(run_id, events, state)
        if payload.get("prior_cursor") != current_cursor:
            return self._cursor_refusal(payload, current_cursor, state)
        if state["terminal"]:
            return self._post_terminal_refusal(payload, current_cursor, state)

        cancellation_pending = _cancellation_requested(events)
        observation_kind = (
            payload.get("observation", {}).get("kind")
            if isinstance(payload.get("observation"), Mapping)
            else None
        )
        if cancellation_pending and observation_kind != "cleanup":
            refusal = _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "REFUSED",
                    "prior_cursor": current_cursor,
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": current_cursor,
                    "state_sha256": _sha256(dict(state)),
                    "reason_codes": ["advance:cancellation_pending"],
                    "intents": [],
                    "budget_settlement": {"reserved": False},
                    "authority_settlement": {"consumed": False},
                },
                "decision_sha256",
            )
            return refusal, []

        observation = _exact(
            payload.get("observation"), _OBSERVATION_FIELDS, "advance:observation", []
        )
        if (
            not isinstance(payload.get("observation"), Mapping)
            or set(payload["observation"]) != _OBSERVATION_FIELDS
        ):
            return None, ["advance:worker_observation_invalid"]
        if observation.get("kind") == "worker_result":
            cleanup_evaluation_time = self._cleanup_observer_now()
            worker_result, lane_release_receipt = _worker_result_release(
                observation.get("result"),
                run_id=run_id,
                intent=observation.get("intent"),
                cleanup_trust_store=self._cleanup_observer_trust_store,
                cleanup_replay_guard=self._cleanup_observer_replay_guard,
                cleanup_evaluation_time=cleanup_evaluation_time,
            )
            if worker_result is None or lane_release_receipt is None:
                return None, ["advance:lane_release_receipt_invalid"]
            observation = dict(observation)
            observation["result"] = worker_result
            observation["lane_release_receipt"] = lane_release_receipt
            observation["lane_release_evaluation_time"] = (
                cleanup_evaluation_time
            )
        control = plan.get("origin", {}).get("control_tower", {})
        if (
            observation.get("kind") == "worker_result"
            and observation.get("result", {}).get("status")
            != "CANDIDATE_READY"
        ):
            return self._observe_terminal_worker_result(
                payload,
                run_id=run_id,
                events=events,
                plan=plan,
                state=state,
                current_cursor=current_cursor,
                observation=observation,
            )
        if control.get("profile_id") == "best_of_n/v1":
            if observation.get("kind") == "worker_result":
                return self._observe_best_candidate(
                    payload,
                    run_id=run_id,
                    events=events,
                    plan=plan,
                    state=state,
                    current_cursor=current_cursor,
                    observation=observation,
                )
            if observation.get("kind") == "comparison_result":
                return self._observe_best_comparison(
                    payload,
                    run_id=run_id,
                    events=events,
                    plan=plan,
                    state=state,
                    current_cursor=current_cursor,
                    observation=observation,
                )
        if control.get("profile_id") == "finite_dag/v1":
            if observation.get("kind") == "worker_result":
                return self._observe_parallel_producer(
                    payload,
                    run_id=run_id,
                    events=events,
                    plan=plan,
                    state=state,
                    current_cursor=current_cursor,
                    observation=observation,
                )
            if observation.get("kind") == "join_result":
                return self._observe_parallel_join(
                    payload,
                    run_id=run_id,
                    events=events,
                    plan=plan,
                    state=state,
                    current_cursor=current_cursor,
                    observation=observation,
                )
        if control.get("profile_id") == "parallel_join/v1":
            if observation.get("kind") == "worker_result":
                return self._observe_parallel_producer(
                    payload,
                    run_id=run_id,
                    events=events,
                    plan=plan,
                    state=state,
                    current_cursor=current_cursor,
                    observation=observation,
                )
            if observation.get("kind") == "join_result":
                return self._observe_parallel_join(
                    payload,
                    run_id=run_id,
                    events=events,
                    plan=plan,
                    state=state,
                    current_cursor=current_cursor,
                    observation=observation,
                )
        if (
            control.get("profile_id") == "execute_verify_repair/v1"
            and observation.get("kind") == "worker_result"
            and isinstance(observation.get("intent"), Mapping)
            and observation["intent"].get("node_id")
            != control.get("dispatch_intent", {}).get("node_id")
        ):
            return self._observe_repair_worker(
                payload,
                run_id=run_id,
                events=events,
                plan=plan,
                state=state,
                current_cursor=current_cursor,
                observation=observation,
            )
        if observation.get("kind") == "verification":
            return self._observe_verification(
                payload,
                run_id=run_id,
                events=events,
                plan=plan,
                state=state,
                current_cursor=current_cursor,
                observation=observation,
            )
        if observation.get("kind") == "cleanup":
            return self._observe_cleanup(
                payload,
                run_id=run_id,
                events=events,
                plan=plan,
                state=state,
                current_cursor=current_cursor,
                observation=observation,
            )
        if observation.get("kind") != "worker_result":
            return None, ["advance:observation_kind_invalid"]
        intent = observation.get("intent")
        if not _intent_valid(intent, "dispatch"):
            return None, ["advance:dispatch_intent_invalid"]

        if control.get("scheduling_mode") == "queued":
            try:
                reservation = next(
                    (
                        record
                        for record in self._scheduler_reservations()
                        if record["run_id"] == run_id
                    ),
                    None,
                )
            except _SCHEDULER_STATE_EXCEPTIONS:
                return None, ["advance:scheduler_reservation_invalid"]
            if (
                reservation is None
                or reservation.get("intent_sha256")
                != intent.get("intent_sha256")
            ):
                return self._state_refusal(
                    payload,
                    current_cursor,
                    state,
                    ["advance:dispatch_not_reserved"],
                )

        if intent != control.get("dispatch_intent"):
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:dispatch_binding_mismatch"],
            )
        try:
            lane_reserved = self._lane_reservation_active(
                run_id, str(intent.get("node_id"))
            )
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["advance:lane_ledger_invalid"]
        if not lane_reserved:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:dispatch_lane_unreserved"],
            )
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        if now_ms < intent["not_before_ms"] or now_ms > intent["expires_at_ms"]:
            return self._state_refusal(
                payload, current_cursor, state, ["advance:dispatch_intent_expired"]
            )
        result_report = worker_transport.validate_worker_result(
            observation.get("result"),
            expected_call_sha256=control.get("worker_call_sha256"),
            expected_manifest_sha256=control.get("model_manifest_sha256"),
        )
        if result_report.get("status") != "PASS":
            return None, ["advance:worker_result_invalid"]
        result = result_report["canonical"]
        if result.get("status") != "CANDIDATE_READY":
            return None, ["advance:worker_result_not_ready"]
        manifest = control.get("model_manifest", {})
        runtime = result.get("runtime", {})
        if (
            runtime.get("logical_model_id") != manifest.get("logical_model_id")
            or runtime.get("served_name") not in manifest.get("served_names", [])
            or runtime.get("checkpoint_revision") != manifest.get("checkpoint_revision")
            or runtime.get("runtime_id") != "provider-free-fake/v1"
        ):
            return None, ["advance:runtime_identity_mismatch"]

        task_spec = control.get("task_spec")
        task_report = contracts.validate_task_spec(task_spec)
        if task_report.get("status") != "PASS":
            return None, ["advance:bound_task_spec_invalid"]
        capability = _bound_executor_capability(control)
        if capability is None:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:bound_capability_invalid"],
            )
        if _worker_result_exceeds_budget(result, task_spec, capability):
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:worker_budget_exceeded"],
            )
        try:
            artifact = self.artifacts.publish(
                result["candidate"]["diff"],
                media_type=task_spec["deliverable"]["media_type"],
                provenance={
                    "producer_run_id": run_id,
                    "producer_node_id": "executor",
                    "task_spec_sha256": task_report["digest"],
                    "content_schema": task_spec["deliverable"]["schema"],
                    "privacy_class": control["privacy_class"],
                    "custody_receipt_sha256": result["evidence"]["sha256"],
                    "source_lineage": task_spec["input_refs"],
                    "consumer_node_ids": ["reviewer"],
                    "retention_state": "terminal_result",
                },
            )
        except ValueError as exc:
            reason = (
                "advance:artifact_provenance_conflict"
                if str(exc) == "artifact_provenance_conflict"
                else "advance:artifact_publish_refused"
            )
            return self._state_refusal(payload, current_cursor, state, [reason])
        checks = [
            {
                "id": check["id"],
                "status": "passed",
                "required": check["required"],
                "evidence_refs": [artifact],
            }
            for check in task_spec["acceptance_checks"]
        ]
        handoff = contracts.seal_handoff_receipt(
            {
                "schema": contracts.HANDOFF_RECEIPT_SCHEMA,
                "disposition": "complete",
                "task_spec_sha256": task_report["digest"],
                "result_summary": "The bounded direct executor produced one verified artifact.",
                "claims": [
                    {
                        "id": "direct-result",
                        "statement": "The direct executor produced the declared artifact.",
                        "epistemic_status": "verified",
                        "evidence_refs": [artifact],
                    }
                ],
                "artifact_refs": [artifact],
                "checks": checks,
                "conflicts": [],
                "unknowns": [],
                "requested_decisions": [],
                "raw_trace_ref": None,
            },
            task_spec=task_spec,
        )
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        verification_intent = _verification_intent(
            dispatch_intent=intent,
            control=control,
            task_spec=task_spec,
            handoff=handoff,
            now_ms=now_ms,
        )
        try:
            self.engine.apply(
                run_id,
                "executor",
                roles=("executor",),
                status="SUCCESS",
                deliverables={
                    "artifact_ref": json.dumps(artifact, sort_keys=True, separators=(",", ":")),
                    "handoff_receipt": json.dumps(handoff, sort_keys=True, separators=(",", ":")),
                    "lane_release_receipt:" + str(intent["node_id"]): json.dumps(
                        observation["lane_release_receipt"],
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    "lane_release_evaluation_time:"
                    + str(intent["node_id"]): observation[
                        "lane_release_evaluation_time"
                    ],
                    "worker_usage": json.dumps(
                        result["usage"], sort_keys=True, separators=(",", ":")
                    ),
                    "worker_timing": json.dumps(
                        result["timing"], sort_keys=True, separators=(",", ":")
                    ),
                    "worker_runtime": json.dumps(
                        result["runtime"], sort_keys=True, separators=(",", ":")
                    ),
                },
                evidence={
                    "executor": handoff["handoff_sha256"],
                    "worker_result": worker_transport.canonical_sha256(result),
                    "verification_intent": verification_intent["intent_sha256"],
                },
                expected_seq=current_cursor["seq"],
                expected_prev_hash=current_cursor["event_hash"],
            )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        except (run_engine.MalformedInputError, run_engine.ProtocolError):
            return None, ["advance:worker_fact_rejected"]

        events = list(self.engine.events(run_id, 0))
        state = self.engine.reduce(plan, events)
        try:
            dispatch_intents, released_lanes, reserved_lanes = (
                self._rebalance_lane_reservations(now_ms)
            )
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["advance:lane_ledger_invalid"]
        decision = _seal(
            {
                "schema": DECISION_SCHEMA,
                "decision_status": "ADVANCED",
                "prior_cursor": current_cursor,
                "accepted_input_sha256": _sha256(payload),
                "resulting_cursor": _cursor(run_id, events, state),
                "state_sha256": _sha256(dict(state)),
                "reason_codes": ["advance:worker_result_applied"],
                "intents": [verification_intent, *dispatch_intents],
                "budget_settlement": {
                    "reserved": True,
                    "released_lanes": released_lanes,
                    "reserved_lanes": reserved_lanes,
                },
                "authority_settlement": {"consumed": False},
            },
            "decision_sha256",
        )
        return decision, []

    def _observe_best_candidate(
        self,
        payload: Mapping[str, Any],
        *,
        run_id: str,
        events: list[Mapping[str, Any]],
        plan: Mapping[str, Any],
        state: Mapping[str, Any],
        current_cursor: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        intent = observation.get("intent")
        if not _intent_valid(intent, "dispatch"):
            return None, ["advance:candidate_intent_invalid"]
        control = plan.get("origin", {}).get("control_tower", {})
        node_id = intent.get("node_id")
        if (
            intent != control.get("dispatch_intents", {}).get(node_id)
            or node_id not in control.get("worker_calls", {})
        ):
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:candidate_binding_mismatch"],
            )
        try:
            lane_reserved = self._lane_reservation_active(
                run_id, str(node_id)
            )
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["advance:lane_ledger_invalid"]
        if not lane_reserved:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:candidate_lane_unreserved"],
            )
        applied_roles = set()
        for event in events:
            if event["kind"] == run_engine.KIND_APPLIED:
                applied_roles.update(
                    json.loads(event["payload"]).get("roles", [])
                )
        if node_id in applied_roles:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:candidate_already_applied"],
            )
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        if now_ms < intent["not_before_ms"] or now_ms > intent["expires_at_ms"]:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:candidate_intent_expired"],
            )
        result_report = worker_transport.validate_worker_result(
            observation.get("result"),
            expected_call_sha256=control["worker_call_hashes"].get(node_id),
            expected_manifest_sha256=control.get("model_manifest_sha256"),
        )
        if result_report.get("status") != "PASS":
            return None, ["advance:candidate_worker_result_invalid"]
        result = result_report["canonical"]
        if result.get("status") != "CANDIDATE_READY":
            return None, ["advance:candidate_worker_result_not_ready"]
        task_spec = control.get("task_specs", {}).get(node_id)
        task_report = contracts.validate_task_spec(task_spec)
        capability = _bound_executor_capability(control)
        if task_report.get("status") != "PASS" or capability is None:
            return None, ["advance:candidate_contract_invalid"]
        if _worker_result_exceeds_budget(result, task_spec, capability):
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:worker_budget_exceeded"],
            )
        manifest = control.get("model_manifest", {})
        runtime = result.get("runtime", {})
        if (
            runtime.get("logical_model_id") != manifest.get("logical_model_id")
            or runtime.get("served_name") not in manifest.get("served_names", [])
            or runtime.get("checkpoint_revision")
            != manifest.get("checkpoint_revision")
            or runtime.get("runtime_id") != "provider-free-fake/v1"
        ):
            return None, ["advance:runtime_identity_mismatch"]
        try:
            artifact = self.artifacts.publish(
                result["candidate"]["diff"],
                media_type=task_spec["deliverable"]["media_type"],
                provenance={
                    "producer_run_id": run_id,
                    "producer_node_id": node_id,
                    "task_spec_sha256": task_report["digest"],
                    "content_schema": task_spec["deliverable"]["schema"],
                    "privacy_class": control["privacy_class"],
                    "custody_receipt_sha256": result["evidence"]["sha256"],
                    "source_lineage": task_spec["input_refs"],
                    "consumer_node_ids": ["comparator", "reviewer"],
                    "retention_state": "consumed_by_join",
                },
            )
        except ValueError as exc:
            reason = (
                "advance:artifact_provenance_conflict"
                if str(exc) == "artifact_provenance_conflict"
                else "advance:artifact_publish_refused"
            )
            return self._state_refusal(
                payload, current_cursor, state, [reason]
            )
        checks = [
            {
                "id": check["id"],
                "status": "passed",
                "required": check["required"],
                "evidence_refs": [artifact],
            }
            for check in task_spec["acceptance_checks"]
        ]
        handoff = contracts.seal_handoff_receipt(
            {
                "schema": contracts.HANDOFF_RECEIPT_SCHEMA,
                "disposition": "complete",
                "task_spec_sha256": task_report["digest"],
                "result_summary": "One isolated candidate is ready for blinded comparison.",
                "claims": [
                    {
                        "id": "candidate-result",
                        "statement": "One budget-matched candidate was produced.",
                        "epistemic_status": "verified",
                        "evidence_refs": [artifact],
                    }
                ],
                "artifact_refs": [artifact],
                "checks": checks,
                "conflicts": [],
                "unknowns": [],
                "requested_decisions": [],
                "raw_trace_ref": None,
            },
            task_spec=task_spec,
        )
        try:
            self.engine.apply(
                run_id,
                node_id,
                roles=(node_id,),
                status="SUCCESS",
                deliverables={
                    "artifact_ref": json.dumps(
                        artifact, sort_keys=True, separators=(",", ":")
                    ),
                    "handoff_receipt": json.dumps(
                        handoff, sort_keys=True, separators=(",", ":")
                    ),
                    "lane_release_receipt:" + str(intent["node_id"]): json.dumps(
                        observation["lane_release_receipt"],
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    "lane_release_evaluation_time:"
                    + str(intent["node_id"]): observation[
                        "lane_release_evaluation_time"
                    ],
                    "worker_usage:" + node_id: json.dumps(
                        result["usage"], sort_keys=True, separators=(",", ":")
                    ),
                    "worker_timing:" + node_id: json.dumps(
                        result["timing"], sort_keys=True, separators=(",", ":")
                    ),
                    "worker_runtime:" + node_id: json.dumps(
                        result["runtime"], sort_keys=True, separators=(",", ":")
                    ),
                },
                evidence={
                    node_id: handoff["handoff_sha256"],
                    "worker_result": worker_transport.canonical_sha256(
                        result
                    ),
                },
                expected_seq=current_cursor["seq"],
                expected_prev_hash=current_cursor["event_hash"],
            )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        except (run_engine.MalformedInputError, run_engine.ProtocolError):
            return None, ["advance:candidate_fact_rejected"]

        final_events = list(self.engine.events(run_id, 0))
        final_state = self.engine.reduce(plan, final_events)
        try:
            dispatch_intents, released_lanes, reserved_lanes = (
                self._rebalance_lane_reservations(now_ms)
            )
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["advance:lane_ledger_invalid"]
        candidate_ids = sorted(control.get("dispatch_intents", {}))
        applied_after = set()
        handoffs = []
        for event in final_events:
            if event["kind"] != run_engine.KIND_APPLIED:
                continue
            facts = json.loads(event["payload"])
            roles = set(facts.get("roles", []))
            applied_after.update(roles)
            if roles & set(candidate_ids):
                raw_handoff = facts.get("deliverables", {}).get(
                    "handoff_receipt"
                )
                if isinstance(raw_handoff, str):
                    handoffs.append(json.loads(raw_handoff))
        intents = list(dispatch_intents)
        reason = "advance:candidate_applied"
        if set(candidate_ids) <= applied_after:
            try:
                comparison = _comparison_intent(
                    dispatch_intent=intent,
                    control=control,
                    task_spec=control["task_spec"],
                    candidate_handoffs=handoffs,
                    now_ms=now_ms,
                )
            except (KeyError, TypeError, ValueError):
                return None, ["advance:comparison_intent_invalid"]
            intents = [comparison, *dispatch_intents]
            reason = "advance:comparison_ready"
        return (
            _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "ADVANCED",
                    "prior_cursor": current_cursor,
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": _cursor(
                        run_id, final_events, final_state
                    ),
                    "state_sha256": _sha256(dict(final_state)),
                    "reason_codes": [reason],
                    "intents": intents,
                    "budget_settlement": {
                        "reserved": True,
                        "released_lanes": released_lanes,
                        "reserved_lanes": reserved_lanes,
                    },
                    "authority_settlement": {"consumed": False},
                },
                "decision_sha256",
            ),
            [],
        )

    def _observe_best_comparison(
        self,
        payload: Mapping[str, Any],
        *,
        run_id: str,
        events: list[Mapping[str, Any]],
        plan: Mapping[str, Any],
        state: Mapping[str, Any],
        current_cursor: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        intent = observation.get("intent")
        if not _intent_valid(intent, "comparison"):
            return None, ["advance:comparison_intent_invalid"]
        control = plan.get("origin", {}).get("control_tower", {})
        handoffs = []
        candidate_ids = set(control.get("dispatch_intents", {}))
        for event in events:
            if event["kind"] != run_engine.KIND_APPLIED:
                continue
            facts = json.loads(event["payload"])
            if not set(facts.get("roles", [])) & candidate_ids:
                continue
            raw_handoff = facts.get("deliverables", {}).get(
                "handoff_receipt"
            )
            if isinstance(raw_handoff, str):
                handoffs.append(json.loads(raw_handoff))
        try:
            expected = _comparison_intent(
                dispatch_intent=next(iter(control["dispatch_intents"].values())),
                control=control,
                task_spec=control["task_spec"],
                candidate_handoffs=handoffs,
                now_ms=intent["not_before_ms"],
            )
        except (KeyError, TypeError, ValueError):
            return None, ["advance:comparison_binding_invalid"]
        if expected != intent:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:comparison_binding_mismatch"],
            )
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        if now_ms < intent["not_before_ms"] or now_ms > intent["expires_at_ms"]:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:comparison_intent_expired"],
            )
        result = observation.get("result")
        if (
            not isinstance(result, Mapping)
            or set(result) != _COMPARISON_RESULT_FIELDS
            or result.get("schema") != COMPARISON_RESULT_SCHEMA
            or not _seal_valid(result, "comparison_sha256")
        ):
            return None, ["advance:comparison_result_invalid"]
        status = result.get("status")
        if status not in {"winner", "synthesis", "tie", "escalate"}:
            return None, ["advance:comparison_status_invalid"]
        labels = [
            candidate["label"]
            for candidate in intent["payload"]["blinded_candidates"]
        ]
        if result.get("blinded_candidate_labels") != labels:
            return None, ["advance:comparison_labels_mismatch"]
        selected = result.get("selected_labels")
        if (
            not isinstance(selected, list)
            or len(selected) != len(set(selected))
            or any(label not in labels for label in selected)
        ):
            return None, ["advance:comparison_selection_invalid"]
        output_body = result.get("output_body")
        if status == "winner" and (len(selected) != 1 or output_body is not None):
            return None, ["advance:comparison_selection_invalid"]
        if status == "synthesis" and (
            not selected
            or intent["payload"]["selection_mode"] != "winner_or_synthesis"
            or not isinstance(output_body, str)
            or not output_body
            or len(output_body.encode("utf-8")) > 65536
        ):
            return None, ["advance:comparison_synthesis_invalid"]
        if status in {"tie", "escalate"} and (
            selected or output_body is not None
        ):
            return None, ["advance:comparison_terminal_invalid"]
        task_spec = intent["payload"]["task_spec"]
        criterion_ids = [
            check["id"] for check in task_spec["acceptance_checks"]
        ]
        if result.get("criterion_ids") != criterion_ids:
            return None, ["advance:comparison_criteria_mismatch"]
        baseline = intent["payload"]["direct_baseline"]
        if (
            result.get("direct_baseline_evidence_sha256")
            != baseline["evidence_sha256"]
            or not isinstance(result.get("evidence_sha256"), str)
            or _SHA256.fullmatch(result["evidence_sha256"]) is None
        ):
            return None, ["advance:comparison_evidence_invalid"]

        if status in {"tie", "escalate"}:
            try:
                self.engine.apply(
                    run_id,
                    task_spec["id"],
                    roles=("integrator",),
                    status="ERROR",
                    deliverables={
                        "comparison_result": json.dumps(
                            result, sort_keys=True, separators=(",", ":")
                        )
                    },
                    evidence={"integrator": result["comparison_sha256"]},
                    expected_seq=current_cursor["seq"],
                    expected_prev_hash=current_cursor["event_hash"],
                )
                compared_events = list(self.engine.events(run_id, 0))
                compared_state = self.engine.reduce(plan, compared_events)
                compared_cursor = _cursor(
                    run_id, compared_events, compared_state
                )
                self.engine.complete(
                    run_id,
                    task_spec["id"],
                    status="ERROR",
                    note="best-of-N comparison did not select a result",
                    expected_seq=compared_cursor["seq"],
                    expected_prev_hash=compared_cursor["event_hash"],
                )
            except run_store.StaleSeqError:
                return self._cas_refusal(payload, run_id)
            final_events = list(self.engine.events(run_id, 0))
            final_state = self.engine.reduce(plan, final_events)
            return (
                _seal(
                    {
                        "schema": DECISION_SCHEMA,
                        "decision_status": "FAILED",
                        "prior_cursor": current_cursor,
                        "accepted_input_sha256": _sha256(payload),
                        "resulting_cursor": _cursor(
                            run_id, final_events, final_state
                        ),
                        "state_sha256": _sha256(dict(final_state)),
                        "reason_codes": [
                            "advance:comparison_tie"
                            if status == "tie"
                            else "advance:comparison_escalated"
                        ],
                        "intents": [],
                        "budget_settlement": {
                            "reserved": False,
                            "settled": True,
                        },
                        "authority_settlement": {
                            "consumed": False,
                            "settled": True,
                        },
                    },
                    "decision_sha256",
                ),
                [],
            )

        by_label = {
            candidate["label"]: candidate["artifact_ref"]
            for candidate in intent["payload"]["blinded_candidates"]
        }
        selected_refs = [by_label[label] for label in selected]
        if status == "winner":
            artifact = selected_refs[0]
        else:
            try:
                artifact = self.artifacts.publish(
                    output_body,
                    media_type=task_spec["deliverable"]["media_type"],
                    provenance={
                        "producer_run_id": run_id,
                        "producer_node_id": task_spec["id"],
                        "task_spec_sha256": task_spec[
                            "task_spec_sha256"
                        ],
                        "content_schema": task_spec["deliverable"]["schema"],
                        "privacy_class": control["privacy_class"],
                        "custody_receipt_sha256": result[
                            "evidence_sha256"
                        ],
                        "source_lineage": selected_refs,
                        "consumer_node_ids": ["reviewer"],
                        "retention_state": "terminal_result",
                    },
                )
            except ValueError:
                return self._state_refusal(
                    payload,
                    current_cursor,
                    state,
                    ["advance:artifact_publish_refused"],
                )
        checks = [
            {
                "id": check["id"],
                "status": "passed",
                "required": check["required"],
                "evidence_refs": [artifact],
            }
            for check in task_spec["acceptance_checks"]
        ]
        handoff = contracts.seal_handoff_receipt(
            {
                "schema": contracts.HANDOFF_RECEIPT_SCHEMA,
                "disposition": "complete",
                "task_spec_sha256": task_spec["task_spec_sha256"],
                "result_summary": "The blinded comparator produced one admissible subject.",
                "claims": [
                    {
                        "id": "compared-result",
                        "statement": "The comparator applied its declared outcome against the direct baseline.",
                        "epistemic_status": "verified",
                        "evidence_refs": [artifact],
                    }
                ],
                "artifact_refs": [artifact],
                "checks": checks,
                "conflicts": [],
                "unknowns": [],
                "requested_decisions": [],
                "raw_trace_ref": None,
            },
            task_spec=task_spec,
        )
        verification_intent = _verification_intent(
            dispatch_intent=intent,
            control=control,
            task_spec=task_spec,
            handoff=handoff,
            now_ms=now_ms,
        )
        try:
            self.engine.apply(
                run_id,
                task_spec["id"],
                roles=("integrator",),
                status="SUCCESS",
                deliverables={
                    "artifact_ref": json.dumps(
                        artifact, sort_keys=True, separators=(",", ":")
                    ),
                    "handoff_receipt": json.dumps(
                        handoff, sort_keys=True, separators=(",", ":")
                    ),
                    "comparison_result": json.dumps(
                        result, sort_keys=True, separators=(",", ":")
                    ),
                },
                evidence={
                    "integrator": handoff["handoff_sha256"],
                    "verification_intent": verification_intent[
                        "intent_sha256"
                    ],
                },
                expected_seq=current_cursor["seq"],
                expected_prev_hash=current_cursor["event_hash"],
            )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        final_events = list(self.engine.events(run_id, 0))
        final_state = self.engine.reduce(plan, final_events)
        return (
            _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "ADVANCED",
                    "prior_cursor": current_cursor,
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": _cursor(
                        run_id, final_events, final_state
                    ),
                    "state_sha256": _sha256(dict(final_state)),
                    "reason_codes": ["advance:comparison_applied"],
                    "intents": [verification_intent],
                    "budget_settlement": {"reserved": True},
                    "authority_settlement": {"consumed": False},
                },
                "decision_sha256",
            ),
            [],
        )

    def _observe_parallel_producer(
        self,
        payload: Mapping[str, Any],
        *,
        run_id: str,
        events: list[Mapping[str, Any]],
        plan: Mapping[str, Any],
        state: Mapping[str, Any],
        current_cursor: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        intent = observation.get("intent")
        if not _intent_valid(intent, "dispatch"):
            return None, ["advance:dispatch_intent_invalid"]
        control = plan.get("origin", {}).get("control_tower", {})
        node_id = intent.get("node_id")
        if intent != control.get("dispatch_intents", {}).get(node_id):
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:dispatch_binding_mismatch"],
            )
        try:
            lane_reserved = self._lane_reservation_active(
                run_id, str(node_id)
            )
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["advance:lane_ledger_invalid"]
        if not lane_reserved:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:dispatch_lane_unreserved"],
            )
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        if now_ms < intent["not_before_ms"] or now_ms > intent["expires_at_ms"]:
            return self._state_refusal(
                payload, current_cursor, state, ["advance:dispatch_intent_expired"]
            )

        applied_producers: set[str] = set()
        prior_handoffs: list[dict[str, Any]] = []
        for event in events:
            if event["kind"] != run_engine.KIND_APPLIED:
                continue
            facts = json.loads(event["payload"])
            roles = set(facts.get("roles", []))
            applied_producers.update(
                role for role in roles if role in control.get("dispatch_intents", {})
            )
            handoff_raw = facts.get("deliverables", {}).get("handoff_receipt")
            if roles & set(control.get("dispatch_intents", {})) and isinstance(
                handoff_raw, str
            ):
                try:
                    handoff_value = json.loads(handoff_raw)
                except (TypeError, ValueError):
                    return None, ["advance:producer_history_invalid"]
                if isinstance(handoff_value, Mapping):
                    prior_handoffs.append(dict(handoff_value))
        if node_id in applied_producers:
            return self._state_refusal(
                payload, current_cursor, state, ["advance:producer_replayed"]
            )
        task_spec = control.get("task_specs", {}).get(node_id)
        task_report = contracts.validate_task_spec(task_spec)
        if task_report.get("status") != "PASS":
            return None, ["advance:bound_task_spec_invalid"]
        if not set(task_spec["dependencies"]) <= applied_producers:
            return self._state_refusal(
                payload, current_cursor, state, ["advance:producer_dependency_pending"]
            )

        result_report = worker_transport.validate_worker_result(
            observation.get("result"),
            expected_call_sha256=control.get("worker_call_hashes", {}).get(node_id),
            expected_manifest_sha256=control.get("model_manifest_sha256"),
        )
        if result_report.get("status") != "PASS":
            return None, ["advance:worker_result_invalid"]
        result = result_report["canonical"]
        if result.get("status") != "CANDIDATE_READY":
            return None, ["advance:worker_result_not_ready"]
        manifest = control.get("model_manifest", {})
        runtime = result.get("runtime", {})
        if (
            runtime.get("logical_model_id") != manifest.get("logical_model_id")
            or runtime.get("served_name") not in manifest.get("served_names", [])
            or runtime.get("checkpoint_revision") != manifest.get("checkpoint_revision")
            or runtime.get("runtime_id") != "provider-free-fake/v1"
        ):
            return None, ["advance:runtime_identity_mismatch"]

        capability = _bound_executor_capability(control)
        if capability is None:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:bound_capability_invalid"],
            )
        if _worker_result_exceeds_budget(result, task_spec, capability):
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:worker_budget_exceeded"],
            )

        try:
            projected_artifact = artifact_ledger.project_artifact_ref(
                result["candidate"]["diff"],
                media_type=task_spec["deliverable"]["media_type"],
            )
        except ValueError:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:artifact_publish_refused"],
            )
        checks = [
            {
                "id": check["id"],
                "status": "passed",
                "required": check["required"],
                "evidence_refs": [projected_artifact],
            }
            for check in task_spec["acceptance_checks"]
        ]
        handoff = contracts.seal_handoff_receipt(
            {
                "schema": contracts.HANDOFF_RECEIPT_SCHEMA,
                "disposition": "complete",
                "task_spec_sha256": task_report["digest"],
                "result_summary": "The bounded producer published one immutable partition artifact.",
                "claims": [
                    {
                        "id": node_id + "-partition",
                        "statement": "The producer completed its admitted partition.",
                        "epistemic_status": "verified",
                        "evidence_refs": [projected_artifact],
                    }
                ],
                "artifact_refs": [projected_artifact],
                "checks": checks,
                "conflicts": [],
                "unknowns": [],
                "requested_decisions": [],
                "raw_trace_ref": None,
            },
            task_spec=task_spec,
        )
        projected_handoffs = prior_handoffs + [handoff]
        projected_refs = sorted(
            {
                (ref["uri"], ref["sha256"]): ref
                for projected_handoff in projected_handoffs
                for ref in projected_handoff["artifact_refs"]
            }.values(),
            key=lambda ref: (ref["uri"], ref["sha256"]),
        )
        projected_handoffs = sorted(
            projected_handoffs,
            key=lambda projected_handoff: projected_handoff[
                "task_spec_sha256"
            ],
        )
        projected_ingress_bytes = _integration_ingress_bytes(
            projected_refs,
            projected_handoffs,
        )
        ingress_limit_bytes = control["task_spec"]["budgets"]["context_tokens"] * 4
        if projected_ingress_bytes > ingress_limit_bytes:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:integration_ingress_exceeded"],
            )
        try:
            artifact = self.artifacts.publish(
                result["candidate"]["diff"],
                media_type=task_spec["deliverable"]["media_type"],
                provenance={
                    "producer_run_id": run_id,
                    "producer_node_id": str(node_id),
                    "task_spec_sha256": task_report["digest"],
                    "content_schema": task_spec["deliverable"]["schema"],
                    "privacy_class": control["privacy_class"],
                    "custody_receipt_sha256": result["evidence"]["sha256"],
                    "source_lineage": task_spec["input_refs"],
                    "consumer_node_ids": [control["task_spec"]["id"]],
                    "retention_state": "consumed_by_join",
                },
            )
        except ValueError as exc:
            reason = (
                "advance:artifact_provenance_conflict"
                if str(exc) == "artifact_provenance_conflict"
                else "advance:artifact_publish_refused"
            )
            return self._state_refusal(
                payload, current_cursor, state, [reason]
            )
        if artifact != projected_artifact:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:artifact_projection_mismatch"],
            )

        applied_after = applied_producers | {str(node_id)}
        next_intents: list[dict[str, Any]] = []

        evidence = {
            str(node_id): handoff["handoff_sha256"],
            "worker_result:" + str(node_id): worker_transport.canonical_sha256(
                result
            ),
        }
        if applied_after == set(control.get("dispatch_intents", {})):
            integration_intent = _integration_intent(
                dispatch_intent=intent,
                control=control,
                task_spec=control["task_spec"],
                producer_handoffs=prior_handoffs + [handoff],
                now_ms=now_ms,
            )
            next_intents = [integration_intent]
            evidence["integration_intent"] = integration_intent["intent_sha256"]
        try:
            self.engine.apply(
                run_id,
                str(node_id),
                roles=(str(node_id),),
                status="SUCCESS",
                deliverables={
                    "artifact_ref": json.dumps(
                        artifact, sort_keys=True, separators=(",", ":")
                    ),
                    "handoff_receipt": json.dumps(
                        handoff, sort_keys=True, separators=(",", ":")
                    ),
                    "lane_release_receipt:" + str(node_id): json.dumps(
                        observation["lane_release_receipt"],
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    "lane_release_evaluation_time:"
                    + str(node_id): observation[
                        "lane_release_evaluation_time"
                    ],
                    "released_node_ids": json.dumps(
                        [], sort_keys=True, separators=(",", ":")
                    ),
                    "worker_usage:" + str(node_id): json.dumps(
                        result["usage"], sort_keys=True, separators=(",", ":")
                    ),
                    "worker_timing:" + str(node_id): json.dumps(
                        result["timing"], sort_keys=True, separators=(",", ":")
                    ),
                    "worker_runtime:" + str(node_id): json.dumps(
                        result["runtime"], sort_keys=True, separators=(",", ":")
                    ),
                },
                evidence=evidence,
                expected_seq=current_cursor["seq"],
                expected_prev_hash=current_cursor["event_hash"],
            )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        except (run_engine.MalformedInputError, run_engine.ProtocolError):
            return None, ["advance:producer_fact_rejected"]
        try:
            dispatch_intents, released_lanes, reserved_lanes = (
                self._rebalance_lane_reservations(now_ms)
            )
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["advance:lane_ledger_invalid"]
        next_intents.extend(dispatch_intents)
        final_events = list(self.engine.events(run_id, 0))
        final_state = self.engine.reduce(plan, final_events)
        reason = (
            "advance:parallel_producers_complete"
            if applied_after == set(control.get("dispatch_intents", {}))
            else "advance:parallel_producer_applied"
        )
        return (
            _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "ADVANCED",
                    "prior_cursor": current_cursor,
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": _cursor(run_id, final_events, final_state),
                    "state_sha256": _sha256(dict(final_state)),
                    "reason_codes": [reason],
                    "intents": next_intents,
                    "budget_settlement": {
                        "reserved": True,
                        "released_lanes": released_lanes,
                        "reserved_lanes": reserved_lanes,
                    },
                    "authority_settlement": {"consumed": False},
                },
                "decision_sha256",
            ),
            [],
        )

    def _observe_parallel_join(
        self,
        payload: Mapping[str, Any],
        *,
        run_id: str,
        events: list[Mapping[str, Any]],
        plan: Mapping[str, Any],
        state: Mapping[str, Any],
        current_cursor: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        intent = observation.get("intent")
        if not _intent_valid(intent, "integration"):
            return None, ["advance:integration_intent_invalid"]
        control = plan.get("origin", {}).get("control_tower", {})
        expected_hashes = []
        applied_producers: set[str] = set()
        for event in events:
            if event["kind"] != run_engine.KIND_APPLIED:
                continue
            facts = json.loads(event["payload"])
            applied_producers.update(
                role
                for role in facts.get("roles", [])
                if role in control.get("dispatch_intents", {})
            )
            candidate = facts.get("evidence", {}).get("integration_intent")
            if candidate is not None:
                expected_hashes.append(candidate)
        missing_producers = sorted(
            set(control.get("dispatch_intents", {})) - applied_producers
        )
        if missing_producers:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                [
                    "advance:join_missing_producers:" + producer_id
                    for producer_id in missing_producers
                ],
            )
        if expected_hashes != [intent.get("intent_sha256")]:
            return self._state_refusal(
                payload, current_cursor, state, ["advance:integration_binding_mismatch"]
            )
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        if now_ms < intent["not_before_ms"] or now_ms > intent["expires_at_ms"]:
            return self._state_refusal(
                payload, current_cursor, state, ["advance:integration_intent_expired"]
            )

        result = observation.get("result")
        if not isinstance(result, Mapping) or set(result) != _JOIN_RESULT_FIELDS:
            return None, ["advance:join_result_invalid"]
        if result.get("schema") != JOIN_RESULT_SCHEMA or result.get("status") != "joined":
            return None, ["advance:join_result_invalid"]
        expected_refs = intent["payload"]["input_artifact_refs"]
        ingress_bytes = _integration_ingress_bytes(
            expected_refs,
            intent["payload"]["producer_handoff_receipts"],
        )
        if (
            intent["payload"].get("ingress_bytes") != ingress_bytes
            or intent["payload"].get("ingress_limit_bytes")
            != intent["payload"]["task_spec"]["budgets"]["context_tokens"] * 4
            or ingress_bytes > intent["payload"].get("ingress_limit_bytes", -1)
        ):
            return self._state_refusal(
                payload, current_cursor, state, ["advance:integration_ingress_invalid"]
            )
        if result.get("input_artifact_refs") != expected_refs:
            return None, ["advance:join_input_mismatch"]
        consumed = result.get("consumed_artifact_refs")
        unused = result.get("unused_artifact_refs")
        if not isinstance(consumed, list) or not isinstance(unused, list):
            return None, ["advance:join_consumption_invalid"]
        expected_keys = {(ref["uri"], ref["sha256"]) for ref in expected_refs}
        consumed_keys = {
            (ref.get("uri"), ref.get("sha256"))
            for ref in consumed
            if isinstance(ref, Mapping)
        }
        unused_keys = {
            (ref.get("uri"), ref.get("sha256"))
            for ref in unused
            if isinstance(ref, Mapping)
        }
        if consumed_keys & unused_keys or consumed_keys | unused_keys != expected_keys:
            return None, ["advance:join_consumption_invalid"]
        for ref in expected_refs:
            try:
                self.artifacts.read(ref)
            except (KeyError, TypeError, ValueError):
                return None, ["advance:join_artifact_unavailable"]
        conflicts = result.get("conflicts")
        if not isinstance(conflicts, list) or any(
            not isinstance(item, str) or not item or len(item) > 4096
            for item in conflicts
        ):
            return None, ["advance:join_conflicts_invalid"]
        if conflicts:
            return self._state_refusal(
                payload, current_cursor, state, ["advance:join_conflict"]
            )
        criterion_ids = result.get("criterion_ids")
        owned = control["workflow_submission"]["join"]["owned_criterion_ids"]
        if criterion_ids != sorted(owned):
            return None, ["advance:join_criteria_mismatch"]
        body = result.get("output_body")
        if not isinstance(body, str) or not body or len(body.encode("utf-8")) > 65536:
            return None, ["advance:join_output_invalid"]
        evidence_digest = result.get("evidence_sha256")
        if evidence_digest:
            if (
                not isinstance(evidence_digest, str)
                or _SHA256.fullmatch(evidence_digest) is None
            ):
                return None, ["advance:join_evidence_invalid"]
        else:
            return None, ["advance:join_evidence_invalid"]

        task_spec = intent["payload"]["task_spec"]
        task_report = contracts.validate_task_spec(task_spec)
        if task_report.get("status") != "PASS" or task_spec != control["task_spec"]:
            return None, ["advance:join_task_spec_invalid"]
        try:
            artifact = self.artifacts.publish(
                body,
                media_type=task_spec["deliverable"]["media_type"],
                provenance={
                    "producer_run_id": run_id,
                    "producer_node_id": task_spec["id"],
                    "task_spec_sha256": task_report["digest"],
                    "content_schema": task_spec["deliverable"]["schema"],
                    "privacy_class": control["privacy_class"],
                    "custody_receipt_sha256": result["evidence_sha256"],
                    "source_lineage": consumed,
                    "consumer_node_ids": ["reviewer"],
                    "retention_state": "terminal_result",
                },
            )
        except ValueError as exc:
            reason = (
                "advance:artifact_provenance_conflict"
                if str(exc) == "artifact_provenance_conflict"
                else "advance:artifact_publish_refused"
            )
            return self._state_refusal(payload, current_cursor, state, [reason])
        checks = [
            {
                "id": check["id"],
                "status": "passed",
                "required": check["required"],
                "evidence_refs": [artifact],
            }
            for check in task_spec["acceptance_checks"]
        ]
        handoff = contracts.seal_handoff_receipt(
            {
                "schema": contracts.HANDOFF_RECEIPT_SCHEMA,
                "disposition": "complete",
                "task_spec_sha256": task_report["digest"],
                "result_summary": "The declared join consumed producer artifacts and emitted one result.",
                "claims": [
                    {
                        "id": "joined-result",
                        "statement": "The join discharged its declared acceptance criteria.",
                        "epistemic_status": "verified",
                        "evidence_refs": [artifact],
                    }
                ],
                "artifact_refs": [artifact],
                "checks": checks,
                "conflicts": [],
                "unknowns": [],
                "requested_decisions": [],
                "raw_trace_ref": None,
            },
            task_spec=task_spec,
        )
        verification_intent = _verification_intent(
            dispatch_intent=intent,
            control=control,
            task_spec=task_spec,
            handoff=handoff,
            now_ms=now_ms,
        )
        try:
            self.engine.apply(
                run_id,
                task_spec["id"],
                roles=("integrator",),
                status="SUCCESS",
                deliverables={
                    "artifact_ref": json.dumps(
                        artifact, sort_keys=True, separators=(",", ":")
                    ),
                    "handoff_receipt": json.dumps(
                        handoff, sort_keys=True, separators=(",", ":")
                    ),
                    "consumed_artifact_refs": json.dumps(
                        consumed, sort_keys=True, separators=(",", ":")
                    ),
                    "unused_artifact_refs": json.dumps(
                        unused, sort_keys=True, separators=(",", ":")
                    ),
                },
                evidence={
                    "integrator": handoff["handoff_sha256"],
                    "verification_intent": verification_intent["intent_sha256"],
                },
                expected_seq=current_cursor["seq"],
                expected_prev_hash=current_cursor["event_hash"],
            )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        except (run_engine.MalformedInputError, run_engine.ProtocolError):
            return None, ["advance:join_fact_rejected"]
        final_events = list(self.engine.events(run_id, 0))
        final_state = self.engine.reduce(plan, final_events)
        return (
            _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "ADVANCED",
                    "prior_cursor": current_cursor,
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": _cursor(run_id, final_events, final_state),
                    "state_sha256": _sha256(dict(final_state)),
                    "reason_codes": [
                        "advance:join_applied"
                        if not unused
                        else "advance:join_applied_with_unused_output"
                    ],
                    "intents": [verification_intent],
                    "budget_settlement": {"reserved": True},
                    "authority_settlement": {"consumed": False},
                },
                "decision_sha256",
            ),
            [],
        )

    def _observe_cleanup(
        self,
        payload: Mapping[str, Any],
        *,
        run_id: str,
        events: list[Mapping[str, Any]],
        plan: Mapping[str, Any],
        state: Mapping[str, Any],
        current_cursor: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        intent = observation.get("intent")
        if not _intent_valid(intent, "cleanup"):
            return None, ["advance:cleanup_intent_invalid"]
        control = plan.get("origin", {}).get("control_tower", {})
        cancellation_facts = []
        for event in events:
            if event["kind"] != run_engine.KIND_APPLIED:
                continue
            cancellation = json.loads(event["payload"]).get("cancellation")
            if isinstance(cancellation, Mapping) and cancellation.get("status") == "requested":
                cancellation_facts.append(cancellation)
        expected_cleanup = None
        if len(cancellation_facts) == 1:
            requested_at_ms = cancellation_facts[0].get("requested_at_ms")
            prior_seq = cancellation_facts[0].get("prior_seq")
            if type(requested_at_ms) is int and type(prior_seq) is int:
                expected_cleanup = _cleanup_intent(
                    control=control,
                    run_id=run_id,
                    context_sha256=state["stream_sha256"],
                    requested_at_ms=requested_at_ms,
                    prior_seq=prior_seq,
                )
        if intent != expected_cleanup:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:cleanup_binding_mismatch"],
            )
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        if now_ms < intent["not_before_ms"]:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:cleanup_intent_not_yet_live"],
            )
        if now_ms > intent["expires_at_ms"]:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:cleanup_intent_expired"],
            )
        result = observation.get("result")
        if not isinstance(result, Mapping) or set(result) != _CLEANUP_FIELDS:
            return None, ["advance:cleanup_observation_invalid"]
        if result.get("schema") != CLEANUP_OBSERVATION_SCHEMA:
            return None, ["advance:cleanup_schema_invalid"]
        status = result.get("status")
        if status not in {"complete", "unknown"}:
            return None, ["advance:cleanup_status_invalid"]
        descendants = result.get("owned_descendants")
        if type(descendants) is not int or descendants < 0:
            return None, ["advance:cleanup_descendants_invalid"]
        if status == "complete" and descendants != 0:
            return None, ["advance:cleanup_descendants_remain"]
        if not _cancellation_requested(events):
            return None, ["advance:cleanup_without_cancellation"]
        ready, ledger_issues = self._ensure_lane_ledger_run()
        if not ready:
            return None, ledger_issues
        try:
            _ledger_events, active_lanes, _authority_state = (
                self._lane_ledger_state()
            )
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["advance:lane_ledger_invalid"]
        cleanup_lane_ids = sorted(
            _lane_identity(active_run_id, node_id)
            for active_run_id, node_id in active_lanes
            if active_run_id == run_id
        )
        if not cleanup_lane_ids:
            cleanup_lane_ids = ["unallocated:" + run_id]
        submitted_receipts = result.get("observer_receipts")
        if (
            not isinstance(submitted_receipts, Mapping)
            or set(submitted_receipts) != set(cleanup_lane_ids)
        ):
            return None, ["advance:cleanup_evidence_invalid"]
        cleanup_evaluation_time = self._cleanup_observer_now()
        evidence_by_lane: dict[str, str] = {}
        for lane_id in cleanup_lane_ids:
            cleanup_payload = _lane_cleanup_payload(
                lane_id=lane_id,
                run_id=run_id,
                route=lane_capacity.CONTROL_TOWER_ROUTE,
                terminal_state="cancelled",
                cleanup_status=status,
                owned_descendants=descendants,
                terminal_evidence_sha256=intent["context_sha256"],
            )
            cleanup_report = _verified_lane_cleanup(
                submitted_receipts[lane_id],
                expected_payload=cleanup_payload,
                trust_store=self._cleanup_observer_trust_store,
                replay_guard=self._cleanup_observer_replay_guard,
                evaluation_time=cleanup_evaluation_time,
            )
            if cleanup_report is None:
                return None, ["advance:cleanup_evidence_invalid"]
            evidence_by_lane[lane_id] = cleanup_report[
                "signed_receipt_sha256"
            ]
        evidence = _sha256(evidence_by_lane)
        try:
            self.engine.append_event(
                run_id,
                run_engine.KIND_APPLIED,
                "kernel",
                {
                    "roles": [],
                    "status": "CLEANUP_OBSERVED",
                    "deliverables": {},
                    "evidence": {},
                    "cleanup": {
                        "status": status,
                        "owned_descendants": descendants,
                        "evidence_sha256": evidence,
                        "evidence_sha256_by_lane": evidence_by_lane,
                        "terminal_evidence_sha256": intent[
                            "context_sha256"
                        ],
                        "observer_receipts": dict(submitted_receipts),
                        "observer_evaluation_times": {
                            lane_id: cleanup_evaluation_time
                            for lane_id in cleanup_lane_ids
                        },
                    },
                },
                expected_seq=current_cursor["seq"],
                expected_prev_hash=current_cursor["event_hash"],
            )
            cleanup_events = list(self.engine.events(run_id, 0))
            cleanup_state = self.engine.reduce(plan, cleanup_events)
            cleanup_cursor = _cursor(run_id, cleanup_events, cleanup_state)
            self.engine.cancel(
                run_id,
                note="control-tower cancellation settled",
                expected_seq=cleanup_cursor["seq"],
                expected_prev_hash=cleanup_cursor["event_hash"],
            )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        dispatch_intents: list[dict[str, Any]] = []
        released_lanes = 0
        reserved_lanes = 0
        if status == "complete" and control.get("profile_id") in _LANE_PROFILES:
            try:
                dispatch_intents, released_lanes, reserved_lanes = (
                    self._rebalance_lane_reservations(now_ms)
                )
            except (
                KeyError,
                TypeError,
                ValueError,
                run_engine.RunKernelError,
            ):
                return None, ["advance:lane_ledger_invalid"]
        final_events = list(self.engine.events(run_id, 0))
        final_state = self.engine.reduce(plan, final_events)
        decision = _seal(
            {
                "schema": DECISION_SCHEMA,
                "decision_status": "TERMINATED",
                "prior_cursor": current_cursor,
                "accepted_input_sha256": _sha256(payload),
                "resulting_cursor": _cursor(run_id, final_events, final_state),
                "state_sha256": _sha256(dict(final_state)),
                "reason_codes": [
                    "advance:cleanup_complete"
                    if status == "complete"
                    else "advance:cleanup_unknown"
                ],
                "intents": dispatch_intents,
                "budget_settlement": {
                    "reserved": bool(dispatch_intents),
                    "settled": True,
                    "released_lanes": released_lanes,
                    "reserved_lanes": reserved_lanes,
                },
                "authority_settlement": {"consumed": False, "settled": True},
            },
            "decision_sha256",
        )
        return decision, []

    def _admit_repair(
        self,
        payload: Mapping[str, Any],
        *,
        run_id: str,
        plan: Mapping[str, Any],
        state: Mapping[str, Any],
        current_cursor: Mapping[str, Any],
        disposition: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        control = plan.get("origin", {}).get("control_tower", {})
        sequence = disposition["repair_sequence"]
        node_id = control["task_id"] + ":repair-" + str(sequence)
        for event in self.engine.events(run_id, 0):
            if event["kind"] != run_engine.KIND_APPLIED:
                continue
            facts = json.loads(event["payload"])
            raw_intent = facts.get("deliverables", {}).get("repair_intent")
            if not isinstance(raw_intent, str):
                continue
            try:
                prior_intent = json.loads(raw_intent)
            except (TypeError, ValueError):
                return None, ["advance:repair_fact_invalid"]
            if prior_intent.get("node_id") == node_id:
                return self._state_refusal(
                    payload,
                    current_cursor,
                    state,
                    ["advance:repair_already_admitted"],
                )
        template = control.get("task_specs", {}).get(node_id)
        if not isinstance(template, Mapping):
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:repair_not_declared"],
            )
        raw_spec = deepcopy(dict(template))
        raw_spec.pop("task_spec_sha256", None)
        raw_spec["input_refs"] = sorted(
            {
                (ref["uri"], ref["sha256"]): ref
                for ref in list(template["input_refs"])
                + list(disposition["permitted_source_refs"])
            }.values(),
            key=lambda ref: (ref["uri"], ref["sha256"]),
        )
        raw_spec["goal"] = disposition["repair_instruction"]
        try:
            repair_spec = contracts.seal_task_spec(raw_spec)
        except contracts.ContractValidationError:
            return None, ["advance:repair_task_spec_invalid"]
        task = control.get("task_brief")
        if not isinstance(task, Mapping):
            return None, ["advance:bound_task_brief_invalid"]
        preparation_view = {
            "preparation_sha256": control["preparation_sha256"],
            "task_brief_sha256": _sha256(task),
            "expires_at_ms": control["expires_at_ms"],
        }
        context_sha256 = _sha256(
            {
                "review_disposition_sha256": disposition[
                    "disposition_sha256"
                ],
                "task_spec_sha256": repair_spec["task_spec_sha256"],
                "input_refs": repair_spec["input_refs"],
            }
        )
        call = _worker_call(
            task,
            repair_spec,
            preparation_view,
            profile_id="execute_verify_repair/v1",
            call_suffix="repair-" + str(sequence),
            input_sha256=context_sha256,
        )
        call_report = worker_transport.validate_worker_call(call)
        capability = _bound_executor_capability(control)
        if call_report.get("status") != "PASS" or capability is None:
            return None, ["advance:repair_dispatch_contract_invalid"]
        manifest = control.get("model_manifest")
        manifest_report = worker_transport.validate_model_manifest(manifest)
        if manifest_report.get("status") != "PASS":
            return None, ["advance:bound_manifest_invalid"]
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        intent = _dispatch_intent(
            task_id=control["task_id"],
            run_id=run_id,
            preparation=preparation_view,
            task_spec=repair_spec,
            logical_plan=control["logical_plan"],
            ready={
                "route": control["route"],
                "reservation_requirements": control[
                    "reservation_requirements"
                ],
            },
            capability=capability,
            call=call,
            call_sha256=call_report["canonical_sha256"],
            manifest=manifest_report["canonical"],
            manifest_sha256=manifest_report["canonical_sha256"],
            now_ms=now_ms,
            plan_revision=control["plan_revision"] + sequence,
            independence_group="repair-" + str(sequence),
        )
        try:
            self.engine.append_event(
                run_id,
                run_engine.KIND_APPLIED,
                "kernel",
                {
                    "roles": [],
                    "status": "ERROR",
                    "deliverables": {
                        "review_disposition": json.dumps(
                            disposition,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        "repair_task_spec": json.dumps(
                            repair_spec,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        "repair_intent": json.dumps(
                            intent,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    },
                    "evidence": {
                        "review_disposition": disposition[
                            "disposition_sha256"
                        ]
                    },
                },
                note="control-tower bounded repair admitted",
                expected_seq=current_cursor["seq"],
                expected_prev_hash=current_cursor["event_hash"],
            )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        events = list(self.engine.events(run_id, 0))
        next_state = self.engine.reduce(plan, events)
        try:
            dispatch_intents, released_lanes, reserved_lanes = (
                self._rebalance_lane_reservations(now_ms)
            )
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["advance:lane_ledger_invalid"]
        return (
            _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "ADVANCED",
                    "prior_cursor": current_cursor,
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": _cursor(run_id, events, next_state),
                    "state_sha256": _sha256(dict(next_state)),
                    "reason_codes": ["advance:repair_admitted"],
                    "intents": dispatch_intents,
                    "budget_settlement": {
                        "reserved": bool(dispatch_intents),
                        "repair_sequence": sequence,
                        "released_lanes": released_lanes,
                        "reserved_lanes": reserved_lanes,
                    },
                    "authority_settlement": {
                        "consumed": False,
                        "scope_sha256": intent["authority_sha256"],
                    },
                },
                "decision_sha256",
            ),
            [],
        )

    def _observe_repair_worker(
        self,
        payload: Mapping[str, Any],
        *,
        run_id: str,
        events: list[Mapping[str, Any]],
        plan: Mapping[str, Any],
        state: Mapping[str, Any],
        current_cursor: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        intent = observation.get("intent")
        if not _intent_valid(intent, "dispatch"):
            return None, ["advance:repair_intent_invalid"]
        matching: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
        repair_claim_sequences: list[int] = []
        for event in events:
            if event["kind"] != run_engine.KIND_APPLIED:
                continue
            facts = json.loads(event["payload"])
            deliverables = facts.get("deliverables", {})
            raw_intent = deliverables.get("repair_intent")
            raw_spec = deliverables.get("repair_task_spec")
            if not isinstance(raw_intent, str) or not isinstance(raw_spec, str):
                continue
            repair_claim_sequences.append(event["seq"])
            try:
                stored_intent = json.loads(raw_intent)
                stored_spec = json.loads(raw_spec)
            except (TypeError, ValueError):
                return None, ["advance:repair_fact_invalid"]
            if stored_intent.get("intent_sha256") == intent.get(
                "intent_sha256"
            ):
                matching.append((event["seq"], stored_intent, stored_spec))
        if (
            len(matching) != 1
            or matching[0][1] != intent
            or matching[0][0] != max(repair_claim_sequences, default=-1)
        ):
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:repair_binding_mismatch"],
            )
        claim_seq = matching[0][0]
        for event in events:
            if event["seq"] <= claim_seq or event["kind"] != run_engine.KIND_APPLIED:
                continue
            facts = json.loads(event["payload"])
            if "executor" in facts.get("roles", []):
                return self._state_refusal(
                    payload,
                    current_cursor,
                    state,
                    ["advance:repair_already_applied"],
                )
        task_spec = matching[0][2]
        task_report = contracts.validate_task_spec(task_spec)
        if task_report.get("status") != "PASS":
            return None, ["advance:repair_task_spec_invalid"]
        control = plan.get("origin", {}).get("control_tower", {})
        try:
            lane_reserved = self._lane_reservation_active(
                run_id, str(intent.get("node_id"))
            )
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["advance:lane_ledger_invalid"]
        if not lane_reserved:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:repair_lane_unreserved"],
            )
        result_report = worker_transport.validate_worker_result(
            observation.get("result"),
            expected_call_sha256=intent["payload"]["worker_call_sha256"],
            expected_manifest_sha256=intent["payload"][
                "model_manifest_sha256"
            ],
        )
        if result_report.get("status") != "PASS":
            return None, ["advance:repair_worker_result_invalid"]
        result = result_report["canonical"]
        if result.get("status") != "CANDIDATE_READY":
            return None, ["advance:repair_worker_result_not_ready"]
        capability = _bound_executor_capability(control)
        if capability is None or _worker_result_exceeds_budget(
            result, task_spec, capability
        ):
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:worker_budget_exceeded"],
            )
        manifest = intent["payload"]["model_manifest"]
        runtime = result.get("runtime", {})
        if (
            runtime.get("logical_model_id") != manifest.get("logical_model_id")
            or runtime.get("served_name") not in manifest.get("served_names", [])
            or runtime.get("checkpoint_revision")
            != manifest.get("checkpoint_revision")
            or runtime.get("runtime_id") != "provider-free-fake/v1"
        ):
            return None, ["advance:runtime_identity_mismatch"]
        try:
            artifact = self.artifacts.publish(
                result["candidate"]["diff"],
                media_type=task_spec["deliverable"]["media_type"],
                provenance={
                    "producer_run_id": run_id,
                    "producer_node_id": task_spec["id"],
                    "task_spec_sha256": task_report["digest"],
                    "content_schema": task_spec["deliverable"]["schema"],
                    "privacy_class": control["privacy_class"],
                    "custody_receipt_sha256": result["evidence"]["sha256"],
                    "source_lineage": task_spec["input_refs"],
                    "consumer_node_ids": ["reviewer"],
                    "retention_state": "terminal_result",
                },
            )
        except ValueError as exc:
            reason = (
                "advance:artifact_provenance_conflict"
                if str(exc) == "artifact_provenance_conflict"
                else "advance:artifact_publish_refused"
            )
            return self._state_refusal(
                payload, current_cursor, state, [reason]
            )
        checks = [
            {
                "id": check["id"],
                "status": "passed",
                "required": check["required"],
                "evidence_refs": [artifact],
            }
            for check in task_spec["acceptance_checks"]
        ]
        handoff = contracts.seal_handoff_receipt(
            {
                "schema": contracts.HANDOFF_RECEIPT_SCHEMA,
                "disposition": "complete",
                "task_spec_sha256": task_report["digest"],
                "result_summary": "One admitted Repair node produced a fresh candidate.",
                "claims": [
                    {
                        "id": "repaired-result",
                        "statement": "The Repair node produced a fresh bounded artifact.",
                        "epistemic_status": "verified",
                        "evidence_refs": [artifact],
                    }
                ],
                "artifact_refs": [artifact],
                "checks": checks,
                "conflicts": [],
                "unknowns": [],
                "requested_decisions": [],
                "raw_trace_ref": None,
            },
            task_spec=task_spec,
        )
        sequence = int(task_spec["id"].rsplit("-", 1)[1])
        verification_intent = _verification_intent(
            dispatch_intent=intent,
            control=control,
            task_spec=task_spec,
            handoff=handoff,
            now_ms=self.clock_ms(),
            completed_repairs=sequence,
        )
        try:
            self.engine.apply(
                run_id,
                "executor",
                roles=("executor",),
                status="SUCCESS",
                deliverables={
                    "artifact_ref": json.dumps(
                        artifact, sort_keys=True, separators=(",", ":")
                    ),
                    "handoff_receipt": json.dumps(
                        handoff, sort_keys=True, separators=(",", ":")
                    ),
                    "lane_release_receipt:" + str(intent["node_id"]): json.dumps(
                        observation["lane_release_receipt"],
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    "lane_release_evaluation_time:"
                    + str(intent["node_id"]): observation[
                        "lane_release_evaluation_time"
                    ],
                    "repair_sequence": str(sequence),
                    "worker_usage:repair-" + str(sequence): json.dumps(
                        result["usage"], sort_keys=True, separators=(",", ":")
                    ),
                    "worker_timing:repair-" + str(sequence): json.dumps(
                        result["timing"], sort_keys=True, separators=(",", ":")
                    ),
                    "worker_runtime:repair-" + str(sequence): json.dumps(
                        result["runtime"], sort_keys=True, separators=(",", ":")
                    ),
                },
                evidence={
                    "executor": handoff["handoff_sha256"],
                    "worker_result": worker_transport.canonical_sha256(
                        result
                    ),
                    "verification_intent": verification_intent[
                        "intent_sha256"
                    ],
                },
                note="control-tower Repair node applied",
                expected_seq=current_cursor["seq"],
                expected_prev_hash=current_cursor["event_hash"],
            )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        except (run_engine.MalformedInputError, run_engine.ProtocolError):
            return None, ["advance:repair_fact_rejected"]
        final_events = list(self.engine.events(run_id, 0))
        final_state = self.engine.reduce(plan, final_events)
        try:
            dispatch_intents, released_lanes, reserved_lanes = (
                self._rebalance_lane_reservations(self.clock_ms())
            )
        except (KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["advance:lane_ledger_invalid"]
        return (
            _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "ADVANCED",
                    "prior_cursor": current_cursor,
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": _cursor(
                        run_id, final_events, final_state
                    ),
                    "state_sha256": _sha256(dict(final_state)),
                    "reason_codes": ["advance:repair_applied"],
                    "intents": [verification_intent, *dispatch_intents],
                    "budget_settlement": {
                        "reserved": True,
                        "repair_sequence": sequence,
                        "released_lanes": released_lanes,
                        "reserved_lanes": reserved_lanes,
                    },
                    "authority_settlement": {"consumed": False},
                },
                "decision_sha256",
            ),
            [],
        )

    def _terminal_review_failure(
        self,
        payload: Mapping[str, Any],
        *,
        run_id: str,
        plan: Mapping[str, Any],
        current_cursor: Mapping[str, Any],
        disposition: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        control = plan.get("origin", {}).get("control_tower", {})
        failure_reason = "advance:verification_escalated"
        if (
            control.get("profile_id") == "execute_verify_repair/v1"
            and isinstance(control.get("workflow_submission"), Mapping)
            and control["workflow_submission"].get("failure_policy") == "fail"
        ):
            failure_reason = "advance:verification_failed"
        try:
            self.engine.apply(
                run_id,
                "reviewer",
                roles=("reviewer",),
                status="ERROR",
                deliverables={
                    "review_disposition": json.dumps(
                        disposition, sort_keys=True, separators=(",", ":")
                    )
                },
                evidence={
                    "reviewer": disposition["disposition_sha256"]
                },
                expected_seq=current_cursor["seq"],
                expected_prev_hash=current_cursor["event_hash"],
            )
            reviewer_events = list(self.engine.events(run_id, 0))
            reviewer_state = self.engine.reduce(plan, reviewer_events)
            reviewer_cursor = _cursor(
                run_id, reviewer_events, reviewer_state
            )
            completion_actor = (
                control["task_spec"]["id"]
                if control.get("profile_id")
                in {"parallel_join/v1", "best_of_n/v1", "finite_dag/v1"}
                else "reviewer"
            )
            self.engine.complete(
                run_id,
                completion_actor,
                status="ERROR",
                note="control-tower verification escalated",
                expected_seq=reviewer_cursor["seq"],
                expected_prev_hash=reviewer_cursor["event_hash"],
            )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        except (run_engine.MalformedInputError, run_engine.ProtocolError):
            return None, ["advance:terminal_fact_rejected"]
        events = list(self.engine.events(run_id, 0))
        final_state = self.engine.reduce(plan, events)
        return (
            _seal(
                {
                    "schema": DECISION_SCHEMA,
                    "decision_status": "FAILED",
                    "prior_cursor": current_cursor,
                    "accepted_input_sha256": _sha256(payload),
                    "resulting_cursor": _cursor(run_id, events, final_state),
                    "state_sha256": _sha256(dict(final_state)),
                    "reason_codes": [failure_reason],
                    "intents": [],
                    "budget_settlement": {
                        "reserved": False,
                        "settled": True,
                    },
                    "authority_settlement": {
                        "consumed": False,
                        "settled": True,
                    },
                },
                "decision_sha256",
            ),
            [],
        )

    def _observe_verification(
        self,
        payload: Mapping[str, Any],
        *,
        run_id: str,
        events: list[Mapping[str, Any]],
        plan: Mapping[str, Any],
        state: Mapping[str, Any],
        current_cursor: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        intent = observation.get("intent")
        if not _intent_valid(intent, "verification"):
            return None, ["advance:verification_intent_invalid"]
        control = plan.get("origin", {}).get("control_tower", {})
        profile_id = control.get("profile_id")
        multi_profile = profile_id in {
            "parallel_join/v1",
            "best_of_n/v1",
            "finite_dag/v1",
        }
        subject_role = "integrator" if multi_profile else "executor"
        expected_intent_hashes = []
        for event in events:
            if event["kind"] != run_engine.KIND_APPLIED:
                continue
            facts = json.loads(event["payload"])
            if subject_role in facts.get("roles", []):
                expected_intent_hashes.append(
                    facts.get("evidence", {}).get("verification_intent")
                )
        if (
            expected_intent_hashes[-1:] != [intent.get("intent_sha256")]
            or intent.get("run_id") != run_id
            or intent.get("preparation_sha256") != control.get("preparation_sha256")
        ):
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:verification_binding_mismatch"],
            )
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        if now_ms < intent["not_before_ms"] or now_ms > intent["expires_at_ms"]:
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:verification_intent_expired"],
            )
        task_spec = intent.get("payload", {}).get("task_spec")
        handoff = intent.get("payload", {}).get("handoff_receipt")
        artifact_refs = intent.get("payload", {}).get("artifact_refs")
        task_report = contracts.validate_task_spec(task_spec)
        handoff_report = contracts.validate_handoff_receipt(
            handoff, task_spec=task_spec
        )
        if task_report.get("status") != "PASS" or handoff_report.get("status") != "PASS":
            return None, ["advance:verification_subject_invalid"]
        if profile_id == "execute_verify_repair/v1":
            template = control.get("task_specs", {}).get(task_spec.get("id"))
            if not isinstance(template, Mapping) or any(
                task_spec.get(field) != template.get(field)
                for field in (
                    "id",
                    "kind",
                    "dependencies",
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
                )
            ):
                return None, ["advance:verification_subject_invalid"]
        elif task_spec != control.get("task_spec"):
            return self._state_refusal(
                payload,
                current_cursor,
                state,
                ["advance:verification_binding_mismatch"],
            )
        if (
            intent.get("context_sha256") != handoff_report.get("digest")
            or artifact_refs != handoff_report["normalized"]["artifact_refs"]
        ):
            return None, ["advance:verification_context_mismatch"]
        for artifact in artifact_refs:
            try:
                self.artifacts.read(artifact)
            except (KeyError, TypeError, ValueError):
                return None, ["advance:verification_artifact_unavailable"]
        review_contract = intent.get("payload", {}).get("review_contract")
        review_contract_fields = {
            "schema",
            "profile_id",
            "repair_limit",
            "completed_repairs",
            "acceptance_sha256",
            "scope_sha256",
            "required_human_approvals",
            "independent_review_required",
            "verification_layers",
            "contract_sha256",
        }
        if (
            not isinstance(review_contract, Mapping)
            or set(review_contract) != review_contract_fields
            or review_contract.get("schema")
            != "orch-dork/control-review-contract/v1"
            or not _seal_valid(review_contract, "contract_sha256")
            or review_contract.get("profile_id") != profile_id
            or review_contract.get("repair_limit")
            != control.get("repair_limit", 0)
            or review_contract.get("acceptance_sha256")
            != _sha256(task_spec["acceptance_checks"])
            or review_contract.get("scope_sha256")
            != control.get("review_scope_sha256")
            or review_contract.get("required_human_approvals")
            != control.get("authority_requirements", [])
            or review_contract.get("independent_review_required")
            is not (
                profile_id in {"best_of_n/v1", "finite_dag/v1"}
                or control.get("task_brief", {}).get("risk_class")
                in {"high", "critical"}
            )
            or review_contract.get("verification_layers")
            != list(workflow_profiles.VERIFICATION_LAYERS)
        ):
            return None, ["advance:review_contract_invalid"]
        completed_repairs = review_contract.get("completed_repairs")
        if type(completed_repairs) is not int or not 0 <= completed_repairs <= 2:
            return None, ["advance:review_contract_invalid"]

        submitted_result = observation.get("result")
        disposition = None
        if (
            isinstance(submitted_result, Mapping)
            and submitted_result.get("schema")
            == workflow_profiles.REVIEW_DISPOSITION_SCHEMA
        ):
            disposition_report = workflow_profiles.validate_review_disposition(
                submitted_result,
                task_spec=task_spec,
                handoff_receipt=handoff,
                expected_profile_id=profile_id,
                repair_limit=review_contract["repair_limit"],
                completed_repairs=completed_repairs,
                acceptance_sha256=review_contract["acceptance_sha256"],
                scope_sha256=review_contract["scope_sha256"],
            )
            if disposition_report.get("status") != "PASS":
                return None, ["advance:review_disposition_invalid"]
            disposition = disposition_report["normalized"]
            verification = disposition["verification_receipt"]
            if verification.get("implementer_identity") != task_spec.get(
                "executor"
            ):
                return None, ["advance:verification_implementer_mismatch"]
            human_layer = next(
                (
                    layer
                    for layer in disposition["layers"]
                    if layer["layer"] == "human_approval"
                ),
                None,
            )
            if (
                review_contract["required_human_approvals"]
                and (
                    not isinstance(human_layer, Mapping)
                    or human_layer.get("status") != "PASS"
                )
            ):
                return None, ["advance:human_approval_evidence_required"]
            independent_layer = next(
                (
                    layer
                    for layer in disposition["layers"]
                    if layer["layer"] == "independent_review"
                ),
                None,
            )
            if (
                review_contract["independent_review_required"]
                and (
                    not isinstance(independent_layer, Mapping)
                    or independent_layer.get("status") != "PASS"
                )
            ):
                return None, ["advance:independent_review_evidence_required"]
            if disposition["decision"] == "REPAIR":
                return self._admit_repair(
                    payload,
                    run_id=run_id,
                    plan=plan,
                    state=state,
                    current_cursor=current_cursor,
                    disposition=disposition,
                )
            if disposition["decision"] == "ESCALATE":
                return self._terminal_review_failure(
                    payload,
                    run_id=run_id,
                    plan=plan,
                    current_cursor=current_cursor,
                    disposition=disposition,
                )
        else:
            if profile_id not in {"direct/v1", "parallel_join/v1"}:
                return None, ["advance:review_disposition_required"]
            verification_report = contracts.validate_verification_receipt(
                submitted_result,
                task_spec=task_spec,
                handoff_receipt=handoff,
            )
            if verification_report.get("status") != "PASS":
                return None, ["advance:verification_receipt_invalid"]
            verification = verification_report["normalized"]
        if (
            verification.get("pass") is not True
            or verification.get("disposition") != "pass"
        ):
            return None, ["advance:verification_not_pass"]
        applied_roles = set()
        for event in events:
            if event["kind"] == "applied":
                applied_roles.update(json.loads(event["payload"]).get("roles", []))
        expected_applied_roles = (
            set(control.get("dispatch_intents", {})) | {"integrator"}
            if multi_profile
            else {"executor"}
        )
        if applied_roles != expected_applied_roles:
            return None, ["advance:verification_phase_invalid"]
        try:
            self.engine.apply(
                run_id,
                "reviewer",
                roles=("reviewer",),
                status="SUCCESS",
                deliverables={
                    "verification_receipt": json.dumps(
                        verification, sort_keys=True, separators=(",", ":")
                    ),
                    **(
                        {
                            "review_disposition": json.dumps(
                                disposition,
                                sort_keys=True,
                                separators=(",", ":"),
                            )
                        }
                        if disposition is not None
                        else {}
                    ),
                },
                evidence={
                    "reviewer": (
                        disposition["disposition_sha256"]
                        if disposition is not None
                        else verification["verification_sha256"]
                    )
                },
                expected_seq=current_cursor["seq"],
                expected_prev_hash=current_cursor["event_hash"],
            )
            reviewer_events = list(self.engine.events(run_id, 0))
            reviewer_state = self.engine.reduce(plan, reviewer_events)
            reviewer_cursor = _cursor(run_id, reviewer_events, reviewer_state)
            completion_actor = (
                control["task_spec"]["id"] if multi_profile else "reviewer"
            )
            self.engine.complete(
                run_id,
                completion_actor,
                status="SUCCESS",
                note="control-tower verification passed",
                expected_seq=reviewer_cursor["seq"],
                expected_prev_hash=reviewer_cursor["event_hash"],
            )
        except run_store.StaleSeqError:
            return self._cas_refusal(payload, run_id)
        except (run_engine.MalformedInputError, run_engine.ProtocolError):
            return None, ["advance:terminal_fact_rejected"]
        final_events = list(self.engine.events(run_id, 0))
        final_state = self.engine.reduce(plan, final_events)
        decision = _seal(
            {
                "schema": DECISION_SCHEMA,
                "decision_status": "COMPLETED",
                "prior_cursor": current_cursor,
                "accepted_input_sha256": _sha256(payload),
                "resulting_cursor": _cursor(run_id, final_events, final_state),
                "state_sha256": _sha256(dict(final_state)),
                "reason_codes": ["advance:verification_passed"],
                "intents": [],
                "budget_settlement": {"reserved": False, "settled": True},
                "authority_settlement": {"consumed": False, "settled": True},
            },
            "decision_sha256",
        )
        return decision, []

    @staticmethod
    def _learning_projection(
        *,
        kind: str,
        run_id: str | None,
        stream_sha256: str | None,
        terminal_bound: bool,
        route_report: Mapping[str, Any] | None,
        strategy_report: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        accepted = all(
            report is None or report.get("status") == "PASS"
            for report in (route_report, strategy_report)
        )
        return _seal(
            {
                "schema": LEARNING_INSPECTION_SCHEMA,
                "kind": kind,
                "decision": (
                    "TERMINAL_PROJECTED"
                    if terminal_bound and accepted
                    else "EVALUATED"
                    if accepted
                    else "EVALUATOR_REJECTED"
                ),
                "run_id": run_id,
                "stream_sha256": stream_sha256,
                "terminal_bound": terminal_bound,
                "source_authority": (
                    "verified_run_engine_stream"
                    if terminal_bound
                    else "submitted_advisory_request"
                ),
                "route_report": (
                    deepcopy(dict(route_report))
                    if isinstance(route_report, Mapping)
                    else None
                ),
                "strategy_report": (
                    deepcopy(dict(strategy_report))
                    if isinstance(strategy_report, Mapping)
                    else None
                ),
                "projection_only": True,
                "append_permitted": False,
                "mutation_permitted": False,
                "policy_mutated": False,
                "production_exploration": False,
                "authority_granted": False,
                "workers_permitted": False,
                "provider_free": True,
                "model_calls": 0,
                "hosted_calls": 0,
            },
            "inspection_sha256",
        )

    @staticmethod
    def _terminal_learning_evidence(
        events: list[Mapping[str, Any]],
        state: Mapping[str, Any],
    ) -> dict[str, str] | None:
        candidates: list[dict[str, str]] = []
        for event in events:
            if event.get("kind") != "applied":
                continue
            try:
                facts = json.loads(event["payload"])
            except (KeyError, TypeError, ValueError):
                return None
            deliverables = facts.get("deliverables")
            if not isinstance(deliverables, Mapping):
                continue
            for field, seal_field in (
                ("verification_receipt", "verification_sha256"),
                ("review_disposition", "disposition_sha256"),
                ("comparison_result", "comparison_sha256"),
            ):
                raw = deliverables.get(field)
                if raw is None:
                    continue
                if not isinstance(raw, str):
                    return None
                try:
                    record = json.loads(raw)
                except (TypeError, ValueError):
                    return None
                if not _seal_valid(record, seal_field):
                    return None
                if field == "verification_receipt":
                    passed = record.get("pass") is True
                    candidates.append(
                        {
                            "status": "PASS" if passed else "FAIL",
                            "stage": "pass" if passed else "failed",
                            "sha256": record[seal_field],
                        }
                    )
                elif field == "review_disposition":
                    decision = record.get("decision")
                    if decision not in {"PASS", "REPAIR", "ESCALATE"}:
                        return None
                    candidates.append(
                        {
                            "status": (
                                "PASS"
                                if decision == "PASS"
                                else "ESCALATED"
                                if decision == "ESCALATE"
                                else "FAIL"
                            ),
                            "stage": (
                                "pass"
                                if decision == "PASS"
                                else "escalated"
                                if decision == "ESCALATE"
                                else "failed"
                            ),
                            "sha256": record[seal_field],
                        }
                    )
                elif record.get("status") in {"tie", "escalate"}:
                    escalated = record.get("status") == "escalate"
                    candidates.append(
                        {
                            "status": "ESCALATED" if escalated else "FAIL",
                            "stage": "escalated" if escalated else "failed",
                            "sha256": record[seal_field],
                        }
                    )

            cleanup = facts.get("cleanup")
            if cleanup is not None:
                if (
                    not isinstance(cleanup, Mapping)
                    or cleanup.get("status") not in {"complete", "unknown"}
                    or not isinstance(cleanup.get("evidence_sha256"), str)
                    or _SHA256.fullmatch(cleanup["evidence_sha256"]) is None
                ):
                    return None
                candidates.append(
                    {
                        "status": "UNKNOWN",
                        "stage": "unknown",
                        "sha256": cleanup["evidence_sha256"],
                    }
                )

        terminal_kind = state.get("terminal_kind")
        execution = state.get("axes", {}).get("execution")
        if terminal_kind == run_engine.KIND_TERMINATED:
            matching = [item for item in candidates if item["status"] == "UNKNOWN"]
            return matching[-1] if matching else None
        if execution == "succeeded":
            matching = [item for item in candidates if item["status"] == "PASS"]
            return matching[-1] if matching else None
        matching = [
            item for item in candidates if item["status"] in {"FAIL", "ESCALATED"}
        ]
        if matching:
            return matching[-1]
        stream_sha256 = state.get("stream_sha256")
        if isinstance(stream_sha256, str) and _SHA256.fullmatch(stream_sha256):
            return {
                "status": "FAIL",
                "stage": "failed",
                "sha256": stream_sha256,
            }
        return None

    @staticmethod
    def _terminal_learning_metrics(
        events: list[Mapping[str, Any]],
        control: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        input_tokens = 0
        output_tokens = 0
        latency_ms = 0
        worker_results = 0
        usage_records = 0
        timing_records = 0
        repair_sequences: set[int] = set()
        artifacts: dict[tuple[str, str], dict[str, Any]] = {}
        handoffs: dict[str, dict[str, Any]] = {}

        for event in events:
            if event.get("kind") != run_engine.KIND_APPLIED:
                continue
            try:
                facts = json.loads(event["payload"])
            except (KeyError, TypeError, ValueError):
                return None
            deliverables = facts.get("deliverables", {})
            evidence = facts.get("evidence", {})
            if not isinstance(deliverables, Mapping) or not isinstance(
                evidence, Mapping
            ):
                return None
            worker_results += sum(
                1
                for key in evidence
                if key == "worker_result" or key.startswith("worker_result:")
            )
            for key, raw in deliverables.items():
                if not isinstance(key, str) or not isinstance(raw, str):
                    return None
                if key == "artifact_ref":
                    try:
                        artifact = json.loads(raw)
                    except (TypeError, ValueError):
                        return None
                    if (
                        not isinstance(artifact, Mapping)
                        or not isinstance(artifact.get("uri"), str)
                        or not isinstance(artifact.get("sha256"), str)
                        or _SHA256.fullmatch(artifact["sha256"]) is None
                        or type(artifact.get("size_bytes")) is not int
                        or artifact["size_bytes"] < 0
                    ):
                        return None
                    artifacts[(artifact["uri"], artifact["sha256"])] = dict(
                        artifact
                    )
                elif key == "handoff_receipt":
                    try:
                        handoff = json.loads(raw)
                    except (TypeError, ValueError):
                        return None
                    if (
                        not isinstance(handoff, Mapping)
                        or not _seal_valid(handoff, "handoff_sha256")
                        or not isinstance(handoff.get("conflicts"), list)
                    ):
                        return None
                    handoffs[handoff["handoff_sha256"]] = dict(handoff)
                elif key == "repair_sequence":
                    try:
                        sequence = int(raw)
                    except (TypeError, ValueError):
                        return None
                    if sequence <= 0 or str(sequence) != raw:
                        return None
                    repair_sequences.add(sequence)
                elif key == "worker_usage" or key.startswith("worker_usage:"):
                    try:
                        usage = json.loads(raw)
                    except (TypeError, ValueError):
                        return None
                    if (
                        not isinstance(usage, Mapping)
                        or usage.get("status") != "exact"
                        or any(
                            type(usage.get(field)) is not int
                            or usage[field] < 0
                            for field in (
                                "input_tokens",
                                "output_tokens",
                                "total_tokens",
                            )
                        )
                        or usage["total_tokens"]
                        != usage["input_tokens"] + usage["output_tokens"]
                    ):
                        return None
                    input_tokens += usage["input_tokens"]
                    output_tokens += usage["output_tokens"]
                    usage_records += 1
                elif _worker_timing_key(key):
                    try:
                        timing = json.loads(raw)
                    except (TypeError, ValueError):
                        return None
                    if (
                        not isinstance(timing, Mapping)
                        or timing.get("status") != "exact"
                        or type(timing.get("wall_time_ms")) is not int
                        or timing["wall_time_ms"] < 0
                    ):
                        return None
                    latency_ms += timing["wall_time_ms"]
                    timing_records += 1

        if usage_records != worker_results or timing_records != worker_results:
            return None
        task_specs = control.get("task_specs")
        if not isinstance(task_specs, Mapping) or any(
            not isinstance(spec, Mapping) or spec.get("allowed_tools") != []
            for spec in task_specs.values()
        ):
            return None
        hosted_calls = control.get("reservation_requirements", {}).get(
            "hosted_calls"
        )
        if hosted_calls != 0:
            return None
        conflicts = sum(len(handoff["conflicts"]) for handoff in handoffs.values())
        return {
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "tool_calls": 0,
                "model_calls": worker_results,
                "hosted_calls": hosted_calls,
            },
            "latency_ms": latency_ms,
            "rework_count": len(repair_sequences),
            "cost": {"currency": "USD", "micros": 0},
            "integration_load": {
                "artifact_count": len(artifacts),
                "ingress_tokens": sum(
                    artifact["size_bytes"] for artifact in artifacts.values()
                ),
                "conflict_count": conflicts,
            },
        }

    @staticmethod
    def _terminal_role_attribution(
        policy: Mapping[str, Any],
        events: list[Mapping[str, Any]],
        state: Mapping[str, Any],
        verification: Mapping[str, str],
        expected_human: str | None,
        route_learning: Any,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        """The role factors and role outcomes of one terminal run (Issue 186).

        There is one row per role and resolved profile of the routing policy
        the run froze under.  A node ran when the stream holds its worker
        result, anchored by its lane-release receipt and carrying exactly one
        exact timing receipt, or, for root labor, its own applied event.
        Elapsed time sums the timing of the worker nodes that ran and repair
        passes count the repair revisions that ran.  A producing row's work
        was accepted when an artifact of its nodes is in the verified
        deliverable: the artifacts a passing verification receipt names,
        closed over what a join consumed into them, and a required human
        approval of that deliverable is credited the same way.  A rejection,
        by the review or by the human, and an escalation count other than zero
        belong only to a sole producing row, because a joint deliverable does
        not say whose work it judged.  A reviewer row judges work rather than
        producing it.  Cost is never priced on this path.  Every missing
        value is a typed unknown, never zero or success; malformed evidence
        returns None.
        """

        known = route_learning.known_factor
        unknown = route_learning.unknown_factor
        nodes = policy.get("nodes")
        routes = policy.get("routes")
        if not isinstance(nodes, Mapping) or not isinstance(routes, Mapping) or not nodes:
            return None
        rows: dict[tuple[str, str], list[str]] = {}
        for node_id, entry in nodes.items():
            if (
                not isinstance(entry, Mapping)
                or not isinstance(entry.get("role"), str)
                or not isinstance(routes.get(entry.get("profile_id")), Mapping)
            ):
                return None
            rows.setdefault((entry["role"], entry["profile_id"]), []).append(node_id)
        root_labor = {
            node_id
            for node_id, entry in nodes.items()
            if routes[entry["profile_id"]].get("adapter") == "root_labor"
        }

        def artifact_sha(raw: Any) -> str:
            reference = json.loads(raw) if isinstance(raw, str) else raw
            if (
                not isinstance(reference, Mapping)
                or not isinstance(reference.get("sha256"), str)
                or _SHA256.fullmatch(reference["sha256"]) is None
            ):
                raise ValueError("artifact_reference_invalid")
            return reference["sha256"]

        anchor = "lane_release_receipt:"
        ran: dict[str, int | None] = {}
        artifacts: dict[str, str] = {}
        repaired: set[str] = set()
        verified: set[str] = set()
        joins: list[tuple[str, list[str]]] = []
        verdicts = 0
        escalations = 0
        try:
            for event in events:
                if event.get("kind") != run_engine.KIND_APPLIED:
                    continue
                facts = json.loads(event["payload"])
                deliverables = facts.get("deliverables") if isinstance(facts, Mapping) else None
                if not isinstance(deliverables, Mapping):
                    continue
                anchored = [
                    key[len(anchor):]
                    for key in deliverables
                    if isinstance(key, str)
                    and key.startswith(anchor)
                    and key[len(anchor):] in nodes
                ]
                if len(anchored) > 1:
                    return None
                artifact = (
                    artifact_sha(deliverables["artifact_ref"])
                    if "artifact_ref" in deliverables
                    else None
                )
                if anchored:
                    timings = [
                        json.loads(raw)
                        for key, raw in deliverables.items()
                        if _worker_timing_key(key)
                    ]
                    if (
                        len(timings) != 1
                        or not isinstance(timings[0], Mapping)
                        or timings[0].get("status") != "exact"
                        or type(timings[0].get("wall_time_ms")) is not int
                        or timings[0]["wall_time_ms"] < 0
                    ):
                        return None
                    ran[anchored[0]] = timings[0]["wall_time_ms"]
                    if artifact is not None:
                        artifacts[anchored[0]] = artifact
                    if "repair_sequence" in deliverables:
                        repaired.add(anchored[0])
                elif event.get("actor_key") in root_labor:
                    ran[event["actor_key"]] = None
                if "consumed_artifact_refs" in deliverables:
                    if artifact is None:
                        return None
                    consumed = json.loads(deliverables["consumed_artifact_refs"])
                    if not isinstance(consumed, list):
                        return None
                    joins.append((artifact, [artifact_sha(item) for item in consumed]))
                judged = False
                raw = deliverables.get("verification_receipt")
                if isinstance(raw, str):
                    judged = True
                    receipt = json.loads(raw)
                    if isinstance(receipt, Mapping) and receipt.get("pass") is True:
                        verified.update(
                            artifact_sha(item) for item in receipt.get("artifact_refs") or []
                        )
                for field, escalated in (
                    ("review_disposition", lambda value: value.get("decision") == "ESCALATE"),
                    ("comparison_result", lambda value: value.get("status") == "escalate"),
                ):
                    raw = deliverables.get(field)
                    if not isinstance(raw, str):
                        continue
                    judged = True
                    verdict = json.loads(raw)
                    if isinstance(verdict, Mapping) and escalated(verdict):
                        escalations += 1
                if judged:
                    verdicts += 1
        except (KeyError, TypeError, ValueError):
            return None

        accepted = set(verified)
        grown = True
        while grown:
            grown = False
            for output, consumed in joins:
                if output in accepted and not set(consumed) <= accepted:
                    accepted.update(consumed)
                    grown = True

        keys = sorted(rows)
        cancelled = state.get("terminal_kind") == run_engine.KIND_TERMINATED
        passed = verification.get("status") == "PASS"
        failed = verification.get("status") in {"FAIL", "ESCALATED"}
        producing = [
            key
            for key in keys
            if key[0] != "reviewer" and any(node in ran for node in rows[key])
        ]
        sole_producer = producing[0] if len(producing) == 1 else None
        assignments: list[dict[str, Any]] = []
        outcomes: list[dict[str, Any]] = []
        for key in keys:
            role, profile_id = key
            route = routes[profile_id]
            node_ids = sorted(rows[key])
            assignments.append(
                {
                    "role": role,
                    "profile_id": profile_id,
                    "profile_sha256": route.get("profile_sha256"),
                    "model": route.get("model"),
                    "effort": route.get("effort"),
                    "adapter": route.get("adapter"),
                    "node_ids": node_ids,
                }
            )
            observed = [node for node in node_ids if node in ran]
            if not observed:
                outcomes.append(
                    {
                        "role": role,
                        "profile_id": profile_id,
                        **{
                            factor: unknown("not_dispatched")
                            for factor in route_learning.ROLE_OUTCOME_FACTORS
                        },
                    }
                )
                continue
            reviewer = role == "reviewer"
            contributed = passed and any(
                artifacts.get(node) in accepted for node in observed
            )
            if cancelled:
                acceptance = unknown("run_cancelled")
            elif reviewer:
                acceptance = unknown("not_attributable")
            elif not verdicts:
                acceptance = unknown("not_reviewed")
            elif contributed:
                acceptance = known("accepted")
            elif failed and key == sole_producer:
                acceptance = known("rejected")
            elif passed or failed:
                acceptance = unknown("not_attributable")
            else:
                acceptance = unknown("not_reviewed")
            if reviewer:
                escalation = unknown("not_attributable")
            elif not verdicts:
                escalation = unknown("not_reviewed")
            elif escalations == 0 or key == sole_producer:
                escalation = known(escalations)
            else:
                escalation = unknown("not_attributable")
            if reviewer:
                human = unknown("not_attributable")
            elif expected_human == "not_required":
                human = known("not_required")
            elif expected_human is None:
                human = unknown("not_observed")
            elif expected_human == "accepted" and contributed:
                human = known("accepted")
            elif expected_human == "rejected" and key == sole_producer:
                human = known("rejected")
            else:
                human = unknown("not_attributable")
            timings = [ran[node] for node in observed]
            outcomes.append(
                {
                    "role": role,
                    "profile_id": profile_id,
                    "acceptance": acceptance,
                    "repair_passes": known(
                        sum(1 for node in observed if node in repaired)
                    ),
                    "elapsed_ms": (
                        known(sum(timings))
                        if all(timing is not None for timing in timings)
                        else unknown("not_observed")
                    ),
                    "cost": unknown("cost_unpriced"),
                    "escalations": escalation,
                    "human_disposition": human,
                }
            )
        role_factors = {
            "registry_generation": policy.get("registry_generation"),
            "registry_sha256": policy.get("registry_sha256"),
            "routing_policy_sha256": policy.get("policy_sha256"),
            "assignments": assignments,
        }
        return role_factors, outcomes

    def _terminal_role_refusal(
        self,
        route_learning: Any,
        route_request: Mapping[str, Any],
        control: Mapping[str, Any],
        events: list[Mapping[str, Any]],
        state: Mapping[str, Any],
        verification: Mapping[str, str],
        expected_human: str | None,
    ) -> str | None:
        """The refusal a terminal projection's role dimension earns, or None.

        A run whose logical plan binds a routing policy records the v2
        factored run, and its role factors and role outcomes must equal what
        the plan's policy and the verified stream give (Issue 186).  The
        policy is derived again from the frozen plan under the active
        registry and must still seal to the digest the plan binds.  A run that
        froze before the registry existed binds no policy and keeps the v1
        record.
        """

        logical_plan = control.get("logical_plan")
        bound = (
            logical_plan.get("routing_policy_sha256")
            if isinstance(logical_plan, Mapping)
            else None
        )
        version_two = (
            route_request.get("schema") == route_learning.RUN_RECORD_REQUEST_SCHEMA_V2
        )
        if bound is None:
            return "inspect:learning_role_factors_unavailable" if version_two else None
        if not version_two:
            return "inspect:learning_role_factors_required"
        policy = _plan_routing_policy(logical_plan)
        if not isinstance(policy, Mapping) or policy.get("policy_sha256") != bound:
            return "inspect:learning_routing_policy_stale"
        attribution = self._terminal_role_attribution(
            policy, events, state, verification, expected_human, route_learning
        )
        if attribution is None:
            return "inspect:learning_role_evidence_invalid"
        role_factors, role_outcomes = attribution
        if route_request.get("role_factors") != role_factors:
            return "inspect:learning_role_factors_mismatch"
        if route_request.get("role_outcome_factors") != role_outcomes:
            return "inspect:learning_role_outcome_mismatch"
        return None

    def _inspect_terminal_learning(
        self, request: Any
    ) -> tuple[dict[str, Any] | None, list[str]]:
        route_learning, strategy_cards = _learning_evaluators()
        if not isinstance(request, Mapping) or set(request) != _TERMINAL_LEARNING_FIELDS:
            return None, ["inspect:learning_terminal_request_invalid"]
        run_id = request.get("run_id")
        route_program = request.get("route_program")
        strategy_program = request.get("strategy_program")
        if (
            not isinstance(run_id, str)
            or not run_id
            or not isinstance(route_program, Mapping)
            or set(route_program) != {"schema", "operation", "request"}
            or route_program.get("schema")
            != route_learning.EVALUATION_REQUEST_SCHEMA
            or route_program.get("operation") != "record_run"
            or not isinstance(route_program.get("request"), Mapping)
            or not isinstance(strategy_program, Mapping)
            or set(strategy_program) != {"schema", "action", "request"}
            or strategy_program.get("schema") != strategy_cards.PROGRAM_SCHEMA
            or strategy_program.get("action") != "propose_card"
            or not isinstance(strategy_program.get("request"), Mapping)
            or set(strategy_program["request"]) != {"source_record"}
            or not isinstance(strategy_program["request"].get("source_record"), Mapping)
        ):
            return None, ["inspect:learning_terminal_request_invalid"]
        try:
            events = list(self.engine.events(run_id, 0))
        except run_engine.NotFoundError:
            return None, ["inspect:learning_run_not_found"]
        try:
            started = json.loads(events[0]["payload"])
            plan = started["plan"]
            state = self.engine.reduce(plan, events)
            control = plan["origin"]["control_tower"]
            task = control["task_brief"]
            control_route = control["route"]
            expected_profile = control_route["profile_id"]
            expected_project = task["project_ref"]["project_id"]
            expected_privacy = task["privacy_class"]
            expected_risk = task["risk_class"]
        except (IndexError, KeyError, TypeError, ValueError, run_engine.RunKernelError):
            return None, ["inspect:learning_run_state_invalid"]
        if state.get("terminal") is not True:
            return None, ["inspect:learning_run_not_terminal"]
        stream_sha256 = state["stream_sha256"]
        terminal_outcome = (
            "cancelled"
            if state.get("terminal_kind") == "terminated"
            else "success"
            if state.get("axes", {}).get("execution") == "succeeded"
            else "failure"
        )
        correctness = (
            "PASS"
            if terminal_outcome == "success"
            else "NOT_APPLICABLE"
            if terminal_outcome == "cancelled"
            else "FAIL"
        )
        verification = self._terminal_learning_evidence(events, state)
        if verification is None:
            return None, ["inspect:learning_verification_missing"]
        metrics = self._terminal_learning_metrics(events, control)
        if metrics is None:
            return None, ["inspect:learning_run_evidence_invalid"]
        event_hashes = {
            event.get("event_hash")
            for event in events
            if isinstance(event.get("event_hash"), str)
        }
        binding_event_sha256 = events[0].get("event_hash")

        route_request = route_program["request"]
        route_task = route_request.get("task_features")
        route_factors = route_request.get("route_factors")
        route_outcome = route_request.get("outcome_factors")
        if not all(
            isinstance(value, Mapping)
            for value in (route_task, route_factors, route_outcome)
        ):
            return None, ["inspect:learning_terminal_request_invalid"]
        if route_request.get("run_id") != run_id:
            return None, ["inspect:learning_route_run_mismatch"]
        if route_request.get("terminal_stream_sha256") != stream_sha256:
            return None, ["inspect:learning_route_stream_mismatch"]
        if route_task.get("task_id") != task.get("task_id"):
            return None, ["inspect:learning_route_task_mismatch"]
        if route_task.get("privacy_class") != expected_privacy:
            return None, ["inspect:learning_route_privacy_mismatch"]
        if route_task.get("risk_class") != expected_risk:
            return None, ["inspect:learning_route_risk_mismatch"]
        if (
            route_task.get("safety_gate") != "PASS"
            or route_task.get("safety_evidence_sha256")
            != binding_event_sha256
        ):
            return None, ["inspect:learning_route_safety_mismatch"]
        if route_factors.get("profile_id") != expected_profile:
            return None, ["inspect:learning_route_profile_mismatch"]
        if (
            route_factors.get("router_report_sha256")
            != control_route.get("route_sha256")
        ):
            return None, ["inspect:learning_route_digest_mismatch"]
        if route_factors.get("cut_strategy") != control_route.get("cut"):
            return None, ["inspect:learning_route_cut_mismatch"]
        if route_factors.get("lane_count") != control_route.get("worker_count"):
            return None, ["inspect:learning_route_count_mismatch"]
        executor_choices = route_factors.get("executor_choices")
        capability = control.get("executor_capability")
        expected_model = (
            capability.get("runtime_identity", {}).get("logical_model_id")
            if isinstance(capability, Mapping)
            else None
        )
        worker_choices = (
            [
                choice
                for choice in (
                    executor_choices if isinstance(executor_choices, list) else []
                )
                if isinstance(choice, Mapping)
                and choice.get("role")
                not in {
                    "planner",
                    "integrator",
                    "comparator",
                    "reviewer",
                    "verifier",
                }
            ]
            if isinstance(executor_choices, list)
            else []
        )
        submitted_groups = sorted(
            {
                choice.get("executor_group")
                for choice in worker_choices
                if isinstance(choice.get("executor_group"), str)
            }
        )
        assignment_models = {
            role: assignment.get("model")
            for role, assignment in started.get("assignments", {}).items()
            if isinstance(role, str) and isinstance(assignment, Mapping)
        }
        if (
            submitted_groups != control_route.get("executor_groups")
            or expected_model is None
            or any(
                choice.get("model_profile") != expected_model
                for choice in worker_choices
            )
            or any(
                choice.get("role") in assignment_models
                and choice.get("model_profile")
                != assignment_models[choice["role"]]
                for choice in executor_choices
                if isinstance(choice, Mapping)
            )
        ):
            return None, ["inspect:learning_route_executors_mismatch"]
        context_choice = route_factors.get("context_choice")
        if (
            not isinstance(context_choice, Mapping)
            or context_choice.get("policy_id")
            != control_route.get("context_policy")
            or context_choice.get("input_tokens")
            != metrics["usage"]["input_tokens"]
            or context_choice.get("ingress_limit_tokens")
            != task["budgets"]["context_tokens"]
        ):
            return None, ["inspect:learning_route_context_mismatch"]
        expected_budget = {
            "token_limit": task["budgets"]["context_tokens"]
            + task["budgets"]["output_tokens"],
            "latency_limit_ms": task["budgets"]["wall_time_ms"],
            "cost_limit_micros": task["budgets"]["cost_microusd"],
        }
        if (
            route_factors.get("budget_sha256")
            != control_route.get("budget_sha256")
            or route_factors.get("budget_choice") != expected_budget
        ):
            return None, ["inspect:learning_route_budget_mismatch"]
        verification_choice = route_factors.get("verification_choice")
        if (
            not isinstance(verification_choice, Mapping)
            or verification_choice.get("policy_id")
            != control_route.get("verification_depth")
        ):
            return None, [
                "inspect:learning_route_verification_policy_mismatch"
            ]
        if route_outcome.get("terminal_outcome") != terminal_outcome:
            return None, ["inspect:learning_route_outcome_mismatch"]
        if route_outcome.get("correctness") != correctness:
            return None, ["inspect:learning_route_correctness_mismatch"]
        if (
            route_outcome.get("verification_status") != verification["status"]
            or route_outcome.get("verification_evidence_sha256")
            != verification["sha256"]
        ):
            return None, ["inspect:learning_route_verification_mismatch"]
        if route_outcome.get("usage") != metrics["usage"]:
            return None, ["inspect:learning_outcome_usage_mismatch"]
        if route_outcome.get("latency_ms") != metrics["latency_ms"]:
            return None, ["inspect:learning_outcome_latency_mismatch"]
        if route_outcome.get("rework_count") != metrics["rework_count"]:
            return None, ["inspect:learning_outcome_rework_mismatch"]
        if route_outcome.get("cost") != metrics["cost"]:
            return None, ["inspect:learning_outcome_cost_mismatch"]
        if route_outcome.get("integration_load") != metrics["integration_load"]:
            return None, ["inspect:learning_outcome_integration_mismatch"]
        privacy_refs = route_outcome.get("privacy_event_refs")
        if (
            privacy_refs != [binding_event_sha256]
            or any(ref not in event_hashes for ref in privacy_refs)
        ):
            return None, ["inspect:learning_outcome_privacy_refs_mismatch"]
        authority_refs = route_outcome.get("authority_event_refs")
        if (
            authority_refs != [binding_event_sha256]
            or any(ref not in event_hashes for ref in authority_refs)
        ):
            return None, ["inspect:learning_outcome_authority_refs_mismatch"]
        expected_human = "not_required"
        if task.get("required_human_approvals"):
            expected_human = None
            for event in events:
                if event.get("kind") != run_engine.KIND_APPLIED:
                    continue
                facts = json.loads(event["payload"])
                raw = facts.get("deliverables", {}).get("review_disposition")
                if not isinstance(raw, str):
                    continue
                disposition = json.loads(raw)
                human_layers = [
                    layer
                    for layer in disposition.get("layers", [])
                    if isinstance(layer, Mapping)
                    and layer.get("layer") == "human_approval"
                ]
                if len(human_layers) == 1:
                    expected_human = (
                        "accepted"
                        if disposition.get("decision") == "PASS"
                        and human_layers[0].get("status") == "PASS"
                        else "rejected"
                    )
        if route_outcome.get("human_disposition") != expected_human:
            return None, ["inspect:learning_outcome_human_mismatch"]
        route_source_refs = route_request.get("source_refs")
        if (
            not isinstance(route_source_refs, list)
            or not any(
                isinstance(ref, str) and run_id in ref
                for ref in route_source_refs
            )
            or not any(
                isinstance(ref, str) and verification["sha256"] in ref
                for ref in route_source_refs
            )
        ):
            return None, ["inspect:learning_route_source_mismatch"]

        role_issue = self._terminal_role_refusal(
            route_learning,
            route_request,
            control,
            events,
            state,
            verification,
            expected_human,
        )
        if role_issue is not None:
            return None, [role_issue]


        source = strategy_program["request"]["source_record"]
        if source.get("run_id") != run_id:
            return None, ["inspect:learning_strategy_run_mismatch"]
        if source.get("run_lineage_sha256") != stream_sha256:
            return None, ["inspect:learning_strategy_stream_mismatch"]
        if source.get("task_fingerprint") != _sha256(task):
            return None, ["inspect:learning_strategy_task_mismatch"]
        if source.get("project_id") != expected_project:
            return None, ["inspect:learning_strategy_project_mismatch"]
        if source.get("privacy_scope") != expected_privacy:
            return None, ["inspect:learning_strategy_privacy_mismatch"]
        if source.get("profile_id") != expected_profile:
            return None, ["inspect:learning_strategy_profile_mismatch"]
        if source.get("terminal_outcome") != terminal_outcome:
            return None, ["inspect:learning_strategy_outcome_mismatch"]
        strategy_source_refs = source.get("source_refs")
        if (
            not isinstance(strategy_source_refs, list)
            or run_id not in strategy_source_refs
            or not any(
                isinstance(ref, str) and stream_sha256 in ref
                for ref in strategy_source_refs
            )
        ):
            return None, ["inspect:learning_strategy_source_mismatch"]
        source_verification = source.get("verification")
        if (
            not isinstance(source_verification, Mapping)
            or source_verification.get("stage") != verification["stage"]
            or source_verification.get("evidence_refs")
            != [verification["sha256"]]
        ):
            return None, ["inspect:learning_strategy_verification_mismatch"]
        if verification["sha256"] not in source.get("evidence_refs", []):
            return None, ["inspect:learning_strategy_evidence_mismatch"]
        expected_strategy_usage = {
            "tokens": metrics["usage"]["input_tokens"]
            + metrics["usage"]["output_tokens"],
            "cost_cents": (metrics["cost"]["micros"] + 9_999) // 10_000,
            "wall_seconds": (metrics["latency_ms"] + 999) // 1000,
        }
        if source.get("usage") != expected_strategy_usage:
            return None, ["inspect:learning_strategy_usage_mismatch"]
        supporting = source.get("supporting_lineages")
        expected_self = {
            "run_id": run_id,
            "lineage_sha256": stream_sha256,
            "outcome": terminal_outcome,
        }
        if not isinstance(supporting, list) or expected_self not in supporting:
            return None, ["inspect:learning_strategy_support_mismatch"]
        if terminal_outcome == "success":
            if source.get("useful_strategy") is None or source.get(
                "failure_pattern"
            ) is not None:
                return None, ["inspect:learning_strategy_kind_mismatch"]
        elif source.get("failure_pattern") is None or source.get(
            "useful_strategy"
        ) is not None:
            return None, ["inspect:learning_strategy_kind_mismatch"]

        route_report = route_learning.evaluate(route_program)
        strategy_report = strategy_cards.evaluate(strategy_program)
        return self._learning_projection(
            kind="terminal_projection",
            run_id=run_id,
            stream_sha256=stream_sha256,
            terminal_bound=True,
            route_report=route_report,
            strategy_report=strategy_report,
        ), []

    def _inspect_learning(
        self, payload: Any
    ) -> tuple[dict[str, Any] | None, list[str]]:
        if (
            not isinstance(payload, Mapping)
            or set(payload) != _LEARNING_INSPECTION_QUERY_FIELDS
            or payload.get("schema") != LEARNING_INSPECTION_QUERY_SCHEMA
            or payload.get("kind") not in {"route", "strategy", "terminal_projection"}
        ):
            return None, ["inspect:learning_query_invalid"]
        kind = payload["kind"]
        if kind == "terminal_projection":
            return self._inspect_terminal_learning(payload.get("request"))
        route_learning, strategy_cards = _learning_evaluators()
        if kind == "route":
            report = route_learning.evaluate(payload.get("request"))
            return self._learning_projection(
                kind=kind,
                run_id=None,
                stream_sha256=None,
                terminal_bound=False,
                route_report=report,
                strategy_report=None,
            ), []
        report = strategy_cards.evaluate(payload.get("request"))
        return self._learning_projection(
            kind=kind,
            run_id=None,
            stream_sha256=None,
            terminal_bound=False,
            route_report=None,
            strategy_report=report,
        ), []

    @staticmethod
    def _optimization_projection(
        *, kind: str, evaluator_report: Mapping[str, Any]
    ) -> dict[str, Any]:
        accepted = evaluator_report.get("status") == "PASS"
        return _seal(
            {
                "schema": OPTIMIZATION_INSPECTION_SCHEMA,
                "kind": kind,
                "decision": "EVALUATED" if accepted else "EVALUATOR_REJECTED",
                "source_authority": "submitted_inactive_evidence",
                "evaluator_report": deepcopy(dict(evaluator_report)),
                "projection_only": True,
                "append_permitted": False,
                "mutation_permitted": False,
                "policy_mutated": False,
                "production_intent_permitted": False,
                "dispatch_permitted": False,
                "shadow_permitted": False,
                "canary_permitted": False,
                "activation_permitted": False,
                "automatic_suspension_permitted": False,
                "bandit_permitted": False,
                "model_training_permitted": False,
                "production_exploration": False,
                "authority_granted": False,
                "workers_permitted": False,
                "provider_free": True,
                "model_calls": 0,
                "hosted_calls": 0,
                "retries": 0,
                "fallbacks": 0,
                "replacements": 0,
                "release_permitted": False,
                "installation_permitted": False,
            },
            "inspection_sha256",
        )

    def _inspect_optimization(
        self, payload: Any
    ) -> tuple[dict[str, Any] | None, list[str]]:
        if (
            not isinstance(payload, Mapping)
            or set(payload) != _OPTIMIZATION_INSPECTION_QUERY_FIELDS
            or payload.get("schema")
            != OPTIMIZATION_INSPECTION_QUERY_SCHEMA
            or payload.get("kind") not in {"topology", "promotion"}
        ):
            return None, ["inspect:optimization_query_invalid"]
        kind = payload["kind"]
        report = _optimization_evaluator(kind).evaluate(payload.get("request"))
        if not isinstance(report, Mapping):
            return None, ["inspect:optimization_evaluator_invalid"]
        return self._optimization_projection(
            kind=kind, evaluator_report=report
        ), []

    def inspect(self, payload: Any) -> tuple[dict[str, Any] | None, list[str]]:
        if (
            isinstance(payload, Mapping)
            and payload.get("schema")
            == OPTIMIZATION_INSPECTION_QUERY_SCHEMA
        ):
            return self._inspect_optimization(payload)
        if (
            isinstance(payload, Mapping)
            and payload.get("schema") == LEARNING_INSPECTION_QUERY_SCHEMA
        ):
            return self._inspect_learning(payload)
        if (
            isinstance(payload, Mapping)
            and payload.get("schema") == SCHEDULER_INSPECTION_QUERY_SCHEMA
        ):
            return self._inspect_scheduler(payload)
        if not isinstance(payload, Mapping) or set(payload) != _INSPECTION_QUERY_FIELDS:
            return None, ["inspect:query_invalid"]
        if payload.get("schema") != INSPECTION_QUERY_SCHEMA:
            return None, ["inspect:schema_invalid"]
        run_id = payload.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            return None, ["inspect:run_id_invalid"]
        after_seq = payload.get("after_seq")
        max_events = payload.get("max_events")
        max_artifacts = payload.get("max_artifacts")
        if type(after_seq) is not int or after_seq < 0:
            return None, ["inspect:after_seq_invalid"]
        if type(max_events) is not int or not 1 <= max_events <= 64:
            return None, ["inspect:max_events_invalid"]
        if type(max_artifacts) is not int or not 0 <= max_artifacts <= 64:
            return None, ["inspect:max_artifacts_invalid"]
        try:
            all_events = list(self.engine.events(run_id, 0))
        except run_engine.NotFoundError:
            return None, ["inspect:run_not_found"]
        started_facts = json.loads(all_events[0]["payload"])
        plan = started_facts["plan"]
        state = self.engine.reduce(plan, all_events)
        available = [event for event in all_events if event["seq"] > after_seq]
        selected = available[:max_events]
        projected = []
        artifacts: list[dict[str, Any]] = []
        for event in selected:
            facts = json.loads(event["payload"])
            projected.append(
                {
                    "seq": event["seq"],
                    "kind": event["kind"],
                    "actor_key": event["actor_key"],
                    "prev_hash": event["prev_hash"],
                    "event_hash": event["event_hash"],
                    "origin": deepcopy(dict(event["origin"])),
                    "facts_sha256": _sha256(facts),
                }
            )
            deliverables = facts.get("deliverables") if isinstance(facts, Mapping) else None
            if isinstance(deliverables, Mapping) and isinstance(deliverables.get("artifact_ref"), str):
                try:
                    ref = json.loads(deliverables["artifact_ref"])
                except (TypeError, ValueError):
                    ref = None
                if isinstance(ref, Mapping):
                    report = contracts.validate_artifact_ref(ref)
                    if report.get("status") == "PASS":
                        artifacts.append(report["normalized"])
        artifacts = sorted(
            {(ref["uri"], ref["sha256"]): ref for ref in artifacts}.values(),
            key=lambda ref: (ref["uri"], ref["sha256"]),
        )
        selected_artifacts = artifacts[:max_artifacts]
        try:
            artifact_records = self.artifacts.records(selected_artifacts)
        except (KeyError, TypeError, ValueError):
            return None, ["inspect:artifact_ledger_invalid"]
        cursor = _cursor(run_id, all_events, state)
        inspection = _seal(
            {
                "schema": INSPECTION_SCHEMA,
                "run_id": run_id,
                "events": projected,
                "state": json.loads(json.dumps(state, sort_keys=True)),
                "artifact_refs": selected_artifacts,
                "artifact_records": artifact_records,
                "next_cursor": cursor,
                "truncated": len(available) > len(selected) or len(artifacts) > max_artifacts,
                "stream_sha256": state["stream_sha256"],
            },
            "inspection_sha256",
        )
        return inspection, []

    def _inspect_scheduler(
        self, payload: Any
    ) -> tuple[dict[str, Any] | None, list[str]]:
        if (
            not isinstance(payload, Mapping)
            or set(payload) != _SCHEDULER_INSPECTION_QUERY_FIELDS
        ):
            return None, ["inspect:scheduler_query_invalid"]
        max_runs = payload.get("max_runs")
        if type(max_runs) is not int or not 1 <= max_runs <= 1024:
            return None, ["inspect:scheduler_max_runs_invalid"]
        if self.scheduler_capacity is None:
            return None, ["inspect:scheduler_not_configured"]
        if not self.store.exists(self._scheduler_run_id()):
            return None, ["inspect:scheduler_not_initialized"]
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["inspect:clock_invalid"]
        try:
            return self._scheduler_view(now_ms, max_runs=max_runs), []
        except _SCHEDULER_STATE_EXCEPTIONS:
            return None, ["inspect:scheduler_state_invalid"]

    def evaluate(self, program: Any) -> dict[str, Any]:
        if isinstance(program, Mapping) and program.get("schema") == PROGRAM_SCHEMA_V2:
            return self._frontier().evaluate(program)
        issues: list[str] = []
        value = _exact(program, _PROGRAM_FIELDS, "program", issues)
        if value.get("schema") != PROGRAM_SCHEMA:
            _issue(issues, "program:schema_invalid")
        program_id = _identifier(value.get("program_id"), "program:program_id", issues)
        operation = value.get("operation")
        if operation not in OPERATIONS:
            _issue(issues, "program:operation_invalid")

        result = None
        if not issues and operation == "prepare":
            result, operation_issues = self.prepare(value.get("payload"))
            issues.extend(operation_issues)
        elif not issues and operation == "advance":
            result, operation_issues = self.advance(value.get("payload"))
            issues.extend(operation_issues)
        elif not issues and operation == "inspect":
            result, operation_issues = self.inspect(value.get("payload"))
            issues.extend(operation_issues)
        elif not issues:
            _issue(issues, "program:operation_not_implemented")

        core = {
            "schema": REPORT_SCHEMA,
            "program_id": program_id or None,
            "operation": operation if operation in OPERATIONS else None,
            "status": "PASS" if not issues else "FAIL",
            "issues": sorted(set(issues)),
            "result": result if not issues else None,
        }
        return {**core, "report_sha256": _sha256(core)}


DEFAULT_TOWER = ControlTower()


def evaluate_control_tower(program: Any, *, tower: ControlTower | None = None) -> dict[str, Any]:
    """Evaluate one closed Control Tower operation through an injected tower."""

    active = tower if tower is not None else DEFAULT_TOWER
    try:
        return active.evaluate(program)
    except (TypeError, ValueError, OverflowError):
        core = {
            "schema": REPORT_SCHEMA,
            "program_id": None,
            "operation": None,
            "status": "FAIL",
            "issues": ["program:hostile_or_non_json_input"],
            "result": None,
        }
        return {**core, "report_sha256": _sha256(core)}


__all__ = [
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "PROGRAM_SCHEMA_V2",
    "REPORT_SCHEMA_V2",
    "TASK_BRIEF_SCHEMA",
    "PLANNING_REQUIREMENT_SCHEMA",
    "PLANNING_SUBMISSION_SCHEMA",
    "ADVANCE_SCHEMA",
    "ENQUEUE_SCHEMA",
    "SCHEDULE_SCHEMA",
    "INSPECTION_QUERY_SCHEMA",
    "LEARNING_INSPECTION_QUERY_SCHEMA",
    "LEARNING_INSPECTION_SCHEMA",
    "OPTIMIZATION_INSPECTION_QUERY_SCHEMA",
    "OPTIMIZATION_INSPECTION_SCHEMA",
    "SCHEDULER_INSPECTION_QUERY_SCHEMA",
    "SCHEDULER_INSPECTION_SCHEMA",
    "SCHEDULER_CURSOR_SCHEMA",
    "SCHEDULER_DECISION_SCHEMA",
    "SCHEDULER_CAPACITY_SCHEMA",
    "CLEANUP_OBSERVATION_SCHEMA",
    "LANE_CLEANUP_PAYLOAD_SCHEMA",
    "POLICY_GENERATION",
    "OPERATIONS",
    "ControlTower",
    "InMemoryArtifactLedger",
    "FilesystemArtifactLedger",
    "evaluate_control_tower",
]
