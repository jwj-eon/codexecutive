#!/usr/bin/env python3
"""Provider-free coordination-efficiency governor for Orch Dork.

The external interface begins with a finite logical worker program. Logical
work is deliberately independent from the live collaboration capacity that a
later scheduler observes. This module is extended ticket-by-ticket behind the
same small, JSON-compatible interface; it never launches a model or provider.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Mapping, Sequence


def _load_sibling(name: str):
    """Load a sibling when this module itself was loaded by file path."""

    try:
        return __import__(name)
    except ImportError:
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


worker_default = _load_sibling("orch_dork_worker_default")
adaptive_contracts = _load_sibling("orch_dork_adaptive_contracts")
routing_verify = _load_sibling("orch_dork_routing_verify")
model_profiles = _load_sibling("orch_dork_model_profile_registry")


def worker_model():
    """The governed worker model, resolved when it is used."""

    return worker_default.configured_worker_model()


def worker_effort():
    """The governed worker effort, resolved when it is used."""

    return worker_default.configured_worker_effort()


def root_model_accepted(candidate, declared=None):
    """Whether a submitted root/planner model is permissible (seam-owned)."""

    return worker_default.root_model_accepted(candidate, declared=declared)


LOGICAL_PLAN_SCHEMA = "orch-dork/logical-plan/v1"
LOGICAL_PLAN_REPORT_SCHEMA = "orch-dork/logical-plan-report/v1"
CONTROLLER_SCHEMA = "orch-dork/coordination-controller/v1"
WAVE_PROGRAM_SCHEMA = "orch-dork/wave-program/v1"
WAVE_PROGRAM_SCHEMA_V2 = "orch-dork/wave-program/v2"
WAVE_PROGRAM_SCHEMA_V3 = "orch-dork/wave-program/v3"
WAVE_REPORT_SCHEMA = "orch-dork/wave-report/v1"
WAVE_PROGRESS_PROGRAM_SCHEMA = "orch-dork/wave-progress-program/v1"
WAVE_PROGRESS_REPORT_SCHEMA = "orch-dork/wave-progress-report/v1"
REPLAN_PROGRAM_SCHEMA = "orch-dork/replan-program/v1"
REPLAN_REPORT_SCHEMA = "orch-dork/replan-report/v1"
ACTIVE_CONTROLLER_PROGRAM_SCHEMA = "orch-dork/active-controller-program/v1"
ACTIVE_CONTROLLER_REPORT_SCHEMA = "orch-dork/active-controller-report/v1"
TICKET_ADMISSION_POLICY_VERSION = "classification-policy/v2"
TICKET_ADMISSION_SCHEMA = "orch-dork/ticket-admission/v2"
TICKET_ADMISSION_EVENT_SCHEMA = "orch-dork/ticket-admission-events/v2"
TICKET_ADMISSION_IDENTITY_FIELDS = {
    "ticket_id",
    "ticket_spec_sha256",
    "acceptance_criteria_sha256",
    "authority_scope_sha256",
    "writable_scope_sha256",
    "root_task_id",
    "invocation_identity_sha256",
    "classification_evidence_sha256",
    "candidate_lanes_sha256",
}
TICKET_ADMISSION_IDENTITY_OPTIONAL_FIELDS = {"policy_version"}
LIMIT_POLICY_PROGRAM_SCHEMA = "orch-dork/limit-policy-program/v1"
LIMIT_POLICY_REPORT_SCHEMA = "orch-dork/limit-policy-report/v1"
PROFILE_LIFECYCLE_PROGRAM_SCHEMA = "orch-dork/profile-lifecycle-program/v1"
PROFILE_LIFECYCLE_REPORT_SCHEMA = "orch-dork/profile-lifecycle-report/v1"
EFFICIENCY_EVALUATION_PROGRAM_SCHEMA = "orch-dork/efficiency-evaluation-program/v1"
EFFICIENCY_EVALUATION_REPORT_SCHEMA = "orch-dork/efficiency-evaluation-report/v1"
BUDGET_PROGRAM_SCHEMA = "orch-dork/budget-program/v1"
BUDGET_REPORT_SCHEMA = "orch-dork/budget-report/v1"
RECOVERY_PROGRAM_SCHEMA = "orch-dork/recovery-program/v1"
RECOVERY_REPORT_SCHEMA = "orch-dork/recovery-report/v1"
GRAPH_PROGRAM_SCHEMA = "orch-dork/execution-graph/v1"
GRAPH_REPORT_SCHEMA = "orch-dork/execution-graph-report/v1"
ROLLOVER_PROGRAM_SCHEMA = "orch-dork/root-rollover-program/v1"
ROLLOVER_REPORT_SCHEMA = "orch-dork/root-rollover-report/v1"
ROLLOVER_CHECKPOINT_SCHEMA = "orch-dork/root-rollover-checkpoint/v1"
LEASE_SCHEMA = "orch-dork/execution-lease/v1"
LEASE_TRANSFER_SCHEMA = "orch-dork/root-rollover-lease-transfer/v1"

LIMIT_DIMENSIONS = (
    "hosted_calls",
    "tokens",
    "cost_microunits",
    "wall_time_ms",
    "turns",
    "children",
    "depth",
    "concurrency",
)
PEAK_DIMENSIONS = {"depth", "concurrency"}
CLEANUP_RESOURCES = (
    "owned_processes",
    "temporary_credentials",
    "locks",
    "tunnels",
    "configuration",
    "recovery_markers",
)
ROLLOVER_TRIGGERS = {
    "capacity_pinned",
    "context_pressure",
    "repeated_large_unchanged_input",
    "sol_requested",
}
ROLLOVER_FORBIDDEN_KEYS = {
    "conversation",
    "messages",
    "prompt",
    "raw_session_body",
    "reasoning",
    "chain_of_thought",
    "credentials",
    "authorization_secret",
}
ACTIVE_LIFECYCLE_FEATURES = {
    "admission",
    "scheduling",
    "membership",
    "custody",
    "release",
    "duplicate_prevention",
    "terminal_handoff",
}
ACTIVE_DECISION_KINDS = {
    "ambiguity",
    "conflict",
    "partial_acceptance",
    "replan",
    "authority_expansion",
    "scope_expansion",
    "quality_tradeoff",
    "final_semantic_acceptance",
}

# Issue 33's ticket-admission module is deliberately a separate lane.  The
# active controller consumes only this small, generic binding vocabulary so it
# can enforce lifecycle boundaries without importing the classifier's private
# representation.  The aliases keep the controller compatible with the
# admission module while its public record is being integrated.
TICKET_ADMISSION_KEYS = (
    "ticket_admission",
    "admission_record",
    "admission",
    "ticket_context",
)
TICKET_CONTEXT_KEYS = ("ticket", "ticket_context", "ticket_record")
TICKET_EVENT_CONTAINER_KEYS = (
    "admission_events",
    "mutation_events",
    "observed_events",
    "lifecycle_events",
)
ADMISSION_HASH_KEYS = (
    "admission_sha256",
    "admission_hash",
    "ticket_admission_hash",
    "sealed_decision_sha256",
    "decision_sha256",
    "sealed_decision_hash",
)
ADMISSION_EVENT_HASH_KEYS = (
    *ADMISSION_HASH_KEYS,
    "completion_admission_sha256",
    "completion_admission_hash",
    "completion_binding",
    "binding",
)
TICKET_LIFECYCLE_EVENTS = {
    "ticket.claimed",
    "admission.issued",
    "admission.invalidated",
    "implementation.started",
    "ticket.completed",
    "ticket.completion",
    "completion.bound",
    "completion",
    "implementation.completed",
}
TICKET_EVENT_EXTRA_FIELDS = {
    "schema",
    "root_task_id",
    "decision",
    "reason",
    "observed",
    "first_mutation",
    "first_write",
    "write_mode",
    "completion_binding",
}
DIRECT_TICKET_CONTEXT_FIELDS = {
    "ticket_id",
    "root_task_id",
    "ticket_spec_sha256",
    "spec_sha256",
    "spec_hash",
    "canonical_spec_sha256",
    "acceptance_criteria_sha256",
    "acceptance_criteria_hash",
    "acceptance_sha256",
    "authority_scope_sha256",
    "authority_scope_hash",
    "scope_sha256",
    "writable_scope_sha256",
    "writable_scope_hash",
    "classification_evidence_sha256",
    "classification_sha256",
    "candidate_lanes_sha256",
    "lanes_sha256",
    "invocation_identity",
    "invocation_id",
    *ADMISSION_HASH_KEYS,
    *TICKET_EVENT_CONTAINER_KEYS,
}
RAW_USAGE_DIMENSIONS = (
    "uncached_input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_tokens",
)
COMPLETION_PHASES = {
    "integration",
    "verification",
    "external_observation",
    "cleanup",
    "final_sol_review",
}
SOFT_REMEDIATIONS = {
    "safe_compaction",
    "narrow_decision_packets",
    "event_driven_waiting",
    "mechanical_work_transfer",
    "optional_node_suppression",
}
PROFILE_LIFECYCLE_STATES = {
    "UNSUPPORTED_OR_BLOCKED",
    "PROVIDER_FREE_READY",
    "HOSTED_CANARY_AUTHORITY_REQUIRED",
    "CANARY_RUNNING",
    "ACTIVE_DEFAULT",
    "SUSPENDED",
}
PROFILE_REGRESSION_KINDS = {"correctness", "lifecycle", "cost", "latency"}
EFFICIENCY_OUTCOMES = {
    "EFFICIENCY_PROVEN",
    "EFFICIENCY_NOT_PROVEN",
    "INCONCLUSIVE",
}
EFFICIENCY_STATES = {
    "AUTHORITY_REQUIRED",
    "COLLECTING",
    *EFFICIENCY_OUTCOMES,
}

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")

PLAN_FIELDS = {
    "schema",
    "plan_id",
    "revision",
    "predecessor_plan_sha256",
    "planner",
    "objective",
    "finite",
    "logical_worker_count",
    "workers",
    "execution",
    "integration",
    "authority",
    "protected_resources",
    "acceptance_criteria",
}
PLAN_OPTIONAL_FIELDS = {
    "acceptance_resource_closure",
    "generation",
    "project",
    "task_node_budget",
    # The sealed routing policy digest a registry-routed plan carries
    # (Issue 185, ADR 0010): present exactly when a node names a profile by
    # its registry identifier, so the policy is part of the frozen plan
    # digest while every alias-only historical plan keeps its digest.
    "routing_policy_sha256",
}
ROUTING_POLICY_FIELD = "routing_policy_sha256"
PLANNER_OPTIONAL_FIELDS = {"effort"}
PROJECT_FIELDS = {
    "project_id",
    "protocol",
    "binding_generation",
    "binding_manifest_sha256",
    "workspace_root",
    "workspace_root_sha256",
    "required_resource_surfaces",
    "research_manifest_required",
    "source_pointer",
}
GENERATION_FIELDS = {
    "source_version",
    "installed_version",
    "task_loaded_version",
    "fresh_task",
}
WORKER_FIELDS = {
    "id",
    "executor",
    "justification",
    "objective",
    "deliverables",
    "owned_resources",
    "excluded_resources",
    "dependencies",
    "verification",
    "optional",
}
# Optional per-node routing profile: the exact identifier of one profile in
# the sealed model-profile registry (ADR 0010, Issue 185).  Absent means the
# registry's default reviewer profile for root labor (executor "sol") and its
# default implementer profile otherwise.  Two ordinary nodes may name two
# distinct profiles.  The three expand-step alias values resolve only through
# the registry's historical replay adapter so archived plans replay.  The
# profile is resolved at validation time into the report routing table and
# routing policy, so the frozen evidence names the role, profile, and exact
# model behind every node.  An optional "role" annotation must agree with
# the node's profile.
#
# Optional declared context bound for one node, in input tokens.  A node that
# must read widely before it can write is the shape that silently loses its
# whole deliverable: the lane spends its window gathering evidence and the
# turn ends before the report exists.  Declaring the bound does not enforce a
# runtime limit -- no surface can preempt a turn -- but it makes the intended
# footprint reviewable at freeze and mechanically comparable against observed
# terminal usage.
WORKER_OPTIONAL_FIELDS = {"model_profile", "context_budget_tokens", "role"}
# A wave terminal may carry the lane's own terminal text. When present it is
# structurally screened before its declared status is believed; see
# `_terminal_results` and orch_dork_degenerate_output.py.
TERMINAL_OPTIONAL_FIELDS = {"terminal_text"}
TERMINAL_TYPED_FIELDS = {"task_spec", "incremental_packets", "handoff_receipt"}


def _node_profile(worker: Mapping[str, Any]) -> dict[str, Any] | None:
    """The registered profile a node resolves through, with the defaults.

    An absent profile means the default reviewer profile (root labor) on a
    "sol" executor and the default implementer profile otherwise, exactly as
    before the registry existed.  An unresolvable value is None.
    """

    profile_value = worker.get("model_profile")
    if profile_value is not None:
        return model_profiles.resolve_node_profile(profile_value)
    role = "reviewer" if worker.get("executor") == "sol" else "implementer"
    return model_profiles.default_profile(role)


def _profile_id_of(value: Any) -> Any:
    """The exact profile identifier behind a node or task-spec profile value."""

    profile = model_profiles.resolve_node_profile(value)
    return profile["profile_id"] if profile is not None else value


def _load_ownership():
    path = Path(__file__).resolve().with_name("orch_dork_ownership.py")
    spec = importlib.util.spec_from_file_location("orch_dork_ownership", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("ownership analyzer unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ownership = _load_ownership()


def _load_custody():
    path = Path(__file__).resolve().with_name("orch_dork_custody.py")
    spec = importlib.util.spec_from_file_location("orch_dork_custody", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("custody analyzer unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


custody = _load_custody()


def _load_plan_closure():
    path = Path(__file__).resolve().with_name("orch_dork_plan_closure.py")
    spec = importlib.util.spec_from_file_location("orch_dork_plan_closure", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("plan closure unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plan_closure = _load_plan_closure()


def _load_degenerate_output():
    path = Path(__file__).resolve().with_name("orch_dork_degenerate_output.py")
    spec = importlib.util.spec_from_file_location("orch_dork_degenerate_output", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("degenerate-output screen unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


degenerate_output = _load_degenerate_output()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, fields: set[str], path: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, f"{path}:not_object")
        return False
    for key in sorted(fields - set(value)):
        _issue(issues, f"{path}:missing:{key}")
    for key in sorted(set(value) - fields):
        _issue(issues, f"{path}:unknown:{key}")
    return set(value) == fields


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _worker_identity(value: Any) -> bool:
    """Accept logical IDs and native canonical collaboration task paths.

    Codex collaboration receipts identify direct subagents with canonical
    leading-slash task paths. Those are runtime identities, not logical plan
    identifiers, so preserve the leading slash while rejecting empty, dot, or
    parent segments and the same non-identifier characters rejected elsewhere.
    """

    if _identifier(value):
        return True
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 256:
        return False
    segments = value[1:].split("/")
    return bool(segments) and all(
        segment not in {"", ".", ".."}
        and _IDENTIFIER.fullmatch(segment) is not None
        and "/" not in segment
        for segment in segments
    )


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 4096


def _string_list(
    value: Any,
    path: str,
    issues: list[str],
    *,
    empty: bool = True,
) -> list[str]:
    if not isinstance(value, list):
        _issue(issues, f"{path}:not_array")
        return []
    if not empty and not value:
        _issue(issues, f"{path}:empty")
    result: list[str] = []
    for index, item in enumerate(value):
        if not _text(item):
            _issue(issues, f"{path}[{index}]:invalid")
        else:
            result.append(item.strip())
    if len(result) != len(set(result)):
        _issue(issues, f"{path}:duplicates")
    return result


def _deliverables_within_ownership(
    deliverables: list[str],
    owned: list[str],
    path: str,
    issues: list[str],
) -> None:
    """Every declared deliverable must sit inside that lane's own write scope.

    A plan that names a deliverable the lane does not own is internally
    contradictory: the lane is required to produce the artifact and its every
    write of that artifact is an out-of-scope access. Custody derives lane
    scope from `owned_resources` alone, so the contradiction only surfaces
    after the wave runs. Catch it at freeze, where it is still cheap.

    Only path-shaped deliverables are checked; see
    `ownership.deliverable_is_path_shaped`.
    """

    # The rule itself lives in the ownership module so that this validator
    # and `orch_dork_policy.validate_plan` cannot drift apart: the same plan
    # must be judged identically whichever surface it is submitted through.
    for index, reason in ownership.deliverables_outside_ownership(
        deliverables, owned
    ):
        _issue(issues, f"{path}.deliverables[{index}]:{reason}")


def _cycle_nodes(dependencies: Mapping[str, Sequence[str]]) -> list[str]:
    """Return every node left in a deterministic Kahn cycle remainder."""

    indegree = {node: 0 for node in dependencies}
    outgoing = {node: [] for node in dependencies}
    for node, required in dependencies.items():
        for predecessor in required:
            if predecessor in indegree:
                indegree[node] += 1
                outgoing[predecessor].append(node)
    ready = sorted(node for node, degree in indegree.items() if degree == 0)
    consumed: list[str] = []
    while ready:
        node = ready.pop(0)
        consumed.append(node)
        for dependent in sorted(outgoing[node]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                ready.append(dependent)
                ready.sort()
    return sorted(set(indegree) - set(consumed))


def _ownership_plan(plan: Mapping[str, Any], workers: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "lanes": [
            {
                "id": worker.get("id"),
                "owned_resources": worker.get("owned_resources", []),
                "excluded_resources": worker.get("excluded_resources", []),
            }
            for worker in workers
        ],
        "protected_resources": plan.get("protected_resources", []),
    }


def _routing_vocabulary(workers: list[Mapping[str, Any]]) -> str:
    """"profile_id" when any node names a profile identifier, else "legacy".

    A registry profile identifier and an onboarded identifier (ADR 0012) both
    name a profile, so either binds the plan to its sealed routing policy.
    """

    for worker in workers:
        if isinstance(worker, Mapping) and model_profiles.is_node_profile_id(worker.get("model_profile")):
            return "profile_id"
    return "legacy"


def plan_core(plan: Mapping[str, Any]) -> dict[str, Any]:
    """The plan without its routing-policy binding: what the policy seals."""

    return {key: value for key, value in plan.items() if key != ROUTING_POLICY_FIELD}


def validate_logical_plan(plan: Any) -> dict[str, Any]:
    """Validate one finite logical program without consulting live capacity.

    A registry-routed plan (one whose nodes name profiles by identifier)
    must carry ``routing_policy_sha256`` equal to the digest of the routing
    policy resolved over its core, so the sealed policy is part of the plan
    digest; :func:`bind_routing_policy` freezes that binding.  A legacy plan
    (alias-only or default-routed) carries no binding and keeps the digest
    archived evidence recorded.
    """

    return _validate_logical_plan(plan, require_binding=True)


def bind_routing_policy(plan: Any) -> dict[str, Any]:
    """Freeze the sealed routing policy into a registry-routed plan.

    Returns a copy of the plan carrying ``routing_policy_sha256`` when its
    nodes name registry profiles, and the plan's core unchanged otherwise.
    A plan that does not validate is returned as its core so the caller's
    validation names the defect.
    """

    if not isinstance(plan, Mapping):
        return plan
    core = plan_core(plan)
    report = _validate_logical_plan(core, require_binding=False)
    policy = report.get("routing_policy")
    if report.get("routing_vocabulary") != "profile_id" or policy is None:
        return core
    return {**core, ROUTING_POLICY_FIELD: policy["policy_sha256"]}


def _validate_logical_plan(plan: Any, *, require_binding: bool) -> dict[str, Any]:
    issues: list[str] = []
    value = plan if isinstance(plan, Mapping) else {}
    if isinstance(plan, Mapping) and set(plan) - PLAN_FIELDS <= PLAN_OPTIONAL_FIELDS:
        _exact(
            plan,
            PLAN_FIELDS | (set(plan) & PLAN_OPTIONAL_FIELDS),
            "plan",
            issues,
        )
    else:
        _exact(plan, PLAN_FIELDS, "plan", issues)
    if value.get("schema") != LOGICAL_PLAN_SCHEMA:
        _issue(issues, "plan:schema_invalid")
    if not _identifier(value.get("plan_id")):
        _issue(issues, "plan:plan_id_invalid")
    revision = value.get("revision")
    if type(revision) is not int or revision < 1:
        _issue(issues, "plan:revision_invalid")
    predecessor = value.get("predecessor_plan_sha256")
    if revision == 1 and predecessor is not None:
        _issue(issues, "plan:initial_predecessor_present")
    if type(revision) is int and revision > 1 and (
        not isinstance(predecessor, str) or _SHA256.fullmatch(predecessor) is None
    ):
        _issue(issues, "plan:predecessor_invalid")
    if not _text(value.get("objective")):
        _issue(issues, "plan:objective_invalid")
    if value.get("finite") is not True:
        _issue(issues, "plan:not_finite")

    planner = value.get("planner")
    planner_fields = {"role", "root_thread_id", "model"}
    if isinstance(planner, Mapping) and set(planner) - planner_fields <= PLANNER_OPTIONAL_FIELDS:
        _exact(
            planner,
            planner_fields | (set(planner) & PLANNER_OPTIONAL_FIELDS),
            "planner",
            issues,
        )
    else:
        _exact(planner, planner_fields, "planner", issues)
    if isinstance(planner, Mapping):
        if planner.get("role") != "sol":
            _issue(issues, "planner:not_sol")
        if not _identifier(planner.get("root_thread_id")):
            _issue(issues, "planner:root_identity_invalid")
        if not root_model_accepted(planner.get("model")):
            _issue(issues, "planner:model_invalid")
        if "effort" in planner and not _identifier(planner.get("effort")):
            _issue(issues, "planner:effort_invalid")

    workers_value = value.get("workers")
    if not isinstance(workers_value, list):
        _issue(issues, "workers:not_array")
        workers_value = []
    if not workers_value:
        _issue(issues, "workers:empty")
    declared_count = value.get("logical_worker_count")
    if type(declared_count) is not int or declared_count < 1:
        _issue(issues, "plan:logical_worker_count_invalid")
    elif declared_count != len(workers_value):
        _issue(issues, "plan:logical_worker_count_mismatch")
    task_node_budget = value.get("task_node_budget")
    if task_node_budget is not None and (
        type(task_node_budget) is not int
        or task_node_budget < 1
        or (
            type(declared_count) is int
            and task_node_budget < declared_count
        )
    ):
        _issue(issues, "plan:task_node_budget_invalid")

    worker_ids: list[str] = []
    dependencies: dict[str, list[str]] = {}
    normalized_workers: list[Mapping[str, Any]] = []
    for index, worker in enumerate(workers_value):
        path = f"workers[{index}]"
        if isinstance(worker, Mapping) and set(worker) - WORKER_FIELDS <= WORKER_OPTIONAL_FIELDS:
            _exact(
                worker,
                WORKER_FIELDS | (set(worker) & WORKER_OPTIONAL_FIELDS),
                path,
                issues,
            )
        else:
            _exact(worker, WORKER_FIELDS, path, issues)
        if not isinstance(worker, Mapping):
            continue
        worker_id = worker.get("id")
        if not _identifier(worker_id):
            _issue(issues, f"{path}:id_invalid")
            worker_id = f"<invalid-{index}>"
        else:
            worker_ids.append(worker_id)
        if worker.get("executor") not in {"sol", "subagent"}:
            _issue(issues, f"{path}:executor_invalid")
        profile_value = worker.get("model_profile")
        if profile_value is not None:
            resolved_profile = model_profiles.resolve_node_profile(profile_value)
            missing_model = model_profiles.onboarding_required(profile_value)
            if missing_model is not None:
                # ADR 0012: the model is onboarded, with a notice, before freeze.
                _issue(issues, f"{path}:model_not_onboarded:{missing_model}")
            elif resolved_profile is None:
                _issue(issues, f"{path}:model_profile_invalid")
            else:
                root_labor = resolved_profile["model_binding"] == "root_executes"
                if root_labor and worker.get("executor") != "sol":
                    _issue(issues, f"{path}:root_labor_requires_sol_executor")
                elif not root_labor and worker.get("executor") == "sol":
                    _issue(issues, f"{path}:sol_executor_requires_root_labor")
        if "role" in worker:
            node_profile = _node_profile(worker)
            if worker.get("role") not in model_profiles.ROLES:
                _issue(issues, f"{path}:role_invalid")
            elif node_profile is not None and node_profile["role"] != worker.get("role"):
                _issue(issues, f"{path}:role_profile_conflict")
        budget_value = worker.get("context_budget_tokens")
        if budget_value is not None and (
            type(budget_value) is not int or budget_value <= 0
        ):
            _issue(issues, f"{path}:context_budget_invalid")
        if not _text(worker.get("justification")):
            _issue(issues, f"{path}:justification_invalid")
        if not _text(worker.get("objective")):
            _issue(issues, f"{path}:objective_invalid")
        declared_deliverables = _string_list(
            worker.get("deliverables"), f"{path}.deliverables", issues, empty=False
        )
        declared_owned = _string_list(
            worker.get("owned_resources"), f"{path}.owned_resources", issues, empty=False
        )
        _deliverables_within_ownership(
            declared_deliverables, declared_owned, path, issues
        )
        _string_list(worker.get("excluded_resources"), f"{path}.excluded_resources", issues)
        required = _string_list(worker.get("dependencies"), f"{path}.dependencies", issues)
        _string_list(worker.get("verification"), f"{path}.verification", issues, empty=False)
        if not isinstance(worker.get("optional"), bool):
            _issue(issues, f"{path}:optional_invalid")
        dependencies[str(worker_id)] = required
        normalized_workers.append(worker)
    if len(worker_ids) != len(set(worker_ids)):
        _issue(issues, "workers:duplicate_ids")
    known = set(worker_ids)
    for worker_id, required in dependencies.items():
        for predecessor_id in required:
            if predecessor_id not in known:
                _issue(issues, f"workers:{worker_id}:unknown_dependency:{predecessor_id}")
            if predecessor_id == worker_id:
                _issue(issues, f"workers:{worker_id}:self_dependency")
    cycle = _cycle_nodes(dependencies)
    if cycle:
        _issue(issues, "workers:cycle:" + ",".join(cycle))

    execution = value.get("execution")
    _exact(
        execution,
        {
            "profile",
            "capacity_source",
            "worker_model",
            "worker_effort",
            "context_policy",
            "workers_can_spawn",
            "retries_allowed",
            "fallbacks_allowed",
            "replacements_allowed",
        },
        "execution",
        issues,
    )
    profile = execution.get("profile") if isinstance(execution, Mapping) else None
    if isinstance(execution, Mapping):
        if profile not in {
            "single_worker/v1",
            "first_completed_worker/v1",
            "finite_dag/v1",
        }:
            _issue(issues, "execution:profile_invalid")
        if execution.get("capacity_source") != "runtime_inventory":
            _issue(issues, "execution:capacity_source_invalid")
        if execution.get("worker_model") != worker_model():
            _issue(issues, "execution:worker_model_invalid")
        if execution.get("worker_effort") != worker_effort():
            _issue(issues, "execution:worker_effort_invalid")
        if execution.get("context_policy") != "none":
            _issue(issues, "execution:context_policy_invalid")
        if execution.get("workers_can_spawn") is not False:
            _issue(issues, "execution:worker_spawn_authority_present")
        for field in ("retries_allowed", "fallbacks_allowed", "replacements_allowed"):
            if execution.get(field) != 0:
                _issue(issues, f"execution:{field}_not_zero")
    if profile == "single_worker/v1":
        if len(workers_value) != 1:
            _issue(issues, "execution:single_worker_count_mismatch")
        elif workers_value[0].get("executor") != "sol":
            _issue(issues, "execution:single_worker_must_be_sol")
    elif profile == "first_completed_worker/v1":
        # The first-completed choreography (first finisher integrates, one
        # release per peer) only makes sense between subagent lanes.
        if workers_value and any(worker.get("executor") != "subagent" for worker in normalized_workers):
            _issue(issues, "execution:delegated_worker_executor_invalid")
    elif workers_value:
        # finite_dag/v1: per-node executor is the sanctioned seam for keeping
        # a high-judgment node (a semantic join, a synthesis) on the root
        # model.  A sol-executed node is root labor, not a spawn: it cannot
        # widen authority, and the scheduler must not count it against
        # worker capacity.  At least one node must remain a subagent, or the
        # plan is not a delegation at all and belongs in single_worker/v1.
        if all(worker.get("executor") == "sol" for worker in normalized_workers):
            _issue(issues, "execution:all_sol_use_single_worker")
    if profile == "first_completed_worker/v1":
        if not 2 <= len(workers_value) <= 4:
            _issue(issues, "execution:first_completed_worker_count_invalid")
        if any(worker.get("dependencies") for worker in normalized_workers):
            _issue(issues, "execution:first_completed_dependencies_present")

    integration = value.get("integration")
    _exact(integration, {"strategy", "release_required", "final_verification"}, "integration", issues)
    if isinstance(integration, Mapping):
        strategy = integration.get("strategy")
        allowed_strategy = {
            "single_worker/v1": "none",
            "first_completed_worker/v1": "first_completed_worker",
            "finite_dag/v1": "dependency_ordered",
        }.get(profile)
        if strategy != allowed_strategy:
            _issue(issues, "integration:strategy_invalid")
        expected_release = profile == "first_completed_worker/v1"
        if integration.get("release_required") is not expected_release:
            _issue(issues, "integration:release_policy_invalid")
        final_checks = _string_list(
            integration.get("final_verification"),
            "integration.final_verification",
            issues,
            empty=profile == "single_worker/v1",
        )
        if profile != "single_worker/v1" and not final_checks:
            _issue(issues, "integration:final_verification_empty")

    authority = value.get("authority")
    _exact(
        authority,
        {"authority_id", "scope", "status", "authorized_worker_ids"},
        "authority",
        issues,
    )
    if isinstance(authority, Mapping):
        if not _identifier(authority.get("authority_id")):
            _issue(issues, "authority:id_invalid")
        if authority.get("scope") not in {"provider_free", "hosted"}:
            _issue(issues, "authority:scope_invalid")
        if authority.get("status") != "granted":
            _issue(issues, "authority:not_granted")
        authorized = _string_list(
            authority.get("authorized_worker_ids"),
            "authority.authorized_worker_ids",
            issues,
            empty=False,
        )
        if set(authorized) != known:
            _issue(issues, "authority:worker_set_mismatch")

    _string_list(value.get("protected_resources"), "protected_resources", issues)
    _string_list(value.get("acceptance_criteria"), "acceptance_criteria", issues, empty=False)

    project = value.get("project")
    if project is not None:
        _exact(project, PROJECT_FIELDS, "project", issues)
        project_value = project if isinstance(project, Mapping) else {}
        for field in (
            "project_id",
            "protocol",
            "binding_manifest_sha256",
            "workspace_root",
            "workspace_root_sha256",
            "source_pointer",
        ):
            if not _text(project_value.get(field)):
                _issue(issues, "project:" + field + "_invalid")
        if (
            not isinstance(project_value.get("binding_manifest_sha256"), str)
            or _SHA256.fullmatch(project_value["binding_manifest_sha256"]) is None
        ):
            _issue(issues, "project:binding_manifest_sha256_invalid")
        if (
            not isinstance(project_value.get("workspace_root_sha256"), str)
            or _SHA256.fullmatch(project_value["workspace_root_sha256"]) is None
        ):
            _issue(issues, "project:workspace_root_sha256_invalid")
        if type(project_value.get("binding_generation")) is not int or project_value.get("binding_generation", 0) < 1:
            _issue(issues, "project:binding_generation_invalid")
        surfaces = _string_list(
            project_value.get("required_resource_surfaces"),
            "project.required_resource_surfaces",
            issues,
        )
        if any(surface not in plan_closure.SURFACES for surface in surfaces):
            _issue(issues, "project:required_resource_surface_invalid")
        if not isinstance(project_value.get("research_manifest_required"), bool):
            _issue(issues, "project:research_manifest_required_invalid")

    generation = value.get("generation")
    if generation is not None:
        _exact(generation, GENERATION_FIELDS, "generation", issues)
        generation_value = generation if isinstance(generation, Mapping) else {}
        for field in ("source_version", "installed_version", "task_loaded_version"):
            if not _identifier(generation_value.get(field)):
                _issue(issues, "generation:" + field + "_invalid")
        if not isinstance(generation_value.get("fresh_task"), bool):
            _issue(issues, "generation:fresh_task_invalid")

    closure_report: dict[str, Any] = {
        "status": "NOT_DECLARED",
        "closed": False,
        "issues": [],
        "requirements": [],
    }
    if value.get("acceptance_resource_closure") is not None:
        closure_value = value.get("acceptance_resource_closure")
        owner = (
            closure_value.get("integration_owner", {})
            if isinstance(closure_value, Mapping)
            else {}
        )
        owner_kind = owner.get("kind") if isinstance(owner, Mapping) else None
        projected = {
            "lanes": [dict(worker) for worker in normalized_workers],
            "acceptance_criteria": list(value.get("acceptance_criteria", [])),
            "protected_resources": list(value.get("protected_resources", [])),
            "decision": {"mode": "orchestrated"},
            "root": {
                "coordination_only_after_freeze": owner_kind != "root",
            },
            "integration": {
                "strategy": (
                    "root"
                    if owner_kind == "root"
                    else "first_completed_worker"
                    if owner_kind == "lane"
                    else "none"
                ),
                "final_verification": list(
                    (value.get("integration") or {}).get("final_verification", [])
                ),
            },
            "acceptance_resource_closure": closure_value,
        }
        closure_report = plan_closure.validate_acceptance_resource_closure(projected)
        for detail in closure_report.get("issues", []):
            _issue(issues, "acceptance_resource_closure:" + str(detail))
        if isinstance(project, Mapping):
            actual_surfaces = {
                row.get("surface")
                for row in closure_report.get("requirements", [])
                if isinstance(row, Mapping)
            }
            for surface in project.get("required_resource_surfaces", []):
                if surface not in actual_surfaces:
                    _issue(
                        issues,
                        "acceptance_resource_closure:required_surface_missing:"
                        + str(surface),
                    )
    try:
        ownership_report = ownership.analyze_ownership(_ownership_plan(value, normalized_workers))
    except Exception:
        _issue(issues, "ownership:analysis_failed")
    else:
        for item in ownership_report.get("issues", []):
            _issue(issues, str(item))

    issues = sorted(issues)
    canonical = dict(value)
    routing_table = {}
    node_routes = {}
    if not issues:
        declared_worker = None
        execution_value = value.get("execution")
        if isinstance(execution_value, Mapping):
            declared_worker = execution_value.get("worker_model")
        for worker in normalized_workers:
            worker_id = worker.get("id")
            if not isinstance(worker_id, str):
                continue
            node_profile = _node_profile(worker)
            profile_id = node_profile["profile_id"]
            binding = node_profile["model_binding"]
            if binding == "root_executes":
                routing_table[worker_id] = {
                    "profile": profile_id,
                    "model": None,
                    "effort": None,
                    "resolution": "root_executes",
                }
            elif binding == "strong_default":
                routing_table[worker_id] = {
                    "profile": profile_id,
                    "model": worker_default.configured_strong_model(),
                    "effort": worker_default.configured_strong_effort(),
                    "resolution": "strong_default",
                }
            elif binding == "profile_model":
                routing_table[worker_id] = {
                    "profile": profile_id,
                    "model": node_profile["default_model"],
                    "effort": node_profile["default_effort"],
                    "resolution": "profile_model",
                }
            else:
                routing_table[worker_id] = {
                    "profile": profile_id,
                    "model": declared_worker or worker_model(),
                    "effort": worker_effort(),
                    "resolution": "plan_declared" if declared_worker else "governed_default",
                }
            node_routes[worker_id] = {
                "profile_id": profile_id,
                "model": routing_table[worker_id]["model"],
                "effort": routing_table[worker_id]["effort"],
                "dependencies": list(worker.get("dependencies", [])),
            }
    plan_sha256 = _sha256(canonical)
    plan_core_sha256 = _sha256(plan_core(canonical))
    routing_vocabulary = _routing_vocabulary(normalized_workers)
    routing_policy = None
    if not issues:
        planner_value = value.get("planner")
        declared_root = (
            planner_value.get("model") if isinstance(planner_value, Mapping) else None
        )
        routing_policy, policy_issues = model_profiles.plan_routing_policy(
            plan_core_sha256, node_routes, root_model=declared_root
        )
        if policy_issues:
            issues = sorted(set(issues) | set(policy_issues))
            routing_table = {}
    bound_policy = value.get(ROUTING_POLICY_FIELD)
    if require_binding and routing_vocabulary == "profile_id":
        if bound_policy is None:
            _issue(issues, "plan:routing_policy_unbound")
        elif not isinstance(bound_policy, str) or _SHA256.fullmatch(bound_policy) is None:
            _issue(issues, "plan:routing_policy_sha256_invalid")
        elif routing_policy is not None and bound_policy != routing_policy["policy_sha256"]:
            _issue(issues, "plan:routing_policy_mismatch")
    elif bound_policy is not None:
        _issue(issues, "plan:routing_policy_sha256_unexpected")
    if issues:
        issues = sorted(set(issues))
        routing_table = {}
        routing_policy = None
    return {
        "schema": LOGICAL_PLAN_REPORT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": issues,
        "plan_sha256": plan_sha256,
        # The digest of the plan without its routing-policy binding; the
        # policy seals this core, and a registry-routed plan's binding seals
        # the policy, so the frozen plan digest covers both (ADR 0010).
        "plan_core_sha256": plan_core_sha256,
        "routing_vocabulary": routing_vocabulary,
        "plan_id": value.get("plan_id"),
        "revision": value.get("revision"),
        "logical_worker_count": len(workers_value),
        "execution_profile": profile,
        "node_routing": {key: routing_table[key] for key in sorted(routing_table)},
        # The sealed registry resolution of this plan: the role and
        # capability profile behind every node, bound to the plan core from
        # the policy side and, for a registry-routed plan, to the plan from
        # the binding side.
        "routing_policy": routing_policy,
        # Every distinct model this plan will actually route to, so the root
        # can prove each one is reachable before committing lanes to depend
        # on it.  A join node that is only reached after every survey lane
        # finishes is the most expensive possible place to discover that its
        # model is unavailable or capped.
        "required_models": sorted(
            {
                entry["model"]
                for entry in routing_table.values()
                if entry.get("model")
            }
        ),
        "live_capacity": {
            "status": "not_consulted",
            "source": "runtime_inventory",
            "value": None,
        },
        "worker_spawn_authority": False,
        "planner_role": planner.get("role") if isinstance(planner, Mapping) else None,
        "planner_model": planner.get("model") if isinstance(planner, Mapping) else None,
        "planner_effort": planner.get("effort") if isinstance(planner, Mapping) else None,
        "project": dict(project) if isinstance(project, Mapping) else None,
        "generation": dict(generation) if isinstance(generation, Mapping) else None,
        "acceptance_resource_closure": closure_report,
        "canonical_plan": canonical,
        "evidence_tier": "submitted",
    }


def build_budget_reservation_program(
    logical_plan: Mapping[str, Any],
    *,
    program_id: str,
    max_total_tokens: int,
) -> dict[str, Any]:
    """Construct one provider-free reservation program for delegated lanes."""

    report = validate_logical_plan(logical_plan)
    if report.get("status") != "PASS":
        raise ValueError("logical_plan:not_valid")
    workers = logical_plan.get("workers", [])
    delegated = [
        row
        for row in workers
        if isinstance(row, Mapping) and row.get("executor") == "subagent"
    ]
    zero = {dimension: 0 for dimension in LIMIT_DIMENSIONS}
    return {
        "schema": BUDGET_PROGRAM_SCHEMA,
        "program_id": program_id,
        "plan_sha256": report["plan_sha256"],
        "budget_policy": {
            "limits": {
                "hosted_calls": 0,
                "tokens": max_total_tokens,
                "cost_microunits": 0,
                "wall_time_ms": 1_000_000,
                "turns": max(1, len(delegated) + 1),
                "children": len(delegated),
                "depth": 1,
                "concurrency": max(1, len(delegated)),
            },
            "reservation_required": True,
        },
        "runtime_window": {
            "status": "complete",
            "evidence_tier": "runtime-observed",
            "source_pointer": "qualification-pre-spawn#budget-window",
            "completed_node_ids": [],
        },
        "runtime_records": [],
        "admission_requests": [
            {
                "node_id": row["id"],
                "dependencies": list(row.get("dependencies", [])),
                "reservation": {
                    **zero,
                    "tokens": max(1, max_total_tokens // max(1, len(delegated))),
                    "turns": 1,
                    "children": 1,
                    "concurrency": 1,
                },
            }
            for row in delegated
        ],
    }


def build_wave_v3_preflight_program(
    logical_plan: Mapping[str, Any],
    *,
    program_id: str,
    task_specs: list[Mapping[str, Any]],
    canary_task_spec: Mapping[str, Any],
    candidate: Mapping[str, Any],
    runtime_observation: Mapping[str, Any],
) -> dict[str, Any]:
    """Construct the canonical zero-observation v3 preflight wave.

    The route canary preflights its own profile's route; every other
    onboarded spawn route the plan requires is preflighted by its onboarding
    probe (ADR 0012).  When onboarded probes cover every required route, a
    canary for a route the plan does not require is left out.
    """

    report = validate_logical_plan(logical_plan)
    if report.get("status") != "PASS":
        raise ValueError("logical_plan:not_valid")
    canary_profile = _profile_id_of(canary_task_spec.get("model_profile"))
    required = _required_route_profiles(logical_plan, report)
    onboarded = [
        entry
        for entry in _onboarded_route_preflights(required)
        if entry["model_profile"] != canary_profile
    ]
    route_preflights = []
    if canary_profile in required or not onboarded:
        route_preflights.append(
            {
                "model_profile": canary_profile,
                "task_spec": deepcopy(dict(canary_task_spec)),
                "preflight": deepcopy(dict(candidate)),
                "runtime_observation": deepcopy(dict(runtime_observation)),
            }
        )
    route_preflights.extend(onboarded)
    return {
        "schema": WAVE_PROGRAM_SCHEMA_V3,
        "program_id": program_id,
        "root_thread_id": logical_plan["planner"]["root_thread_id"],
        "logical_plan": deepcopy(dict(logical_plan)),
        "observations": [],
        "route_preflights": route_preflights,
        "task_specs": [
            {
                "logical_worker_id": row["logical_worker_id"],
                "task_spec": deepcopy(dict(row["task_spec"])),
            }
            for row in task_specs
        ],
        "completion_reserve": {
            "context_tokens": 100,
            "output_tokens": 100,
            "tool_calls": 1,
        },
    }


def _required_route_profiles(plan: Mapping[str, Any], plan_report: Mapping[str, Any]) -> list[str]:
    """The profile of every spawn route a plan requires, in plan order."""

    routing_table = plan_report.get("node_routing", {})
    profiles: list[str] = []
    for worker in plan.get("workers", []):
        if not isinstance(worker, Mapping) or worker.get("executor") != "subagent":
            continue
        route = routing_table.get(worker.get("id"), {}) if isinstance(routing_table, Mapping) else {}
        profile = route.get("profile") if isinstance(route, Mapping) else None
        if isinstance(profile, str) and profile not in profiles:
            profiles.append(profile)
    return profiles


def _onboarded_route_preflights(required: Sequence[str]) -> list[dict[str, Any]]:
    """One onboarding preflight per onboarded spawn route (ADR 0012).

    An onboarded route's typed preflight is the onboarding probe that spawned
    its model once as a V1 worker; the entry carries that sealed profile.
    """

    entries = []
    for profile_id in required:
        capability = model_profiles.onboarded_capability_profile(profile_id)
        if capability is None:
            continue
        record = model_profiles.onboarded_profiles.onboarded(capability["default_model"])
        entries.append({"model_profile": profile_id, "onboarded_profile": deepcopy(record)})
    return entries


def _onboarded_route_preflight(
    item: Mapping[str, Any],
    *,
    path: str,
    required_routes: Mapping[str, tuple[Any, Any]],
    counts: dict[str, int],
    issues: list[str],
) -> dict[str, Any]:
    """Validate one onboarded route's preflight: its onboarding probe.

    The sealed profile must be the exact one the plan's routing policy froze
    (the synthesized capability profile binds its digest), name the route's
    model, and have passed onboarding: reachable, on V1, and current.
    """

    before = len(issues)
    capability = model_profiles.onboarded_capability_profile(item.get("model_profile"))
    if capability is None:
        # No onboarded profile to key the preflight by: name the entry.
        _issue(issues, f"{path}:model_profile_invalid")
        profile = None
    else:
        profile = str(item["model_profile"])
        counts[profile] = counts.get(profile, 0) + 1
    record = item.get("onboarded_profile")
    expected_model, expected_effort = required_routes.get(profile, (None, None))
    record_issues = model_profiles.onboarded_profiles.validate_profile(record)
    label = profile if profile is not None else path
    if record_issues:
        _issue(issues, f"route_preflights:{label}:onboarded_profile_invalid")
    elif capability is not None and record["profile_sha256"] != capability["onboarded_profile_sha256"]:
        _issue(issues, f"route_preflights:{label}:onboarded_profile_mismatch")
    elif capability is not None:
        if record["model"] != expected_model:
            _issue(issues, f"route_preflights:{label}:runtime_route_mismatch")
        for reason in model_profiles.onboarded_profiles.not_passed_reasons(record):
            _issue(issues, f"route_preflights:{label}:onboarding_not_passed:{reason}")
    if profile is not None and profile not in required_routes:
        _issue(issues, f"route_preflights:{label}:unrequired_route")
    passed = len(issues) == before
    digest = record.get("profile_sha256") if isinstance(record, Mapping) and not record_issues else None
    return {
        "model_profile": label,
        "status": "PASS" if passed else "FAIL",
        "spawn_permitted": passed,
        "evidence_tier": "onboarded",
        "runtime_observation_sha256": None,
        "task_spec_sha256": None,
        "candidate_sha256": None,
        "preflight_sha256": digest,
        "handoff_sha256": None,
        "incremental_packet_sha256s": [],
        "session_id": None,
        "observed_route": (
            {"model": expected_model, "effort": expected_effort, "context_policy": "none", "session_id": None}
            if passed
            else None
        ),
        "observed_usage": None,
        "source_pointer": "onboarded-profile:" + digest if digest is not None else None,
    }


def logical_plan_from_v1(
    plan: Mapping[str, Any],
    *,
    plan_id: str,
    root_thread_id: str,
    authority_id: str,
) -> dict[str, Any]:
    """Represent an existing small v1 plan through the explicit compatibility profile."""

    if not isinstance(plan, Mapping) or plan.get("schema") != "orch-dork/plan/v1":
        raise ValueError("legacy plan must use orch-dork/plan/v1")
    decision = plan.get("decision") if isinstance(plan.get("decision"), Mapping) else {}
    root = plan.get("root") if isinstance(plan.get("root"), Mapping) else {}
    lanes = plan.get("lanes") if isinstance(plan.get("lanes"), list) else []
    workers = []
    for lane in lanes:
        if not isinstance(lane, Mapping):
            raise ValueError("legacy lane must be an object")
        workers.append(
            {
                "id": lane.get("id"),
                "executor": "subagent",
                "justification": lane.get("objective"),
                "objective": lane.get("objective"),
                "deliverables": list(lane.get("deliverables", [])),
                "owned_resources": list(lane.get("owned_resources", [])),
                "excluded_resources": list(lane.get("excluded_resources", [])),
                "dependencies": list(lane.get("dependencies", [])),
                "verification": list(lane.get("verification", [])),
                "optional": False,
            }
        )
    result = {
        "schema": LOGICAL_PLAN_SCHEMA,
        "plan_id": plan_id,
        "revision": 1,
        "predecessor_plan_sha256": None,
        "planner": {
            "role": "sol",
            "root_thread_id": root_thread_id,
            "model": root.get("model"),
        },
        "objective": decision.get("reason"),
        "finite": True,
        "logical_worker_count": len(workers),
        "workers": workers,
        "execution": {
            "profile": "first_completed_worker/v1",
            "capacity_source": "runtime_inventory",
            "worker_model": ((plan.get("children") or {}).get("model")),
            "worker_effort": ((plan.get("children") or {}).get("effort")),
            "context_policy": ((plan.get("children") or {}).get("context_policy")),
            "workers_can_spawn": False,
            "retries_allowed": ((plan.get("children") or {}).get("retries_allowed")),
            "fallbacks_allowed": ((plan.get("children") or {}).get("fallbacks_allowed")),
            "replacements_allowed": 0,
        },
        "integration": {
            "strategy": ((plan.get("integration") or {}).get("strategy")),
            "release_required": ((plan.get("integration") or {}).get("release_required")),
            "final_verification": list(((plan.get("integration") or {}).get("final_verification", []))),
        },
        "authority": {
            "authority_id": authority_id,
            "scope": "provider_free",
            "status": "granted",
            "authorized_worker_ids": [worker["id"] for worker in workers],
        },
        "protected_resources": list(plan.get("protected_resources", [])),
        "acceptance_criteria": list(plan.get("acceptance_criteria", [])),
    }
    report = validate_logical_plan(result)
    if report["status"] != "PASS":
        raise ValueError("legacy plan cannot be represented: " + ", ".join(report["issues"]))
    return result


def _inventory_capacity(
    inventory: Any, *, root_thread_id: str, issues: list[str]
) -> dict[str, Any]:
    fields = {
        "schema",
        "root_thread_id",
        "capacity",
        "retirement_supported",
        "workers",
    }
    _exact(inventory, fields, "inventory", issues)
    value = inventory if isinstance(inventory, Mapping) else {}
    if value.get("schema") != "orch-dork/collaboration-inventory/v1":
        _issue(issues, "inventory:schema_invalid")
    if value.get("root_thread_id") != root_thread_id:
        _issue(issues, "inventory:root_identity_mismatch")
    capacity = value.get("capacity")
    if type(capacity) is not int or capacity < 0:
        _issue(issues, "inventory:capacity_invalid")
        capacity = 0
    retirement_supported = value.get("retirement_supported")
    if not isinstance(retirement_supported, bool):
        _issue(issues, "inventory:retirement_capability_unknown")
    workers = value.get("workers")
    if not isinstance(workers, list):
        _issue(issues, "inventory:workers_not_array")
        workers = []
    occupied = 0
    seen: set[str] = set()
    occupied_ids: list[str] = []
    for index, worker in enumerate(workers):
        path = f"inventory.workers[{index}]"
        _exact(worker, {"worker_id", "status", "attempt_id"}, path, issues)
        if not isinstance(worker, Mapping):
            continue
        worker_id = worker.get("worker_id")
        status = worker.get("status")
        if not _worker_identity(worker_id) or worker_id in seen:
            _issue(issues, f"{path}:worker_identity_invalid")
            continue
        seen.add(worker_id)
        if status not in {
            "running",
            "completed",
            "errored",
            "interrupted",
            "shutdown",
            "pending_init",
            "not_found",
        }:
            _issue(issues, f"{path}:status_invalid")
            continue
        if status not in {"shutdown", "not_found"}:
            occupied += 1
            occupied_ids.append(worker_id)
    if occupied > capacity:
        _issue(issues, "inventory:occupied_exceeds_capacity")
    return {
        "capacity": capacity,
        "occupied_slots": occupied,
        "free_slots": max(0, capacity - occupied),
        "occupied_worker_ids": sorted(occupied_ids),
        "inventory_sha256": _sha256(value),
        "retirement_supported": retirement_supported,
    }


def _creation_results(
    values: Any,
    *,
    selected: Sequence[str],
    root_thread_id: str,
    session_required: bool = False,
    issues: list[str],
) -> tuple[bool, list[dict[str, Any]]]:
    if not isinstance(values, list):
        _issue(issues, "creations:not_array")
        values = []
    selected_set = set(selected)
    by_node: dict[str, list[Mapping[str, Any]]] = {}
    worker_ids: set[str] = set()
    accepted: list[dict[str, Any]] = []
    for index, result in enumerate(values):
        path = f"creations[{index}]"
        fields = {
                "logical_worker_id",
                "worker_id",
                "status",
                "fresh",
                "parent_thread_id",
            }
        if session_required:
            fields.add("session_id")
        _exact(
            result,
            fields,
            path,
            issues,
        )
        if not isinstance(result, Mapping):
            continue
        logical_id = result.get("logical_worker_id")
        worker_id = result.get("worker_id")
        session_id = result.get("session_id")
        by_node.setdefault(str(logical_id), []).append(result)
        if logical_id not in selected_set:
            _issue(issues, f"creations:unselected_node:{logical_id}")
        if not _worker_identity(worker_id) or worker_id in worker_ids:
            _issue(issues, f"creations:worker_identity_invalid:{logical_id}")
        else:
            worker_ids.add(worker_id)
        if result.get("status") != "created":
            _issue(issues, f"creations:not_confirmed:{logical_id}")
        if result.get("fresh") is not True:
            _issue(issues, f"creations:not_fresh:{logical_id}")
        if result.get("parent_thread_id") != root_thread_id:
            _issue(issues, f"creations:parent_mismatch:{logical_id}")
        if session_required and not _identifier(session_id):
            _issue(issues, f"creations:session_identity_invalid:{logical_id}")
        if (
                logical_id in selected_set
            and _worker_identity(worker_id)
            and result.get("status") == "created"
            and result.get("fresh") is True
            and result.get("parent_thread_id") == root_thread_id
            and (not session_required or _identifier(session_id))
        ):
            member = {"logical_worker_id": logical_id, "worker_id": worker_id}
            if session_required:
                member["session_id"] = session_id
            accepted.append(member)
    for logical_id in selected:
        if len(by_node.get(logical_id, [])) != 1:
            _issue(
                issues,
                f"creations:result_count:{logical_id}:{len(by_node.get(logical_id, []))}",
            )
    if len(values) != len(selected):
        _issue(issues, f"creations:count:{len(values)}!={len(selected)}")
    return not issues, sorted(accepted, key=lambda item: item["logical_worker_id"])


def _usage_fact(value: Any, path: str, issues: list[str]) -> dict[str, Any]:
    fields = {
        "status",
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
        "source_pointer",
    }
    _exact(value, fields, path, issues)
    item = value if isinstance(value, Mapping) else {}
    status = item.get("status")
    if status == "unknown":
        if any(item.get(key) is not None for key in fields - {"status", "source_pointer"}):
            _issue(issues, f"{path}:unknown_has_values")
    elif status == "observed":
        numeric = {
            key: item.get(key)
            for key in (
                "input_tokens",
                "cached_input_tokens",
                "output_tokens",
                "reasoning_tokens",
                "total_tokens",
            )
        }
        if any(type(number) is not int or number < 0 for number in numeric.values()):
            _issue(issues, f"{path}:components_invalid")
        elif (
            numeric["cached_input_tokens"] > numeric["input_tokens"]
            or numeric["reasoning_tokens"] > numeric["output_tokens"]
            or numeric["total_tokens"]
            != numeric["input_tokens"] + numeric["output_tokens"]
        ):
            _issue(issues, f"{path}:arithmetic_invalid")
    else:
        _issue(issues, f"{path}:status_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, f"{path}:source_pointer_invalid")
    return dict(item)


def _completion_reserve(value: Any, *, path: str, issues: list[str]) -> dict[str, int]:
    """Validate the shared positive reserve contract once for every caller."""

    _exact(
        value,
        {"context_tokens", "output_tokens", "tool_calls"},
        path,
        issues,
    )
    source = value if isinstance(value, Mapping) else {}
    reserve: dict[str, int] = {}
    for field in ("context_tokens", "output_tokens", "tool_calls"):
        amount = source.get(field)
        if type(amount) is not int or amount <= 0:
            _issue(issues, f"{path}:{field}_invalid")
            amount = 0
        reserve[field] = amount
    if not any(reserve.values()):
        _issue(issues, f"{path}:must_protect_capacity")
    return reserve


def evaluate_wave_progress(program: Any) -> dict[str, Any]:
    """Evaluate a live prefix of TaskSpec-bound incremental packet events."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(
        program,
        {
            "schema",
            "progress_id",
            "task_specs",
            "completion_reserve",
            "events",
        },
        "program",
        issues,
    )
    if value.get("schema") != WAVE_PROGRESS_PROGRAM_SCHEMA:
        _issue(issues, "progress:schema_invalid")
    if not _identifier(value.get("progress_id")):
        _issue(issues, "progress:id_invalid")

    specs_value = value.get("task_specs")
    if not isinstance(specs_value, list) or not specs_value:
        _issue(issues, "progress:task_specs_invalid")
        specs_value = []
    specs: dict[str, dict[str, Any]] = {}
    workers: dict[str, str] = {}
    task_digests: dict[str, str] = {}
    for index, row in enumerate(specs_value):
        path = f"task_specs[{index}]"
        _exact(row, {"logical_worker_id", "worker_id", "task_spec"}, path, issues)
        item = row if isinstance(row, Mapping) else {}
        logical_id = item.get("logical_worker_id")
        worker_id = item.get("worker_id")
        if not _identifier(logical_id) or logical_id in specs:
            _issue(issues, f"{path}:logical_worker_invalid_or_duplicate")
            continue
        if not _worker_identity(worker_id) or worker_id in workers.values():
            _issue(issues, f"{path}:worker_invalid_or_duplicate")
        task_report = adaptive_contracts.validate_task_spec(item.get("task_spec"))
        normalized = task_report.get("normalized")
        if not task_report.get("valid") or not isinstance(normalized, Mapping):
            _issue(issues, f"{path}:task_spec_invalid")
            continue
        if normalized.get("id") != logical_id:
            _issue(issues, f"{path}:task_spec_worker_mismatch")
        if normalized.get("executor") != "subagent":
            _issue(issues, f"{path}:task_spec_executor_invalid")
        specs[str(logical_id)] = dict(normalized)
        workers[str(logical_id)] = str(worker_id)
        task_digests[str(logical_id)] = str(task_report.get("digest"))

    reserve = _completion_reserve(
        value.get("completion_reserve"),
        path="completion_reserve",
        issues=issues,
    )

    events_value = value.get("events")
    if not isinstance(events_value, list):
        _issue(issues, "progress:events_not_array")
        events_value = []
    states = {
        logical_id: {
            "logical_worker_id": logical_id,
            "worker_id": workers[logical_id],
            "packet_count": 0,
            "packet_sha256s": [],
            "packets": [],
            "next_sequence": 1,
            "latest_usage": None,
            "remaining": None,
            "stop_required": False,
            "stop_reason": None,
        }
        for logical_id in sorted(specs)
    }
    seen_packet_ids: set[str] = set()
    seen_packet_digests: set[str] = set()
    for index, event in enumerate(events_value):
        path = f"events[{index}]"
        _exact(
            event,
            {
                "seq",
                "type",
                "logical_worker_id",
                "worker_id",
                "packet",
                "evidence_pointer",
            },
            path,
            issues,
        )
        item = event if isinstance(event, Mapping) else {}
        if type(item.get("seq")) is not int or item.get("seq") != index + 1:
            _issue(issues, f"{path}:sequence_not_contiguous")
        if item.get("type") != "packet.observed":
            _issue(issues, f"{path}:type_invalid")
        logical_id = item.get("logical_worker_id")
        if logical_id not in states:
            _issue(issues, f"{path}:unknown_worker")
            continue
        state = states[str(logical_id)]
        if item.get("worker_id") != state["worker_id"]:
            _issue(issues, f"{path}:worker_binding_mismatch")
        if not _text(item.get("evidence_pointer")):
            _issue(issues, f"{path}:evidence_pointer_invalid")
        if state["stop_required"]:
            _issue(issues, f"progress:packet_after_stop:{logical_id}")

        packet_report = adaptive_contracts.validate_incremental_claim_packet(
            item.get("packet"),
            task_spec=specs[str(logical_id)],
        )
        normalized = packet_report.get("normalized")
        if not packet_report.get("valid") or not isinstance(normalized, Mapping):
            _issue(issues, f"{path}:packet_invalid")
            for detail in packet_report.get("issues", []):
                _issue(issues, f"{path}:packet_issue:{detail}")
            continue
        packet_id = str(normalized.get("packet_id"))
        packet_digest = str(packet_report.get("digest"))
        if packet_id in seen_packet_ids:
            _issue(issues, f"progress:duplicate_packet_id:{packet_id}")
        if packet_digest in seen_packet_digests:
            _issue(issues, f"progress:duplicate_packet_sha256:{packet_digest}")
        seen_packet_ids.add(packet_id)
        seen_packet_digests.add(packet_digest)
        if normalized.get("task_spec_sha256") != task_digests[str(logical_id)]:
            _issue(issues, f"{path}:task_spec_digest_mismatch")
        if normalized.get("sequence") != state["next_sequence"]:
            _issue(issues, f"progress:sequence_not_contiguous:{logical_id}")
        usage = normalized.get("usage", {})
        previous = state["latest_usage"]
        if isinstance(previous, Mapping) and any(
            usage.get(field, 0) < previous.get(field, 0)
            for field in ("input_tokens", "output_tokens", "total_tokens", "tool_calls")
        ):
            _issue(issues, f"progress:usage_not_monotonic:{logical_id}")
        budgets = specs[str(logical_id)].get("budgets", {})
        remaining = {
            "context_tokens": budgets.get("context_tokens", 0)
            - usage.get("input_tokens", 0),
            "output_tokens": budgets.get("output_tokens", 0)
            - usage.get("output_tokens", 0),
            "tool_calls": budgets.get("tool_calls", 0)
            - usage.get("tool_calls", 0),
        }
        state.update(
            {
                "packet_count": state["packet_count"] + 1,
                "packet_sha256s": [*state["packet_sha256s"], packet_digest],
                "packets": [*state["packets"], dict(normalized)],
                "next_sequence": int(normalized.get("sequence", 0)) + 1,
                "latest_usage": dict(usage),
                "remaining": remaining,
            }
        )
        if any(remaining[field] < reserve[field] for field in reserve):
            state["stop_required"] = True
            state["stop_reason"] = "completion_reserve"

    stop_ids = sorted(
        logical_id
        for logical_id, state in states.items()
        if state["stop_required"]
    )
    core = {
        "schema": WAVE_PROGRESS_REPORT_SCHEMA,
        "status": "FAIL" if issues else "PASS",
        "progress_id": value.get("progress_id"),
        "event_count": len(events_value),
        "event_prefix_sha256": _sha256(events_value),
        "worker_states": [states[key] for key in sorted(states)],
        "stop_required_worker_ids": stop_ids,
        "continuation_permitted": not issues and not stop_ids,
        "issues": sorted(issues),
        "evidence_tier": "submitted",
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "report_sha256": _sha256(core)}


def _typed_terminal_contracts(
    terminal: Mapping[str, Any],
    *,
    logical_id: str,
    worker: Mapping[str, Any],
    status: str,
    usage: Mapping[str, Any],
    task_spec_override: Mapping[str, Any] | None = None,
    prevalidated_packets: Sequence[Mapping[str, Any]] | None = None,
    issues: list[str],
) -> tuple[str, dict[str, Any]]:
    """Validate the versioned task, progress, and handoff at the public seam."""

    if "terminal_text" in terminal:
        _issue(issues, f"terminals:freeform_output_forbidden:{logical_id}")
        status = "failed_contract"

    task_spec = (
        task_spec_override
        if task_spec_override is not None
        else terminal.get("task_spec")
    )
    task_report = adaptive_contracts.validate_task_spec(task_spec)
    normalized_task = task_report.get("normalized")
    task_digest = task_report.get("digest")
    if not task_report.get("valid") or not isinstance(normalized_task, Mapping):
        _issue(issues, f"terminals:task_spec_invalid:{logical_id}")
        status = "failed_contract"
        normalized_task = None
        task_digest = None
    else:
        if normalized_task.get("id") != logical_id:
            _issue(issues, f"terminals:task_spec_worker_mismatch:{logical_id}")
            status = "failed_contract"
        if normalized_task.get("executor") != "subagent":
            _issue(issues, f"terminals:task_spec_executor_invalid:{logical_id}")
            status = "failed_contract"
        expected_profile = _node_profile(worker)
        expected_profile_id = (
            expected_profile["profile_id"] if expected_profile is not None else None
        )
        if _profile_id_of(normalized_task.get("model_profile")) != expected_profile_id:
            _issue(issues, f"terminals:task_spec_route_mismatch:{logical_id}")
            status = "failed_contract"

    raw_packets = (
        list(prevalidated_packets)
        if prevalidated_packets is not None
        else terminal.get("incremental_packets")
    )
    if not isinstance(raw_packets, list) or not raw_packets:
        _issue(issues, f"terminals:incremental_packets_required:{logical_id}")
        raw_packets = []
        status = "failed_contract"
    packets: list[dict[str, Any]] = []
    packet_usages: list[Mapping[str, Any]] = []
    for packet_index, packet in enumerate(raw_packets):
        if prevalidated_packets is not None:
            normalized_packet = packet if isinstance(packet, Mapping) else None
        else:
            packet_report = adaptive_contracts.validate_incremental_claim_packet(
                packet,
                task_spec=task_spec,
            )
            if not packet_report.get("valid"):
                _issue(
                    issues,
                    f"terminals:incremental_invalid:{logical_id}:{packet_index}",
                )
                for item in packet_report.get("issues", []):
                    _issue(
                        issues,
                        f"terminals:incremental_issue:{logical_id}:{packet_index}:{item}",
                    )
                status = "failed_contract"
                continue
            normalized_packet = packet_report.get("normalized")
        if isinstance(normalized_packet, Mapping):
            packets.append(dict(normalized_packet))
            packet_usages.append(normalized_packet.get("usage", {}))
    if [packet.get("sequence") for packet in packets] != list(
        range(1, len(packets) + 1)
    ):
        _issue(
            issues,
            f"terminals:incremental_sequence_not_contiguous:{logical_id}",
        )
        status = "failed_contract"
    for previous, current in zip(packet_usages, packet_usages[1:]):
        if any(
            type(previous.get(field)) is int
            and type(current.get(field)) is int
            and current[field] < previous[field]
            for field in ("input_tokens", "output_tokens", "total_tokens", "tool_calls")
        ):
            _issue(issues, f"terminals:incremental_usage_not_monotonic:{logical_id}")
            status = "failed_contract"
            break
    if packet_usages and usage.get("status") == "observed":
        latest_usage = packet_usages[-1]
        if any(
            type(latest_usage.get(packet_field)) is int
            and type(usage.get(terminal_field)) is int
            and usage[terminal_field] < latest_usage[packet_field]
            for packet_field, terminal_field in (
                ("input_tokens", "input_tokens"),
                ("output_tokens", "output_tokens"),
                ("total_tokens", "total_tokens"),
            )
        ):
            _issue(
                issues,
                f"terminals:terminal_usage_precedes_progress:{logical_id}",
            )
            status = "failed_contract"

    handoff_report = adaptive_contracts.validate_handoff_receipt(
        terminal.get("handoff_receipt"),
        task_spec=task_spec,
    )
    handoff = handoff_report.get("normalized")
    if not handoff_report.get("valid") or not isinstance(handoff, Mapping):
        _issue(issues, f"terminals:typed_handoff_required:{logical_id}")
        for item in handoff_report.get("issues", []):
            _issue(issues, f"terminals:handoff_issue:{logical_id}:{item}")
        status = "failed_contract"
        handoff = None
    else:
        disposition = handoff.get("disposition")
        expected_dispositions = {
            "completed": {"complete"},
            "failed": {"failed"},
            "cancelled": {"blocked", "failed"},
            "timed_out": {"blocked", "failed"},
        }
        if disposition not in expected_dispositions.get(status, {disposition}):
            _issue(issues, f"terminals:handoff_disposition_mismatch:{logical_id}")
            status = "failed_contract"

    task_budget = None
    if normalized_task is not None:
        limits = normalized_task.get("budgets", {})
        observed = {
            "context_tokens": usage.get("input_tokens"),
            "output_tokens": usage.get("output_tokens"),
        }
        task_budget = {
            "status": "unknown" if usage.get("status") != "observed" else "within_limit",
            "limits": {
                "context_tokens": limits.get("context_tokens"),
                "output_tokens": limits.get("output_tokens"),
            },
            "observed": observed if usage.get("status") == "observed" else None,
        }
        if usage.get("status") != "observed":
            _issue(issues, f"terminals:task_budget_unknown:{logical_id}")
            status = "failed_budget_unknown"
        else:
            for budget_field, usage_field in (
                ("context_tokens", "input_tokens"),
                ("output_tokens", "output_tokens"),
            ):
                limit = limits.get(budget_field)
                actual = usage.get(usage_field)
                if type(limit) is int and type(actual) is int and actual > limit:
                    _issue(
                        issues,
                        f"terminals:{budget_field.removesuffix('_tokens')}_budget_exceeded:{logical_id}",
                    )
                    task_budget["status"] = "exceeded"
                    status = "failed_budget_exceeded"

    return status, {
        "task_spec_sha256": task_digest,
        "incremental_packets": packets,
        "handoff_receipt": dict(handoff) if isinstance(handoff, Mapping) else None,
        "task_spec_budget": task_budget,
    }


def _terminal_results(
    values: Any,
    *,
    members: Sequence[Mapping[str, Any]],
    workers: Mapping[str, Mapping[str, Any]],
    typed_version: int,
    task_specs: Mapping[str, Mapping[str, Any]] | None = None,
    progress_states: Mapping[str, Mapping[str, Any]] | None = None,
    runtime_observations: Mapping[str, Mapping[str, Any]] | None = None,
    issues: list[str],
) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        _issue(issues, "terminals:not_array")
        values = []
    expected = {
        str(member["logical_worker_id"]): str(member["worker_id"])
        for member in members
    }
    by_node: dict[str, list[Mapping[str, Any]]] = {}
    result: list[dict[str, Any]] = []
    for index, terminal in enumerate(values):
        path = f"terminals[{index}]"
        # `terminal_text` is optional so historical fixtures stay valid, but a
        # lane that does submit its terminal text is screened before the status
        # it declares is believed.
        required = {
            "logical_worker_id",
            "worker_id",
            "status",
            "usage",
            "evidence_pointer",
        }
        if typed_version == 2:
            required |= TERMINAL_TYPED_FIELDS
        elif typed_version == 3:
            required.add("handoff_receipt")
        if (
            isinstance(terminal, Mapping)
            and set(terminal) - required <= TERMINAL_OPTIONAL_FIELDS
        ):
            _exact(
                terminal,
                required | (set(terminal) & TERMINAL_OPTIONAL_FIELDS),
                path,
                issues,
            )
        else:
            _exact(terminal, required, path, issues)
        if not isinstance(terminal, Mapping):
            continue
        logical_id = terminal.get("logical_worker_id")
        worker_id = terminal.get("worker_id")
        by_node.setdefault(str(logical_id), []).append(terminal)
        if logical_id not in expected:
            _issue(issues, f"terminals:unknown_node:{logical_id}")
        elif worker_id != expected[logical_id]:
            _issue(issues, f"terminals:worker_mismatch:{logical_id}")
        status = terminal.get("status")
        if status not in {"completed", "failed", "cancelled", "timed_out"}:
            _issue(issues, f"terminals:status_invalid:{logical_id}")
        # Structural screening of the lane's own terminal text. A degenerate
        # answer is quarantined as a typed lane failure: the declared status is
        # overridden, the evidence is preserved on the row, and the wave is not
        # allowed to absorb it as a normal completion. Nothing here retries,
        # replaces, or substitutes the lane -- Sol's replan seam owns recovery.
        screen = None
        if "terminal_text" in terminal:
            screen = degenerate_output.evaluate_terminal_output(
                terminal.get("terminal_text")
            )
            if screen["status"] == "DEGENERATE":
                _issue(
                    issues,
                    "terminals:degenerate_output:"
                    + f"{logical_id}:"
                    + ",".join(screen["triggered_detectors"]),
                )
                status = "failed_degenerate_output"
        usage_issues: list[str] = []
        usage = _usage_fact(terminal.get("usage"), f"{path}.usage", usage_issues)
        issues.extend(item for item in usage_issues if item not in issues)
        typed_contracts: dict[str, Any] = {}
        if typed_version:
            task_spec_override = None
            prevalidated_packets = None
            if typed_version == 3:
                spec_record = (task_specs or {}).get(str(logical_id), {})
                task_spec_override = spec_record.get("raw")
                progress_state = (progress_states or {}).get(str(logical_id), {})
                prevalidated_packets = progress_state.get("packets", [])
                runtime_observation = (runtime_observations or {}).get(
                    str(logical_id), {}
                )
                runtime_usage = runtime_observation.get("usage", {})
                if any(
                    usage.get(field) != runtime_usage.get(field)
                    for field in (
                        "input_tokens",
                        "cached_input_tokens",
                        "output_tokens",
                        "reasoning_tokens",
                        "total_tokens",
                    )
                ):
                    _issue(
                        issues,
                        f"terminals:runtime_usage_mismatch:{logical_id}",
                    )
                    status = "failed_contract"
                if (
                    runtime_observation.get("terminal_schema")
                    != adaptive_contracts.HANDOFF_RECEIPT_SCHEMA
                    or runtime_observation.get("terminal_json_sha256")
                    != adaptive_contracts.json_sha256(
                        terminal.get("handoff_receipt")
                    )
                ):
                    _issue(
                        issues,
                        f"terminals:runtime_handoff_mismatch:{logical_id}",
                    )
                    status = "failed_contract"
                if (
                    progress_state.get("stop_required")
                    and terminal.get("status") == "completed"
                ):
                    _issue(
                        issues,
                        f"terminals:completed_after_budget_stop:{logical_id}",
                    )
                    status = "failed_budget_exceeded"
            status, typed_contracts = _typed_terminal_contracts(
                terminal,
                logical_id=str(logical_id),
                worker=workers.get(str(logical_id), {}),
                status=str(status),
                usage=usage,
                task_spec_override=task_spec_override,
                prevalidated_packets=prevalidated_packets,
                issues=issues,
            )
        budget = None
        context_limit = workers.get(str(logical_id), {}).get(
            "context_budget_tokens"
        )
        if type(context_limit) is int and context_limit > 0:
            if usage.get("status") != "observed":
                status = "failed_budget_unknown"
                budget = {
                    "status": "unknown",
                    "dimension": "input_tokens",
                    "limit": context_limit,
                    "observed": None,
                }
            elif usage.get("input_tokens", 0) > context_limit:
                status = "failed_budget_exceeded"
                budget = {
                    "status": "exceeded",
                    "dimension": "input_tokens",
                    "limit": context_limit,
                    "observed": usage.get("input_tokens"),
                }
            else:
                budget = {
                    "status": "within_limit",
                    "dimension": "input_tokens",
                    "limit": context_limit,
                    "observed": usage.get("input_tokens"),
                }
        if not _text(terminal.get("evidence_pointer")):
            _issue(issues, f"{path}:evidence_pointer_invalid")
        result.append(
            {
                "logical_worker_id": logical_id,
                "worker_id": worker_id,
                "status": status,
                "usage": usage,
                "budget": budget,
                "evidence_pointer": terminal.get("evidence_pointer"),
                **typed_contracts,
            }
        )
        if screen is not None:
            # Evidence travels with the row so a quarantining root can report
            # exactly which pattern fired without re-reading the poisoned text.
            # Samples inside the verdict are already length-bounded.
            result[-1]["output_screen"] = screen
    for logical_id in sorted(expected):
        if len(by_node.get(logical_id, [])) != 1:
            _issue(
                issues,
                f"terminals:result_count:{logical_id}:{len(by_node.get(logical_id, []))}",
            )
    if len(values) != len(expected):
        _issue(issues, f"terminals:count:{len(values)}!={len(expected)}")
    return sorted(result, key=lambda item: str(item["logical_worker_id"]))


def _wave_plan(
    plan: Mapping[str, Any], selected: Sequence[str]
) -> dict[str, Any]:
    workers = {
        worker.get("id"): worker
        for worker in plan.get("workers", [])
        if isinstance(worker, Mapping)
    }
    return {
        "lanes": [
            {
                "id": worker_id,
                "owned_resources": list(
                    workers[worker_id].get("owned_resources", [])
                ),
                "excluded_resources": list(
                    workers[worker_id].get("excluded_resources", [])
                ),
            }
            for worker_id in selected
        ],
        "protected_resources": list(plan.get("protected_resources", [])),
    }


def _wave_custody(
    plan: Mapping[str, Any],
    *,
    logical_plan_sha256: str,
    selected: Sequence[str],
    members: Sequence[Mapping[str, Any]],
    event_bundle: Any,
    typed_version: int = 1,
) -> dict[str, Any]:
    """Compute custody from structural events; never accept a PASS label."""

    wave_plan = _wave_plan(plan, selected)
    wave_plan_sha256 = _sha256(wave_plan)
    spawn_wave = {
        "schema": "orch-dork/spawn-wave/v1",
        "status": "PASS",
        "complete": True,
        "plan_sha256": wave_plan_sha256,
        "members": [
            {
                "lane_id": member["logical_worker_id"],
                "worker_id": member["worker_id"],
            }
            for member in members
        ],
        "replacement_permitted": False,
        "reuse_permitted": False,
    }
    if isinstance(event_bundle, Mapping) and event_bundle.get("schema") == custody.DEPENDENCY_ORDERED_EVENT_SCHEMA:
        report = custody.evaluate_dependency_ordered_custody(wave_plan, spawn_wave, event_bundle)
        if (type(typed_version) is not int or typed_version != 3
                or plan.get("execution", {}).get("profile") != "finite_dag/v1"
                or plan.get("integration", {}).get("strategy") != "dependency_ordered"
                or plan.get("integration", {}).get("release_required") is not False):
            report.update(status="FAIL", event_conformance=False,
                issues=sorted(set([*report["issues"], "custody:dependency_ordered_profile_mismatch"])))
    else:
        report = custody.evaluate_custody(wave_plan, spawn_wave, event_bundle)
    return {
        **report,
        "logical_plan_sha256": logical_plan_sha256,
        "wave_plan_sha256": wave_plan_sha256,
        "evidence_tier": "provider-free-fixture",
    }


def _terminal_observation_matches(
    observation: Mapping[str, Any],
    terminal: Any,
    *,
    terminal_schema: str,
) -> bool:
    """Return whether one sealed observation binds the exact terminal JSON."""

    return (
        observation.get("terminal_schema") == terminal_schema
        and observation.get("terminal_json_sha256")
        == adaptive_contracts.json_sha256(terminal)
    )


def _project_observer_bound_preflight(
    candidate: Mapping[str, Any],
    observation: Mapping[str, Any],
    *,
    expected_model: Any,
    expected_effort: Any,
    task_spec: Any,
) -> dict[str, Any]:
    """Project observer-owned native facts into the existing v1 gate."""

    runtime_route = observation.get("route", {})
    runtime_usage = observation.get("usage", {})
    observed_usage = {
        "status": runtime_usage.get("status"),
        "input_tokens": runtime_usage.get("input_tokens"),
        "output_tokens": runtime_usage.get("output_tokens"),
        "total_tokens": runtime_usage.get("total_tokens"),
        "tool_calls": runtime_usage.get("tool_calls"),
    }
    handoff = candidate.get("handoff_receipt", {})
    packet = {
        "schema": adaptive_contracts.INCREMENTAL_CLAIM_PACKET_SCHEMA,
        "packet_id": candidate.get("preflight_id"),
        "task_spec_sha256": candidate.get("task_spec_sha256"),
        "sequence": 1,
        "claims": handoff.get("claims", []),
        "artifact_refs": handoff.get("artifact_refs", []),
        "checks": handoff.get("checks", []),
        "usage": observed_usage,
        "source_pointer": str(observation.get("source_pointer")) + "#typed-output",
    }
    projected = {
        "schema": adaptive_contracts.HANDOFF_PREFLIGHT_SCHEMA,
        "preflight_id": candidate.get("preflight_id"),
        "task_spec_sha256": candidate.get("task_spec_sha256"),
        "expected_route": {
            "model": expected_model,
            "effort": expected_effort,
            "context_policy": "none",
        },
        "observed_route": {
            "model": runtime_route.get("model"),
            "effort": runtime_route.get("effort"),
            "context_policy": runtime_route.get("context_policy"),
            "session_id": runtime_route.get("session_id"),
        },
        "capability_profile": candidate.get("capability_profile"),
        "handoff_receipt": handoff,
        "incremental_packets": [packet],
        "observed_usage": observed_usage,
        "evidence": {
            "tier": "runtime_observed",
            "source_pointer": observation.get("source_pointer"),
            "source_sha256": observation.get("source_sha256"),
        },
    }
    return adaptive_contracts.validate_handoff_preflight(
        projected,
        task_spec=task_spec,
    )


def _route_preflight_reports(
    value: Any,
    *,
    plan: Mapping[str, Any],
    plan_report: Mapping[str, Any],
    runtime_observation_required: bool = False,
    issues: list[str],
) -> list[dict[str, Any]]:
    """Validate one runtime-observed typed-output canary per spawn route.

    An onboarded route's preflight is its onboarding probe (ADR 0012), bound
    to the profile digest the plan's routing policy froze.
    """

    if not isinstance(value, list):
        _issue(issues, "route_preflights:not_array")
        value = []
    routing_table = plan_report.get("node_routing", {})
    required_routes: dict[str, tuple[Any, Any]] = {}
    for worker in plan.get("workers", []):
        if not isinstance(worker, Mapping) or worker.get("executor") != "subagent":
            continue
        worker_id = worker.get("id")
        route = routing_table.get(worker_id, {}) if isinstance(routing_table, Mapping) else {}
        profile = route.get("profile")
        if isinstance(profile, str):
            required_routes[profile] = (route.get("model"), route.get("effort"))

    counts: dict[str, int] = {}
    reports: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        path = f"route_preflights[{index}]"
        if isinstance(raw, Mapping) and set(raw) == {"model_profile", "onboarded_profile"}:
            # ADR 0012: an onboarded route's preflight is its onboarding probe.
            reports.append(
                _onboarded_route_preflight(
                    raw, path=path, required_routes=required_routes, counts=counts, issues=issues
                )
            )
            continue
        fields = {"model_profile", "task_spec", "preflight"}
        if runtime_observation_required:
            fields.add("runtime_observation")
        _exact(raw, fields, path, issues)
        item = raw if isinstance(raw, Mapping) else {}
        profile = item.get("model_profile")
        if not _identifier(profile) or model_profiles.resolve_node_profile(profile) is None:
            _issue(issues, f"{path}:model_profile_invalid")
            profile = f"<invalid-{index}>"
        profile = str(_profile_id_of(profile))
        counts[profile] = counts.get(profile, 0) + 1

        task_spec = item.get("task_spec")
        task_report = adaptive_contracts.validate_task_spec(task_spec)
        normalized_task = task_report.get("normalized")
        if not task_report.get("valid") or not isinstance(normalized_task, Mapping):
            _issue(issues, f"route_preflights:{profile}:task_spec_invalid")
        else:
            if normalized_task.get("executor") != "subagent":
                _issue(issues, f"route_preflights:{profile}:executor_invalid")
            if _profile_id_of(normalized_task.get("model_profile")) != profile:
                _issue(issues, f"route_preflights:{profile}:task_route_mismatch")

        runtime_observation = None
        runtime_validation = None
        if runtime_observation_required:
            runtime_validation = routing_verify.validate_session_runtime_observation(
                item.get("runtime_observation")
            )
            if not runtime_validation.get("valid"):
                _issue(
                    issues,
                    f"route_preflights:{profile}:runtime_observation_invalid",
                )
            else:
                runtime_observation = runtime_validation.get("normalized")

        expected_model, expected_effort = required_routes.get(profile, (None, None))
        raw_preflight = item.get("preflight")
        candidate_mode = (
            runtime_observation_required
            and isinstance(raw_preflight, Mapping)
            and raw_preflight.get("schema")
            == adaptive_contracts.HANDOFF_PREFLIGHT_CANDIDATE_SCHEMA
        )
        candidate_report = None
        if candidate_mode:
            candidate_report = (
                adaptive_contracts.validate_handoff_preflight_candidate(
                    raw_preflight,
                    task_spec=task_spec,
                )
            )
            normalized_candidate = candidate_report.get("normalized")
            if not candidate_report.get("candidate_valid") or not isinstance(
                normalized_candidate, Mapping
            ):
                _issue(
                    issues,
                    f"route_preflights:{profile}:preflight_candidate_invalid",
                )
                for detail in candidate_report.get("issues", []):
                    _issue(issues, f"route_preflights:{profile}:{detail}")
                normalized_candidate = {}

            terminal_bound = False
            if runtime_observation is not None:
                terminal_bound = _terminal_observation_matches(
                    runtime_observation,
                    raw_preflight,
                    terminal_schema=(
                        adaptive_contracts.HANDOFF_PREFLIGHT_CANDIDATE_SCHEMA
                    ),
                )
                if not terminal_bound:
                    _issue(
                        issues,
                        f"route_preflights:{profile}:terminal_observation_mismatch",
                    )
                runtime_route = runtime_observation.get("route", {})
                if (
                    runtime_route.get("model") != expected_model
                    or runtime_route.get("effort") != expected_effort
                    or runtime_route.get("context_policy") != "none"
                    or runtime_route.get("inherited_history") is not False
                ):
                    _issue(
                        issues,
                        f"route_preflights:{profile}:runtime_route_mismatch",
                    )

            if (
                normalized_candidate
                and runtime_observation is not None
                and terminal_bound
            ):
                preflight_report = _project_observer_bound_preflight(
                    normalized_candidate,
                    runtime_observation,
                    expected_model=expected_model,
                    expected_effort=expected_effort,
                    task_spec=task_spec,
                )
            else:
                preflight_report = {
                    "status": "FAIL",
                    "spawn_permitted": False,
                    "issues": [],
                    "normalized": None,
                    "digest": None,
                    "evidence_tier": "submitted",
                }
        else:
            preflight_report = adaptive_contracts.validate_handoff_preflight(
                raw_preflight,
                task_spec=task_spec,
            )

        normalized_preflight = preflight_report.get("normalized")
        if not preflight_report.get("spawn_permitted") or not isinstance(
            normalized_preflight, Mapping
        ):
            _issue(issues, f"route_preflights:{profile}:preflight_invalid")
            for detail in preflight_report.get("issues", []):
                _issue(issues, f"route_preflights:{profile}:{detail}")
            normalized_preflight = {}

        if runtime_observation is not None and not candidate_mode:
            observed_route = normalized_preflight.get("observed_route", {})
            observed_usage = normalized_preflight.get("observed_usage", {})
            runtime_route = runtime_observation.get("route", {})
            runtime_usage = runtime_observation.get("usage", {})
            if not _terminal_observation_matches(
                runtime_observation,
                raw_preflight,
                terminal_schema=adaptive_contracts.HANDOFF_PREFLIGHT_SCHEMA,
            ):
                _issue(
                    issues,
                    f"route_preflights:{profile}:terminal_observation_mismatch",
                )
            if any(
                runtime_route.get(field) != observed_route.get(field)
                for field in ("model", "effort", "context_policy", "session_id")
            ) or runtime_route.get("inherited_history") is not False:
                _issue(
                    issues,
                    f"route_preflights:{profile}:runtime_route_mismatch",
                )
            if any(
                runtime_usage.get(field) != observed_usage.get(field)
                for field in (
                    "input_tokens",
                    "output_tokens",
                    "total_tokens",
                    "tool_calls",
                )
            ):
                _issue(
                    issues,
                    f"route_preflights:{profile}:runtime_usage_mismatch",
                )

        expected_route = normalized_preflight.get("expected_route", {})
        if profile not in required_routes:
            _issue(issues, f"route_preflights:{profile}:unrequired_route")
        elif (
            expected_route.get("model") != expected_model
            or expected_route.get("effort") != expected_effort
            or expected_route.get("context_policy") != "none"
        ):
            _issue(issues, f"route_preflights:{profile}:frozen_route_mismatch")

        handoff = normalized_preflight.get("handoff_receipt")
        packets = normalized_preflight.get("incremental_packets", [])
        reports.append(
            {
                "model_profile": profile,
                "status": preflight_report.get("status"),
                "spawn_permitted": bool(preflight_report.get("spawn_permitted")),
                "evidence_tier": (
                    "runtime-observed"
                    if runtime_observation is not None
                    else preflight_report.get("evidence_tier")
                ),
                "runtime_observation_sha256": (
                    runtime_validation.get("digest")
                    if isinstance(runtime_validation, Mapping)
                    else None
                ),
                "task_spec_sha256": task_report.get("digest"),
                "candidate_sha256": (
                    candidate_report.get("digest")
                    if isinstance(candidate_report, Mapping)
                    else None
                ),
                "preflight_sha256": preflight_report.get("digest"),
                "handoff_sha256": (
                    adaptive_contracts.json_sha256(handoff)
                    if isinstance(handoff, Mapping)
                    else None
                ),
                "incremental_packet_sha256s": [
                    adaptive_contracts.json_sha256(packet)
                    for packet in packets
                    if isinstance(packet, Mapping)
                ],
                "session_id": normalized_preflight.get("observed_route", {}).get(
                    "session_id"
                ),
                "observed_route": normalized_preflight.get("observed_route"),
                "observed_usage": normalized_preflight.get("observed_usage"),
                "source_pointer": normalized_preflight.get("evidence", {}).get(
                    "source_pointer"
                ),
            }
        )
    for profile in sorted(required_routes):
        if counts.get(profile, 0) == 0:
            _issue(issues, f"route_preflights:{profile}:missing")
        elif counts[profile] != 1:
            _issue(issues, f"route_preflights:{profile}:count:{counts[profile]}")
    return sorted(reports, key=lambda row: str(row["model_profile"]))


def _wave_task_specs(
    value: Any,
    *,
    plan: Mapping[str, Any],
    plan_report: Mapping[str, Any],
    issues: list[str],
) -> dict[str, dict[str, Any]]:
    """Bind one TaskSpecV2 to every delegated logical worker before events."""

    if not isinstance(value, list):
        _issue(issues, "task_specs:not_array")
        value = []
    routing_table = plan_report.get("node_routing", {})
    required = {
        str(worker.get("id"))
        for worker in plan.get("workers", [])
        if isinstance(worker, Mapping) and worker.get("executor") == "subagent"
    }
    result: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(value):
        path = f"task_specs[{index}]"
        _exact(raw, {"logical_worker_id", "task_spec"}, path, issues)
        item = raw if isinstance(raw, Mapping) else {}
        logical_id = item.get("logical_worker_id")
        if not _identifier(logical_id) or logical_id in result:
            _issue(issues, f"{path}:worker_invalid_or_duplicate")
            continue
        report = adaptive_contracts.validate_task_spec(item.get("task_spec"))
        normalized = report.get("normalized")
        if not report.get("valid") or not isinstance(normalized, Mapping):
            _issue(issues, f"{path}:task_spec_invalid")
            continue
        if normalized.get("id") != logical_id:
            _issue(issues, f"{path}:task_spec_worker_mismatch")
        route = routing_table.get(logical_id, {}) if isinstance(routing_table, Mapping) else {}
        if (
            normalized.get("executor") != "subagent"
            or _profile_id_of(normalized.get("model_profile")) != route.get("profile")
        ):
            _issue(issues, f"{path}:task_spec_route_mismatch")
        result[str(logical_id)] = {
            "raw": dict(item.get("task_spec"))
            if isinstance(item.get("task_spec"), Mapping)
            else {},
            "normalized": dict(normalized),
            "digest": report.get("digest"),
        }
    for logical_id in sorted(required - set(result)):
        _issue(issues, f"task_specs:{logical_id}:missing")
    for logical_id in sorted(set(result) - required):
        _issue(issues, f"task_specs:{logical_id}:unrequired")
    return result


def run_wave_program(program: Any) -> dict[str, Any]:
    """Drain a finite logical program through fresh capacity-bound waves.

    The caller supplies authoritative inventory and bounded wave outcomes. The
    controller selects workers deterministically and never polls, launches, or
    edits the logical plan. Every logical worker appears exactly once in the
    final reconciliation, including pending and aborted nodes.
    """

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    program_schema = value.get("schema")
    typed_version = (
        3
        if program_schema == WAVE_PROGRAM_SCHEMA_V3
        else 2
        if program_schema == WAVE_PROGRAM_SCHEMA_V2
        else 0
    )
    typed_required = typed_version > 0
    version_metadata = {
        "contract_version": program_schema,
        "deprecated": program_schema == WAVE_PROGRAM_SCHEMA,
        "migration_target": (
            WAVE_PROGRAM_SCHEMA_V3
            if program_schema == WAVE_PROGRAM_SCHEMA
            else None
        ),
        "qualification_scope": (
            "replay_only"
            if program_schema == WAVE_PROGRAM_SCHEMA
            else "compatibility"
            if program_schema == WAVE_PROGRAM_SCHEMA_V2
            else "runtime_bound"
            if program_schema == WAVE_PROGRAM_SCHEMA_V3
            else "unknown"
        ),
    }
    program_fields = {
        "schema",
        "program_id",
        "root_thread_id",
        "logical_plan",
        "observations",
    }
    if typed_required:
        program_fields.add("route_preflights")
    if typed_version == 3:
        program_fields.update({"task_specs", "completion_reserve"})
    _exact(
        program,
        program_fields,
        "program",
        issues,
    )
    if value.get("schema") not in {
        WAVE_PROGRAM_SCHEMA,
        WAVE_PROGRAM_SCHEMA_V2,
        WAVE_PROGRAM_SCHEMA_V3,
    }:
        _issue(issues, "program:schema_invalid")
    if not _identifier(value.get("program_id")):
        _issue(issues, "program:id_invalid")
    root_thread_id = value.get("root_thread_id")
    if not _identifier(root_thread_id):
        _issue(issues, "program:root_identity_invalid")
        root_thread_id = "<invalid-root>"
    plan_report = validate_logical_plan(value.get("logical_plan"))
    if plan_report["status"] != "PASS":
        for item in plan_report["issues"]:
            _issue(issues, "logical_plan:" + item)
    plan = value.get("logical_plan") if isinstance(value.get("logical_plan"), Mapping) else {}
    plan_sha256 = plan_report["plan_sha256"]
    worker_rows = plan.get("workers") if isinstance(plan.get("workers"), list) else []
    workers = {
        worker["id"]: worker
        for worker in worker_rows
        if isinstance(worker, Mapping) and isinstance(worker.get("id"), str)
    }
    states = {worker_id: "pending" for worker_id in workers}
    terminal_facts: dict[str, dict[str, Any]] = {}
    wave_reports: list[dict[str, Any]] = []
    observations = value.get("observations")
    if not isinstance(observations, list):
        _issue(issues, "program:observations_not_array")
        observations = []

    task_specs: dict[str, dict[str, Any]] = {}
    if typed_version == 3 and not issues:
        task_specs = _wave_task_specs(
            value.get("task_specs"),
            plan=plan,
            plan_report=plan_report,
            issues=issues,
        )
        _completion_reserve(
            value.get("completion_reserve"),
            path="completion_reserve",
            issues=issues,
        )

    preflight_reports: list[dict[str, Any]] = []
    preflight_passed = not typed_required
    if typed_required and not issues:
        preflight_issues: list[str] = []
        preflight_reports = _route_preflight_reports(
            value.get("route_preflights"),
            plan=plan,
            plan_report=plan_report,
            runtime_observation_required=typed_version == 3,
            issues=preflight_issues,
        )
        if preflight_issues:
            issues.extend(item for item in preflight_issues if item not in issues)
            return {
                **version_metadata,
                "schema": WAVE_REPORT_SCHEMA,
                "status": "PREFLIGHT_REJECTED",
                "program_id": value.get("program_id"),
                "plan_sha256": plan_sha256,
                "logical_worker_count": len(workers),
                "wave_count": 0,
                "waves": [],
                "reconciliation": [
                    {
                        "logical_worker_id": worker_id,
                        "status": "pending",
                        "wave_id": None,
                    }
                    for worker_id in sorted(states)
                ],
                "pending_worker_ids": sorted(states),
                "failed_worker_ids": [],
                "issues": sorted(set(issues)),
                "next_event": "route_preflight_required",
                "automatic_retries": 0,
                "automatic_replacements": 0,
                "model_poll_wakes": 0,
                "spawn_permitted": False,
                "route_preflights": preflight_reports,
                "preflight_evidence_tier": "submitted",
                "evidence_tier": "submitted-fixture",
            }
        preflight_passed = True

    if plan_report["execution_profile"] == "single_worker/v1" and not issues:
        worker_id = next(iter(workers), None)
        if worker_id is not None:
            states[worker_id] = "sol_execution_required"
        return {
            **version_metadata,
            "schema": WAVE_REPORT_SCHEMA,
            "status": "ATOMIC_SOL",
            "program_id": value.get("program_id"),
            "plan_sha256": plan_sha256,
            "logical_worker_count": len(workers),
            "wave_count": 0,
            "waves": [],
            "reconciliation": [
                {"logical_worker_id": worker_id, "status": states[worker_id], "wave_id": None}
                for worker_id in sorted(states)
            ],
            "pending_worker_ids": [],
            "issues": [],
            "next_event": "sol_execute_atomic",
            "automatic_retries": 0,
            "automatic_replacements": 0,
            "model_poll_wakes": 0,
            **(
                {
                    "spawn_permitted": preflight_passed,
                    "route_preflights": preflight_reports,
                    "preflight_evidence_tier": (
                        "runtime_observed" if preflight_passed else "not_evaluated"
                    ),
                }
                if typed_required
                else {}
            ),
        }

    for observation_index, observation in enumerate(observations):
        if issues:
            break
        wave_issues: list[str] = []
        observation_fields = {
                "wave_id",
                "inventory",
                "creations",
                "terminals",
                "custody_events",
            }
        if typed_version == 3:
            observation_fields.update({"routing_program", "progress_events"})
        _exact(
            observation,
            observation_fields,
            f"observations[{observation_index}]",
            wave_issues,
        )
        if not isinstance(observation, Mapping):
            issues.extend(wave_issues)
            break
        wave_id = observation.get("wave_id")
        if not _identifier(wave_id) or any(row["wave_id"] == wave_id for row in wave_reports):
            _issue(wave_issues, "wave:id_invalid_or_duplicate")
        capacity = _inventory_capacity(
            observation.get("inventory"),
            root_thread_id=str(root_thread_id),
            issues=wave_issues,
        )
        pending = sorted(worker_id for worker_id, status in states.items() if status == "pending")
        completed = {worker_id for worker_id, status in states.items() if status == "completed"}
        ready = [
            worker_id
            for worker_id in pending
            if set(workers[worker_id].get("dependencies", [])) <= completed
        ]
        if capacity["free_slots"] == 0:
            wave_reports.append(
                {
                    "wave_id": wave_id,
                    "status": "WAITING" if capacity["capacity"] > 0 else "UNAVAILABLE",
                    "plan_sha256": plan_sha256,
                    "inventory": capacity,
                    "selected_worker_ids": [],
                    "members": [],
                    "terminal_results": [],
                    "custody": {"status": "not_started"},
                    "issues": sorted(wave_issues),
                    "next_event": "capacity_changed",
                }
            )
            if wave_issues:
                issues.extend(wave_issues)
            continue
        selected = ready[: capacity["free_slots"]]
        if not selected:
            wave_reports.append(
                {
                    "wave_id": wave_id,
                    "status": "BLOCKED_DEPENDENCIES",
                    "plan_sha256": plan_sha256,
                    "inventory": capacity,
                    "selected_worker_ids": [],
                    "members": [],
                    "terminal_results": [],
                    "custody": {"status": "not_started"},
                    "issues": sorted(wave_issues),
                    "next_event": "sol_decision_required",
                }
            )
            break

        creation_issues: list[str] = []
        creation_ok, members = _creation_results(
            observation.get("creations"),
            selected=selected,
            root_thread_id=str(root_thread_id),
            session_required=typed_version == 3,
            issues=creation_issues,
        )
        if not creation_ok:
            for worker_id in selected:
                states[worker_id] = "aborted_partial_wave"
            wave_reports.append(
                {
                    "wave_id": wave_id,
                    "status": "FAILED_PARTIAL_WAVE",
                    "plan_sha256": plan_sha256,
                    "inventory": capacity,
                    "selected_worker_ids": selected,
                    "members": members,
                    "terminal_results": [],
                    "custody": {"status": "not_started"},
                    "issues": sorted(set([*wave_issues, *creation_issues])),
                    "next_event": "sol_decision_required",
                    "reuse_permitted": False,
                    "replacement_permitted": False,
                }
            )
            issues.extend(item for item in creation_issues if item not in issues)
            break

        routing_report: dict[str, Any] = {"status": "not_required"}
        progress_report: dict[str, Any] = {"status": "not_required"}
        progress_states: dict[str, Mapping[str, Any]] = {}
        runtime_observations: dict[str, Mapping[str, Any]] = {}
        if typed_version == 3:
            routing_program = observation.get("routing_program")
            routing_report = routing_verify.verify_wave_routing(routing_program)
            derived_members = sorted(
                [
                    {
                        "lane_id": member["logical_worker_id"],
                        "role": "worker",
                        "worker_id": member["worker_id"],
                        "session_id": member["session_id"],
                    }
                    for member in members
                ],
                key=lambda row: row["lane_id"],
            )
            submitted_members = (
                routing_program.get("expected_members")
                if isinstance(routing_program, Mapping)
                else None
            )
            if (
                routing_report.get("status") != "PASS"
                or not isinstance(submitted_members, list)
                or sorted(
                    [dict(row) for row in submitted_members if isinstance(row, Mapping)],
                    key=lambda row: str(row.get("lane_id")),
                )
                != derived_members
            ):
                for worker_id in selected:
                    states[worker_id] = "failed_routing"
                routing_issues = ["routing:verification_failed"]
                routing_issues.extend(
                    "routing:" + str(item)
                    for item in routing_report.get("issues", [])
                )
                wave_all_issues = sorted(
                    set([*wave_issues, *routing_issues])
                )
                wave_reports.append(
                    {
                        "wave_id": wave_id,
                        "status": "FAILED_ROUTING",
                        "plan_sha256": plan_sha256,
                        "inventory": capacity,
                        "selected_worker_ids": selected,
                        "members": members,
                        "terminal_results": [],
                        "custody": {"status": "not_started"},
                        "routing": dict(routing_report),
                        "progress": {"status": "not_started"},
                        "issues": wave_all_issues,
                        "next_event": "sol_decision_required",
                        "reuse_permitted": False,
                        "replacement_permitted": False,
                    }
                )
                issues.extend(item for item in wave_all_issues if item not in issues)
                break

            member_by_logical_id = {
                str(member["logical_worker_id"]): member for member in members
            }
            progress_program = {
                "schema": WAVE_PROGRESS_PROGRAM_SCHEMA,
                "progress_id": f"{value.get('program_id')}:{wave_id}",
                "task_specs": [
                    {
                        "logical_worker_id": logical_id,
                        "worker_id": member_by_logical_id[logical_id]["worker_id"],
                        "task_spec": task_specs[logical_id]["raw"],
                    }
                    for logical_id in selected
                ],
                "completion_reserve": dict(value.get("completion_reserve", {})),
                "events": observation.get("progress_events"),
            }
            progress_report = evaluate_wave_progress(progress_program)
            progress_states = {
                str(row.get("logical_worker_id")): row
                for row in progress_report.get("worker_states", [])
                if isinstance(row, Mapping)
            }
            runtime_observations = {
                str(lane.get("lane_id")): lane.get("session_observation", {})
                for lane in routing_program.get("lanes", [])
                if isinstance(lane, Mapping)
            }
            if progress_report.get("status") != "PASS":
                for worker_id in selected:
                    states[worker_id] = "failed_progress"
                progress_issues = ["progress:verification_failed"]
                progress_issues.extend(
                    "progress:" + str(item)
                    for item in progress_report.get("issues", [])
                )
                wave_all_issues = sorted(
                    set([*wave_issues, *progress_issues])
                )
                wave_reports.append(
                    {
                        "wave_id": wave_id,
                        "status": "FAILED_PROGRESS",
                        "plan_sha256": plan_sha256,
                        "inventory": capacity,
                        "selected_worker_ids": selected,
                        "members": members,
                        "terminal_results": [],
                        "custody": {"status": "not_started"},
                        "routing": dict(routing_report),
                        "progress": dict(progress_report),
                        "issues": wave_all_issues,
                        "next_event": "sol_decision_required",
                        "reuse_permitted": False,
                        "replacement_permitted": False,
                    }
                )
                issues.extend(item for item in wave_all_issues if item not in issues)
                break

        try:
            custody_map = _wave_custody(
                plan,
                logical_plan_sha256=plan_sha256,
                selected=selected,
                members=members,
                event_bundle=observation.get("custody_events"),
                typed_version=typed_version,
            )
        except Exception:
            custody_map = {
                "status": "FAIL",
                "issues": ["custody:evaluation_failed"],
                "evidence_tier": "provider-free-fixture",
            }
        custody_issues = (
            [
                "custody:not_bound:" + str(item)
                for item in custody_map.get("issues", [])
            ]
            if custody_map.get("status") != "PASS"
            else []
        )
        terminal_issues: list[str] = []
        terminals = _terminal_results(
            observation.get("terminals"),
            members=members,
            workers=workers,
            typed_version=typed_version,
            task_specs=task_specs,
            progress_states=progress_states,
            runtime_observations=runtime_observations,
            issues=terminal_issues,
        )
        wave_all_issues = sorted(set([*wave_issues, *custody_issues, *terminal_issues]))
        quarantined = sorted(
            str(terminal["logical_worker_id"])
            for terminal in terminals
            if terminal["status"] == "failed_degenerate_output"
        )
        specific_failures = {
            str(terminal["logical_worker_id"]): str(terminal["status"])
            for terminal in terminals
            if str(terminal["status"])
            in {
                "failed_contract",
                "failed_degenerate_output",
                "failed_budget_exceeded",
                "failed_budget_unknown",
            }
        }
        if wave_all_issues:
            for worker_id in selected:
                # A quarantined lane keeps its own typed failure rather than
                # being flattened into generic wave-evidence failure, so the
                # reconciliation names why that specific lane failed.
                states[worker_id] = specific_failures.get(
                    worker_id,
                    "failed_wave_evidence",
                )
            for terminal in terminals:
                logical_id = str(terminal["logical_worker_id"])
                if logical_id in specific_failures:
                    terminal_facts[logical_id] = {**terminal, "wave_id": wave_id}
            issues.extend(item for item in wave_all_issues if item not in issues)
            # Degenerate output is named as its own wave status only when it is
            # the sole reason the wave failed; any other evidence defect keeps
            # the broader, more serious classification.
            wave_status = (
                "FAILED_DEGENERATE_OUTPUT"
                if quarantined
                and all(
                    item.startswith("terminals:degenerate_output:")
                    for item in wave_all_issues
                )
                else "FAILED_WAVE_EVIDENCE"
            )
            next_event = "sol_decision_required"
        else:
            for terminal in terminals:
                logical_id = str(terminal["logical_worker_id"])
                states[logical_id] = str(terminal["status"])
                terminal_facts[logical_id] = {**terminal, "wave_id": wave_id}
            wave_status = "COMPLETED"
            next_event = "next_capacity_inventory"
        wave_reports.append(
            {
                "wave_id": wave_id,
                "status": wave_status,
                "plan_sha256": plan_sha256,
                "inventory": capacity,
                "selected_worker_ids": selected,
                "members": members,
                "terminal_results": terminals,
                "custody": dict(custody_map),
                **(
                    {
                        "routing": dict(routing_report),
                        "progress": dict(progress_report),
                    }
                    if typed_version == 3
                    else {}
                ),
                "issues": wave_all_issues,
                "next_event": next_event,
                "reuse_permitted": False,
                "replacement_permitted": False,
                "quarantined_worker_ids": quarantined,
            }
        )
        if wave_all_issues:
            break

    pending_ids = sorted(worker_id for worker_id, status in states.items() if status == "pending")
    failed_ids = sorted(
        worker_id
        for worker_id, status in states.items()
        if status
        in {
            "failed",
            "cancelled",
            "timed_out",
            "aborted_partial_wave",
            "failed_wave_evidence",
            "failed_degenerate_output",
            "failed_budget_exceeded",
            "failed_budget_unknown",
            "failed_contract",
            "failed_routing",
            "failed_progress",
        }
    )
    if issues:
        status = "FAILED"
        next_event = "sol_decision_required"
    elif pending_ids:
        status = "WAITING"
        next_event = "capacity_changed"
    elif failed_ids:
        status = "DRAINED_WITH_FAILURES"
        next_event = "sol_decision_required"
    else:
        status = "DRAINED"
        next_event = "terminal_handoff"
    reconciliation = []
    for worker_id in sorted(states):
        terminal = terminal_facts.get(worker_id, {})
        row = {
            "logical_worker_id": worker_id,
            "status": states[worker_id],
            "wave_id": terminal.get("wave_id"),
            "worker_id": terminal.get("worker_id"),
            "usage": terminal.get("usage"),
            "budget": terminal.get("budget"),
            "evidence_pointer": terminal.get("evidence_pointer"),
        }
        if states[worker_id] == "failed_degenerate_output":
            row["output_screen"] = terminal.get("output_screen")
        if typed_required:
            row.update(
                {
                    "task_spec_sha256": terminal.get("task_spec_sha256"),
                    "incremental_packets": terminal.get("incremental_packets"),
                    "handoff_receipt": terminal.get("handoff_receipt"),
                    "task_spec_budget": terminal.get("task_spec_budget"),
                }
            )
        reconciliation.append(row)
    return {
        **version_metadata,
        "schema": WAVE_REPORT_SCHEMA,
        "status": status,
        "program_id": value.get("program_id"),
        "plan_sha256": plan_sha256,
        "logical_worker_count": len(workers),
        "wave_count": len(wave_reports),
        "waves": wave_reports,
        "reconciliation": reconciliation,
        "pending_worker_ids": pending_ids,
        "failed_worker_ids": failed_ids,
        "issues": sorted(set(issues)),
        "next_event": next_event,
        "automatic_retries": 0,
        "automatic_replacements": 0,
        "model_poll_wakes": 0,
        "evidence_tier": "submitted-fixture",
        **(
            {
                "spawn_permitted": preflight_passed,
                "route_preflights": preflight_reports,
                "preflight_evidence_tier": (
                    "runtime-observed"
                    if preflight_passed and typed_version == 3
                    else "runtime_observed"
                    if preflight_passed
                    else "not_evaluated"
                ),
            }
            if typed_required
            else {}
        ),
    }


def _replan_history(value: Any, *, current_plan: Mapping[str, Any], issues: list[str]) -> dict[str, Any]:
    """Validate immutable plan and node history without interpreting its evidence."""

    _exact(value, {"plan_revisions", "node_results"}, "history", issues)
    source = value if isinstance(value, Mapping) else {}
    revisions_value = source.get("plan_revisions")
    if not isinstance(revisions_value, list):
        _issue(issues, "history.plan_revisions:not_array")
        revisions_value = []
    revisions: list[dict[str, Any]] = []
    revision_numbers: set[int] = set()
    for index, revision in enumerate(revisions_value):
        path = f"history.plan_revisions[{index}]"
        _exact(revision, {"revision", "plan_sha256", "status", "source_pointer"}, path, issues)
        item = revision if isinstance(revision, Mapping) else {}
        number = item.get("revision")
        digest = item.get("plan_sha256")
        if type(number) is not int or number < 1 or number in revision_numbers:
            _issue(issues, f"{path}:revision_invalid_or_duplicate")
        else:
            revision_numbers.add(number)
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            _issue(issues, f"{path}:plan_sha256_invalid")
        if item.get("status") not in {"superseded", "active", "failed"}:
            _issue(issues, f"{path}:status_invalid")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")
        revisions.append(dict(item))

    current_sha = _sha256(current_plan)
    current_revision = current_plan.get("revision")
    matches = [
        item
        for item in revisions
        if item.get("revision") == current_revision
        and item.get("plan_sha256") == current_sha
        and item.get("status") == "active"
    ]
    if len(matches) != 1:
        _issue(issues, "history:current_plan_not_bound_once")

    results_value = source.get("node_results")
    if not isinstance(results_value, list):
        _issue(issues, "history.node_results:not_array")
        results_value = []
    known_nodes = {
        worker.get("id")
        for worker in current_plan.get("workers", [])
        if isinstance(worker, Mapping)
    }
    results: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()
    for index, result in enumerate(results_value):
        path = f"history.node_results[{index}]"
        _exact(
            result,
            {
                "node_id",
                "status",
                "artifact_pointers",
                "custody_event_pointers",
                "usage",
                "hard_limit_decision_pointers",
                "evidence_pointer",
            },
            path,
            issues,
        )
        item = result if isinstance(result, Mapping) else {}
        node_id = item.get("node_id")
        if not _identifier(node_id) or node_id in seen_nodes:
            _issue(issues, f"{path}:node_identity_invalid_or_duplicate")
        else:
            seen_nodes.add(str(node_id))
        if node_id not in known_nodes:
            _issue(issues, f"{path}:unknown_node")
        if item.get("status") not in {
            "pending",
            "running",
            "completed",
            "failed",
            "cancelled",
            "timed_out",
            "aborted_partial_wave",
            "failed_wave_evidence",
            "failed_degenerate_output",
        }:
            _issue(issues, f"{path}:status_invalid")
        _string_list(item.get("artifact_pointers"), f"{path}.artifact_pointers", issues)
        _string_list(item.get("custody_event_pointers"), f"{path}.custody_event_pointers", issues)
        _usage_fact(item.get("usage"), f"{path}.usage", issues)
        _string_list(
            item.get("hard_limit_decision_pointers"),
            f"{path}.hard_limit_decision_pointers",
            issues,
        )
        if not _text(item.get("evidence_pointer")):
            _issue(issues, f"{path}:evidence_pointer_invalid")
        results.append(dict(item))
    return {
        "plan_revisions": revisions,
        "node_results": results,
        "history_sha256": _sha256(source),
    }


def _dependency_dispositions(
    plan: Mapping[str, Any],
    node_results: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    workers = {
        str(worker["id"]): worker
        for worker in plan.get("workers", [])
        if isinstance(worker, Mapping) and isinstance(worker.get("id"), str)
    }
    statuses = {worker_id: "pending" for worker_id in workers}
    for result in node_results:
        node_id = result.get("node_id")
        if node_id in statuses:
            statuses[str(node_id)] = str(result.get("status"))
    failed_statuses = {
        "failed",
        "cancelled",
        "timed_out",
        "aborted_partial_wave",
        "failed_wave_evidence",
        # A quarantined lane is a real local failure, so Sol's replan seam
        # can act on it exactly like any other -- that seam, not this
        # controller, is how a root recovers.
        "failed_degenerate_output",
    }
    failed = {node_id for node_id, status in statuses.items() if status in failed_statuses}
    completed = {node_id for node_id, status in statuses.items() if status == "completed"}
    blocked_by: dict[str, set[str]] = {node_id: set() for node_id in workers}
    changed = True
    while changed:
        changed = False
        for node_id, worker in workers.items():
            before = set(blocked_by[node_id])
            for predecessor in worker.get("dependencies", []):
                if predecessor in failed:
                    blocked_by[node_id].add(str(predecessor))
                blocked_by[node_id].update(blocked_by.get(str(predecessor), set()))
            if blocked_by[node_id] != before:
                changed = True
    blocked = [
        {"node_id": node_id, "failed_ancestor_ids": sorted(ancestors)}
        for node_id, ancestors in sorted(blocked_by.items())
        if ancestors and statuses[node_id] not in failed_statuses and statuses[node_id] != "completed"
    ]
    blocked_ids = {item["node_id"] for item in blocked}
    ready = [
        node_id
        for node_id, worker in sorted(workers.items())
        if statuses[node_id] == "pending"
        and node_id not in blocked_ids
        and set(worker.get("dependencies", [])) <= completed
    ]
    pending = [
        node_id
        for node_id in sorted(workers)
        if statuses[node_id] in {"pending", "running"}
        and node_id not in blocked_ids
        and node_id not in ready
    ]
    return {
        "ready_node_ids": ready,
        "blocked_nodes": blocked,
        "failed_node_ids": sorted(failed),
        "completed_node_ids": sorted(completed),
        "pending_node_ids": pending,
    }


def evaluate_replan_program(program: Any) -> dict[str, Any]:
    """Evaluate one Sol-authored immutable plan revision and local failure impact."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(
        program,
        {"schema", "program_id", "current_plan", "persisted_root", "history", "request"},
        "replan_program",
        issues,
    )
    if value.get("schema") != REPLAN_PROGRAM_SCHEMA:
        _issue(issues, "replan_program:schema_invalid")
    if not _identifier(value.get("program_id")):
        _issue(issues, "replan_program:id_invalid")

    current_report = validate_logical_plan(value.get("current_plan"))
    if current_report["status"] != "PASS":
        for item in current_report["issues"]:
            _issue(issues, "current_plan:" + item)
    current_plan = value.get("current_plan") if isinstance(value.get("current_plan"), Mapping) else {}
    current_sha = current_report["plan_sha256"]

    root = value.get("persisted_root")
    _exact(
        root,
        {"thread_id", "model", "effort", "binding_status", "source_pointer"},
        "persisted_root",
        issues,
    )
    root_value = root if isinstance(root, Mapping) else {}
    if not _identifier(root_value.get("thread_id")):
        _issue(issues, "persisted_root:thread_identity_invalid")
    if not root_model_accepted(root_value.get("model")):
        _issue(issues, "persisted_root:model_invalid")
    if root_value.get("effort") not in {"low", "medium", "high", "xhigh", "max", "ultra"}:
        _issue(issues, "persisted_root:effort_invalid")
    if root_value.get("binding_status") != "BOUND":
        _issue(issues, "persisted_root:not_bound")
    if not _text(root_value.get("source_pointer")):
        _issue(issues, "persisted_root:source_pointer_invalid")
    planner = current_plan.get("planner") if isinstance(current_plan.get("planner"), Mapping) else {}
    if planner.get("root_thread_id") != root_value.get("thread_id"):
        _issue(issues, "persisted_root:current_plan_owner_mismatch")

    history = _replan_history(value.get("history"), current_plan=current_plan, issues=issues)
    request = value.get("request")
    _exact(
        request,
        {
            "status",
            "author",
            "predecessor_plan_sha256",
            "proposed_plan",
            "decision_basis",
            "authority",
            "semantic_decisions",
        },
        "request",
        issues,
    )
    request_value = request if isinstance(request, Mapping) else {}
    request_status = request_value.get("status")
    if request_status not in {"none", "submitted"}:
        _issue(issues, "request:status_invalid")

    decisions_value = request_value.get("semantic_decisions")
    if not isinstance(decisions_value, list):
        _issue(issues, "request.semantic_decisions:not_array")
        decisions_value = []
    semantic_decisions: list[dict[str, Any]] = []
    decision_kinds: set[str] = set()
    for index, decision in enumerate(decisions_value):
        path = f"request.semantic_decisions[{index}]"
        _exact(decision, {"kind", "status", "source_pointer"}, path, issues)
        item = decision if isinstance(decision, Mapping) else {}
        kind = item.get("kind")
        if kind not in {"partial_result", "scope_change", "additional_authority"} or kind in decision_kinds:
            _issue(issues, f"{path}:kind_invalid_or_duplicate")
        else:
            decision_kinds.add(str(kind))
        if item.get("status") not in {"accepted", "rejected", "authority_required"}:
            _issue(issues, f"{path}:status_invalid")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")
        semantic_decisions.append(dict(item))

    proposed_plan: Mapping[str, Any] | None = None
    proposed_report: dict[str, Any] | None = None
    if request_status == "none":
        for field in (
            "author",
            "predecessor_plan_sha256",
            "proposed_plan",
            "decision_basis",
            "authority",
        ):
            if request_value.get(field) is not None:
                _issue(issues, f"request:none_has_{field}")
        if semantic_decisions:
            _issue(issues, "request:none_has_semantic_decisions")
    elif request_status == "submitted":
        author = request_value.get("author")
        _exact(
            author,
            {"role", "thread_id", "model", "binding_status", "source_pointer"},
            "request.author",
            issues,
        )
        author_value = author if isinstance(author, Mapping) else {}
        if author_value.get("role") != "sol":
            _issue(issues, "request:author_not_sol")
        if author_value.get("thread_id") != root_value.get("thread_id"):
            _issue(issues, "request:stale_or_wrong_root")
        if author_value.get("model") != root_value.get("model"):
            _issue(issues, "request:author_model_invalid")
        if author_value.get("binding_status") != "BOUND":
            _issue(issues, "request:author_unbound")
        if not _text(author_value.get("source_pointer")):
            _issue(issues, "request:author_source_pointer_invalid")
        if request_value.get("predecessor_plan_sha256") != current_sha:
            _issue(issues, "request:predecessor_plan_mismatch")

        proposed_report = validate_logical_plan(request_value.get("proposed_plan"))
        if proposed_report["status"] != "PASS":
            for item in proposed_report["issues"]:
                _issue(issues, "proposed_plan:" + item)
        proposed_plan = (
            request_value.get("proposed_plan")
            if isinstance(request_value.get("proposed_plan"), Mapping)
            else {}
        )
        if proposed_plan.get("revision") != current_plan.get("revision", 0) + 1:
            _issue(issues, "request:revision_not_next")
        if proposed_plan.get("predecessor_plan_sha256") != current_sha:
            _issue(issues, "request:proposed_predecessor_mismatch")
        proposed_planner = (
            proposed_plan.get("planner")
            if isinstance(proposed_plan.get("planner"), Mapping)
            else {}
        )
        if proposed_planner.get("root_thread_id") != root_value.get("thread_id"):
            _issue(issues, "request:proposed_plan_owner_mismatch")

        basis = request_value.get("decision_basis")
        _exact(basis, {"kind", "summary", "source_pointers"}, "request.decision_basis", issues)
        basis_value = basis if isinstance(basis, Mapping) else {}
        if basis_value.get("kind") not in {
            "failure_response",
            "scope_change",
            "partial_result",
            "authority_change",
            "semantic_replan",
        }:
            _issue(issues, "request.decision_basis:kind_invalid")
        if not _text(basis_value.get("summary")):
            _issue(issues, "request.decision_basis:summary_invalid")
        _string_list(
            basis_value.get("source_pointers"),
            "request.decision_basis.source_pointers",
            issues,
            empty=False,
        )
        authority = request_value.get("authority")
        _exact(authority, {"authority_id", "status", "scope", "source_pointer"}, "request.authority", issues)
        authority_value = authority if isinstance(authority, Mapping) else {}
        if not _identifier(authority_value.get("authority_id")):
            _issue(issues, "request.authority:id_invalid")
        if authority_value.get("status") != "granted":
            _issue(issues, "request.authority:not_granted")
        if authority_value.get("scope") != "provider_free_replan":
            _issue(issues, "request.authority:scope_invalid")
        if not _text(authority_value.get("source_pointer")):
            _issue(issues, "request.authority:source_pointer_invalid")

    changes = {
        "retained_node_ids": [],
        "added_node_ids": [],
        "removed_node_ids": [],
        "dependency_changed_node_ids": [],
    }
    effective_plan = current_plan
    authority_required = any(
        item.get("status") == "authority_required" for item in semantic_decisions
    )
    replan_accepted = request_status == "submitted" and not issues and not authority_required
    if proposed_plan is not None:
        current_workers = {
            str(worker["id"]): worker
            for worker in current_plan.get("workers", [])
            if isinstance(worker, Mapping) and isinstance(worker.get("id"), str)
        }
        proposed_workers = {
            str(worker["id"]): worker
            for worker in proposed_plan.get("workers", [])
            if isinstance(worker, Mapping) and isinstance(worker.get("id"), str)
        }
        current_ids = set(current_workers)
        proposed_ids = set(proposed_workers)
        retained = sorted(current_ids & proposed_ids)
        changes = {
            "retained_node_ids": retained,
            "added_node_ids": sorted(proposed_ids - current_ids),
            "removed_node_ids": sorted(current_ids - proposed_ids),
            "dependency_changed_node_ids": sorted(
                node_id
                for node_id in retained
                if sorted(current_workers[node_id].get("dependencies", []))
                != sorted(proposed_workers[node_id].get("dependencies", []))
            ),
        }
        if replan_accepted:
            effective_plan = proposed_plan

    dispositions = _dependency_dispositions(effective_plan, history["node_results"])
    if issues:
        status = "FAIL"
        decision_state = "REPLAN_REJECTED"
    elif authority_required:
        status = "PASS"
        decision_state = "AUTHORITY_REQUIRED"
        replan_accepted = False
    elif replan_accepted:
        status = "PASS"
        decision_state = "REPLAN_ACCEPTED"
    elif dispositions["failed_node_ids"] or dispositions["blocked_nodes"]:
        status = "PASS"
        decision_state = "SOL_DECISION_REQUIRED"
    else:
        status = "PASS"
        decision_state = "CONTINUE"
    if dispositions["ready_node_ids"] and decision_state == "SOL_DECISION_REQUIRED":
        next_event = "schedule_ready_and_wake_sol"
    elif decision_state == "AUTHORITY_REQUIRED":
        next_event = "sol_decision_required"
    elif dispositions["ready_node_ids"]:
        next_event = "schedule_ready"
    elif decision_state == "SOL_DECISION_REQUIRED":
        next_event = "sol_decision_required"
    elif not dispositions["pending_node_ids"]:
        next_event = "terminal_handoff"
    else:
        next_event = "dependency_event"
    core = {
        "schema": REPLAN_REPORT_SCHEMA,
        "status": status,
        "program_id": value.get("program_id"),
        "current_plan_sha256": current_sha,
        "effective_plan_sha256": _sha256(effective_plan),
        "current_revision": current_plan.get("revision"),
        "effective_revision": effective_plan.get("revision"),
        "proposed_plan_sha256": (
            proposed_report.get("plan_sha256") if proposed_report is not None else None
        ),
        "replan_accepted": replan_accepted,
        "decision_state": decision_state,
        "changes": changes,
        "decision_basis": (
            dict(request_value["decision_basis"])
            if isinstance(request_value.get("decision_basis"), Mapping)
            else None
        ),
        "replan_authority": (
            dict(request_value["authority"])
            if isinstance(request_value.get("authority"), Mapping)
            else None
        ),
        "history_preserved": True,
        "preserved_history_sha256": history["history_sha256"],
        "semantic_decisions": semantic_decisions,
        "dispositions": dispositions,
        "next_event": next_event,
        "automatic_retries": 0,
        "automatic_replacements": 0,
        "automatic_fallbacks": 0,
        "automatic_resumes": 0,
        "workers_can_spawn": False,
        "issues": sorted(issues),
        "evidence_tier": "submitted-fixture",
    }
    return {**core, "report_sha256": _sha256(core)}


def _active_fact(
    value: Any,
    path: str,
    issues: list[str],
    *,
    units: set[str],
) -> dict[str, Any]:
    _exact(value, {"status", "value", "unit", "reason", "source_pointer"}, path, issues)
    item = value if isinstance(value, Mapping) else {}
    status = item.get("status")
    number = item.get("value")
    unit = item.get("unit")
    reason = item.get("reason")
    if status == "known":
        if type(number) is not int or number < 0:
            _issue(issues, f"{path}:value_invalid")
        if unit not in units:
            _issue(issues, f"{path}:unit_invalid")
        if reason is not None:
            _issue(issues, f"{path}:known_has_reason")
    elif status == "unknown":
        if number is not None or unit is not None:
            _issue(issues, f"{path}:unknown_has_values")
        if not _text(reason):
            _issue(issues, f"{path}:unknown_reason_invalid")
    else:
        _issue(issues, f"{path}:status_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, f"{path}:source_pointer_invalid")
    return dict(item)


def _admission_hash(value: Any) -> str | None:
    """Return the one public sealed-admission digest from a generic record.

    The ticket-admission implementation owns the record shape.  The active
    controller intentionally knows only the stable digest aliases and a few
    identity locations; this prevents lifecycle code from depending on the
    classifier's internal representation.
    """

    if isinstance(value, Mapping):
        for key in ADMISSION_HASH_KEYS:
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
        for key in ("identity", "admission_identity", "binding", "decision", "record"):
            candidate = value.get(key)
            found = _admission_hash(candidate)
            if found is not None:
                return found
    return None


def _admission_ticket_id(value: Any) -> str | None:
    if isinstance(value, Mapping):
        candidate = value.get("ticket_id")
        if isinstance(candidate, str) and candidate:
            return candidate
        for key in ("identity", "admission_identity", "binding", "decision", "record", "ticket"):
            found = _admission_ticket_id(value.get(key))
            if found is not None:
                return found
    return None


def _validate_ticket_admission_identity(value: Any) -> tuple[dict[str, Any], list[str]]:
    """Normalize and validate the frozen v2 identity contract.

    The controller never reclassifies a ticket.  It only checks that a sealed
    record carries every identity component required to bind a lifecycle
    event.  Aliases are accepted solely for the documented compatibility
    surface; the normalized result always uses the v2 names.
    """

    identity = _admission_identity(value)
    issues: list[str] = []
    if not isinstance(value, Mapping):
        return identity, ["ticket_admission_identity_missing:record"]
    # ``policy_version`` is an envelope field in canonical v2, but retaining it
    # in the normalized identity lets callers compare the full contract.
    source_identity = value.get("identity") if isinstance(value.get("identity"), Mapping) else value
    for field in sorted(TICKET_ADMISSION_IDENTITY_FIELDS):
        candidate = identity.get(field)
        if field == "ticket_id" or field == "root_task_id":
            if not _identifier(candidate):
                issues.append(f"ticket_admission_identity_invalid:{field}")
        elif not isinstance(candidate, str) or _SHA256.fullmatch(candidate) is None:
            issues.append(f"ticket_admission_identity_invalid:{field}")
    if isinstance(source_identity, Mapping):
        for field in sorted(set(source_identity) - TICKET_ADMISSION_IDENTITY_FIELDS - TICKET_ADMISSION_IDENTITY_OPTIONAL_FIELDS):
            # Unknown fields are advisory, not a hard failure, so the
            # controller can consume forward-compatible sanitized metadata.
            if field not in {"schema", "decision", "admitted", "events"}:
                issues.append(f"ticket_admission_identity_unknown:{field}")
    return identity, sorted(set(issues))


_ADMISSION_IDENTITY_ALIASES = {
    "ticket_id": ("ticket_id",),
    "ticket_spec_sha256": (
        "ticket_spec_sha256",
        "spec_sha256",
        "spec_hash",
        "canonical_spec_sha256",
    ),
    "acceptance_criteria_sha256": (
        "acceptance_criteria_sha256",
        "acceptance_criteria_hash",
        "acceptance_sha256",
    ),
    "authority_scope_sha256": (
        "authority_scope_sha256",
        "authority_scope_hash",
        "scope_sha256",
    ),
    "writable_scope_sha256": (
        "writable_scope_sha256",
        "writable_scope_hash",
    ),
    "root_task_id": ("root_task_id", "root_thread_id"),
    "invocation_identity_sha256": (
        "invocation_identity_sha256",
        "invocation_identity",
        "invocation_id",
    ),
    "classification_evidence_sha256": (
        "classification_evidence_sha256",
        "classification_sha256",
    ),
    "candidate_lanes_sha256": (
        "candidate_lanes_sha256",
        "lanes_sha256",
    ),
}


def _admission_identity(value: Any) -> dict[str, Any]:
    """Extract only identity fields that are stable across ticket records."""

    result: dict[str, Any] = {}
    if not isinstance(value, Mapping):
        return result
    for canonical, aliases in _ADMISSION_IDENTITY_ALIASES.items():
        for key in aliases:
            candidate = value.get(key)
            if candidate is not None:
                result[canonical] = candidate
                break
    for key in ("identity", "admission_identity", "binding", "ticket", "ticket_context", "record"):
        nested = _admission_identity(value.get(key))
        for field, candidate in nested.items():
            result.setdefault(field, candidate)
    return result


def _ticket_admission_binding(program: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize optional ticket context for lifecycle-bound controller gates."""

    candidates: list[Mapping[str, Any]] = []
    for key in TICKET_ADMISSION_KEYS:
        candidate = program.get(key)
        if isinstance(candidate, Mapping):
            candidates.append(candidate)
    for key in TICKET_CONTEXT_KEYS:
        candidate = program.get(key)
        if isinstance(candidate, Mapping) and candidate not in candidates:
            candidates.append(candidate)
    # The ticket-admission module's durable events are also a supported handoff
    # form.  A controller replay may receive only the append-only stream, so a
    # claim/issued event establishes the binding just as an envelope does.
    event_context: list[Mapping[str, Any]] = []
    event_values: list[Any] = []
    for event_key in ("events", *TICKET_EVENT_CONTAINER_KEYS):
        candidate_events = program.get(event_key)
        if isinstance(candidate_events, list):
            event_values.extend(candidate_events)
        elif isinstance(candidate_events, Mapping):
            event_values.append(candidate_events)
    for event in event_values:
        if not isinstance(event, Mapping):
            continue
        event_type = event.get("type")
        if event_type in TICKET_LIFECYCLE_EVENTS or any(
            event.get(key) is not None for key in ("ticket_id", *ADMISSION_EVENT_HASH_KEYS)
        ):
            event_context.append(event)
    # A caller may put the current ticket identity directly beside the active
    # program.  It is still ticket context, even when no sealed decision was
    # supplied (which must fail closed at the first mutation boundary).
    # Do not mistake the active-controller's ordinary root_thread_id for
    # ticket context.  A direct identity only counts when a ticket/spec,
    # acceptance, scope, invocation, or admission digest is present.
    direct_identity = _admission_identity(
        {key: program.get(key) for key in DIRECT_TICKET_CONTEXT_FIELDS if key in program}
    )
    direct_hash = _admission_hash(program)
    # Once a ticket envelope/hash has opted into this gate, accept the active
    # root aliases as identity fields too.  A bare root_thread_id by itself is
    # intentionally not enough to activate ticket gating for legacy fixtures.
    if candidates or direct_hash is not None or "ticket_id" in program:
        for key, canonical in (("root_task_id", "root_thread_id"), ("root_thread_id", "root_thread_id")):
            candidate = program.get(key)
            if candidate is not None:
                direct_identity.setdefault(canonical, candidate)
    # Lifecycle events opt into the gate, but they are observations rather
    # than the admission record itself.  Keeping them out of ``candidates`` is
    # important: a first write must not mint its own admission merely because
    # it carries a digest.
    has_context = bool(candidates) or bool(event_context) or bool(direct_identity) or direct_hash is not None
    if not has_context:
        return {
            "required": False,
            "ticket_id": None,
            "admission_sha256": None,
            "identity": {},
            "status": None,
            "records": [],
        }
    records = list(candidates)
    admission_record = candidates[0] if candidates else (program if direct_hash is not None else {})
    identity = _admission_identity(admission_record)
    identity_conflicts: list[str] = []
    for field, candidate in direct_identity.items():
        if field in identity and identity[field] != candidate:
            identity_conflicts.append(field)
        else:
            identity.setdefault(field, candidate)
    # The active program's root identity is outside the ticket envelope but is
    # still part of the admission identity contract.
    admission_root = identity.get("root_thread_id")
    active_root = program.get("root_thread_id")
    if admission_root is not None and active_root is not None and admission_root != active_root:
        identity_conflicts.append("root_thread_id")
    identity_issues: list[str] = []
    if admission_record:
        _, identity_issues = _validate_ticket_admission_identity(admission_record)
    status = None
    for record in records:
        for source in (record, record.get("decision") if isinstance(record, Mapping) else None):
            if isinstance(source, Mapping):
                for key in ("status", "decision", "decision_kind", "outcome"):
                    candidate = source.get(key)
                    if isinstance(candidate, str) and candidate in {
                        "ATOMIC_ADMITTED",
                        "ORCHESTRATION_PLAN_REQUIRED",
                        "REFUSED",
                        "RECLASSIFICATION_REQUIRED",
                    }:
                        status = candidate
                        break
            if status is not None:
                break
        if status is not None:
            break
    return {
        "required": True,
        "ticket_id": identity.get("ticket_id") or _admission_ticket_id(admission_record),
        "admission_sha256": _admission_hash(admission_record) or direct_hash,
        "identity": identity,
        "status": status,
        "identity_conflicts": sorted(set(identity_conflicts)),
        "identity_issues": sorted(set(identity_issues)),
        "records": records,
    }


def _event_admission_hash(event: Mapping[str, Any]) -> tuple[str | None, bool]:
    values = [event.get(key) for key in ADMISSION_EVENT_HASH_KEYS if event.get(key) is not None]
    values = [value for value in values if isinstance(value, str)]
    if not values:
        return None, False
    return values[0], len(set(values)) > 1


def _ticket_event_stream(
    program: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    """Return explicit admission lifecycle events kept outside controller events."""

    result: list[Mapping[str, Any]] = []
    for key in TICKET_EVENT_CONTAINER_KEYS:
        value = program.get(key)
        if isinstance(value, list):
            result.extend(item for item in value if isinstance(item, Mapping))
        elif isinstance(value, Mapping):
            result.append(value)
    if result:
        return result
    for record in binding.get("records", []):
        value = record.get("events") if isinstance(record, Mapping) else None
        if isinstance(value, list):
            result.extend(
                item
                for item in value
                if isinstance(item, Mapping) and item.get("observed") is not False
            )
    return result


def _canonical_ticket_admission_issues(
    event: Mapping[str, Any],
    event_type: str,
    binding: Mapping[str, Any],
) -> list[str]:
    """Produce stable issue labels shared with the project-adapter seam."""

    expected = binding.get("admission_sha256")
    observed, conflicting = _event_admission_hash(event)
    issues: list[str] = []
    if conflicting:
        issues.append("ticket_admission_event_hash_conflict:" + event_type)
    if observed is None or not isinstance(expected, str):
        issues.append("ticket_admission_event_hash_missing:" + event_type)
    elif observed != expected:
        issues.append("ticket_admission_event_hash_mismatch:" + event_type)
    expected_ticket = binding.get("ticket_id")
    if event.get("ticket_id") is None or not isinstance(expected_ticket, str):
        issues.append("ticket_admission_event_ticket_missing:" + event_type)
    elif event.get("ticket_id") != expected_ticket:
        issues.append("ticket_admission_event_ticket_mismatch:" + event_type)
    return issues


def _check_ticket_admission_event(
    event: Mapping[str, Any],
    binding: Mapping[str, Any],
    path: str,
    issues: list[str],
    *,
    boundary: str,
) -> bool:
    """Enforce hash + ticket identity at one active lifecycle boundary."""

    if not binding.get("required"):
        return True
    expected_hash = binding.get("admission_sha256")
    observed_hash, conflicting = _event_admission_hash(event)
    event_type = str(event.get("type") or "resource.access")
    if conflicting:
        _issue(issues, f"{path}:ticket_admission_hash_conflict")
        _issue(issues, f"ticket_admission_event_hash_conflict:{event_type}")
    if not isinstance(expected_hash, str) or _SHA256.fullmatch(expected_hash) is None:
        _issue(issues, f"{path}:ticket_admission_missing_current_hash")
        _issue(issues, f"ticket_admission_event_hash_missing:{event_type}")
    if observed_hash is None:
        _issue(issues, f"{path}:ticket_admission_hash_required:{boundary}")
        _issue(issues, f"ticket_admission_event_hash_missing:{event_type}")
    elif observed_hash != expected_hash:
        _issue(issues, f"{path}:ticket_admission_hash_mismatch:{boundary}")
        _issue(issues, f"ticket_admission_event_hash_mismatch:{event_type}")
    expected_ticket = binding.get("ticket_id")
    observed_ticket = event.get("ticket_id")
    if not isinstance(expected_ticket, str) or not expected_ticket:
        _issue(issues, f"{path}:ticket_admission_missing_ticket_id")
    if observed_ticket is None:
        _issue(issues, f"{path}:ticket_id_required:{boundary}")
        _issue(issues, f"ticket_admission_event_ticket_missing:{event_type}")
    elif observed_ticket != expected_ticket:
        _issue(issues, f"{path}:ticket_id_mismatch:{boundary}")
        _issue(issues, f"ticket_admission_event_ticket_mismatch:{event_type}")
    status = binding.get("status")
    if status in {"REFUSED", "RECLASSIFICATION_REQUIRED"}:
        _issue(issues, f"{path}:ticket_admission_{str(status).lower()}")
    for field in binding.get("identity_conflicts", []):
        _issue(issues, f"{path}:ticket_admission_identity_mismatch:{field}")
    for field_issue in binding.get("identity_issues", []):
        _issue(issues, f"{path}:{field_issue}")
    return (
        not any(item.startswith(path + ":ticket_admission") or item.startswith(path + ":ticket_id") for item in issues)
    )


def _ticket_binding_status(binding: Mapping[str, Any], issues: Sequence[str]) -> str:
    if not binding.get("required"):
        return "NOT_APPLICABLE"
    if any(
        item.startswith("ticket_admission_")
        or item.startswith("ticket_admission.")
        or ":ticket_admission" in item
        or ":ticket_id" in item
        for item in issues
    ):
        return "REJECTED"
    if binding.get("admission_sha256") and binding.get("ticket_id"):
        return "BOUND"
    return "MISSING"


def run_active_controller(program: Any) -> dict[str, Any]:
    """Replay one closed provider-free event stream through active lifecycle rules."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    # Ticket admission is optional for historical active-controller fixtures,
    # but once any ticket context is supplied it becomes mandatory at every
    # implementation mutation boundary.  Remove that optional envelope before
    # validating the legacy active-program shape.
    raw_value = program if isinstance(program, Mapping) else {}
    base_value = {
        key: item
        for key, item in raw_value.items()
        if key
        not in set(TICKET_ADMISSION_KEYS)
        | set(TICKET_CONTEXT_KEYS)
        | DIRECT_TICKET_CONTEXT_FIELDS
    }
    _exact(
        base_value,
        {
            "schema",
            "controller_id",
            "root_thread_id",
            "logical_plan",
            "support",
            "authority",
            "adapter",
            "previous_packet",
            "telemetry",
            "events",
        },
        "active_program",
        issues,
    )
    if value.get("schema") != ACTIVE_CONTROLLER_PROGRAM_SCHEMA:
        _issue(issues, "active_program:schema_invalid")
    if not _identifier(value.get("controller_id")):
        _issue(issues, "active_program:id_invalid")
    root_thread_id = value.get("root_thread_id")
    if not _identifier(root_thread_id):
        _issue(issues, "active_program:root_identity_invalid")

    plan_report = validate_logical_plan(value.get("logical_plan"))
    if plan_report["status"] != "PASS":
        for item in plan_report["issues"]:
            _issue(issues, "logical_plan:" + item)
    plan = value.get("logical_plan") if isinstance(value.get("logical_plan"), Mapping) else {}
    if plan.get("planner", {}).get("root_thread_id") != root_thread_id:
        _issue(issues, "active_program:plan_root_mismatch")
    plan_sha = plan_report["plan_sha256"]
    workers = {
        str(worker["id"]): worker
        for worker in plan.get("workers", [])
        if isinstance(worker, Mapping) and isinstance(worker.get("id"), str)
    }
    ticket_binding = _ticket_admission_binding(value)
    ticket_binding_events: list[dict[str, Any]] = []
    ticket_mutation_seen = {
        "implementation.started": False,
        "resource.write": False,
        "completion": False,
    }

    def consume_ticket_event(event: Mapping[str, Any], path: str) -> None:
        """Apply ticket-boundary checks to an external admission event."""

        event_type = str(event.get("type") or event.get("event") or "")
        if event_type not in TICKET_LIFECYCLE_EVENTS and event_type != "resource.access":
            return
        if event_type == "resource.access":
            operation = str(event.get("operation", event.get("mode", ""))).lower()
            if operation not in {"write", "create", "modify", "delete", "mutation"}:
                return
            if ticket_mutation_seen["resource.write"]:
                return
            _check_ticket_admission_event(
                event,
                ticket_binding,
                path,
                issues,
                boundary="first_resource_write",
            )
            ticket_mutation_seen["resource.write"] = True
            ticket_binding_events.append(
                {
                    "seq": event.get("seq"),
                    "type": event_type,
                    "ticket_id": event.get("ticket_id"),
                    "admission_sha256": _event_admission_hash(event)[0],
                    "source_pointer": event.get("source_pointer"),
                }
            )
            return
        boundary = {
            "ticket.claimed": "ticket_claim",
            "admission.issued": "admission_issued",
            "admission.invalidated": "admission_invalidated",
            "implementation.started": "implementation_started",
            "ticket.completed": "ticket_completion",
            "ticket.completion": "ticket_completion",
            "completion.bound": "ticket_completion",
            "completion": "ticket_completion",
            "implementation.completed": "ticket_completion",
        }[event_type]
        _check_ticket_admission_event(
            event,
            ticket_binding,
            path,
            issues,
            boundary=boundary,
        )
        ticket_binding_events.append(
            {
                "seq": event.get("seq"),
                "type": event_type,
                "ticket_id": event.get("ticket_id"),
                "admission_sha256": _event_admission_hash(event)[0],
                "source_pointer": event.get("source_pointer"),
            }
        )
        if event_type == "implementation.started":
            ticket_mutation_seen["implementation.started"] = True
        elif event_type in {"ticket.completed", "ticket.completion", "completion.bound", "completion", "implementation.completed"}:
            ticket_mutation_seen["completion"] = True

    # Admission events may be carried separately from the active runtime
    # stream (the project adapter calls this ``admission_events``).  Validate
    # those facts before replaying worker lifecycle events, preserving their
    # durable order in the report without requiring duplicate controller event
    # records.
    external_events = _ticket_event_stream(value, ticket_binding)
    for external_index, external_event in enumerate(external_events):
        consume_ticket_event(external_event, f"ticket_admission.events[{external_index}]")

    support = value.get("support")
    _exact(
        support,
        {"status", "surface", "controller_version", "lifecycle_features", "source_pointer"},
        "support",
        issues,
    )
    support_value = support if isinstance(support, Mapping) else {}
    support_status = support_value.get("status")
    if support_status not in {"supported", "unsupported", "unavailable"}:
        _issue(issues, "support:status_invalid")
    if not _identifier(support_value.get("surface")):
        _issue(issues, "support:surface_invalid")
    if not _identifier(support_value.get("controller_version")):
        _issue(issues, "support:controller_version_invalid")
    features = set(
        _string_list(
            support_value.get("lifecycle_features"),
            "support.lifecycle_features",
            issues,
        )
    )
    if support_status == "supported" and features != ACTIVE_LIFECYCLE_FEATURES:
        _issue(issues, "support:lifecycle_features_incomplete")
    if not _text(support_value.get("source_pointer")):
        _issue(issues, "support:source_pointer_invalid")

    authority = value.get("authority")
    _exact(authority, {"authority_id", "status", "scope", "source_pointer"}, "authority", issues)
    authority_value = authority if isinstance(authority, Mapping) else {}
    if not _identifier(authority_value.get("authority_id")):
        _issue(issues, "authority:id_invalid")
    if authority_value.get("status") not in {"granted", "required", "revoked"}:
        _issue(issues, "authority:status_invalid")
    if authority_value.get("scope") != "provider_free_program":
        _issue(issues, "authority:scope_invalid")
    if not _text(authority_value.get("source_pointer")):
        _issue(issues, "authority:source_pointer_invalid")

    adapter = value.get("adapter")
    _exact(
        adapter,
        {
            "adapter_id",
            "status",
            "blocked_node_ids",
            "protected_resources",
            "validation_pointers",
            "source_pointer",
        },
        "adapter",
        issues,
    )
    adapter_value = adapter if isinstance(adapter, Mapping) else {}
    if not _identifier(adapter_value.get("adapter_id")):
        _issue(issues, "adapter:id_invalid")
    if adapter_value.get("status") not in {"PASS", "FAIL", "UNAVAILABLE"}:
        _issue(issues, "adapter:status_invalid")
    blocked_by_adapter = set(
        _string_list(adapter_value.get("blocked_node_ids"), "adapter.blocked_node_ids", issues)
    )
    for node_id in blocked_by_adapter - set(workers):
        _issue(issues, f"adapter:unknown_blocked_node:{node_id}")
    adapter_protected = _string_list(
        adapter_value.get("protected_resources"), "adapter.protected_resources", issues
    )
    _string_list(
        adapter_value.get("validation_pointers"),
        "adapter.validation_pointers",
        issues,
    )
    if not _text(adapter_value.get("source_pointer")):
        _issue(issues, "adapter:source_pointer_invalid")

    previous = value.get("previous_packet")
    _exact(
        previous,
        {"version", "last_event_seq", "stable_evidence_pointers"},
        "previous_packet",
        issues,
    )
    previous_value = previous if isinstance(previous, Mapping) else {}
    previous_version = previous_value.get("version")
    previous_seq = previous_value.get("last_event_seq")
    if type(previous_version) is not int or previous_version < 0:
        _issue(issues, "previous_packet:version_invalid")
        previous_version = 0
    if type(previous_seq) is not int or previous_seq < 0:
        _issue(issues, "previous_packet:last_event_seq_invalid")
        previous_seq = 0
    stable_pointers = set(
        _string_list(
            previous_value.get("stable_evidence_pointers"),
            "previous_packet.stable_evidence_pointers",
            issues,
        )
    )

    telemetry = value.get("telemetry")
    _exact(telemetry, {"usage", "context_pressure", "completion_reserve"}, "telemetry", issues)
    telemetry_value = telemetry if isinstance(telemetry, Mapping) else {}
    usage_fact = _usage_fact(telemetry_value.get("usage"), "telemetry.usage", issues)
    context_fact = _active_fact(
        telemetry_value.get("context_pressure"),
        "telemetry.context_pressure",
        issues,
        units={"input_tokens"},
    )
    reserve_fact = _active_fact(
        telemetry_value.get("completion_reserve"),
        "telemetry.completion_reserve",
        issues,
        units={"tokens", "capacity_units"},
    )

    states = {node_id: "pending" for node_id in workers}
    memberships: dict[str, str] = {}
    worker_to_node: dict[str, str] = {}
    releases: set[tuple[str, str]] = set()
    outstanding: list[str] = []
    mechanical_actions: list[dict[str, Any]] = []
    decision_requests: list[dict[str, Any]] = []
    sol_decisions: dict[str, str] = {}
    terminal_observation: dict[str, Any] | None = None
    evidence_pointers: list[str] = []
    material_changes: list[dict[str, Any]] = []
    events_value = value.get("events")
    if not isinstance(events_value, list):
        _issue(issues, "events:not_array")
        events_value = []
    last_seq = 0
    allowed_event_fields = {
        "capacity.observed": {"seq", "type", "capacity", "free_slots", "source_pointer"},
        "worker.created": {
            "seq", "type", "node_id", "worker_id", "parent_thread_id", "fresh", "source_pointer"
        },
        "resource.access": {
            "seq", "type", "node_id", "worker_id", "resource", "operation", "phase", "source_pointer"
        },
        "ticket.claimed": {"seq", "type", "ticket_id", "source_pointer"},
        "admission.issued": {"seq", "type", "ticket_id", "source_pointer"},
        "admission.invalidated": {"seq", "type", "ticket_id", "source_pointer"},
        "implementation.started": {"seq", "type", "ticket_id", "source_pointer"},
        "ticket.completed": {"seq", "type", "ticket_id", "status", "source_pointer"},
        "ticket.completion": {"seq", "type", "ticket_id", "status", "source_pointer"},
        "completion.bound": {"seq", "type", "ticket_id", "source_pointer"},
        "completion": {"seq", "type", "ticket_id", "source_pointer"},
        "implementation.completed": {"seq", "type", "ticket_id", "status", "source_pointer"},
        "worker.completed": {"seq", "type", "node_id", "worker_id", "source_pointer"},
        "worker.failed": {"seq", "type", "node_id", "worker_id", "source_pointer"},
        "timeout.observed": {"seq", "type", "node_id", "worker_id", "source_pointer"},
        "lane.released": {
            "seq", "type", "from_node_id", "to_node_id", "owner_worker_id", "target_worker_id", "source_pointer"
        },
        "decision.requested": {"seq", "type", "kind", "reason", "options", "source_pointer"},
        "sol.decision_recorded": {"seq", "type", "kind", "outcome", "source_pointer"},
        "run.terminal_observed": {"seq", "type", "status", "evidence_tier", "source_pointer"},
    }

    def node_dispositions() -> dict[str, Any]:
        return _dependency_dispositions(
            plan,
            [{"node_id": node_id, "status": status} for node_id, status in states.items()],
        )

    for index, event in enumerate(events_value):
        path = f"events[{index}]"
        if not isinstance(event, Mapping):
            _issue(issues, f"{path}:not_object")
            continue
        event_type = event.get("type")
        required = allowed_event_fields.get(str(event_type))
        if required is None:
            _issue(issues, f"{path}:type_invalid")
            continue
        # Admission digest fields are intentionally optional at the schema
        # layer so legacy records remain readable; the boundary checker below
        # makes them required whenever ticket context is active.
        event_for_shape = {
            key: item
            for key, item in event.items()
            if key not in set(ADMISSION_EVENT_HASH_KEYS) | {"ticket_id"}
        }
        shape_fields = set(required) - {"ticket_id"}
        if event_type in TICKET_LIFECYCLE_EVENTS:
            # Durable admission events carry a schema/root pointer, decision,
            # and observed markers in addition to the controller's compact
            # lifecycle fields.  Require the compact fields but tolerate only
            # the documented sanitized extras.
            for field in sorted(shape_fields - set(event_for_shape)):
                _issue(issues, f"{path}:missing:{field}")
            allowed = shape_fields | TICKET_EVENT_EXTRA_FIELDS
            for key in sorted(set(event_for_shape) - allowed):
                _issue(issues, f"{path}:unknown:{key}")
        else:
            _exact(event_for_shape, shape_fields, path, issues)
        seq = event.get("seq")
        if type(seq) is not int or seq <= last_seq:
            _issue(issues, f"{path}:sequence_invalid")
        else:
            last_seq = seq
        pointer = event.get("source_pointer")
        if not _text(pointer):
            _issue(issues, f"{path}:source_pointer_invalid")
        else:
            evidence_pointers.append(str(pointer))
        if type(seq) is int and seq > previous_seq:
            change = {"seq": seq, "type": event_type, "source_pointer": pointer}
            for field in ("node_id", "from_node_id", "to_node_id", "kind", "status"):
                if field in event:
                    change[field] = event.get(field)
            material_changes.append(change)

        if event_type in TICKET_LIFECYCLE_EVENTS:
            boundary = {
                "ticket.claimed": "ticket_claim",
                "admission.issued": "admission_issued",
                "admission.invalidated": "admission_invalidated",
                "implementation.started": "implementation_started",
                "ticket.completed": "ticket_completion",
                "ticket.completion": "ticket_completion",
                "completion.bound": "ticket_completion",
                "completion": "ticket_completion",
                "implementation.completed": "ticket_completion",
            }[str(event_type)]
            _check_ticket_admission_event(
                event,
                ticket_binding,
                path,
                issues,
                boundary=boundary,
            )
            ticket_binding_events.append(
                {
                    "seq": seq,
                    "type": event_type,
                    "ticket_id": event.get("ticket_id"),
                    "admission_sha256": _event_admission_hash(event)[0],
                    "source_pointer": pointer,
                }
            )
            if event_type == "implementation.started":
                ticket_mutation_seen["implementation.started"] = True
            elif event_type in {"ticket.completed", "ticket.completion", "completion.bound", "completion", "implementation.completed"}:
                ticket_mutation_seen["completion"] = True
        elif event_type == "capacity.observed":
            if outstanding:
                _issue(issues, f"{path}:prior_admission_unresolved")
            capacity_value = event.get("capacity")
            free_slots = event.get("free_slots")
            if (
                type(capacity_value) is not int
                or capacity_value < 0
                or type(free_slots) is not int
                or free_slots < 0
                or free_slots > capacity_value
            ):
                _issue(issues, f"{path}:capacity_invalid")
                free_slots = 0
            disposition = node_dispositions()
            ready = [
                node_id
                for node_id in disposition["ready_node_ids"]
                if node_id not in blocked_by_adapter
            ]
            outstanding = ready[: int(free_slots)]
            mechanical_actions.append(
                {
                    "seq": seq,
                    "action": "admit_wave",
                    "node_ids": list(outstanding),
                    "source_pointer": pointer,
                }
            )
        elif event_type == "worker.created":
            node_id = event.get("node_id")
            worker_id = event.get("worker_id")
            if node_id not in outstanding:
                _issue(issues, f"{path}:node_not_admitted")
            if node_id in memberships or worker_id in worker_to_node:
                _issue(issues, f"{path}:duplicate_membership")
            if event.get("fresh") is not True:
                _issue(issues, f"{path}:worker_not_fresh")
            if event.get("parent_thread_id") != root_thread_id:
                _issue(issues, f"{path}:parent_mismatch")
            if node_id in workers and _worker_identity(worker_id):
                memberships[str(node_id)] = str(worker_id)
                worker_to_node[str(worker_id)] = str(node_id)
                states[str(node_id)] = "running"
            if node_id in outstanding:
                outstanding.remove(str(node_id))
        elif event_type == "resource.access":
            node_id = event.get("node_id")
            worker_id = event.get("worker_id")
            if memberships.get(str(node_id)) != worker_id:
                _issue(issues, f"{path}:membership_mismatch")
            if event.get("operation") not in {"read", "write"}:
                _issue(issues, f"{path}:operation_invalid")
            if event.get("phase") not in {"initial", "integration"}:
                _issue(issues, f"{path}:phase_invalid")
            try:
                resource = ownership.normalize_resource(
                    f"{event.get('operation')}:{event.get('resource')}"
                )
                owned = [
                    ownership.normalize_resource(item)
                    for item in workers.get(str(node_id), {}).get("owned_resources", [])
                ]
                protected = [
                    ownership.normalize_resource(item)
                    for item in [*plan.get("protected_resources", []), *adapter_protected]
                ]
            except Exception:
                _issue(issues, f"{path}:resource_invalid")
                continue
            if event.get("operation") == "write" and not ticket_mutation_seen["resource.write"]:
                _check_ticket_admission_event(
                    event,
                    ticket_binding,
                    path,
                    issues,
                    boundary="first_resource_write",
                )
                ticket_mutation_seen["resource.write"] = True
            if event.get("operation") == "write" and any(
                ownership.resource_contains(scope, resource) for scope in protected
            ):
                _issue(issues, f"{path}:protected_resource_access")
            own_access = any(ownership.resource_contains(scope, resource) for scope in owned)
            if not own_access:
                owner_nodes = [
                    owner_id
                    for owner_id, worker in workers.items()
                    if any(
                        ownership.resource_contains(ownership.normalize_resource(item), resource)
                        for item in worker.get("owned_resources", [])
                    )
                ]
                if event.get("phase") != "integration" or any(
                    (owner_id, str(node_id)) not in releases for owner_id in owner_nodes
                ):
                    _issue(issues, f"{path}:cross_lane_access_before_release")
        elif event_type in {"worker.completed", "worker.failed", "timeout.observed"}:
            node_id = str(event.get("node_id"))
            worker_id = event.get("worker_id")
            if memberships.get(node_id) != worker_id:
                _issue(issues, f"{path}:membership_mismatch")
            if states.get(node_id) != "running":
                _issue(issues, f"{path}:node_not_running")
            states[node_id] = {
                "worker.completed": "completed",
                "worker.failed": "failed",
                "timeout.observed": "timed_out",
            }[str(event_type)]
        elif event_type == "lane.released":
            from_node = str(event.get("from_node_id"))
            to_node = str(event.get("to_node_id"))
            pair = (from_node, to_node)
            if pair in releases:
                _issue(issues, f"{path}:duplicate_release")
            if states.get(from_node) != "completed":
                _issue(issues, f"{path}:owner_not_completed")
            if memberships.get(from_node) != event.get("owner_worker_id"):
                _issue(issues, f"{path}:owner_membership_mismatch")
            if memberships.get(to_node) != event.get("target_worker_id"):
                _issue(issues, f"{path}:target_membership_mismatch")
            if from_node not in workers or to_node not in workers:
                _issue(issues, f"{path}:unknown_node")
            releases.add(pair)
        elif event_type == "decision.requested":
            kind = event.get("kind")
            if kind not in ACTIVE_DECISION_KINDS:
                _issue(issues, f"{path}:kind_invalid")
            if not _text(event.get("reason")):
                _issue(issues, f"{path}:reason_invalid")
            options = _string_list(event.get("options"), f"{path}.options", issues, empty=False)
            if len(options) > 4:
                _issue(issues, f"{path}:options_unbounded")
            decision_requests.append(
                {
                    "kind": kind,
                    "reason": event.get("reason"),
                    "options": options,
                    "source_pointer": pointer,
                }
            )
        elif event_type == "sol.decision_recorded":
            kind = event.get("kind")
            if kind not in ACTIVE_DECISION_KINDS:
                _issue(issues, f"{path}:kind_invalid")
            if event.get("outcome") not in {
                "accepted",
                "rejected",
                "replan_required",
                "authority_required",
            }:
                _issue(issues, f"{path}:outcome_invalid")
            sol_decisions[str(kind)] = str(event.get("outcome"))
        elif event_type == "run.terminal_observed":
            if terminal_observation is not None:
                _issue(issues, f"{path}:duplicate_terminal_observation")
            if event.get("status") != "terminal":
                _issue(issues, f"{path}:status_invalid")
            if event.get("evidence_tier") not in {"runtime-observed", "sealed-runtime"}:
                _issue(issues, f"{path}:evidence_tier_invalid")
            terminal_observation = dict(event)

    if outstanding:
        mechanical_actions.append(
            {
                "seq": last_seq,
                "action": "await_creation_receipts",
                "node_ids": list(outstanding),
                "source_pointer": "controller#outstanding-admission",
            }
        )
    dispositions = node_dispositions()
    blocked_ids = {item["node_id"] for item in dispositions["blocked_nodes"]}
    settled = all(
        state in {"completed", "failed", "timed_out"} or node_id in blocked_ids
        for node_id, state in states.items()
    )
    if terminal_observation is not None and not settled:
        _issue(issues, "terminal:observed_before_nodes_settled")
    final_accepted = sol_decisions.get("final_semantic_acceptance") == "accepted"
    unresolved_requests = [
        item for item in decision_requests if item["kind"] not in sol_decisions
    ]
    if terminal_observation is not None and settled and not final_accepted and not any(
        item["kind"] == "final_semantic_acceptance" for item in unresolved_requests
    ):
        unresolved_requests.append(
            {
                "kind": "final_semantic_acceptance",
                "reason": "Externally observed terminal state requires final Sol acceptance",
                "options": ["accept", "reject"],
                "source_pointer": str(terminal_observation.get("source_pointer")),
            }
        )

    authority_blocked = authority_value.get("status") != "granted"
    adapter_blocked = adapter_value.get("status") != "PASS"
    support_blocked = support_status != "supported"
    sol_wake = bool(unresolved_requests) or authority_blocked
    delta_pointers = sorted(
        pointer
        for pointer in set(evidence_pointers)
        if pointer not in stable_pointers
        and any(
            change.get("source_pointer") == pointer and change.get("seq", 0) > previous_seq
            for change in material_changes
        )
    )
    packet = None
    if sol_wake:
        requests = list(unresolved_requests)
        if authority_blocked and not any(
            item["kind"] == "authority_expansion" for item in requests
        ):
            requests.append(
                {
                    "kind": "authority_expansion",
                    "reason": "Provider-free program authority is not granted",
                    "options": ["grant exact authority", "leave blocked"],
                    "source_pointer": authority_value.get("source_pointer"),
                }
            )
        packet = {
            "schema": "orch-dork/sol-decision-packet/v1",
            "version": int(previous_version) + 1,
            "objective": plan.get("objective"),
            "plan_revision": plan.get("revision"),
            "plan_sha256": plan_sha,
            "from_event_seq": previous_seq,
            "through_event_seq": last_seq,
            "material_changes": material_changes,
            "worker_state": {
                "states": [
                    {"node_id": node_id, "status": states[node_id]}
                    for node_id in sorted(states)
                ],
                "memberships": [
                    {"node_id": node_id, "worker_id": memberships[node_id]}
                    for node_id in sorted(memberships)
                ],
            },
            "dependency_state": dispositions,
            "evidence_pointers": delta_pointers,
            "requested_decisions": requests,
            "authority": dict(authority_value),
            "usage": usage_fact,
            "context_pressure": context_fact,
            "completion_reserve": reserve_fact,
        }

    if issues:
        status = "FAIL"
        next_event = "repair_closed_evidence"
    elif support_blocked:
        status = "UNSUPPORTED_ACTIVE"
        next_event = "active_support_required"
    elif adapter_blocked:
        status = "ADAPTER_BLOCKED"
        next_event = "adapter_repair_required"
    elif authority_blocked:
        status = "AUTHORITY_REQUIRED"
        next_event = "sol_decision_required"
    elif packet is not None:
        status = "SOL_DECISION_REQUIRED"
        next_event = "sol_decision_required"
    elif terminal_observation is not None and settled and final_accepted:
        status = "TERMINAL_HANDOFF"
        next_event = "external_completion_boundary"
    else:
        status = "ACTIVE"
        next_event = "runtime_event"
    core = {
        "schema": ACTIVE_CONTROLLER_REPORT_SCHEMA,
        "status": status,
        "controller_id": value.get("controller_id"),
        "plan_sha256": plan_sha,
        "plan_revision": plan.get("revision"),
        "support_status": support_status,
        "advisory_fallback_used": False,
        "authority_status": authority_value.get("status"),
        "adapter_status": adapter_value.get("status"),
        "ticket_admission_required": bool(ticket_binding.get("required")),
        "ticket_id": ticket_binding.get("ticket_id"),
        "ticket_admission_sha256": ticket_binding.get("admission_sha256"),
        "ticket_admission_status": ticket_binding.get("status"),
        "ticket_admission_events": ticket_binding_events,
        "ticket_admission_policy_version": (
            TICKET_ADMISSION_POLICY_VERSION if ticket_binding.get("required") else None
        ),
        "ticket_admission_binding_status": _ticket_binding_status(ticket_binding, issues),
        "ticket_admission_bound": _ticket_binding_status(ticket_binding, issues) == "BOUND",
        "states": [
            {"node_id": node_id, "status": states[node_id]}
            for node_id in sorted(states)
        ],
        "memberships": [
            {"node_id": node_id, "worker_id": memberships[node_id]}
            for node_id in sorted(memberships)
        ],
        "releases": [
            {"from_node_id": source, "to_node_id": target}
            for source, target in sorted(releases)
        ],
        "dependency_state": dispositions,
        "mechanical_actions": mechanical_actions,
        "sol_wake": sol_wake,
        "sol_packet": packet,
        "terminal_observation": terminal_observation,
        "terminal_handoff_permitted": (
            terminal_observation is not None and settled and final_accepted and not issues
        ),
        "model_poll_wakes": 0,
        "automatic_retries": 0,
        "automatic_replacements": 0,
        "automatic_fallbacks": 0,
        "workers_can_spawn": False,
        "next_event": next_event,
        "issues": sorted(issues),
        "evidence_tier": "submitted-fixture",
    }
    return {**core, "report_sha256": _sha256(core)}


def _raw_usage_vector(value: Any, path: str, issues: list[str]) -> dict[str, Any]:
    fields = {"status", *RAW_USAGE_DIMENSIONS, "reason", "source_pointer"}
    _exact(value, fields, path, issues)
    item = value if isinstance(value, Mapping) else {}
    status = item.get("status")
    if status == "known":
        for dimension in RAW_USAGE_DIMENSIONS:
            number = item.get(dimension)
            if type(number) is not int or number < 0:
                _issue(issues, f"{path}:{dimension}_invalid")
        if item.get("reason") is not None:
            _issue(issues, f"{path}:known_has_reason")
    elif status == "unknown":
        if any(item.get(dimension) is not None for dimension in RAW_USAGE_DIMENSIONS):
            _issue(issues, f"{path}:unknown_has_values")
        if not _text(item.get("reason")):
            _issue(issues, f"{path}:unknown_reason_invalid")
    else:
        _issue(issues, f"{path}:status_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, f"{path}:source_pointer_invalid")
    return dict(item)


def _zero_raw_vector() -> dict[str, int]:
    return {dimension: 0 for dimension in RAW_USAGE_DIMENSIONS}


def _add_raw_vector(total: dict[str, int], fact: Mapping[str, Any]) -> None:
    if fact.get("status") != "known":
        return
    for dimension in RAW_USAGE_DIMENSIONS:
        total[dimension] += int(fact.get(dimension, 0))


def _weighted_cost(vector: Mapping[str, int], weights: Mapping[str, int]) -> int:
    return sum(int(vector.get(dimension, 0)) * int(weights.get(dimension, 0)) for dimension in RAW_USAGE_DIMENSIONS)


def evaluate_limit_policy(program: Any) -> dict[str, Any]:
    """Separate hard limits, soft targets, and protected completion reserve."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(
        program,
        {"schema", "program_id", "plan_sha256", "policy", "ledger", "candidate_action"},
        "limit_program",
        issues,
    )
    if value.get("schema") != LIMIT_POLICY_PROGRAM_SCHEMA:
        _issue(issues, "limit_program:schema_invalid")
    if not _identifier(value.get("program_id")):
        _issue(issues, "limit_program:id_invalid")
    plan_sha = value.get("plan_sha256")
    if not isinstance(plan_sha, str) or _SHA256.fullmatch(plan_sha) is None:
        _issue(issues, "limit_program:plan_sha256_invalid")

    policy = value.get("policy")
    _exact(
        policy,
        {"policy_version", "hard_limits", "soft_targets", "completion_reserve", "cost_weights"},
        "policy",
        issues,
    )
    policy_value = policy if isinstance(policy, Mapping) else {}
    if not _identifier(policy_value.get("policy_version")):
        _issue(issues, "policy:version_invalid")

    weights_value = policy_value.get("cost_weights")
    _exact(
        weights_value,
        {"version", "microunits_per_token", "source_pointer"},
        "policy.cost_weights",
        issues,
    )
    weights_source = weights_value if isinstance(weights_value, Mapping) else {}
    if not _identifier(weights_source.get("version")):
        _issue(issues, "policy.cost_weights:version_invalid")
    weights = weights_source.get("microunits_per_token")
    _exact(weights, set(RAW_USAGE_DIMENSIONS), "policy.cost_weights.microunits_per_token", issues)
    weights_map = weights if isinstance(weights, Mapping) else {}
    for dimension in RAW_USAGE_DIMENSIONS:
        if type(weights_map.get(dimension)) is not int or weights_map.get(dimension, -1) < 0:
            _issue(issues, f"policy.cost_weights:{dimension}_invalid")
    if not _text(weights_source.get("source_pointer")):
        _issue(issues, "policy.cost_weights:source_pointer_invalid")

    dimension_names = set(RAW_USAGE_DIMENSIONS) | {"weighted_cost_microunits"}
    hard_value = policy_value.get("hard_limits")
    if not isinstance(hard_value, list):
        _issue(issues, "policy.hard_limits:not_array")
        hard_value = []
    hard_limits: list[dict[str, Any]] = []
    hard_ids: set[str] = set()
    hard_dimensions: set[str] = set()
    for index, limit in enumerate(hard_value):
        path = f"policy.hard_limits[{index}]"
        _exact(
            limit,
            {"limit_id", "kind", "dimension", "ceiling", "disposition", "authority_id", "source_pointer"},
            path,
            issues,
        )
        item = limit if isinstance(limit, Mapping) else {}
        limit_id = item.get("limit_id")
        dimension = item.get("dimension")
        if not _identifier(limit_id) or limit_id in hard_ids:
            _issue(issues, f"{path}:id_invalid_or_duplicate")
        else:
            hard_ids.add(str(limit_id))
        if item.get("kind") not in {"authority", "safety"}:
            _issue(issues, f"{path}:kind_invalid")
        if dimension not in dimension_names or dimension in hard_dimensions:
            _issue(issues, f"{path}:dimension_invalid_or_duplicate")
        else:
            hard_dimensions.add(str(dimension))
        if type(item.get("ceiling")) is not int or item.get("ceiling", -1) < 0:
            _issue(issues, f"{path}:ceiling_invalid")
        expected_disposition = "AUTHORITY_REQUIRED" if item.get("kind") == "authority" else "SAFETY_BLOCKED"
        if item.get("disposition") != expected_disposition:
            _issue(issues, f"{path}:disposition_mismatch")
        if item.get("kind") == "authority" and not _identifier(item.get("authority_id")):
            _issue(issues, f"{path}:authority_id_invalid")
        if item.get("kind") == "safety" and item.get("authority_id") is not None:
            _issue(issues, f"{path}:unexpected_authority_id")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")
        hard_limits.append(dict(item))
    for dimension in RAW_USAGE_DIMENSIONS:
        if dimension not in hard_dimensions:
            _issue(issues, f"policy.hard_limits:raw_ceiling_missing:{dimension}")

    soft_value = policy_value.get("soft_targets")
    if not isinstance(soft_value, list):
        _issue(issues, "policy.soft_targets:not_array")
        soft_value = []
    soft_targets: list[dict[str, Any]] = []
    soft_ids: set[str] = set()
    for index, target in enumerate(soft_value):
        path = f"policy.soft_targets[{index}]"
        _exact(
            target,
            {"target_id", "dimension", "target", "remediations", "source_pointer"},
            path,
            issues,
        )
        item = target if isinstance(target, Mapping) else {}
        target_id = item.get("target_id")
        if not _identifier(target_id) or target_id in soft_ids:
            _issue(issues, f"{path}:id_invalid_or_duplicate")
        else:
            soft_ids.add(str(target_id))
        if item.get("dimension") not in dimension_names:
            _issue(issues, f"{path}:dimension_invalid")
        if type(item.get("target")) is not int or item.get("target", -1) < 0:
            _issue(issues, f"{path}:target_invalid")
        remediations = set(_string_list(item.get("remediations"), f"{path}.remediations", issues, empty=False))
        for remediation in remediations - SOFT_REMEDIATIONS:
            _issue(issues, f"{path}:remediation_invalid:{remediation}")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")
        soft_targets.append(dict(item))

    reserve = policy_value.get("completion_reserve")
    _exact(reserve, {"allocation", "allowed_phases", "source_pointer"}, "policy.completion_reserve", issues)
    reserve_value = reserve if isinstance(reserve, Mapping) else {}
    reserve_fact = _raw_usage_vector(reserve_value.get("allocation"), "policy.completion_reserve.allocation", issues)
    allowed_phases = set(
        _string_list(reserve_value.get("allowed_phases"), "policy.completion_reserve.allowed_phases", issues, empty=False)
    )
    if allowed_phases != COMPLETION_PHASES:
        _issue(issues, "policy.completion_reserve:allowed_phases_incomplete")
    if not _text(reserve_value.get("source_pointer")):
        _issue(issues, "policy.completion_reserve:source_pointer_invalid")

    ledger = value.get("ledger")
    _exact(ledger, {"records"}, "ledger", issues)
    records_value = ledger.get("records") if isinstance(ledger, Mapping) else None
    if not isinstance(records_value, list):
        _issue(issues, "ledger.records:not_array")
        records_value = []
    record_ids: set[str] = set()
    records: list[dict[str, Any]] = []
    incurred = _zero_raw_vector()
    reserved = _zero_raw_vector()
    completion_incurred = _zero_raw_vector()
    telemetry_unknowns: list[dict[str, Any]] = []
    if reserve_fact.get("status") == "unknown":
        telemetry_unknowns.append(
            {
                "scope": "completion_reserve",
                "record_id": None,
                "reason": reserve_fact.get("reason"),
                "source_pointer": reserve_fact.get("source_pointer"),
            }
        )
    reconciliation: dict[tuple[int, str], dict[str, Any]] = {}
    for index, record in enumerate(records_value):
        path = f"ledger.records[{index}]"
        _exact(
            record,
            {"record_id", "plan_revision", "wave_id", "kind", "phase", "optional", "usage", "source_pointer"},
            path,
            issues,
        )
        item = record if isinstance(record, Mapping) else {}
        record_id = item.get("record_id")
        if not _identifier(record_id) or record_id in record_ids:
            _issue(issues, f"{path}:id_invalid_or_duplicate")
        else:
            record_ids.add(str(record_id))
        if type(item.get("plan_revision")) is not int or item.get("plan_revision", 0) < 1:
            _issue(issues, f"{path}:plan_revision_invalid")
        if not _identifier(item.get("wave_id")):
            _issue(issues, f"{path}:wave_id_invalid")
        if item.get("kind") not in {"incurred", "reserved"}:
            _issue(issues, f"{path}:kind_invalid")
        phase = item.get("phase")
        if phase not in {"execution", "optional_execution", *COMPLETION_PHASES}:
            _issue(issues, f"{path}:phase_invalid")
        if not isinstance(item.get("optional"), bool):
            _issue(issues, f"{path}:optional_invalid")
        fact = _raw_usage_vector(item.get("usage"), f"{path}.usage", issues)
        revision_key = item.get("plan_revision") if type(item.get("plan_revision")) is int else 0
        wave_key = item.get("wave_id") if isinstance(item.get("wave_id"), str) else "invalid"
        scope = reconciliation.setdefault(
            (revision_key, wave_key),
            {
                "plan_revision": revision_key,
                "wave_id": wave_key,
                "incurred": _zero_raw_vector(),
                "reserved": _zero_raw_vector(),
                "record_ids": [],
                "unknown_record_ids": [],
            },
        )
        scope["record_ids"].append(record_id)
        if fact.get("status") == "unknown":
            telemetry_unknowns.append(
                {
                    "scope": "ledger",
                    "record_id": record_id,
                    "reason": fact.get("reason"),
                    "source_pointer": fact.get("source_pointer"),
                }
            )
            scope["unknown_record_ids"].append(record_id)
        elif item.get("kind") == "incurred":
            _add_raw_vector(incurred, fact)
            _add_raw_vector(scope["incurred"], fact)
            if phase in COMPLETION_PHASES:
                _add_raw_vector(completion_incurred, fact)
        else:
            _add_raw_vector(reserved, fact)
            _add_raw_vector(scope["reserved"], fact)
        if item.get("optional") is True and phase in COMPLETION_PHASES:
            _issue(issues, f"{path}:completion_phase_cannot_be_optional")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")
        records.append(dict(item))

    candidate = value.get("candidate_action")
    _exact(
        candidate,
        {"action_id", "node_id", "required", "optional", "phase", "reservation", "source_pointer"},
        "candidate_action",
        issues,
    )
    candidate_value = candidate if isinstance(candidate, Mapping) else {}
    if not _identifier(candidate_value.get("action_id")):
        _issue(issues, "candidate_action:id_invalid")
    if not _identifier(candidate_value.get("node_id")):
        _issue(issues, "candidate_action:node_id_invalid")
    if not isinstance(candidate_value.get("required"), bool) or not isinstance(candidate_value.get("optional"), bool):
        _issue(issues, "candidate_action:required_optional_invalid")
    if candidate_value.get("required") == candidate_value.get("optional"):
        _issue(issues, "candidate_action:must_be_exactly_required_or_optional")
    candidate_phase = candidate_value.get("phase")
    if candidate_phase not in {"execution", "optional_execution", *COMPLETION_PHASES}:
        _issue(issues, "candidate_action:phase_invalid")
    candidate_fact = _raw_usage_vector(candidate_value.get("reservation"), "candidate_action.reservation", issues)
    if candidate_fact.get("status") == "unknown":
        telemetry_unknowns.append(
            {
                "scope": "candidate_action",
                "record_id": candidate_value.get("action_id"),
                "reason": candidate_fact.get("reason"),
                "source_pointer": candidate_fact.get("source_pointer"),
            }
        )
    if candidate_value.get("optional") is True and candidate_phase != "optional_execution":
        _issue(issues, "candidate_action:optional_phase_invalid")
    if candidate_phase in COMPLETION_PHASES and candidate_value.get("required") is not True:
        _issue(issues, "candidate_action:completion_must_be_required")
    if not _text(candidate_value.get("source_pointer")):
        _issue(issues, "candidate_action:source_pointer_invalid")

    candidate_known = candidate_fact.get("status") == "known"
    ledger_known = not any(item.get("scope") == "ledger" for item in telemetry_unknowns)
    measurement_known = candidate_known and ledger_known
    candidate_vector = _zero_raw_vector()
    if candidate_known:
        _add_raw_vector(candidate_vector, candidate_fact)
    total_before = {dimension: incurred[dimension] + reserved[dimension] for dimension in RAW_USAGE_DIMENSIONS}
    total_after = {dimension: total_before[dimension] + candidate_vector[dimension] for dimension in RAW_USAGE_DIMENSIONS}
    weighted_before = _weighted_cost(total_before, weights_map)
    weighted_candidate = _weighted_cost(candidate_vector, weights_map)
    weighted_after = weighted_before + weighted_candidate
    metric_before = {**total_before, "weighted_cost_microunits": weighted_before}
    metric_after = {**total_after, "weighted_cost_microunits": weighted_after}
    reconciliation_rows: list[dict[str, Any]] = []
    for key in sorted(reconciliation):
        scope = reconciliation[key]
        combined = {
            dimension: scope["incurred"][dimension] + scope["reserved"][dimension]
            for dimension in RAW_USAGE_DIMENSIONS
        }
        reconciliation_rows.append(
            {
                **scope,
                "record_ids": sorted(scope["record_ids"], key=str),
                "unknown_record_ids": sorted(scope["unknown_record_ids"], key=str),
                "measurement_status": "unknown" if scope["unknown_record_ids"] else "known",
                "combined": combined,
                "weighted_cost_microunits": _weighted_cost(combined, weights_map),
            }
        )

    hard_dispositions: list[dict[str, Any]] = []
    hard_blocked = False
    remaining: dict[str, int | None] = {dimension: None for dimension in RAW_USAGE_DIMENSIONS}
    for limit in hard_limits:
        dimension = str(limit.get("dimension"))
        before = int(metric_before.get(dimension, 0))
        after = int(metric_after.get(dimension, 0))
        ceiling = int(limit.get("ceiling", 0))
        exceeded = measurement_known and after > ceiling
        if not measurement_known:
            outcome = "TELEMETRY_REQUIRED"
            blocked = True
        elif exceeded:
            outcome = str(limit.get("disposition"))
            blocked = True
        else:
            outcome = "PASS"
            blocked = False
        hard_blocked = hard_blocked or blocked
        hard_dispositions.append(
            {
                "limit_id": limit.get("limit_id"),
                "kind": limit.get("kind"),
                "dimension": dimension,
                "ceiling": ceiling,
                "before": before,
                "candidate": int(candidate_vector.get(dimension, weighted_candidate if dimension == "weighted_cost_microunits" else 0)),
                "after": after,
                "remaining": max(0, ceiling - before),
                "outcome": outcome,
                "authority_id": limit.get("authority_id"),
                "source_pointer": limit.get("source_pointer"),
            }
        )
        if dimension in RAW_USAGE_DIMENSIONS:
            remaining[dimension] = max(0, ceiling - before)

    reserve_vector = _zero_raw_vector()
    if reserve_fact.get("status") == "known":
        _add_raw_vector(reserve_vector, reserve_fact)
    reserve_unknown = reserve_fact.get("status") != "known"
    reserve_dispositions: list[dict[str, Any]] = []
    reserve_blocked = False
    for dimension in RAW_USAGE_DIMENSIONS:
        available = remaining.get(dimension)
        required_reserve = reserve_vector[dimension]
        candidate_amount = candidate_vector[dimension]
        if reserve_unknown or available is None or not measurement_known:
            outcome = "TELEMETRY_REQUIRED"
            blocked = True
            after_optional = None
        elif candidate_phase in COMPLETION_PHASES:
            after_optional = max(0, available - candidate_amount)
            outcome = "RESERVE_SPEND_PERMITTED" if candidate_amount <= available else "RESERVE_EXHAUSTED"
            blocked = candidate_amount > available
        else:
            after_optional = max(0, available - candidate_amount)
            blocked = after_optional < required_reserve
            outcome = "RESERVE_PROTECTED" if not blocked else "RESERVE_PROTECTED_BLOCK"
        reserve_blocked = reserve_blocked or blocked
        reserve_dispositions.append(
            {
                "dimension": dimension,
                "hard_remaining_before": available,
                "candidate": candidate_amount,
                "reserved_for_completion": required_reserve,
                "remaining_after_candidate": after_optional,
                "outcome": outcome,
            }
        )

    soft_dispositions: list[dict[str, Any]] = []
    declared_remediations: list[str] = []
    soft_overrun = False
    for target in soft_targets:
        dimension = str(target.get("dimension"))
        before = int(metric_before.get(dimension, 0))
        after = int(metric_after.get(dimension, 0))
        threshold = int(target.get("target", 0))
        exceeded = measurement_known and after > threshold
        remediations = sorted(set(target.get("remediations", []))) if exceeded else []
        declared_remediations.extend(remediations)
        soft_overrun = soft_overrun or exceeded
        soft_dispositions.append(
            {
                "target_id": target.get("target_id"),
                "dimension": dimension,
                "target": threshold,
                "before": before,
                "after": after,
                "outcome": "SOFT_OVERRUN" if exceeded else ("TELEMETRY_UNKNOWN" if not measurement_known else "PASS"),
                "remediations": remediations,
                "required_work_continues": bool(candidate_value.get("required")) and not hard_blocked and not reserve_blocked,
                "source_pointer": target.get("source_pointer"),
            }
        )

    telemetry_blocked = not measurement_known or reserve_unknown
    if issues:
        status = "FAIL"
        action_disposition = "BLOCKED_INVALID_POLICY"
        admitted = False
    elif telemetry_blocked:
        status = "TELEMETRY_REQUIRED"
        action_disposition = "BLOCKED_TELEMETRY_REQUIRED"
        admitted = False
    elif hard_blocked:
        status = "HARD_BLOCKED"
        action_disposition = "BLOCKED_HARD_LIMIT"
        admitted = False
    elif reserve_blocked:
        status = "RESERVE_BLOCKED"
        action_disposition = "OPTIONAL_SUPPRESSED" if candidate_value.get("optional") else "BLOCKED_RESERVE_REQUIRED"
        admitted = False
    elif soft_overrun:
        status = "SOFT_REMEDIATION"
        action_disposition = "ADMITTED_WITH_REMEDIATION"
        admitted = True
    else:
        status = "PASS"
        action_disposition = "ADMITTED"
        admitted = True
    core = {
        "schema": LIMIT_POLICY_REPORT_SCHEMA,
        "status": status,
        "program_id": value.get("program_id"),
        "plan_sha256": plan_sha,
        "policy_version": policy_value.get("policy_version"),
        "categories": ["hard_authority_or_safety", "soft_efficiency", "completion_reserve"],
        "candidate_action_id": candidate_value.get("action_id"),
        "candidate_admitted": admitted,
        "action_disposition": action_disposition,
        "hard_dispositions": hard_dispositions,
        "soft_dispositions": soft_dispositions,
        "completion_reserve_dispositions": reserve_dispositions,
        "remediations": sorted(set(declared_remediations)),
        "raw_usage": {
            "incurred": incurred,
            "reserved": reserved,
            "candidate": candidate_vector,
            "total_before": total_before,
            "total_after": total_after,
            "completion_incurred": completion_incurred,
        },
        "weighted_cost": {
            "version": weights_source.get("version"),
            "microunits_per_token": dict(weights_map),
            "before_microunits": weighted_before,
            "candidate_microunits": weighted_candidate,
            "after_microunits": weighted_after,
        },
        "ledger_record_count": len(records),
        "ledger_measurement_complete": ledger_known,
        "reconciliation": reconciliation_rows,
        "telemetry_unknowns": telemetry_unknowns,
        "completed_work_preserved": True,
        "incurred_usage_preserved": True,
        "required_work_abandoned": False,
        "automatic_retries": 0,
        "issues": sorted(issues),
        "evidence_tier": "submitted-fixture",
    }
    return {**core, "report_sha256": _sha256(core)}


def evaluate_profile_lifecycle(program: Any) -> dict[str, Any]:
    """Derive one exact profile's durable activation or suspension state."""

    issues: list[str] = []
    blockers: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(
        program,
        {
            "schema",
            "lifecycle_id",
            "profile",
            "history",
            "provider_free_qualification",
            "hosted_canary_authority",
            "hosted_canary",
            "regressions",
        },
        "profile_program",
        issues,
    )
    if value.get("schema") != PROFILE_LIFECYCLE_PROGRAM_SCHEMA:
        _issue(issues, "profile_program:schema_invalid")
    if not _identifier(value.get("lifecycle_id")):
        _issue(issues, "profile_program:id_invalid")

    profile = value.get("profile")
    _exact(
        profile,
        {
            "profile_id",
            "version",
            "support_status",
            "collaboration_surface",
            "surface_version",
            "plan_schema",
            "root_model",
            "root_effort",
            "worker_model",
            "worker_effort",
            "context_policy",
            "controller_version",
            "adapters",
            "lifecycle_features",
            "source_pointer",
        },
        "profile",
        issues,
    )
    profile_value = profile if isinstance(profile, Mapping) else {}
    for field in (
        "profile_id",
        "version",
        "collaboration_surface",
        "surface_version",
        "plan_schema",
        "root_model",
        "root_effort",
        "worker_model",
        "worker_effort",
        "context_policy",
        "controller_version",
    ):
        if not _identifier(profile_value.get(field)):
            _issue(issues, f"profile:{field}_invalid")
    if profile_value.get("support_status") not in {"supported", "unsupported", "blocked"}:
        _issue(issues, "profile:support_status_invalid")
    adapters = _string_list(profile_value.get("adapters"), "profile.adapters", issues, empty=False)
    features = set(
        _string_list(
            profile_value.get("lifecycle_features"),
            "profile.lifecycle_features",
            issues,
            empty=False,
        )
    )
    if profile_value.get("support_status") == "supported" and features != ACTIVE_LIFECYCLE_FEATURES:
        _issue(issues, "profile:lifecycle_features_incomplete")
    if not _text(profile_value.get("source_pointer")):
        _issue(issues, "profile:source_pointer_invalid")
    profile_sha = _sha256(profile_value)

    history_value = value.get("history")
    if not isinstance(history_value, list):
        _issue(issues, "history:not_array")
        history_value = []
    history: list[dict[str, Any]] = []
    history_ids: set[str] = set()
    previous_state: str | None = None
    previous_seq = 0
    for index, event in enumerate(history_value):
        path = f"history[{index}]"
        _exact(
            event,
            {
                "event_id",
                "seq",
                "from_state",
                "to_state",
                "reason",
                "profile_sha256",
                "evidence_pointers",
                "event_sha256",
            },
            path,
            issues,
        )
        item = event if isinstance(event, Mapping) else {}
        event_id = item.get("event_id")
        if not _identifier(event_id) or event_id in history_ids:
            _issue(issues, f"{path}:id_invalid_or_duplicate")
        else:
            history_ids.add(str(event_id))
        seq = item.get("seq")
        if type(seq) is not int or seq != previous_seq + 1:
            _issue(issues, f"{path}:sequence_invalid")
        else:
            previous_seq = seq
        if item.get("from_state") != previous_state:
            _issue(issues, f"{path}:from_state_mismatch")
        to_state = item.get("to_state")
        if to_state not in PROFILE_LIFECYCLE_STATES:
            _issue(issues, f"{path}:to_state_invalid")
        else:
            previous_state = str(to_state)
        if item.get("profile_sha256") != profile_sha:
            _issue(issues, f"{path}:profile_mismatch")
        if not _text(item.get("reason")):
            _issue(issues, f"{path}:reason_invalid")
        _string_list(item.get("evidence_pointers"), f"{path}.evidence_pointers", issues, empty=False)
        event_core = {key: item.get(key) for key in item if key != "event_sha256"}
        if item.get("event_sha256") != _sha256(event_core):
            _issue(issues, f"{path}:event_hash_mismatch")
        history.append(dict(item))
    history_sha = _sha256(history)

    qualification = value.get("provider_free_qualification")
    _exact(
        qualification,
        {
            "suite_id",
            "status",
            "profile_sha256",
            "suite_sha256",
            "test_count",
            "evidence_tier",
            "source_pointer",
        },
        "provider_free_qualification",
        issues,
    )
    qualification_value = qualification if isinstance(qualification, Mapping) else {}
    if not _identifier(qualification_value.get("suite_id")):
        _issue(issues, "provider_free_qualification:suite_id_invalid")
    if qualification_value.get("status") not in {"PASS", "FAIL", "UNKNOWN"}:
        _issue(issues, "provider_free_qualification:status_invalid")
    if qualification_value.get("profile_sha256") != profile_sha:
        blockers.append("provider_free_profile_mismatch")
    suite_sha = qualification_value.get("suite_sha256")
    if not isinstance(suite_sha, str) or _SHA256.fullmatch(suite_sha) is None:
        _issue(issues, "provider_free_qualification:suite_sha256_invalid")
    if type(qualification_value.get("test_count")) is not int or qualification_value.get("test_count", -1) < 0:
        _issue(issues, "provider_free_qualification:test_count_invalid")
    if qualification_value.get("status") == "PASS" and qualification_value.get("test_count", 0) < 1:
        _issue(issues, "provider_free_qualification:pass_without_tests")
    if qualification_value.get("evidence_tier") not in {"submitted", "runtime-observed", "sealed-runtime"}:
        _issue(issues, "provider_free_qualification:evidence_tier_invalid")
    if not _text(qualification_value.get("source_pointer")):
        _issue(issues, "provider_free_qualification:source_pointer_invalid")

    authority = value.get("hosted_canary_authority")
    _exact(
        authority,
        {
            "status",
            "authority_id",
            "scope",
            "profile_sha256",
            "canary_id",
            "grant_sha256",
            "source_pointer",
        },
        "hosted_canary_authority",
        issues,
    )
    authority_value = authority if isinstance(authority, Mapping) else {}
    authority_status = authority_value.get("status")
    if authority_status not in {"not_requested", "required", "granted"}:
        _issue(issues, "hosted_canary_authority:status_invalid")
    if not _identifier(authority_value.get("canary_id")):
        _issue(issues, "hosted_canary_authority:canary_id_invalid")
    if authority_value.get("scope") != "hosted_canary":
        _issue(issues, "hosted_canary_authority:scope_invalid")
    if authority_value.get("profile_sha256") != profile_sha:
        blockers.append("authority_profile_mismatch")
    grant_sha = authority_value.get("grant_sha256")
    if authority_status == "granted":
        if not _identifier(authority_value.get("authority_id")):
            _issue(issues, "hosted_canary_authority:authority_id_invalid")
        if not isinstance(grant_sha, str) or _SHA256.fullmatch(grant_sha) is None:
            _issue(issues, "hosted_canary_authority:grant_sha256_invalid")
    elif authority_value.get("authority_id") is not None or grant_sha is not None:
        _issue(issues, "hosted_canary_authority:ungranted_identity_present")
    if not _text(authority_value.get("source_pointer")):
        _issue(issues, "hosted_canary_authority:source_pointer_invalid")

    canary = value.get("hosted_canary")
    _exact(
        canary,
        {
            "canary_id",
            "status",
            "profile_sha256",
            "authority_id",
            "binding_status",
            "evidence_tier",
            "receipt_sha256",
            "receipt_verification",
            "lifecycle_outcome",
            "correctness_outcome",
            "independent_observer",
            "attempt_count",
            "retries",
            "consumed",
            "source_pointer",
        },
        "hosted_canary",
        issues,
    )
    canary_value = canary if isinstance(canary, Mapping) else {}
    canary_status = canary_value.get("status")
    if canary_status not in {"not_started", "running", "clean", "failed"}:
        _issue(issues, "hosted_canary:status_invalid")
    if canary_value.get("canary_id") != authority_value.get("canary_id"):
        blockers.append("canary_identity_mismatch")
    if canary_value.get("profile_sha256") != profile_sha:
        blockers.append("canary_profile_mismatch")
    if canary_value.get("binding_status") not in {"BOUND", "UNBOUND", "CONTRADICTORY", "NOT_APPLICABLE"}:
        _issue(issues, "hosted_canary:binding_status_invalid")
    if canary_value.get("evidence_tier") not in {"none", "runtime-observed", "sealed-runtime"}:
        _issue(issues, "hosted_canary:evidence_tier_invalid")
    if canary_value.get("receipt_verification") not in {"not_available", "verified", "mismatch", "unknown"}:
        _issue(issues, "hosted_canary:receipt_verification_invalid")
    if canary_value.get("lifecycle_outcome") not in {"not_observed", "PASS", "FAIL", "UNKNOWN"}:
        _issue(issues, "hosted_canary:lifecycle_outcome_invalid")
    if canary_value.get("correctness_outcome") not in {"not_observed", "PASS", "FAIL", "UNKNOWN"}:
        _issue(issues, "hosted_canary:correctness_outcome_invalid")
    if not isinstance(canary_value.get("independent_observer"), bool):
        _issue(issues, "hosted_canary:independent_observer_invalid")
    if type(canary_value.get("attempt_count")) is not int or canary_value.get("attempt_count", -1) < 0:
        _issue(issues, "hosted_canary:attempt_count_invalid")
    if canary_value.get("retries") != 0:
        _issue(issues, "hosted_canary:retries_forbidden")
    if not isinstance(canary_value.get("consumed"), bool):
        _issue(issues, "hosted_canary:consumed_invalid")
    if not _text(canary_value.get("source_pointer")):
        _issue(issues, "hosted_canary:source_pointer_invalid")
    receipt_sha = canary_value.get("receipt_sha256")
    if canary_status in {"clean", "failed"}:
        if not isinstance(receipt_sha, str) or _SHA256.fullmatch(receipt_sha) is None:
            _issue(issues, "hosted_canary:receipt_sha256_invalid")
        if canary_value.get("attempt_count") != 1 or canary_value.get("consumed") is not True:
            blockers.append("canary_not_exactly_once")
    elif receipt_sha is not None:
        _issue(issues, "hosted_canary:premature_receipt")

    clean_canary = all(
        (
            canary_status == "clean",
            authority_status == "granted",
            canary_value.get("authority_id") == authority_value.get("authority_id"),
            canary_value.get("binding_status") == "BOUND",
            canary_value.get("evidence_tier") == "sealed-runtime",
            canary_value.get("receipt_verification") == "verified",
            canary_value.get("lifecycle_outcome") == "PASS",
            canary_value.get("correctness_outcome") == "PASS",
            canary_value.get("independent_observer") is True,
            canary_value.get("attempt_count") == 1,
            canary_value.get("retries") == 0,
            canary_value.get("consumed") is True,
        )
    )
    if canary_status == "clean" and not clean_canary:
        blockers.append("canary_not_cleanly_bound")
    if canary_value.get("receipt_verification") == "mismatch":
        blockers.append("canary_receipt_mismatch")

    regressions_value = value.get("regressions")
    if not isinstance(regressions_value, list):
        _issue(issues, "regressions:not_array")
        regressions_value = []
    regression_ids: set[str] = set()
    open_safety_regressions: list[str] = []
    resolved_safety_regressions: list[str] = []
    efficiency_regressions: list[str] = []
    unrelated_regressions: list[str] = []
    regression_pointers: list[str] = []
    for index, regression in enumerate(regressions_value):
        path = f"regressions[{index}]"
        _exact(
            regression,
            {
                "regression_id",
                "profile_sha256",
                "kind",
                "verified",
                "outcome",
                "evidence_tier",
                "source_pointer",
                "resolution_status",
                "resolution_pointer",
            },
            path,
            issues,
        )
        item = regression if isinstance(regression, Mapping) else {}
        regression_id = item.get("regression_id")
        if not _identifier(regression_id) or regression_id in regression_ids:
            _issue(issues, f"{path}:id_invalid_or_duplicate")
        else:
            regression_ids.add(str(regression_id))
        if item.get("kind") not in PROFILE_REGRESSION_KINDS:
            _issue(issues, f"{path}:kind_invalid")
        if not isinstance(item.get("verified"), bool):
            _issue(issues, f"{path}:verified_invalid")
        if item.get("outcome") not in {"regressed", "passed", "unknown"}:
            _issue(issues, f"{path}:outcome_invalid")
        if item.get("evidence_tier") not in {"submitted", "runtime-observed", "sealed-runtime"}:
            _issue(issues, f"{path}:evidence_tier_invalid")
        if item.get("resolution_status") not in {"open", "verified_resolved"}:
            _issue(issues, f"{path}:resolution_status_invalid")
        if item.get("resolution_status") == "verified_resolved":
            if not _text(item.get("resolution_pointer")):
                _issue(issues, f"{path}:resolution_pointer_invalid")
        elif item.get("resolution_pointer") is not None:
            _issue(issues, f"{path}:unexpected_resolution_pointer")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")
        else:
            regression_pointers.append(str(item.get("source_pointer")))
        if item.get("profile_sha256") != profile_sha:
            if isinstance(regression_id, str):
                unrelated_regressions.append(regression_id)
            continue
        if item.get("verified") is True and item.get("outcome") == "regressed":
            if item.get("kind") in {"correctness", "lifecycle"}:
                if item.get("resolution_status") == "open":
                    open_safety_regressions.append(str(regression_id))
                else:
                    resolved_safety_regressions.append(str(regression_id))
            else:
                efficiency_regressions.append(str(regression_id))

    prior_suspended = previous_state == "SUSPENDED"
    recovery_eligible = bool(prior_suspended and resolved_safety_regressions and not open_safety_regressions)
    if issues:
        state = "UNSUPPORTED_OR_BLOCKED"
        reason = "invalid_profile_lifecycle_program"
        next_event = "repair_provider_free_contract"
    elif prior_suspended:
        state = "SUSPENDED"
        reason = "profile_remains_suspended_pending_requalification"
        next_event = "provider_free_requalification" if recovery_eligible else "verified_regression_resolution"
    elif open_safety_regressions:
        state = "SUSPENDED"
        reason = "verified_profile_local_correctness_or_lifecycle_regression"
        next_event = "verified_regression_resolution"
    elif profile_value.get("support_status") != "supported":
        state = "UNSUPPORTED_OR_BLOCKED"
        reason = "profile_support_unavailable"
        next_event = "provider_free_support"
    elif blockers:
        state = "UNSUPPORTED_OR_BLOCKED"
        reason = "profile_evidence_blocked"
        next_event = "repair_or_replace_invalid_evidence"
    elif qualification_value.get("status") != "PASS":
        state = "UNSUPPORTED_OR_BLOCKED"
        reason = "provider_free_qualification_not_passed"
        next_event = "provider_free_qualification"
    elif authority_status == "not_requested":
        state = "PROVIDER_FREE_READY"
        reason = "provider_free_suite_passed"
        next_event = "request_exact_canary_authority"
    elif authority_status == "required":
        state = "HOSTED_CANARY_AUTHORITY_REQUIRED"
        reason = "exact_hosted_canary_authority_missing"
        next_event = "authority_grant"
    elif canary_status == "running":
        state = "CANARY_RUNNING"
        reason = "exact_authorized_canary_running"
        next_event = "canary_terminal_evidence"
    elif clean_canary:
        state = "ACTIVE_DEFAULT"
        reason = "provider_free_and_clean_bound_canary_passed"
        next_event = "runtime_event"
    else:
        state = "PROVIDER_FREE_READY"
        reason = "exact_authority_granted_canary_not_started"
        next_event = "start_exact_canary"

    evidence_pointers = sorted(
        {
            str(pointer)
            for pointer in (
                profile_value.get("source_pointer"),
                qualification_value.get("source_pointer"),
                authority_value.get("source_pointer"),
                canary_value.get("source_pointer"),
                *regression_pointers,
            )
            if _text(pointer)
        }
    )
    transition = None
    if not issues and state != previous_state:
        transition_core = {
            "event_id": f"profile-transition-{previous_seq + 1}",
            "seq": previous_seq + 1,
            "from_state": previous_state,
            "to_state": state,
            "reason": reason,
            "profile_sha256": profile_sha,
            "evidence_pointers": evidence_pointers,
        }
        transition = {**transition_core, "event_sha256": _sha256(transition_core)}

    core = {
        "schema": PROFILE_LIFECYCLE_REPORT_SCHEMA,
        "status": "FAIL" if issues else "PASS",
        "lifecycle_id": value.get("lifecycle_id"),
        "profile_id": profile_value.get("profile_id"),
        "profile_version": profile_value.get("version"),
        "profile_sha256": profile_sha,
        "state": state,
        "previous_state": previous_state,
        "transition": transition,
        "automatic_activation": state == "ACTIVE_DEFAULT" and previous_state != "ACTIVE_DEFAULT",
        "automatic_suspension": state == "SUSPENDED" and previous_state != "SUSPENDED",
        "governed_active_default": state == "ACTIVE_DEFAULT",
        "advisory_fallback_used": False,
        "explicit_advisory_is_separate": True,
        "authority_inferred": False,
        "authority_status": authority_status,
        "canary_consumed": bool(canary_value.get("consumed")),
        "open_safety_regression_ids": sorted(open_safety_regressions),
        "resolved_safety_regression_ids": sorted(resolved_safety_regressions),
        "efficiency_only_regression_ids": sorted(efficiency_regressions),
        "unrelated_regression_ids": sorted(unrelated_regressions),
        "recovery_eligible": recovery_eligible,
        "history_preserved": True,
        "history_sha256": history_sha,
        "historical_transition_count": len(history),
        "blockers": sorted(set(blockers)),
        "issues": sorted(issues),
        "next_event": next_event,
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "registry_projection": {
            "kind": "profile_lifecycle",
            "profile_id": profile_value.get("profile_id"),
            "profile_sha256": profile_sha,
            "state": state,
            "source_authority": "profile_lifecycle_report",
            "history_sha256": history_sha,
        },
        "evidence_tier": "submitted-fixture",
    }
    return {**core, "report_sha256": _sha256(core)}


def _known_scalar_fact(value: Any, path: str, issues: list[str]) -> dict[str, Any]:
    _exact(value, {"status", "value", "reason", "source_pointer"}, path, issues)
    item = value if isinstance(value, Mapping) else {}
    if item.get("status") == "known":
        if type(item.get("value")) is not int or item.get("value", -1) < 0:
            _issue(issues, f"{path}:value_invalid")
        if item.get("reason") is not None:
            _issue(issues, f"{path}:known_has_reason")
    elif item.get("status") == "unknown":
        if item.get("value") is not None:
            _issue(issues, f"{path}:unknown_has_value")
        if not _text(item.get("reason")):
            _issue(issues, f"{path}:unknown_reason_invalid")
    else:
        _issue(issues, f"{path}:status_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, f"{path}:source_pointer_invalid")
    return dict(item)


def _signed_bps(numerator_delta: int, baseline: int) -> int | None:
    if baseline == 0:
        return 0 if numerator_delta == 0 else None
    return (numerator_delta * 10_000) // baseline


def evaluate_efficiency_program(program: Any) -> dict[str, Any]:
    """Close one finite matched efficiency evaluation from supplied evidence."""

    issues: list[str] = []
    unknowns: list[dict[str, Any]] = []
    contradictions: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(
        program,
        {"schema", "evaluation_id", "contract", "history", "collection", "profile_lifecycle"},
        "evaluation_program",
        issues,
    )
    if value.get("schema") != EFFICIENCY_EVALUATION_PROGRAM_SCHEMA:
        _issue(issues, "evaluation_program:schema_invalid")
    if not _identifier(value.get("evaluation_id")):
        _issue(issues, "evaluation_program:id_invalid")

    contract = value.get("contract")
    _exact(
        contract,
        {
            "version",
            "finite",
            "conditions",
            "trial_order",
            "fixture",
            "routing",
            "plan_sha256",
            "authority",
            "correctness_checks",
            "cost_weights",
            "decision_rules",
            "failure_policy",
            "terminal_rules",
            "source_pointer",
        },
        "contract",
        issues,
    )
    contract_value = contract if isinstance(contract, Mapping) else {}
    if not _identifier(contract_value.get("version")):
        _issue(issues, "contract:version_invalid")
    if contract_value.get("finite") is not True:
        _issue(issues, "contract:finite_required")
    conditions = _string_list(contract_value.get("conditions"), "contract.conditions", issues, empty=False)
    if conditions != ["baseline", "active"]:
        _issue(issues, "contract:conditions_must_be_baseline_then_active")
    plan_sha = contract_value.get("plan_sha256")
    if not isinstance(plan_sha, str) or _SHA256.fullmatch(plan_sha) is None:
        _issue(issues, "contract:plan_sha256_invalid")
    if not _text(contract_value.get("source_pointer")):
        _issue(issues, "contract:source_pointer_invalid")
    contract_sha = _sha256(contract_value)

    history_value = value.get("history")
    if not isinstance(history_value, list):
        _issue(issues, "history:not_array")
        history_value = []
    history: list[dict[str, Any]] = []
    history_ids: set[str] = set()
    previous_state: str | None = None
    previous_seq = 0
    for index, event in enumerate(history_value):
        path = f"history[{index}]"
        _exact(
            event,
            {
                "event_id",
                "seq",
                "from_state",
                "to_state",
                "reason",
                "contract_sha256",
                "evidence_pointers",
                "event_sha256",
            },
            path,
            issues,
        )
        item = event if isinstance(event, Mapping) else {}
        event_id = item.get("event_id")
        if not _identifier(event_id) or event_id in history_ids:
            _issue(issues, f"{path}:id_invalid_or_duplicate")
        else:
            history_ids.add(str(event_id))
        seq = item.get("seq")
        if type(seq) is not int or seq != previous_seq + 1:
            _issue(issues, f"{path}:sequence_invalid")
        else:
            previous_seq = seq
        if item.get("from_state") != previous_state:
            _issue(issues, f"{path}:from_state_mismatch")
        if item.get("to_state") not in EFFICIENCY_STATES:
            _issue(issues, f"{path}:to_state_invalid")
        else:
            previous_state = str(item.get("to_state"))
        if item.get("contract_sha256") != contract_sha:
            _issue(issues, f"{path}:contract_mismatch")
        if not _text(item.get("reason")):
            _issue(issues, f"{path}:reason_invalid")
        _string_list(item.get("evidence_pointers"), f"{path}.evidence_pointers", issues, empty=False)
        event_core = {key: item.get(key) for key in item if key != "event_sha256"}
        if item.get("event_sha256") != _sha256(event_core):
            _issue(issues, f"{path}:event_hash_mismatch")
        history.append(dict(item))
    history_sha = _sha256(history)

    fixture = contract_value.get("fixture")
    _exact(fixture, {"fixture_id", "fixture_sha256", "source_pointer"}, "contract.fixture", issues)
    fixture_value = fixture if isinstance(fixture, Mapping) else {}
    if not _identifier(fixture_value.get("fixture_id")):
        _issue(issues, "contract.fixture:id_invalid")
    fixture_sha = fixture_value.get("fixture_sha256")
    if not isinstance(fixture_sha, str) or _SHA256.fullmatch(fixture_sha) is None:
        _issue(issues, "contract.fixture:sha256_invalid")
    if not _text(fixture_value.get("source_pointer")):
        _issue(issues, "contract.fixture:source_pointer_invalid")

    routing = contract_value.get("routing")
    _exact(routing, {"baseline", "active"}, "contract.routing", issues)
    routing_value = routing if isinstance(routing, Mapping) else {}
    normalized_routes: dict[str, dict[str, Any]] = {}
    for condition in ("baseline", "active"):
        route = routing_value.get(condition)
        path = f"contract.routing.{condition}"
        _exact(route, {"model", "effort", "context_policy", "source_pointer"}, path, issues)
        item = route if isinstance(route, Mapping) else {}
        for field in ("model", "effort", "context_policy"):
            if not _identifier(item.get(field)):
                _issue(issues, f"{path}:{field}_invalid")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")
        normalized_routes[condition] = dict(item)

    trial_order_value = contract_value.get("trial_order")
    if not isinstance(trial_order_value, list) or not trial_order_value:
        _issue(issues, "contract.trial_order:not_nonempty_array")
        trial_order_value = []
    expected_trials: list[dict[str, Any]] = []
    expected_by_id: dict[str, dict[str, Any]] = {}
    condition_counts = {"baseline": 0, "active": 0}
    for index, trial in enumerate(trial_order_value):
        path = f"contract.trial_order[{index}]"
        _exact(trial, {"trial_id", "ordinal", "condition"}, path, issues)
        item = trial if isinstance(trial, Mapping) else {}
        trial_id = item.get("trial_id")
        if not _identifier(trial_id) or trial_id in expected_by_id:
            _issue(issues, f"{path}:id_invalid_or_duplicate")
        elif isinstance(trial_id, str):
            expected_by_id[trial_id] = dict(item)
        if item.get("ordinal") != index + 1:
            _issue(issues, f"{path}:ordinal_invalid")
        condition = item.get("condition")
        if condition not in {"baseline", "active"}:
            _issue(issues, f"{path}:condition_invalid")
        else:
            condition_counts[str(condition)] += 1
        expected_trials.append(dict(item))
    if condition_counts["baseline"] < 1 or condition_counts["baseline"] != condition_counts["active"]:
        _issue(issues, "contract.trial_order:matched_sample_invalid")

    checks = _string_list(
        contract_value.get("correctness_checks"),
        "contract.correctness_checks",
        issues,
        empty=False,
    )
    check_set = set(checks)

    weights_source = contract_value.get("cost_weights")
    _exact(
        weights_source,
        {"version", "microunits_per_token", "source_pointer"},
        "contract.cost_weights",
        issues,
    )
    weights_value = weights_source if isinstance(weights_source, Mapping) else {}
    if not _identifier(weights_value.get("version")):
        _issue(issues, "contract.cost_weights:version_invalid")
    weights = weights_value.get("microunits_per_token")
    _exact(weights, set(RAW_USAGE_DIMENSIONS), "contract.cost_weights.microunits_per_token", issues)
    weights_map = weights if isinstance(weights, Mapping) else {}
    for dimension in RAW_USAGE_DIMENSIONS:
        if type(weights_map.get(dimension)) is not int or weights_map.get(dimension, -1) < 0:
            _issue(issues, f"contract.cost_weights:{dimension}_invalid")
    if not _text(weights_value.get("source_pointer")):
        _issue(issues, "contract.cost_weights:source_pointer_invalid")

    authority = contract_value.get("authority")
    _exact(
        authority,
        {
            "status",
            "authority_id",
            "scope",
            "evaluation_id",
            "grant_sha256",
            "max_trials",
            "source_pointer",
        },
        "contract.authority",
        issues,
    )
    authority_value = authority if isinstance(authority, Mapping) else {}
    authority_status = authority_value.get("status")
    if authority_status not in {"required", "granted"}:
        _issue(issues, "contract.authority:status_invalid")
    if authority_value.get("scope") != "finite_efficiency_evaluation":
        _issue(issues, "contract.authority:scope_invalid")
    if authority_value.get("evaluation_id") != value.get("evaluation_id"):
        _issue(issues, "contract.authority:evaluation_id_mismatch")
    if authority_value.get("max_trials") != len(expected_trials):
        _issue(issues, "contract.authority:max_trials_mismatch")
    if authority_status == "granted":
        if not _identifier(authority_value.get("authority_id")):
            _issue(issues, "contract.authority:authority_id_invalid")
        grant_sha = authority_value.get("grant_sha256")
        if not isinstance(grant_sha, str) or _SHA256.fullmatch(grant_sha) is None:
            _issue(issues, "contract.authority:grant_sha256_invalid")
    elif authority_value.get("authority_id") is not None or authority_value.get("grant_sha256") is not None:
        _issue(issues, "contract.authority:ungranted_identity_present")
    if not _text(authority_value.get("source_pointer")):
        _issue(issues, "contract.authority:source_pointer_invalid")

    decision_rules = contract_value.get("decision_rules")
    _exact(
        decision_rules,
        {
            "primary_metrics",
            "secondary_metrics",
            "minimum_quality_delta_bps",
            "maximum_raw_component_increase_bps",
            "minimum_weighted_cost_reduction_bps",
            "maximum_latency_increase_bps",
            "minimum_lifecycle_reliability_delta_bps",
        },
        "contract.decision_rules",
        issues,
    )
    decision_value = decision_rules if isinstance(decision_rules, Mapping) else {}
    primary = set(
        _string_list(
            decision_value.get("primary_metrics"),
            "contract.decision_rules.primary_metrics",
            issues,
            empty=False,
        )
    )
    expected_primary = {
        "accepted_quality",
        "attributable_token_components",
        "weighted_cost",
        "critical_path_latency",
        "lifecycle_reliability",
    }
    if primary != expected_primary:
        _issue(issues, "contract.decision_rules:primary_metrics_invalid")
    secondary = _string_list(
        decision_value.get("secondary_metrics"),
        "contract.decision_rules.secondary_metrics",
        issues,
        empty=False,
    )
    if secondary != ["sol_share_bps"]:
        _issue(issues, "contract.decision_rules:secondary_metrics_invalid")
    for field in (
        "minimum_quality_delta_bps",
        "minimum_weighted_cost_reduction_bps",
        "maximum_latency_increase_bps",
        "minimum_lifecycle_reliability_delta_bps",
    ):
        if type(decision_value.get(field)) is not int:
            _issue(issues, f"contract.decision_rules:{field}_invalid")
    raw_increase = decision_value.get("maximum_raw_component_increase_bps")
    _exact(
        raw_increase,
        set(RAW_USAGE_DIMENSIONS),
        "contract.decision_rules.maximum_raw_component_increase_bps",
        issues,
    )
    raw_increase_value = raw_increase if isinstance(raw_increase, Mapping) else {}
    for dimension in RAW_USAGE_DIMENSIONS:
        if type(raw_increase_value.get(dimension)) is not int:
            _issue(issues, f"contract.decision_rules:{dimension}_increase_invalid")

    failure_policy = contract_value.get("failure_policy")
    _exact(
        failure_policy,
        {"retries", "replacements", "fallbacks", "missing_evidence", "correctness_regression"},
        "contract.failure_policy",
        issues,
    )
    failure_value = failure_policy if isinstance(failure_policy, Mapping) else {}
    for field in ("retries", "replacements", "fallbacks"):
        if failure_value.get(field) != 0:
            _issue(issues, f"contract.failure_policy:{field}_must_be_zero")
    if failure_value.get("missing_evidence") != "INCONCLUSIVE":
        _issue(issues, "contract.failure_policy:missing_evidence_invalid")
    if failure_value.get("correctness_regression") != "EFFICIENCY_NOT_PROVEN_AND_SUSPEND_PROFILE":
        _issue(issues, "contract.failure_policy:correctness_regression_invalid")

    terminal_rules = contract_value.get("terminal_rules")
    _exact(
        terminal_rules,
        {"outcomes", "incomplete", "contradictory", "auto_close", "later_promotion_required"},
        "contract.terminal_rules",
        issues,
    )
    terminal_value = terminal_rules if isinstance(terminal_rules, Mapping) else {}
    outcomes = set(
        _string_list(terminal_value.get("outcomes"), "contract.terminal_rules.outcomes", issues, empty=False)
    )
    if outcomes != EFFICIENCY_OUTCOMES:
        _issue(issues, "contract.terminal_rules:outcomes_invalid")
    if terminal_value.get("incomplete") != "INCONCLUSIVE":
        _issue(issues, "contract.terminal_rules:incomplete_invalid")
    if terminal_value.get("contradictory") != "INCONCLUSIVE":
        _issue(issues, "contract.terminal_rules:contradictory_invalid")
    if terminal_value.get("auto_close") is not True:
        _issue(issues, "contract.terminal_rules:auto_close_required")
    if terminal_value.get("later_promotion_required") is not False:
        _issue(issues, "contract.terminal_rules:later_promotion_forbidden")

    profile = value.get("profile_lifecycle")
    _exact(
        profile,
        {"profile_id", "profile_sha256", "state", "report_sha256", "source_pointer"},
        "profile_lifecycle",
        issues,
    )
    profile_value = profile if isinstance(profile, Mapping) else {}
    if not _identifier(profile_value.get("profile_id")):
        _issue(issues, "profile_lifecycle:profile_id_invalid")
    for field in ("profile_sha256", "report_sha256"):
        sha = profile_value.get(field)
        if not isinstance(sha, str) or _SHA256.fullmatch(sha) is None:
            _issue(issues, f"profile_lifecycle:{field}_invalid")
    if profile_value.get("state") not in PROFILE_LIFECYCLE_STATES:
        _issue(issues, "profile_lifecycle:state_invalid")
    if not _text(profile_value.get("source_pointer")):
        _issue(issues, "profile_lifecycle:source_pointer_invalid")

    collection = value.get("collection")
    _exact(collection, {"status", "trials", "source_pointer"}, "collection", issues)
    collection_value = collection if isinstance(collection, Mapping) else {}
    collection_status = collection_value.get("status")
    if collection_status not in {"open", "closed", "deadline_reached"}:
        _issue(issues, "collection:status_invalid")
    if not _text(collection_value.get("source_pointer")):
        _issue(issues, "collection:source_pointer_invalid")
    trials_value = collection_value.get("trials")
    if not isinstance(trials_value, list):
        _issue(issues, "collection.trials:not_array")
        trials_value = []

    observed_ids: set[str] = set()
    trial_summaries: list[dict[str, Any]] = []
    totals = {
        condition: {
            "trial_count": 0,
            "accepted_count": 0,
            "raw_usage": _zero_raw_vector(),
            "weighted_cost_microunits": 0,
            "critical_path_ms": 0,
            "lifecycle_pass_count": 0,
            "sol_share_bps_total": 0,
        }
        for condition in ("baseline", "active")
    }
    metric_unknown = False
    active_correctness_regression_trials: list[str] = []
    active_lifecycle_regression_trials: list[str] = []
    for index, trial in enumerate(trials_value):
        path = f"collection.trials[{index}]"
        _exact(
            trial,
            {
                "trial_id",
                "ordinal",
                "condition",
                "fixture_sha256",
                "route",
                "plan_sha256",
                "binding_status",
                "evidence_tier",
                "source_binding",
                "correctness",
                "usage",
                "timing",
                "lifecycle",
                "sol_share",
                "receipt",
            },
            path,
            issues,
        )
        item = trial if isinstance(trial, Mapping) else {}
        trial_id = item.get("trial_id")
        evidence_reasons: list[str] = []
        if not _identifier(trial_id):
            _issue(issues, f"{path}:trial_id_invalid")
        elif trial_id in observed_ids:
            contradictions.append(f"duplicate_trial:{trial_id}")
        else:
            observed_ids.add(str(trial_id))
        expected = expected_by_id.get(str(trial_id))
        if expected is None:
            evidence_reasons.append("undeclared_trial")
        else:
            if item.get("ordinal") != index + 1:
                evidence_reasons.append("collection_order_mismatch")
            if item.get("ordinal") != expected.get("ordinal"):
                evidence_reasons.append("ordinal_mismatch")
            if item.get("condition") != expected.get("condition"):
                evidence_reasons.append("condition_mismatch")
        condition = item.get("condition")
        if condition not in {"baseline", "active"}:
            _issue(issues, f"{path}:condition_invalid")
            condition = "baseline"
        if item.get("fixture_sha256") != fixture_sha:
            evidence_reasons.append("fixture_mismatch")
        if item.get("plan_sha256") != plan_sha:
            evidence_reasons.append("plan_mismatch")

        route = item.get("route")
        _exact(route, {"model", "effort", "context_policy"}, f"{path}.route", issues)
        route_value = route if isinstance(route, Mapping) else {}
        expected_route = normalized_routes.get(str(condition), {})
        for field in ("model", "effort", "context_policy"):
            if not _identifier(route_value.get(field)):
                _issue(issues, f"{path}.route:{field}_invalid")
            if route_value.get(field) != expected_route.get(field):
                evidence_reasons.append(f"route_{field}_mismatch")

        binding_status = item.get("binding_status")
        if binding_status not in {"BOUND", "UNBOUND", "CONTRADICTORY"}:
            _issue(issues, f"{path}:binding_status_invalid")
        elif binding_status != "BOUND":
            evidence_reasons.append(f"binding_{str(binding_status).lower()}")
        if item.get("evidence_tier") not in {"runtime-observed", "sealed-runtime"}:
            _issue(issues, f"{path}:evidence_tier_invalid")
        elif item.get("evidence_tier") != "sealed-runtime":
            evidence_reasons.append("evidence_not_sealed_runtime")

        source_binding = item.get("source_binding")
        _exact(
            source_binding,
            {"status", "source_id", "source_sha256", "source_pointer"},
            f"{path}.source_binding",
            issues,
        )
        source_value = source_binding if isinstance(source_binding, Mapping) else {}
        if source_value.get("status") not in {"verified", "mismatch", "unknown"}:
            _issue(issues, f"{path}.source_binding:status_invalid")
        elif source_value.get("status") != "verified":
            evidence_reasons.append(f"source_binding_{source_value.get('status')}")
        if not _identifier(source_value.get("source_id")):
            _issue(issues, f"{path}.source_binding:source_id_invalid")
        source_sha = source_value.get("source_sha256")
        if not isinstance(source_sha, str) or _SHA256.fullmatch(source_sha) is None:
            _issue(issues, f"{path}.source_binding:source_sha256_invalid")
        if not _text(source_value.get("source_pointer")):
            _issue(issues, f"{path}.source_binding:source_pointer_invalid")

        correctness = item.get("correctness")
        _exact(correctness, {"status", "checks", "source_pointer"}, f"{path}.correctness", issues)
        correctness_value = correctness if isinstance(correctness, Mapping) else {}
        correctness_status = correctness_value.get("status")
        if correctness_status not in {"accepted", "rejected", "unknown"}:
            _issue(issues, f"{path}.correctness:status_invalid")
        check_results = correctness_value.get("checks")
        if not isinstance(check_results, list):
            _issue(issues, f"{path}.correctness.checks:not_array")
            check_results = []
        observed_checks: set[str] = set()
        observed_check_outcomes: list[str] = []
        for check_index, result in enumerate(check_results):
            result_path = f"{path}.correctness.checks[{check_index}]"
            _exact(result, {"check_id", "outcome", "source_pointer"}, result_path, issues)
            result_value = result if isinstance(result, Mapping) else {}
            check_id = result_value.get("check_id")
            if check_id not in check_set or check_id in observed_checks:
                evidence_reasons.append("correctness_check_set_mismatch")
            elif isinstance(check_id, str):
                observed_checks.add(check_id)
            if result_value.get("outcome") not in {"PASS", "FAIL", "UNKNOWN"}:
                _issue(issues, f"{result_path}:outcome_invalid")
            else:
                observed_check_outcomes.append(str(result_value.get("outcome")))
            if not _text(result_value.get("source_pointer")):
                _issue(issues, f"{result_path}:source_pointer_invalid")
        if observed_checks != check_set:
            evidence_reasons.append("correctness_check_set_mismatch")
        expected_correctness_status = (
            "rejected" if "FAIL" in observed_check_outcomes else
            "unknown" if "UNKNOWN" in observed_check_outcomes else
            "accepted"
        )
        if correctness_status != expected_correctness_status:
            evidence_reasons.append("correctness_summary_mismatch")
        if not _text(correctness_value.get("source_pointer")):
            _issue(issues, f"{path}.correctness:source_pointer_invalid")

        usage_fact = _raw_usage_vector(item.get("usage"), f"{path}.usage", issues)
        timing_fact = _known_scalar_fact(item.get("timing"), f"{path}.timing", issues)
        sol_share_fact = _known_scalar_fact(item.get("sol_share"), f"{path}.sol_share", issues)
        if sol_share_fact.get("status") == "known" and sol_share_fact.get("value", 0) > 10_000:
            _issue(issues, f"{path}.sol_share:value_out_of_range")

        lifecycle = item.get("lifecycle")
        _exact(lifecycle, {"status", "reason", "source_pointer"}, f"{path}.lifecycle", issues)
        lifecycle_value = lifecycle if isinstance(lifecycle, Mapping) else {}
        lifecycle_status = lifecycle_value.get("status")
        if lifecycle_status not in {"PASS", "FAIL", "UNKNOWN"}:
            _issue(issues, f"{path}.lifecycle:status_invalid")
        if lifecycle_status == "PASS" and lifecycle_value.get("reason") is not None:
            _issue(issues, f"{path}.lifecycle:pass_has_reason")
        if lifecycle_status != "PASS" and not _text(lifecycle_value.get("reason")):
            _issue(issues, f"{path}.lifecycle:reason_invalid")
        if not _text(lifecycle_value.get("source_pointer")):
            _issue(issues, f"{path}.lifecycle:source_pointer_invalid")

        receipt = item.get("receipt")
        _exact(receipt, {"sealed", "receipt_sha256", "verification", "source_pointer"}, f"{path}.receipt", issues)
        receipt_value = receipt if isinstance(receipt, Mapping) else {}
        if not isinstance(receipt_value.get("sealed"), bool):
            _issue(issues, f"{path}.receipt:sealed_invalid")
        receipt_sha = receipt_value.get("receipt_sha256")
        if not isinstance(receipt_sha, str) or _SHA256.fullmatch(receipt_sha) is None:
            _issue(issues, f"{path}.receipt:sha256_invalid")
        if receipt_value.get("verification") not in {"verified", "mismatch", "unknown"}:
            _issue(issues, f"{path}.receipt:verification_invalid")
        if receipt_value.get("sealed") is not True or receipt_value.get("verification") != "verified":
            evidence_reasons.append("receipt_not_verified")
        if not _text(receipt_value.get("source_pointer")):
            _issue(issues, f"{path}.receipt:source_pointer_invalid")

        for metric_name, fact in (
            ("usage", usage_fact),
            ("timing", timing_fact),
            ("sol_share", sol_share_fact),
        ):
            if fact.get("status") != "known":
                metric_unknown = True
                unknowns.append(
                    {
                        "trial_id": trial_id,
                        "metric": metric_name,
                        "reason": fact.get("reason"),
                        "source_pointer": fact.get("source_pointer"),
                    }
                )
        if correctness_status == "unknown":
            metric_unknown = True
            unknowns.append(
                {
                    "trial_id": trial_id,
                    "metric": "accepted_quality",
                    "reason": "correctness_unknown",
                    "source_pointer": correctness_value.get("source_pointer"),
                }
            )
        if lifecycle_status == "UNKNOWN":
            metric_unknown = True
            unknowns.append(
                {
                    "trial_id": trial_id,
                    "metric": "lifecycle_reliability",
                    "reason": lifecycle_value.get("reason"),
                    "source_pointer": lifecycle_value.get("source_pointer"),
                }
            )
        if evidence_reasons:
            contradictions.extend(f"{trial_id}:{reason}" for reason in sorted(set(evidence_reasons)))

        totals[str(condition)]["trial_count"] += 1
        if correctness_status == "accepted":
            totals[str(condition)]["accepted_count"] += 1
        elif correctness_status == "rejected" and condition == "active" and isinstance(trial_id, str):
            active_correctness_regression_trials.append(trial_id)
        if usage_fact.get("status") == "known":
            _add_raw_vector(totals[str(condition)]["raw_usage"], usage_fact)
            totals[str(condition)]["weighted_cost_microunits"] += _weighted_cost(usage_fact, weights_map)
        if timing_fact.get("status") == "known":
            totals[str(condition)]["critical_path_ms"] += int(timing_fact.get("value", 0))
        if lifecycle_status == "PASS":
            totals[str(condition)]["lifecycle_pass_count"] += 1
        elif lifecycle_status == "FAIL" and condition == "active" and isinstance(trial_id, str):
            active_lifecycle_regression_trials.append(trial_id)
        if sol_share_fact.get("status") == "known":
            totals[str(condition)]["sol_share_bps_total"] += int(sol_share_fact.get("value", 0))
        trial_summaries.append(
            {
                "trial_id": trial_id,
                "ordinal": item.get("ordinal"),
                "condition": condition,
                "binding_status": binding_status,
                "source_binding": dict(source_value),
                "correctness_status": correctness_status,
                "raw_usage": dict(usage_fact),
                "weighted_cost_microunits": (
                    _weighted_cost(usage_fact, weights_map) if usage_fact.get("status") == "known" else None
                ),
                "critical_path_ms": timing_fact.get("value"),
                "lifecycle_status": lifecycle_status,
                "sol_share_bps": sol_share_fact.get("value"),
                "receipt_sha256": receipt_sha,
                "evidence_reasons": sorted(set(evidence_reasons)),
            }
        )

    missing_trial_ids = sorted(set(expected_by_id) - observed_ids)
    extra_trial_ids = sorted(observed_ids - set(expected_by_id))
    if extra_trial_ids:
        contradictions.extend(f"undeclared_trial:{trial_id}" for trial_id in extra_trial_ids)
    incomplete = bool(missing_trial_ids or len(trials_value) != len(expected_trials))

    condition_metrics: dict[str, dict[str, Any]] = {}
    for condition in ("baseline", "active"):
        row = totals[condition]
        count = condition_counts.get(condition, 0)
        condition_metrics[condition] = {
            "trial_count": row["trial_count"],
            "accepted_quality_bps": (row["accepted_count"] * 10_000 // count) if count else None,
            "raw_usage": row["raw_usage"],
            "weighted_cost_microunits": row["weighted_cost_microunits"],
            "critical_path_ms": row["critical_path_ms"],
            "lifecycle_reliability_bps": (row["lifecycle_pass_count"] * 10_000 // count) if count else None,
            "sol_share_bps": (row["sol_share_bps_total"] // count) if count else None,
        }

    deltas: dict[str, Any] = {
        "quality_delta_bps": None,
        "raw_component_increase_bps": {dimension: None for dimension in RAW_USAGE_DIMENSIONS},
        "weighted_cost_reduction_bps": None,
        "latency_increase_bps": None,
        "lifecycle_reliability_delta_bps": None,
    }
    decision_checks: list[dict[str, Any]] = []
    complete_metrics = not incomplete and not metric_unknown and not contradictions
    if complete_metrics:
        baseline = condition_metrics["baseline"]
        active = condition_metrics["active"]
        deltas["quality_delta_bps"] = active["accepted_quality_bps"] - baseline["accepted_quality_bps"]
        for dimension in RAW_USAGE_DIMENSIONS:
            base_amount = baseline["raw_usage"][dimension]
            active_amount = active["raw_usage"][dimension]
            deltas["raw_component_increase_bps"][dimension] = _signed_bps(
                active_amount - base_amount,
                base_amount,
            )
        deltas["weighted_cost_reduction_bps"] = _signed_bps(
            baseline["weighted_cost_microunits"] - active["weighted_cost_microunits"],
            baseline["weighted_cost_microunits"],
        )
        deltas["latency_increase_bps"] = _signed_bps(
            active["critical_path_ms"] - baseline["critical_path_ms"],
            baseline["critical_path_ms"],
        )
        deltas["lifecycle_reliability_delta_bps"] = (
            active["lifecycle_reliability_bps"] - baseline["lifecycle_reliability_bps"]
        )
        if any(
            value is None
            for value in (
                deltas["weighted_cost_reduction_bps"],
                deltas["latency_increase_bps"],
                *deltas["raw_component_increase_bps"].values(),
            )
        ):
            metric_unknown = True
            unknowns.append(
                {
                    "trial_id": None,
                    "metric": "relative_delta",
                    "reason": "zero_baseline_denominator",
                    "source_pointer": contract_value.get("source_pointer"),
                }
            )
            complete_metrics = False

    if complete_metrics:
        decision_checks.append(
            {
                "metric": "accepted_quality",
                "actual_bps": deltas["quality_delta_bps"],
                "operator": ">=",
                "threshold_bps": decision_value.get("minimum_quality_delta_bps"),
                "passed": deltas["quality_delta_bps"] >= decision_value.get("minimum_quality_delta_bps"),
            }
        )
        for dimension in RAW_USAGE_DIMENSIONS:
            actual = deltas["raw_component_increase_bps"][dimension]
            threshold = raw_increase_value.get(dimension)
            decision_checks.append(
                {
                    "metric": dimension,
                    "actual_bps": actual,
                    "operator": "<=",
                    "threshold_bps": threshold,
                    "passed": actual <= threshold,
                }
            )
        decision_checks.extend(
            [
                {
                    "metric": "weighted_cost",
                    "actual_bps": deltas["weighted_cost_reduction_bps"],
                    "operator": ">=",
                    "threshold_bps": decision_value.get("minimum_weighted_cost_reduction_bps"),
                    "passed": deltas["weighted_cost_reduction_bps"] >= decision_value.get("minimum_weighted_cost_reduction_bps"),
                },
                {
                    "metric": "critical_path_latency",
                    "actual_bps": deltas["latency_increase_bps"],
                    "operator": "<=",
                    "threshold_bps": decision_value.get("maximum_latency_increase_bps"),
                    "passed": deltas["latency_increase_bps"] <= decision_value.get("maximum_latency_increase_bps"),
                },
                {
                    "metric": "lifecycle_reliability",
                    "actual_bps": deltas["lifecycle_reliability_delta_bps"],
                    "operator": ">=",
                    "threshold_bps": decision_value.get("minimum_lifecycle_reliability_delta_bps"),
                    "passed": deltas["lifecycle_reliability_delta_bps"] >= decision_value.get("minimum_lifecycle_reliability_delta_bps"),
                },
            ]
        )

    if issues:
        state = "INCONCLUSIVE"
        status = "FAIL"
        terminal = False
        outcome = None
        next_event = "repair_provider_free_contract"
    elif authority_status != "granted":
        state = "AUTHORITY_REQUIRED"
        status = "PASS"
        terminal = False
        outcome = None
        next_event = "exact_evaluation_authority"
    elif incomplete and collection_status == "open":
        state = "COLLECTING"
        status = "PASS"
        terminal = False
        outcome = None
        next_event = "next_declared_trial"
    elif incomplete or contradictions or metric_unknown:
        state = "INCONCLUSIVE"
        status = "PASS"
        terminal = True
        outcome = "INCONCLUSIVE"
        next_event = "terminal"
    elif all(check["passed"] for check in decision_checks):
        state = "EFFICIENCY_PROVEN"
        status = "PASS"
        terminal = True
        outcome = "EFFICIENCY_PROVEN"
        next_event = "terminal"
    else:
        state = "EFFICIENCY_NOT_PROVEN"
        status = "PASS"
        terminal = True
        outcome = "EFFICIENCY_NOT_PROVEN"
        next_event = "terminal"

    if previous_state in EFFICIENCY_OUTCOMES:
        if state != previous_state:
            _issue(issues, "history:terminal_outcome_immutable")
            status = "FAIL"
        state = previous_state
        terminal = True
        outcome = previous_state
        next_event = "terminal"

    correctness_regression = bool(active_correctness_regression_trials)
    lifecycle_regression = bool(active_lifecycle_regression_trials)
    suspension_signal = {
        "required": correctness_regression or lifecycle_regression,
        "profile_id": profile_value.get("profile_id"),
        "profile_sha256": profile_value.get("profile_sha256"),
        "kinds": sorted(
            (["correctness"] if correctness_regression else [])
            + (["lifecycle"] if lifecycle_regression else [])
        ),
        "trial_ids": sorted(
            set(active_correctness_regression_trials + active_lifecycle_regression_trials)
        ),
        "source_evaluation_id": value.get("evaluation_id"),
        "source_contract_sha256": contract_sha,
    }
    transition = None
    if not issues and state != previous_state:
        transition_pointers = sorted(
            {
                str(pointer)
                for pointer in (
                    contract_value.get("source_pointer"),
                    collection_value.get("source_pointer"),
                    profile_value.get("source_pointer"),
                    *[
                        ((trial.get("receipt") or {}).get("source_pointer"))
                        for trial in trials_value
                        if isinstance(trial, Mapping)
                    ],
                )
                if _text(pointer)
            }
        )
        transition_core = {
            "event_id": f"evaluation-transition-{previous_seq + 1}",
            "seq": previous_seq + 1,
            "from_state": previous_state,
            "to_state": state,
            "reason": (
                "exact_authority_required" if state == "AUTHORITY_REQUIRED" else
                "finite_collection_in_progress" if state == "COLLECTING" else
                "finite_evaluation_auto_closed"
            ),
            "contract_sha256": contract_sha,
            "evidence_pointers": transition_pointers,
        }
        transition = {**transition_core, "event_sha256": _sha256(transition_core)}

    sealed_inputs_sha = _sha256(
        {
            "contract": contract_value,
            "history": history,
            "collection": collection_value,
            "profile_lifecycle": profile_value,
        }
    )
    terminal_seal = None
    if terminal and outcome is not None:
        terminal_core = {
            "schema": "orch-dork/efficiency-terminal-seal/v1",
            "evaluation_id": value.get("evaluation_id"),
            "contract_sha256": contract_sha,
            "history_sha256": history_sha,
            "transition_sha256": transition.get("event_sha256") if transition else None,
            "sealed_inputs_sha256": sealed_inputs_sha,
            "outcome": outcome,
            "condition_metrics_sha256": _sha256(condition_metrics),
            "deltas_sha256": _sha256(deltas),
            "unknowns_sha256": _sha256(sorted(unknowns, key=lambda row: _canonical(row))),
            "contradictions_sha256": _sha256(sorted(set(contradictions))),
            "profile_suspension_required": suspension_signal["required"],
        }
        terminal_seal = {**terminal_core, "seal_sha256": _sha256(terminal_core)}

    registry_projection = {
        "kind": "efficiency_evaluation",
        "evaluation_id": value.get("evaluation_id"),
        "contract_sha256": contract_sha,
        "state": state,
        "terminal_outcome": outcome,
        "history_sha256": history_sha,
        "historical_transition_count": len(history),
        "transition": transition,
        "trial_summaries": trial_summaries,
        "condition_metrics": condition_metrics,
        "deltas": deltas,
        "unknowns": sorted(unknowns, key=lambda row: _canonical(row)),
        "contradictions": sorted(set(contradictions)),
        "profile_suspension_signal": suspension_signal,
        "source_authority": "efficiency_evaluation_report",
        "rebuildable": True,
    }
    core = {
        "schema": EFFICIENCY_EVALUATION_REPORT_SCHEMA,
        "status": status,
        "evaluation_id": value.get("evaluation_id"),
        "contract_version": contract_value.get("version"),
        "contract_sha256": contract_sha,
        "sealed_inputs_sha256": sealed_inputs_sha,
        "state": state,
        "previous_state": previous_state,
        "transition": transition,
        "history_sha256": history_sha,
        "historical_transition_count": len(history),
        "terminal": terminal,
        "terminal_outcome": outcome,
        "terminal_seal": terminal_seal,
        "expected_trial_count": len(expected_trials),
        "observed_trial_count": len(trials_value),
        "missing_trial_ids": missing_trial_ids,
        "extra_trial_ids": extra_trial_ids,
        "trial_summaries": trial_summaries,
        "condition_metrics": condition_metrics,
        "deltas": deltas,
        "decision_checks": decision_checks,
        "primary_metrics": sorted(primary),
        "secondary_metrics": secondary,
        "model_share_has_threshold": False,
        "cost_weights_version": weights_value.get("version"),
        "unknowns": sorted(unknowns, key=lambda row: _canonical(row)),
        "contradictions": sorted(set(contradictions)),
        "profile_state_preserved": profile_value.get("state"),
        "efficiency_controls_safety_activation": False,
        "profile_suspension_signal": suspension_signal,
        "authority_inferred": False,
        "later_promotion_required": False,
        "automatic_retries": 0,
        "automatic_replacements": 0,
        "automatic_fallbacks": 0,
        "next_event": next_event,
        "issues": sorted(issues),
        "registry_projection": registry_projection,
        "evidence_tier": "submitted-fixture",
    }
    return {**core, "report_sha256": _sha256(core)}


def _budget_amounts(value: Any, path: str, issues: list[str]) -> dict[str, dict[str, Any]]:
    _exact(value, set(LIMIT_DIMENSIONS), path, issues)
    source = value if isinstance(value, Mapping) else {}
    result: dict[str, dict[str, Any]] = {}
    for dimension in LIMIT_DIMENSIONS:
        fact = source.get(dimension)
        _exact(fact, {"status", "value", "reason"}, f"{path}.{dimension}", issues)
        item = fact if isinstance(fact, Mapping) else {}
        status = item.get("status")
        number = item.get("value")
        reason = item.get("reason")
        if status == "known":
            if type(number) is not int or number < 0:
                _issue(issues, f"{path}.{dimension}:value_invalid")
            if reason is not None:
                _issue(issues, f"{path}.{dimension}:known_has_reason")
        elif status == "unknown":
            if number is not None:
                _issue(issues, f"{path}.{dimension}:unknown_has_value")
            if not _identifier(reason):
                _issue(issues, f"{path}.{dimension}:unknown_reason_invalid")
        else:
            _issue(issues, f"{path}.{dimension}:status_invalid")
        result[dimension] = {
            "status": status,
            "value": number,
            "reason": reason,
        }
    return result


def _budget_vector(value: Any, path: str, issues: list[str]) -> dict[str, int]:
    _exact(value, set(LIMIT_DIMENSIONS), path, issues)
    source = value if isinstance(value, Mapping) else {}
    result: dict[str, int] = {}
    for dimension in LIMIT_DIMENSIONS:
        number = source.get(dimension)
        if type(number) is not int or number < 0:
            _issue(issues, f"{path}.{dimension}:invalid")
            number = 0
        result[dimension] = number
    return result


def evaluate_budget_program(program: Any) -> dict[str, Any]:
    """Reconcile runtime-observed consumption and reserve downstream work.

    The ledger is pure and provider-free. A complete runtime window makes an
    absent event an observed zero; an incomplete or submitted window keeps
    every affected dimension unknown. Unknown is never coerced to zero.
    """

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(
        program,
        {
            "schema",
            "program_id",
            "plan_sha256",
            "budget_policy",
            "runtime_window",
            "runtime_records",
            "admission_requests",
        },
        "budget_program",
        issues,
    )
    if value.get("schema") != BUDGET_PROGRAM_SCHEMA:
        _issue(issues, "budget_program:schema_invalid")
    if not _identifier(value.get("program_id")):
        _issue(issues, "budget_program:id_invalid")
    plan_sha = value.get("plan_sha256")
    if not isinstance(plan_sha, str) or _SHA256.fullmatch(plan_sha) is None:
        _issue(issues, "budget_program:plan_sha256_invalid")

    policy = value.get("budget_policy")
    _exact(policy, {"limits", "reservation_required"}, "budget_policy", issues)
    policy_value = policy if isinstance(policy, Mapping) else {}
    limits = _budget_vector(policy_value.get("limits"), "budget_policy.limits", issues)
    if policy_value.get("reservation_required") is not True:
        _issue(issues, "budget_policy:reservation_not_required")

    window = value.get("runtime_window")
    _exact(
        window,
        {"status", "evidence_tier", "source_pointer", "completed_node_ids"},
        "runtime_window",
        issues,
    )
    window_value = window if isinstance(window, Mapping) else {}
    window_status = window_value.get("status")
    if window_status not in {"complete", "incomplete"}:
        _issue(issues, "runtime_window:status_invalid")
    trusted_window = window_value.get("evidence_tier") in {
        "runtime-observed",
        "sealed-runtime",
    }
    if not trusted_window and window_value.get("evidence_tier") != "submitted":
        _issue(issues, "runtime_window:evidence_tier_invalid")
    if not _text(window_value.get("source_pointer")):
        _issue(issues, "runtime_window:source_pointer_invalid")
    completed_nodes = set(
        _string_list(
            window_value.get("completed_node_ids"),
            "runtime_window.completed_node_ids",
            issues,
        )
    )

    consumed_values = {dimension: 0 for dimension in LIMIT_DIMENSIONS}
    unknown_reasons: dict[str, set[str]] = {
        dimension: set() for dimension in LIMIT_DIMENSIONS
    }
    if window_status != "complete":
        for dimension in LIMIT_DIMENSIONS:
            unknown_reasons[dimension].add("runtime_window_incomplete")
    if not trusted_window:
        for dimension in LIMIT_DIMENSIONS:
            unknown_reasons[dimension].add("runtime_evidence_untrusted")

    records = value.get("runtime_records")
    if not isinstance(records, list):
        _issue(issues, "runtime_records:not_array")
        records = []
    record_ids: set[str] = set()
    hosted_generation_count = 0
    rejected_local_replay_count = 0
    normalized_records: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        path = f"runtime_records[{index}]"
        _exact(
            record,
            {
                "record_id",
                "node_id",
                "kind",
                "evidence_tier",
                "source_pointer",
                "amounts",
            },
            path,
            issues,
        )
        item = record if isinstance(record, Mapping) else {}
        record_id = item.get("record_id")
        if not _identifier(record_id) or record_id in record_ids:
            _issue(issues, f"{path}:record_id_invalid")
        else:
            record_ids.add(record_id)
        if item.get("node_id") is not None and not _identifier(item.get("node_id")):
            _issue(issues, f"{path}:node_id_invalid")
        kind = item.get("kind")
        if kind not in {
            "hosted_generation",
            "rejected_local_replay",
            "controller_turn",
            "child_lifecycle",
            "wall_interval",
        }:
            _issue(issues, f"{path}:kind_invalid")
        tier = item.get("evidence_tier")
        trusted_record = tier in {"runtime-observed", "sealed-runtime"}
        if not trusted_record and tier != "submitted":
            _issue(issues, f"{path}:evidence_tier_invalid")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")
        amounts = _budget_amounts(item.get("amounts"), f"{path}.amounts", issues)
        if kind == "hosted_generation":
            hosted_generation_count += 1
            hosted_fact = amounts["hosted_calls"]
            if hosted_fact["status"] == "known" and hosted_fact["value"] < 1:
                _issue(issues, f"{path}:hosted_generation_without_call")
        elif kind == "rejected_local_replay":
            rejected_local_replay_count += 1
            hosted_fact = amounts["hosted_calls"]
            if hosted_fact["status"] == "known" and hosted_fact["value"] != 0:
                _issue(issues, f"{path}:local_replay_counted_as_hosted")
        for dimension, fact in amounts.items():
            if not trusted_record:
                unknown_reasons[dimension].add("runtime_record_untrusted")
            elif fact["status"] == "unknown":
                unknown_reasons[dimension].add(str(fact["reason"]))
            elif dimension in PEAK_DIMENSIONS:
                consumed_values[dimension] = max(
                    consumed_values[dimension], int(fact["value"])
                )
            else:
                consumed_values[dimension] += int(fact["value"])
        normalized_records.append(dict(item))

    requests = value.get("admission_requests")
    if not isinstance(requests, list):
        _issue(issues, "admission_requests:not_array")
        requests = []
    request_ids: set[str] = set()
    parsed_requests: list[tuple[str, list[str], dict[str, int]]] = []
    for index, request in enumerate(requests):
        path = f"admission_requests[{index}]"
        _exact(request, {"node_id", "dependencies", "reservation"}, path, issues)
        item = request if isinstance(request, Mapping) else {}
        node_id = item.get("node_id")
        if not _identifier(node_id) or node_id in request_ids:
            _issue(issues, f"{path}:node_id_invalid")
            node_id = f"<invalid-{index}>"
        else:
            request_ids.add(str(node_id))
        dependencies = _string_list(item.get("dependencies"), f"{path}.dependencies", issues)
        reservation = _budget_vector(item.get("reservation"), f"{path}.reservation", issues)
        parsed_requests.append((str(node_id), dependencies, reservation))

    consumed: dict[str, dict[str, Any]] = {}
    for dimension in LIMIT_DIMENSIONS:
        reasons = sorted(unknown_reasons[dimension])
        consumed[dimension] = (
            {"status": "unknown", "value": None, "reasons": reasons}
            if reasons
            else {"status": "known", "value": consumed_values[dimension], "reasons": []}
        )

    reserved = {dimension: 0 for dimension in LIMIT_DIMENSIONS}
    admitted: set[str] = set()
    rejected: set[str] = set()
    decisions: list[dict[str, Any]] = []
    for node_id, dependencies, reservation in parsed_requests:
        reasons: list[str] = []
        for dependency in dependencies:
            if dependency in rejected:
                reasons.append(f"dependency_not_started:{dependency}")
            elif dependency not in completed_nodes and dependency not in admitted:
                reasons.append(f"dependency_unavailable:{dependency}")
        for dimension in LIMIT_DIMENSIONS:
            fact = consumed[dimension]
            if fact["status"] != "known":
                reasons.append(f"budget_unknown:{dimension}")
                continue
            if dimension in PEAK_DIMENSIONS:
                projected = max(
                    int(fact["value"]), reserved[dimension], reservation[dimension]
                )
            else:
                projected = int(fact["value"]) + reserved[dimension] + reservation[dimension]
            if projected > limits[dimension]:
                reasons.append(f"budget_exhausted:{dimension}")
        if reasons:
            rejected.add(node_id)
            decisions.append(
                {
                    "node_id": node_id,
                    "status": "NOT_STARTED",
                    "reservation": reservation,
                    "reasons": sorted(set(reasons)),
                }
            )
            continue
        admitted.add(node_id)
        for dimension in LIMIT_DIMENSIONS:
            if dimension in PEAK_DIMENSIONS:
                reserved[dimension] = max(reserved[dimension], reservation[dimension])
            else:
                reserved[dimension] += reservation[dimension]
        decisions.append(
            {
                "node_id": node_id,
                "status": "RESERVED",
                "reservation": reservation,
                "reasons": [],
            }
        )

    remaining: dict[str, dict[str, Any]] = {}
    for dimension in LIMIT_DIMENSIONS:
        fact = consumed[dimension]
        if fact["status"] != "known":
            remaining[dimension] = {
                "status": "unknown",
                "value": None,
                "reasons": list(fact["reasons"]),
            }
            continue
        if dimension in PEAK_DIMENSIONS:
            committed = max(int(fact["value"]), reserved[dimension])
        else:
            committed = int(fact["value"]) + reserved[dimension]
        remaining[dimension] = {
            "status": "known",
            "value": max(0, limits[dimension] - committed),
            "reasons": [],
        }

    unknown_dimensions = sorted(
        dimension for dimension, fact in consumed.items() if fact["status"] == "unknown"
    )
    exhausted_dimensions = sorted(
        {
            reason.split(":", 1)[1]
            for decision in decisions
            for reason in decision["reasons"]
            if reason.startswith("budget_exhausted:")
        }
    )
    if issues:
        status = "FAIL"
    elif unknown_dimensions:
        status = "BUDGET_UNKNOWN"
    elif any(decision["status"] == "NOT_STARTED" for decision in decisions):
        status = "BUDGET_EXHAUSTED"
    else:
        status = "PASS"
    core = {
        "schema": BUDGET_REPORT_SCHEMA,
        "status": status,
        "program_id": value.get("program_id"),
        "plan_sha256": plan_sha,
        "limits": limits,
        "consumed": consumed,
        "reserved": reserved,
        "remaining": remaining,
        "admission_decisions": decisions,
        "hosted_generation_count": hosted_generation_count,
        "rejected_local_replay_count": rejected_local_replay_count,
        "unknown_dimensions": unknown_dimensions,
        "exhausted_dimensions": exhausted_dimensions,
        "issues": sorted(issues),
        "runtime_record_count": len(normalized_records),
        "automatic_retries": 0,
        "automatic_replacements": 0,
        "automatic_fallbacks": 0,
        "evidence_tier": (
            "runtime-observed" if trusted_window and window_status == "complete" else "submitted"
        ),
    }
    return {**core, "receipt_sha256": _sha256(core)}


def evaluate_recovery_program(program: Any) -> dict[str, Any]:
    """Evaluate append-only cancellation, cleanup, and separate recovery authority."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(
        program,
        {
            "schema",
            "program_id",
            "plan_identity",
            "process_group",
            "events",
            "cleanup_observation",
            "recovery_request",
            "persisted_usage",
            "persisted_task_ids",
        },
        "recovery_program",
        issues,
    )
    if value.get("schema") != RECOVERY_PROGRAM_SCHEMA:
        _issue(issues, "recovery_program:schema_invalid")
    if not _identifier(value.get("program_id")):
        _issue(issues, "recovery_program:id_invalid")

    identity = value.get("plan_identity")
    _exact(
        identity,
        {"plan_id", "plan_sha256", "authority_id"},
        "plan_identity",
        issues,
    )
    identity_value = identity if isinstance(identity, Mapping) else {}
    if not _identifier(identity_value.get("plan_id")):
        _issue(issues, "plan_identity:plan_id_invalid")
    plan_sha = identity_value.get("plan_sha256")
    if not isinstance(plan_sha, str) or _SHA256.fullmatch(plan_sha) is None:
        _issue(issues, "plan_identity:sha256_invalid")
    if not _identifier(identity_value.get("authority_id")):
        _issue(issues, "plan_identity:authority_id_invalid")

    process_group = value.get("process_group")
    _exact(
        process_group,
        {"process_group_id", "owned_process_ids"},
        "process_group",
        issues,
    )
    process_value = process_group if isinstance(process_group, Mapping) else {}
    process_group_id = process_value.get("process_group_id")
    if not _identifier(process_group_id):
        _issue(issues, "process_group:id_invalid")
    owned_process_ids = set(
        _string_list(
            process_value.get("owned_process_ids"),
            "process_group.owned_process_ids",
            issues,
        )
    )

    events = value.get("events")
    if not isinstance(events, list):
        _issue(issues, "events:not_array")
        events = []
    if not events:
        _issue(issues, "events:empty")
    allowed_events = {
        "cancel.requested",
        "timeout.observed",
        "process.signal",
        "process.exited",
    }
    sequences: list[int] = []
    cancellation_kinds: list[str] = []
    normalized_events: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        path = f"events[{index}]"
        _exact(
            event,
            {
                "seq",
                "type",
                "node_id",
                "process_group_id",
                "process_id",
                "status",
                "source_pointer",
            },
            path,
            issues,
        )
        item = event if isinstance(event, Mapping) else {}
        seq = item.get("seq")
        if type(seq) is not int or seq < 1:
            _issue(issues, f"{path}:seq_invalid")
        else:
            sequences.append(seq)
        event_type = item.get("type")
        if event_type not in allowed_events:
            _issue(issues, f"{path}:type_invalid")
        elif event_type in {"cancel.requested", "timeout.observed"}:
            cancellation_kinds.append(str(event_type))
        if not _identifier(item.get("node_id")):
            _issue(issues, f"{path}:node_id_invalid")
        if item.get("process_group_id") != process_group_id:
            _issue(issues, f"{path}:process_group_mismatch")
        process_id = item.get("process_id")
        if event_type in {"process.signal", "process.exited"}:
            if process_id not in owned_process_ids:
                _issue(issues, f"{path}:process_not_owned")
        elif process_id is not None:
            _issue(issues, f"{path}:unexpected_process_id")
        if not _identifier(item.get("status")):
            _issue(issues, f"{path}:status_invalid")
        if not _text(item.get("source_pointer")):
            _issue(issues, f"{path}:source_pointer_invalid")
        normalized_events.append(dict(item))
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
        _issue(issues, "events:sequence_not_strict")
    if len(cancellation_kinds) != 1:
        _issue(issues, f"events:terminal_trigger_count:{len(cancellation_kinds)}")

    cleanup = value.get("cleanup_observation")
    _exact(
        cleanup,
        {"evidence_tier", "source_pointer", "forced_termination", "resources"},
        "cleanup_observation",
        issues,
    )
    cleanup_value = cleanup if isinstance(cleanup, Mapping) else {}
    cleanup_tier = cleanup_value.get("evidence_tier")
    cleanup_trusted = cleanup_tier in {"runtime-observed", "sealed-runtime"}
    if not cleanup_trusted and cleanup_tier != "submitted":
        _issue(issues, "cleanup_observation:evidence_tier_invalid")
    if not _text(cleanup_value.get("source_pointer")):
        _issue(issues, "cleanup_observation:source_pointer_invalid")
    if not isinstance(cleanup_value.get("forced_termination"), bool):
        _issue(issues, "cleanup_observation:forced_termination_invalid")
    resources = cleanup_value.get("resources")
    _exact(resources, set(CLEANUP_RESOURCES), "cleanup_observation.resources", issues)
    resource_value = resources if isinstance(resources, Mapping) else {}
    cleanup_facts: dict[str, dict[str, Any]] = {}
    for resource in CLEANUP_RESOURCES:
        fact = resource_value.get(resource)
        _exact(fact, {"status", "source_pointer"}, f"cleanup.{resource}", issues)
        fact_value = fact if isinstance(fact, Mapping) else {}
        status = fact_value.get("status")
        if status not in {"clean", "dirty", "unknown"}:
            _issue(issues, f"cleanup.{resource}:status_invalid")
        if not _text(fact_value.get("source_pointer")):
            _issue(issues, f"cleanup.{resource}:source_pointer_invalid")
        cleanup_facts[resource] = dict(fact_value)

    recovery = value.get("recovery_request")
    _exact(
        recovery,
        {
            "status",
            "new_plan_id",
            "predecessor_plan_sha256",
            "policy_version",
            "authority",
        },
        "recovery_request",
        issues,
    )
    recovery_value = recovery if isinstance(recovery, Mapping) else {}
    recovery_status = recovery_value.get("status")
    recovery_permitted = False
    if recovery_status == "none":
        if any(
            recovery_value.get(field) is not None
            for field in (
                "new_plan_id",
                "predecessor_plan_sha256",
                "policy_version",
                "authority",
            )
        ):
            _issue(issues, "recovery_request:none_has_values")
    elif recovery_status == "requested":
        new_plan_id = recovery_value.get("new_plan_id")
        if not _identifier(new_plan_id) or new_plan_id == identity_value.get("plan_id"):
            _issue(issues, "recovery_request:new_identity_invalid")
        if recovery_value.get("predecessor_plan_sha256") != plan_sha:
            _issue(issues, "recovery_request:predecessor_mismatch")
        if not _identifier(recovery_value.get("policy_version")):
            _issue(issues, "recovery_request:policy_version_invalid")
        authority = recovery_value.get("authority")
        _exact(
            authority,
            {"authority_id", "status", "scope"},
            "recovery_request.authority",
            issues,
        )
        authority_value = authority if isinstance(authority, Mapping) else {}
        if authority_value.get("status") != "granted":
            _issue(issues, "recovery_request:authority_not_granted")
        if authority_value.get("scope") != "recovery":
            _issue(issues, "recovery_request:authority_scope_invalid")
        if not _identifier(authority_value.get("authority_id")):
            _issue(issues, "recovery_request:authority_id_invalid")
        recovery_permitted = not any(
            item.startswith("recovery_request:") for item in issues
        )
    else:
        _issue(issues, "recovery_request:status_invalid")

    usage_issues: list[str] = []
    usage = _usage_fact(value.get("persisted_usage"), "persisted_usage", usage_issues)
    issues.extend(item for item in usage_issues if item not in issues)
    persisted_task_ids = _string_list(
        value.get("persisted_task_ids"), "persisted_task_ids", issues
    )
    unknown_cleanup = sorted(
        resource
        for resource, fact in cleanup_facts.items()
        if fact.get("status") == "unknown"
    )
    dirty_cleanup = sorted(
        resource
        for resource, fact in cleanup_facts.items()
        if fact.get("status") == "dirty"
    )
    if not cleanup_trusted:
        unknown_cleanup = sorted(set([*unknown_cleanup, *CLEANUP_RESOURCES]))
    recovery_permitted = (
        recovery_permitted
        and cleanup_trusted
        and not unknown_cleanup
        and not dirty_cleanup
    )
    if issues:
        status = "FAIL"
    elif dirty_cleanup:
        status = "CLEANUP_FAILED"
    elif unknown_cleanup:
        status = "RECOVERY_REQUIRED"
    else:
        status = "CANCELLED_CLEAN" if cancellation_kinds == ["cancel.requested"] else "TIMED_OUT_CLEAN"
    core = {
        "schema": RECOVERY_REPORT_SCHEMA,
        "status": status,
        "program_id": value.get("program_id"),
        "plan_identity": dict(identity_value),
        "process_group": dict(process_value),
        "terminal_trigger": cancellation_kinds[0] if len(cancellation_kinds) == 1 else None,
        "events": normalized_events,
        "events_sha256": _sha256(normalized_events),
        "cleanup": cleanup_facts,
        "cleanup_unknown": unknown_cleanup,
        "cleanup_dirty": dirty_cleanup,
        "forced_termination_observed": cleanup_value.get("forced_termination"),
        "termination_is_cleanup": False,
        "recovery_request": dict(recovery_value),
        "recovery_permitted": recovery_permitted,
        "new_attempt_required": recovery_status == "requested",
        "persisted_usage": usage,
        "persisted_task_ids": persisted_task_ids,
        "usage_rolled_back": False,
        "tasks_rolled_back": False,
        "issues": sorted(issues),
        "retries_permitted": False,
        "replacements_permitted": False,
        "fallbacks_permitted": False,
        "evidence_tier": cleanup_tier,
    }
    return {**core, "receipt_sha256": _sha256(core)}


def _graph_depth(node_ids: Sequence[str], edges: Sequence[Mapping[str, Any]]) -> int:
    predecessors = {node_id: [] for node_id in node_ids}
    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")
        if source in predecessors and target in predecessors:
            predecessors[target].append(source)
    depths = {node_id: 1 for node_id in node_ids}
    remaining = set(node_ids)
    while remaining:
        ready = sorted(
            node_id
            for node_id in remaining
            if all(predecessor not in remaining for predecessor in predecessors[node_id])
        )
        if not ready:
            return 0
        for node_id in ready:
            if predecessors[node_id]:
                depths[node_id] = 1 + max(depths[item] for item in predecessors[node_id])
            remaining.remove(node_id)
    return max(depths.values(), default=0)


def qualify_execution_graph(program: Any) -> dict[str, Any]:
    """Validate and qualify one finite dependency graph from closed evidence."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(
        program,
        {
            "schema",
            "graph_id",
            "plan_sha256",
            "nodes",
            "edges",
            "joins",
            "bounds",
            "authority",
            "integration",
            "observation",
        },
        "graph",
        issues,
    )
    if value.get("schema") != GRAPH_PROGRAM_SCHEMA:
        _issue(issues, "graph:schema_invalid")
    if not _identifier(value.get("graph_id")):
        _issue(issues, "graph:id_invalid")
    plan_sha = value.get("plan_sha256")
    if not isinstance(plan_sha, str) or _SHA256.fullmatch(plan_sha) is None:
        _issue(issues, "graph:plan_sha256_invalid")

    nodes_value = value.get("nodes")
    if not isinstance(nodes_value, list):
        _issue(issues, "nodes:not_array")
        nodes_value = []
    node_ids: list[str] = []
    nodes: dict[str, Mapping[str, Any]] = {}
    for index, node in enumerate(nodes_value):
        path = f"nodes[{index}]"
        _exact(
            node,
            {"id", "objective", "owned_resources", "verification", "optional"},
            path,
            issues,
        )
        if not isinstance(node, Mapping):
            continue
        node_id = node.get("id")
        if not _identifier(node_id) or node_id in nodes:
            _issue(issues, f"{path}:id_invalid_or_duplicate")
            continue
        node_ids.append(str(node_id))
        nodes[str(node_id)] = node
        if not _text(node.get("objective")):
            _issue(issues, f"{path}:objective_invalid")
        _string_list(node.get("owned_resources"), f"{path}.owned_resources", issues, empty=False)
        _string_list(node.get("verification"), f"{path}.verification", issues, empty=False)
        if not isinstance(node.get("optional"), bool):
            _issue(issues, f"{path}:optional_invalid")
    if not node_ids:
        _issue(issues, "nodes:empty")

    edges_value = value.get("edges")
    if not isinstance(edges_value, list):
        _issue(issues, "edges:not_array")
        edges_value = []
    edge_ids: list[str] = []
    edges: dict[str, Mapping[str, Any]] = {}
    dependency_map = {node_id: [] for node_id in node_ids}
    for index, edge in enumerate(edges_value):
        path = f"edges[{index}]"
        _exact(edge, {"id", "type", "source", "target"}, path, issues)
        if not isinstance(edge, Mapping):
            continue
        edge_id = edge.get("id")
        if not _identifier(edge_id) or edge_id in edges:
            _issue(issues, f"{path}:id_invalid_or_duplicate")
            continue
        edge_ids.append(str(edge_id))
        edges[str(edge_id)] = edge
        if edge.get("type") not in {"dependency", "artifact", "release"}:
            _issue(issues, f"{path}:type_invalid")
        source = edge.get("source")
        target = edge.get("target")
        if source not in nodes:
            _issue(issues, f"{path}:source_unknown")
        if target not in nodes:
            _issue(issues, f"{path}:target_unknown")
        if source == target:
            _issue(issues, f"{path}:self_edge")
        if source in nodes and target in nodes:
            dependency_map[str(target)].append(str(source))
    cycle = _cycle_nodes(dependency_map)
    if cycle:
        _issue(issues, "graph:cycle:" + ",".join(cycle))
    computed_depth = _graph_depth(node_ids, list(edges.values()))

    bounds = value.get("bounds")
    _exact(
        bounds,
        {"node_count", "max_depth", "max_concurrency", "max_turns"},
        "bounds",
        issues,
    )
    bounds_value = bounds if isinstance(bounds, Mapping) else {}
    for field in ("node_count", "max_depth", "max_concurrency", "max_turns"):
        number = bounds_value.get(field)
        if type(number) is not int or number < 1:
            _issue(issues, f"bounds:{field}_invalid")
    if bounds_value.get("node_count") != len(nodes):
        _issue(issues, "bounds:node_count_mismatch")
    if type(bounds_value.get("max_depth")) is int and computed_depth > bounds_value["max_depth"]:
        _issue(issues, "bounds:depth_exceeded")

    authority = value.get("authority")
    _exact(
        authority,
        {"authority_id", "status", "authorized_node_ids", "authorized_edge_ids"},
        "authority",
        issues,
    )
    authority_value = authority if isinstance(authority, Mapping) else {}
    if not _identifier(authority_value.get("authority_id")):
        _issue(issues, "authority:id_invalid")
    if authority_value.get("status") != "granted":
        _issue(issues, "authority:not_granted")
    authorized_nodes = set(
        _string_list(authority_value.get("authorized_node_ids"), "authority.authorized_node_ids", issues)
    )
    authorized_edges = set(
        _string_list(authority_value.get("authorized_edge_ids"), "authority.authorized_edge_ids", issues)
    )
    if authorized_nodes != set(node_ids):
        _issue(issues, "authority:node_set_mismatch")
    if authorized_edges != set(edge_ids):
        _issue(issues, "authority:edge_set_mismatch")

    integration = value.get("integration")
    _exact(integration, {"profile", "strategy"}, "integration", issues)
    integration_value = integration if isinstance(integration, Mapping) else {}
    profile = integration_value.get("profile")
    strategy = integration_value.get("strategy")
    if profile == "first_completed_worker/v1":
        if strategy != "first_completed_worker":
            _issue(issues, "integration:first_completed_strategy_invalid")
    elif profile == "bounded_dag/v1":
        if strategy != "join_target":
            _issue(issues, "integration:dag_strategy_invalid")
    else:
        _issue(issues, "integration:profile_invalid")

    joins_value = value.get("joins")
    if not isinstance(joins_value, list):
        _issue(issues, "joins:not_array")
        joins_value = []
    joins: dict[str, dict[str, Any]] = {}
    for index, join in enumerate(joins_value):
        path = f"joins[{index}]"
        _exact(
            join,
            {"id", "target_node_id", "input_edge_ids", "mode", "quorum"},
            path,
            issues,
        )
        if not isinstance(join, Mapping):
            continue
        join_id = join.get("id")
        if not _identifier(join_id) or join_id in joins:
            _issue(issues, f"{path}:id_invalid_or_duplicate")
            continue
        target = join.get("target_node_id")
        if target not in nodes:
            _issue(issues, f"{path}:target_unknown")
        inputs = _string_list(join.get("input_edge_ids"), f"{path}.input_edge_ids", issues, empty=False)
        for edge_id in inputs:
            if edge_id not in edges:
                _issue(issues, f"{path}:input_edge_unknown:{edge_id}")
            elif edges[edge_id].get("target") != target:
                _issue(issues, f"{path}:input_target_mismatch:{edge_id}")
        mode = join.get("mode")
        quorum = join.get("quorum")
        if mode == "all":
            if quorum != len(inputs):
                _issue(issues, f"{path}:all_quorum_mismatch")
        elif mode == "quorum":
            if type(quorum) is not int or not 1 <= quorum <= len(inputs):
                _issue(issues, f"{path}:quorum_invalid")
        else:
            _issue(issues, f"{path}:mode_invalid")
        joins[str(join_id)] = {
            "id": str(join_id),
            "target_node_id": target,
            "input_edge_ids": inputs,
            "mode": mode,
            "quorum": quorum,
        }

    observation = value.get("observation")
    _exact(
        observation,
        {
            "node_results",
            "join_results",
            "release_results",
            "observed_bounds",
            "counters",
            "final_verification",
        },
        "observation",
        issues,
    )
    observation_value = observation if isinstance(observation, Mapping) else {}
    node_results_value = observation_value.get("node_results")
    if not isinstance(node_results_value, list):
        _issue(issues, "observation.node_results:not_array")
        node_results_value = []
    node_results: dict[str, Mapping[str, Any]] = {}
    for index, result in enumerate(node_results_value):
        path = f"observation.node_results[{index}]"
        _exact(
            result,
            {"node_id", "status", "completion_seq", "evidence_pointer"},
            path,
            issues,
        )
        if not isinstance(result, Mapping):
            continue
        node_id = result.get("node_id")
        if node_id not in nodes:
            _issue(issues, f"{path}:undeclared_node")
        elif node_id in node_results:
            _issue(issues, f"{path}:duplicate_node")
        else:
            node_results[str(node_id)] = result
        if result.get("status") not in {"completed", "failed", "timed_out", "cancelled"}:
            _issue(issues, f"{path}:status_invalid")
        if type(result.get("completion_seq")) is not int or result["completion_seq"] < 1:
            _issue(issues, f"{path}:completion_seq_invalid")
        if not _text(result.get("evidence_pointer")):
            _issue(issues, f"{path}:evidence_pointer_invalid")
    if set(node_results) != set(node_ids):
        _issue(issues, "observation:node_result_set_mismatch")
    result_sequences = [item.get("completion_seq") for item in node_results.values()]
    if len(result_sequences) != len(set(result_sequences)):
        _issue(issues, "observation:completion_seq_duplicate")

    observed_bounds = observation_value.get("observed_bounds")
    _exact(observed_bounds, {"depth", "concurrency", "turns"}, "observation.observed_bounds", issues)
    observed_bounds_value = observed_bounds if isinstance(observed_bounds, Mapping) else {}
    for field, bound_field in (("depth", "max_depth"), ("concurrency", "max_concurrency"), ("turns", "max_turns")):
        number = observed_bounds_value.get(field)
        if type(number) is not int or number < 0:
            _issue(issues, f"observation.observed_bounds:{field}_invalid")
        elif type(bounds_value.get(bound_field)) is int and number > bounds_value[bound_field]:
            _issue(issues, f"observation.observed_bounds:{field}_exceeded")

    counters = observation_value.get("counters")
    _exact(
        counters,
        {"retries", "replacements", "fallbacks", "undeclared_events"},
        "observation.counters",
        issues,
    )
    counters_value = counters if isinstance(counters, Mapping) else {}
    for field in ("retries", "replacements", "fallbacks", "undeclared_events"):
        if counters_value.get(field) != 0:
            _issue(issues, f"observation.counters:{field}_not_zero")

    join_results_value = observation_value.get("join_results")
    if not isinstance(join_results_value, list):
        _issue(issues, "observation.join_results:not_array")
        join_results_value = []
    join_results: dict[str, Mapping[str, Any]] = {}
    expected_releases: set[tuple[str, str, str]] = set()
    join_outcomes: list[dict[str, Any]] = []
    for index, result in enumerate(join_results_value):
        path = f"observation.join_results[{index}]"
        _exact(
            result,
            {"join_id", "accepted_inputs", "excluded_inputs", "selected_integrator_node_id", "continued"},
            path,
            issues,
        )
        if not isinstance(result, Mapping):
            continue
        join_id = result.get("join_id")
        if join_id not in joins:
            _issue(issues, f"{path}:undeclared_join")
            continue
        if join_id in join_results:
            _issue(issues, f"{path}:duplicate_join")
        join_results[str(join_id)] = result
        join = joins[str(join_id)]
        accepted_value = result.get("accepted_inputs")
        excluded_value = result.get("excluded_inputs")
        if not isinstance(accepted_value, list):
            _issue(issues, f"{path}.accepted_inputs:not_array")
            accepted_value = []
        if not isinstance(excluded_value, list):
            _issue(issues, f"{path}.excluded_inputs:not_array")
            excluded_value = []
        accepted: list[tuple[str, str]] = []
        excluded: list[tuple[str, str]] = []
        for item_index, item in enumerate(accepted_value):
            item_path = f"{path}.accepted_inputs[{item_index}]"
            _exact(item, {"edge_id", "source_node_id", "evidence_pointer"}, item_path, issues)
            item_value = item if isinstance(item, Mapping) else {}
            edge_id = item_value.get("edge_id")
            source = item_value.get("source_node_id")
            if edge_id not in join["input_edge_ids"]:
                _issue(issues, f"{item_path}:edge_not_declared_for_join")
            elif edges[edge_id].get("source") != source:
                _issue(issues, f"{item_path}:source_mismatch")
            if source not in node_results or node_results[source].get("status") != "completed":
                _issue(issues, f"{item_path}:source_not_completed")
            if not _text(item_value.get("evidence_pointer")):
                _issue(issues, f"{item_path}:evidence_pointer_invalid")
            accepted.append((str(edge_id), str(source)))
        for item_index, item in enumerate(excluded_value):
            item_path = f"{path}.excluded_inputs[{item_index}]"
            _exact(item, {"edge_id", "source_node_id", "reason", "evidence_pointer"}, item_path, issues)
            item_value = item if isinstance(item, Mapping) else {}
            edge_id = item_value.get("edge_id")
            source = item_value.get("source_node_id")
            if edge_id not in join["input_edge_ids"]:
                _issue(issues, f"{item_path}:edge_not_declared_for_join")
            elif edges[edge_id].get("source") != source:
                _issue(issues, f"{item_path}:source_mismatch")
            source_status = node_results.get(str(source), {}).get("status")
            if item_value.get("reason") != source_status or source_status not in {"failed", "timed_out", "cancelled"}:
                _issue(issues, f"{item_path}:reason_mismatch")
            if not _text(item_value.get("evidence_pointer")):
                _issue(issues, f"{item_path}:evidence_pointer_invalid")
            excluded.append((str(edge_id), str(source)))
        observed_inputs = [edge_id for edge_id, _ in [*accepted, *excluded]]
        if len(observed_inputs) != len(set(observed_inputs)) or set(observed_inputs) != set(join["input_edge_ids"]):
            _issue(issues, f"{path}:input_partition_mismatch")
        enough = len(accepted) >= int(join.get("quorum") or 0)
        if result.get("continued") is not enough:
            _issue(issues, f"{path}:continuation_mismatch")
        selected_integrator = result.get("selected_integrator_node_id")
        if strategy == "join_target":
            expected_integrator = join["target_node_id"]
        else:
            completed_accepted = [
                source for _, source in accepted if source in node_results
            ]
            expected_integrator = min(
                completed_accepted,
                key=lambda node_id: (node_results[node_id]["completion_seq"], node_id),
                default=None,
            )
        if selected_integrator != expected_integrator:
            _issue(issues, f"{path}:integrator_selection_mismatch")
        if enough and expected_integrator is not None:
            for edge_id, source in accepted:
                if source != expected_integrator:
                    expected_releases.add((edge_id, source, str(expected_integrator)))
        join_outcomes.append(
            {
                "join_id": join_id,
                "continued": enough,
                "accepted_edge_ids": sorted(edge_id for edge_id, _ in accepted),
                "excluded_edge_ids": sorted(edge_id for edge_id, _ in excluded),
                "selected_integrator_node_id": expected_integrator,
            }
        )
    if set(join_results) != set(joins):
        _issue(issues, "observation:join_result_set_mismatch")

    release_results_value = observation_value.get("release_results")
    if not isinstance(release_results_value, list):
        _issue(issues, "observation.release_results:not_array")
        release_results_value = []
    observed_releases: list[tuple[str, str, str]] = []
    for index, release in enumerate(release_results_value):
        path = f"observation.release_results[{index}]"
        _exact(release, {"edge_id", "source_node_id", "target_node_id", "evidence_pointer"}, path, issues)
        item = release if isinstance(release, Mapping) else {}
        edge_id = item.get("edge_id")
        source = item.get("source_node_id")
        target = item.get("target_node_id")
        if edge_id not in edges:
            _issue(issues, f"{path}:undeclared_edge")
        if not _text(item.get("evidence_pointer")):
            _issue(issues, f"{path}:evidence_pointer_invalid")
        observed_releases.append((str(edge_id), str(source), str(target)))
    if len(observed_releases) != len(set(observed_releases)) or set(observed_releases) != expected_releases:
        _issue(issues, "observation:release_set_mismatch")

    final_verification = observation_value.get("final_verification")
    _exact(final_verification, {"status", "evidence_pointer"}, "observation.final_verification", issues)
    final_value = final_verification if isinstance(final_verification, Mapping) else {}
    if final_value.get("status") != "PASS":
        _issue(issues, "observation:final_verification_failed")
    if not _text(final_value.get("evidence_pointer")):
        _issue(issues, "observation:final_evidence_pointer_invalid")

    graph_outcome = "QUALIFIED" if not issues and all(item["continued"] for item in join_outcomes) else "UNQUALIFIED"
    core = {
        "schema": GRAPH_REPORT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "qualified": graph_outcome == "QUALIFIED",
        "graph_outcome": graph_outcome,
        "graph_id": value.get("graph_id"),
        "plan_sha256": plan_sha,
        "graph_sha256": _sha256({key: value.get(key) for key in ("nodes", "edges", "joins", "bounds", "authority", "integration")}),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "computed_depth": computed_depth,
        "join_outcomes": join_outcomes,
        "release_count": len(observed_releases),
        "issues": sorted(issues),
        "retries_permitted": False,
        "replacements_permitted": False,
        "fallbacks_permitted": False,
        "evidence_tier": "submitted-fixture",
    }
    return {**core, "receipt_sha256": _sha256(core)}


def _privacy_issues(value: Any, path: str = "checkpoint") -> list[str]:
    issues: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in ROLLOVER_FORBIDDEN_KEYS:
                issues.append(f"{path}:forbidden:{normalized}")
            issues.extend(_privacy_issues(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            issues.extend(_privacy_issues(item, f"{path}[{index}]"))
    return issues


def _rollover_fact(
    value: Any,
    path: str,
    issues: list[str],
    *,
    units: set[str],
) -> dict[str, Any]:
    _exact(value, {"status", "value", "unit", "reason", "source_pointer"}, path, issues)
    item = value if isinstance(value, Mapping) else {}
    status = item.get("status")
    number = item.get("value")
    unit = item.get("unit")
    reason = item.get("reason")
    if status == "known":
        if type(number) is not int or number < 0:
            _issue(issues, f"{path}:value_invalid")
        if unit not in units:
            _issue(issues, f"{path}:unit_invalid")
        if reason is not None:
            _issue(issues, f"{path}:known_has_reason")
    elif status == "unknown":
        if number is not None or unit is not None:
            _issue(issues, f"{path}:unknown_has_measurement")
        if not _identifier(reason):
            _issue(issues, f"{path}:unknown_reason_invalid")
    else:
        _issue(issues, f"{path}:status_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, f"{path}:source_pointer_invalid")
    return dict(item)


def _rollover_checkpoint(value: Any, issues: list[str]) -> tuple[dict[str, Any], str]:
    fields = {
        "schema",
        "marker",
        "program_id",
        "ticket_id",
        "plan_revision",
        "plan_sha256",
        "worker_state",
        "custody",
        "releases",
        "artifacts",
        "usage",
        "context_pressure",
        "capacity",
        "authority",
        "hard_limits",
        "worktree",
        "routing",
        "boundary",
        "next_action",
    }
    _exact(value, fields, "checkpoint", issues)
    checkpoint = dict(value) if isinstance(value, Mapping) else {}
    if checkpoint.get("schema") != ROLLOVER_CHECKPOINT_SCHEMA:
        _issue(issues, "checkpoint:schema_invalid")
    for field in ("marker", "program_id", "ticket_id"):
        if not _identifier(checkpoint.get(field)):
            _issue(issues, f"checkpoint:{field}_invalid")
    revision = checkpoint.get("plan_revision")
    if type(revision) is not int or revision < 1:
        _issue(issues, "checkpoint:plan_revision_invalid")
    plan_sha = checkpoint.get("plan_sha256")
    if not isinstance(plan_sha, str) or _SHA256.fullmatch(plan_sha) is None:
        _issue(issues, "checkpoint:plan_sha256_invalid")

    worker_state = checkpoint.get("worker_state")
    _exact(
        worker_state,
        {"pending", "terminal", "unresolved"},
        "checkpoint.worker_state",
        issues,
    )
    worker_value = worker_state if isinstance(worker_state, Mapping) else {}
    worker_sets: dict[str, set[str]] = {}
    for state in ("pending", "terminal", "unresolved"):
        worker_sets[state] = set(
            _string_list(
                worker_value.get(state),
                f"checkpoint.worker_state.{state}",
                issues,
            )
        )
    all_workers = [item for values in worker_sets.values() for item in values]
    if len(all_workers) != len(set(all_workers)):
        _issue(issues, "checkpoint.worker_state:overlap")

    for name in ("custody", "releases"):
        pointer = checkpoint.get(name)
        _exact(pointer, {"status", "source_pointer", "sha256"}, f"checkpoint.{name}", issues)
        pointer_value = pointer if isinstance(pointer, Mapping) else {}
        if pointer_value.get("status") not in {"preserved", "not_applicable", "unknown"}:
            _issue(issues, f"checkpoint.{name}:status_invalid")
        if not _text(pointer_value.get("source_pointer")):
            _issue(issues, f"checkpoint.{name}:source_pointer_invalid")
        digest = pointer_value.get("sha256")
        if pointer_value.get("status") == "preserved":
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                _issue(issues, f"checkpoint.{name}:sha256_invalid")
        elif digest is not None:
            _issue(issues, f"checkpoint.{name}:unexpected_sha256")

    artifacts = checkpoint.get("artifacts")
    if not isinstance(artifacts, list):
        _issue(issues, "checkpoint.artifacts:not_array")
        artifacts = []
    artifact_roles: set[str] = set()
    for index, artifact in enumerate(artifacts):
        path = f"checkpoint.artifacts[{index}]"
        _exact(artifact, {"role", "path", "sha256"}, path, issues)
        item = artifact if isinstance(artifact, Mapping) else {}
        role = item.get("role")
        if not _identifier(role) or role in artifact_roles:
            _issue(issues, f"{path}:role_invalid_or_duplicate")
        else:
            artifact_roles.add(str(role))
        if not _text(item.get("path")):
            _issue(issues, f"{path}:path_invalid")
        digest = item.get("sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            _issue(issues, f"{path}:sha256_invalid")

    usage = _rollover_fact(
        checkpoint.get("usage"),
        "checkpoint.usage",
        issues,
        units={"tokens"},
    )
    context = _rollover_fact(
        checkpoint.get("context_pressure"),
        "checkpoint.context_pressure",
        issues,
        units={"input_tokens"},
    )
    capacity = _rollover_fact(
        checkpoint.get("capacity"),
        "checkpoint.capacity",
        issues,
        units={"free_worker_slots"},
    )
    checkpoint["usage"] = usage
    checkpoint["context_pressure"] = context
    checkpoint["capacity"] = capacity

    authority = checkpoint.get("authority")
    _exact(
        authority,
        {"authority_id", "status", "scope", "source_pointer"},
        "checkpoint.authority",
        issues,
    )
    authority_value = authority if isinstance(authority, Mapping) else {}
    if not _identifier(authority_value.get("authority_id")):
        _issue(issues, "checkpoint.authority:id_invalid")
    if authority_value.get("status") != "granted":
        _issue(issues, "checkpoint.authority:not_granted")
    if authority_value.get("scope") != "program_continuation":
        _issue(issues, "checkpoint.authority:scope_invalid")
    if not _text(authority_value.get("source_pointer")):
        _issue(issues, "checkpoint.authority:source_pointer_invalid")

    hard_limits = checkpoint.get("hard_limits")
    _exact(hard_limits, {"source_pointer", "sha256"}, "checkpoint.hard_limits", issues)
    hard_value = hard_limits if isinstance(hard_limits, Mapping) else {}
    if not _text(hard_value.get("source_pointer")):
        _issue(issues, "checkpoint.hard_limits:source_pointer_invalid")
    hard_sha = hard_value.get("sha256")
    if not isinstance(hard_sha, str) or _SHA256.fullmatch(hard_sha) is None:
        _issue(issues, "checkpoint.hard_limits:sha256_invalid")

    worktree = checkpoint.get("worktree")
    _exact(
        worktree,
        {"root", "baseline_sha256", "dirty_paths"},
        "checkpoint.worktree",
        issues,
    )
    worktree_value = worktree if isinstance(worktree, Mapping) else {}
    if not isinstance(worktree_value.get("root"), str) or not Path(worktree_value["root"]).is_absolute():
        _issue(issues, "checkpoint.worktree:root_invalid")
    baseline = worktree_value.get("baseline_sha256")
    if not isinstance(baseline, str) or _SHA256.fullmatch(baseline) is None:
        _issue(issues, "checkpoint.worktree:baseline_invalid")
    _string_list(worktree_value.get("dirty_paths"), "checkpoint.worktree.dirty_paths", issues)

    routing = checkpoint.get("routing")
    _exact(
        routing,
        {"model", "effort", "host", "project_id", "cwd", "context_policy"},
        "checkpoint.routing",
        issues,
    )
    routing_value = routing if isinstance(routing, Mapping) else {}
    if not root_model_accepted(routing_value.get("model")):
        _issue(issues, "checkpoint.routing:model_invalid")
    if routing_value.get("effort") not in {"low", "medium", "high", "xhigh", "max", "ultra"}:
        _issue(issues, "checkpoint.routing:effort_invalid")
    for field in ("host", "project_id"):
        if not _identifier(routing_value.get(field)):
            _issue(issues, f"checkpoint.routing:{field}_invalid")
    if routing_value.get("cwd") != worktree_value.get("root"):
        _issue(issues, "checkpoint.routing:cwd_mismatch")
    if routing_value.get("context_policy") != "none":
        _issue(issues, "checkpoint.routing:context_policy_invalid")

    boundary = checkpoint.get("boundary")
    _exact(
        boundary,
        {
            "ticket_or_wave_checkpointed",
            "launched_workers_accounted",
            "external_outcomes",
            "predecessor_implementation_stopped",
        },
        "checkpoint.boundary",
        issues,
    )
    boundary_value = boundary if isinstance(boundary, Mapping) else {}
    for field in (
        "ticket_or_wave_checkpointed",
        "launched_workers_accounted",
        "predecessor_implementation_stopped",
    ):
        if boundary_value.get(field) is not True:
            _issue(issues, f"checkpoint.boundary:{field}_not_true")
    if boundary_value.get("external_outcomes") not in {"resolved", "durably_blocked"}:
        _issue(issues, "checkpoint.boundary:external_outcomes_invalid")
    if not _text(checkpoint.get("next_action")):
        _issue(issues, "checkpoint:next_action_invalid")
    for privacy_issue in _privacy_issues(checkpoint):
        _issue(issues, privacy_issue)
    return checkpoint, _sha256(checkpoint)


def evaluate_root_rollover(program: Any) -> dict[str, Any]:
    """Evaluate a safe exactly-once root rollover without launching a task."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(
        program,
        {
            "schema",
            "rollover_id",
            "predecessor_thread_id",
            "trigger",
            "checkpoint",
            "creation",
            "inventory",
            "successor",
            "predecessor_observation",
            "lease",
            "previous_rollover_ids",
        },
        "rollover",
        issues,
    )
    if value.get("schema") != ROLLOVER_PROGRAM_SCHEMA:
        _issue(issues, "rollover:schema_invalid")
    if not _identifier(value.get("rollover_id")):
        _issue(issues, "rollover:id_invalid")
    predecessor_id = value.get("predecessor_thread_id")
    if not _identifier(predecessor_id):
        _issue(issues, "rollover:predecessor_identity_invalid")

    trigger = value.get("trigger")
    _exact(
        trigger,
        {"type", "status", "value", "policy_version", "source_pointer"},
        "trigger",
        issues,
    )
    trigger_value = trigger if isinstance(trigger, Mapping) else {}
    trigger_type = trigger_value.get("type")
    if trigger_type not in ROLLOVER_TRIGGERS:
        _issue(issues, "trigger:type_invalid")
    if trigger_value.get("status") != "observed" or trigger_value.get("value") is not True:
        _issue(issues, "trigger:not_observed_true")
    if not _identifier(trigger_value.get("policy_version")):
        _issue(issues, "trigger:policy_version_invalid")
    if not _text(trigger_value.get("source_pointer")):
        _issue(issues, "trigger:source_pointer_invalid")

    checkpoint, checkpoint_sha = _rollover_checkpoint(value.get("checkpoint"), issues)
    marker = checkpoint.get("marker")
    routing = checkpoint.get("routing") if isinstance(checkpoint.get("routing"), Mapping) else {}
    worktree = checkpoint.get("worktree") if isinstance(checkpoint.get("worktree"), Mapping) else {}
    authority = checkpoint.get("authority") if isinstance(checkpoint.get("authority"), Mapping) else {}

    prior_ids = _string_list(value.get("previous_rollover_ids"), "previous_rollover_ids", issues)
    loop_blocked = bool(prior_ids) and trigger_type != "sol_requested"
    if loop_blocked:
        _issue(issues, "rollover:automatic_loop_prevented")

    creation = value.get("creation")
    _exact(
        creation,
        {
            "status",
            "attempt_count",
            "marker",
            "requested_at",
            "returned_thread_id",
            "source_pointer",
        },
        "creation",
        issues,
    )
    creation_value = creation if isinstance(creation, Mapping) else {}
    creation_status = creation_value.get("status")
    if creation_status not in {"not_attempted", "created", "failed", "timed_out", "ambiguous"}:
        _issue(issues, "creation:status_invalid")
    expected_attempts = 0 if creation_status == "not_attempted" else 1
    if creation_value.get("attempt_count") != expected_attempts:
        _issue(issues, "creation:attempt_count_invalid")
    if creation_value.get("marker") != marker:
        _issue(issues, "creation:marker_mismatch")
    if creation_status == "not_attempted":
        if any(creation_value.get(field) is not None for field in ("requested_at", "returned_thread_id", "source_pointer")):
            _issue(issues, "creation:not_attempted_has_result")
    else:
        if not _text(creation_value.get("requested_at")):
            _issue(issues, "creation:requested_at_invalid")
        if not _text(creation_value.get("source_pointer")):
            _issue(issues, "creation:source_pointer_invalid")
    if creation_status == "created":
        if not _identifier(creation_value.get("returned_thread_id")):
            _issue(issues, "creation:returned_identity_invalid")
    elif creation_value.get("returned_thread_id") is not None:
        _issue(issues, "creation:unexpected_returned_identity")

    inventory = value.get("inventory")
    _exact(inventory, {"status", "source_pointer", "candidates"}, "inventory", issues)
    inventory_value = inventory if isinstance(inventory, Mapping) else {}
    if inventory_value.get("status") not in {"not_run", "observed"}:
        _issue(issues, "inventory:status_invalid")
    candidates_value = inventory_value.get("candidates")
    if not isinstance(candidates_value, list):
        _issue(issues, "inventory:candidates_not_array")
        candidates_value = []
    matching_candidates: list[dict[str, Any]] = []
    candidate_ids: set[str] = set()
    for index, candidate in enumerate(candidates_value):
        path = f"inventory.candidates[{index}]"
        _exact(
            candidate,
            {"thread_id", "marker", "host", "project_id", "cwd", "created_at"},
            path,
            issues,
        )
        item = candidate if isinstance(candidate, Mapping) else {}
        thread_id = item.get("thread_id")
        if not _identifier(thread_id) or thread_id in candidate_ids:
            _issue(issues, f"{path}:thread_id_invalid_or_duplicate")
        else:
            candidate_ids.add(str(thread_id))
        if not _text(item.get("created_at")):
            _issue(issues, f"{path}:created_at_invalid")
        if (
            item.get("marker") == marker
            and item.get("host") == routing.get("host")
            and item.get("project_id") == routing.get("project_id")
            and item.get("cwd") == routing.get("cwd")
        ):
            matching_candidates.append(dict(item))
    if inventory_value.get("status") == "not_run":
        if inventory_value.get("source_pointer") is not None or candidates_value:
            _issue(issues, "inventory:not_run_has_values")
    elif not _text(inventory_value.get("source_pointer")):
        _issue(issues, "inventory:source_pointer_invalid")
    if len(matching_candidates) > 1:
        _issue(issues, "creation:duplicate_successors")
    if creation_status == "created":
        if len(matching_candidates) != 1:
            _issue(issues, "creation:created_candidate_count_invalid")
        elif matching_candidates[0]["thread_id"] != creation_value.get("returned_thread_id"):
            _issue(issues, "creation:returned_candidate_mismatch")
    resolved_thread_id = creation_value.get("returned_thread_id")
    if (
        creation_status in {"failed", "timed_out", "ambiguous"}
        and len(matching_candidates) == 1
    ):
        resolved_thread_id = matching_candidates[0]["thread_id"]

    successor = value.get("successor")
    _exact(
        successor,
        {
            "status",
            "thread_id",
            "checkpoint_sha256",
            "model",
            "effort",
            "host",
            "project_id",
            "cwd",
            "context_policy",
            "read_only",
            "worktree_baseline_sha256",
            "dirty_paths",
            "authority_id",
            "capacity",
            "context_pressure",
            "acknowledgement",
            "source_pointer",
        },
        "successor",
        issues,
    )
    successor_value = successor if isinstance(successor, Mapping) else {}
    successor_status = successor_value.get("status")
    if successor_status not in {"not_observed", "observed"}:
        _issue(issues, "successor:status_invalid")
    successor_verified = False
    successor_capacity: dict[str, Any] = {}
    successor_context: dict[str, Any] = {}
    if successor_status == "not_observed":
        if any(successor_value.get(field) is not None for field in set(successor_value) - {"status"}):
            _issue(issues, "successor:not_observed_has_values")
    else:
        expected_thread_id = resolved_thread_id
        if successor_value.get("thread_id") != expected_thread_id:
            _issue(issues, "successor:identity_mismatch")
        if successor_value.get("checkpoint_sha256") != checkpoint_sha:
            _issue(issues, "successor:checkpoint_mismatch")
        for field in ("model", "effort", "host", "project_id", "cwd"):
            if successor_value.get(field) != routing.get(field):
                _issue(issues, f"successor:{field}_mismatch")
        if successor_value.get("context_policy") != "none":
            _issue(issues, "successor:context_inherited")
        if successor_value.get("read_only") is not True:
            _issue(issues, "successor:not_read_only")
        if successor_value.get("worktree_baseline_sha256") != worktree.get("baseline_sha256"):
            _issue(issues, "successor:worktree_baseline_mismatch")
        dirty_paths = _string_list(successor_value.get("dirty_paths"), "successor.dirty_paths", issues)
        if dirty_paths != worktree.get("dirty_paths"):
            _issue(issues, "successor:dirty_paths_mismatch")
        if successor_value.get("authority_id") != authority.get("authority_id"):
            _issue(issues, "successor:authority_mismatch")
        successor_capacity = _rollover_fact(
            successor_value.get("capacity"),
            "successor.capacity",
            issues,
            units={"free_worker_slots"},
        )
        successor_context = _rollover_fact(
            successor_value.get("context_pressure"),
            "successor.context_pressure",
            issues,
            units={"input_tokens"},
        )
        if successor_value.get("acknowledgement") != "PASS":
            _issue(issues, "successor:acknowledgement_failed")
        if not _text(successor_value.get("source_pointer")):
            _issue(issues, "successor:source_pointer_invalid")
        successor_verified = not any(item.startswith("successor:") for item in issues)

    predecessor = value.get("predecessor_observation")
    _exact(
        predecessor,
        {"status", "thread_id", "frozen", "source_pointer"},
        "predecessor_observation",
        issues,
    )
    predecessor_value = predecessor if isinstance(predecessor, Mapping) else {}
    predecessor_status = predecessor_value.get("status")
    if predecessor_status not in {"active", "terminal", "unknown"}:
        _issue(issues, "predecessor_observation:status_invalid")
    if predecessor_value.get("thread_id") != predecessor_id:
        _issue(issues, "predecessor_observation:identity_mismatch")
    if not isinstance(predecessor_value.get("frozen"), bool):
        _issue(issues, "predecessor_observation:frozen_invalid")
    if not _text(predecessor_value.get("source_pointer")):
        _issue(issues, "predecessor_observation:source_pointer_invalid")
    predecessor_terminal = predecessor_status == "terminal" and predecessor_value.get("frozen") is True

    lease = value.get("lease")
    _exact(
        lease,
        {
            "schema",
            "version",
            "owner_thread_id",
            "expected_owner_thread_id",
            "expected_version",
            "transfer_status",
            "source_pointer",
        },
        "lease",
        issues,
    )
    lease_value = lease if isinstance(lease, Mapping) else {}
    if lease_value.get("schema") != "orch-dork/execution-lease/v1":
        _issue(issues, "lease:schema_invalid")
    version = lease_value.get("version")
    expected_version = lease_value.get("expected_version")
    if type(version) is not int or version < 1:
        _issue(issues, "lease:version_invalid")
    if type(expected_version) is not int or expected_version < 1:
        _issue(issues, "lease:expected_version_invalid")
    if lease_value.get("expected_owner_thread_id") != predecessor_id:
        _issue(issues, "lease:expected_owner_mismatch")
    transfer_status = lease_value.get("transfer_status")
    if transfer_status not in {"not_requested", "transferred", "conflict"}:
        _issue(issues, "lease:transfer_status_invalid")
    if not _text(lease_value.get("source_pointer")):
        _issue(issues, "lease:source_pointer_invalid")
    if transfer_status == "not_requested":
        if lease_value.get("owner_thread_id") != predecessor_id or version != expected_version:
            _issue(issues, "lease:pretransfer_state_invalid")
    elif transfer_status == "transferred":
        if not successor_verified or not predecessor_terminal:
            _issue(issues, "lease:transfer_prerequisites_missing")
        if lease_value.get("owner_thread_id") != successor_value.get("thread_id"):
            _issue(issues, "lease:successor_owner_mismatch")
        if type(expected_version) is int and version != expected_version + 1:
            _issue(issues, "lease:cas_version_mismatch")
    if predecessor_status == "active" and lease_value.get("owner_thread_id") != predecessor_id:
        _issue(issues, "lease:duplicate_active_ownership")

    predecessor_capacity = checkpoint.get("capacity", {})
    if trigger_type == "capacity_pinned":
        if predecessor_capacity.get("status") != "known" or predecessor_capacity.get("value") != 0:
            _issue(issues, "trigger:capacity_not_pinned")
        if successor_status != "observed":
            capacity_outcome = "NOT_PROVEN"
        elif successor_capacity.get("status") == "known" and successor_capacity.get("value", 0) > 0:
            capacity_outcome = "CAPACITY_RECOVERED"
        else:
            capacity_outcome = "NOT_PROVEN"
    else:
        capacity_outcome = "NOT_APPLICABLE"
    predecessor_context = checkpoint.get("context_pressure", {})
    if trigger_type in {"context_pressure", "repeated_large_unchanged_input"}:
        if successor_status != "observed":
            context_outcome = "NOT_PROVEN"
        elif (
            predecessor_context.get("status") == "known"
            and successor_context.get("status") == "known"
            and successor_context.get("value", 0) < predecessor_context.get("value", 0)
        ):
            context_outcome = "CONTEXT_REDUCED"
        else:
            context_outcome = "NOT_PROVEN"
    else:
        context_outcome = "NOT_APPLICABLE"

    if loop_blocked:
        status = "ROLLOVER_LOOP_BLOCKED"
    elif issues:
        status = "FAIL"
    elif creation_status == "not_attempted":
        status = "READY_TO_CREATE"
    elif creation_status in {"failed", "timed_out", "ambiguous"} and resolved_thread_id is None:
        status = "OUTCOME_UNKNOWN"
    elif not successor_verified:
        status = "SUCCESSOR_VERIFICATION_REQUIRED"
    elif not predecessor_terminal:
        status = "PREDECESSOR_TERMINAL_REQUIRED"
    elif transfer_status != "transferred":
        status = "LEASE_TRANSFER_REQUIRED"
    else:
        status = "ROLLOVER_COMPLETE"
    continuity = "CONTINUITY_PASS" if status == "ROLLOVER_COMPLETE" else "CONTINUITY_FAIL"
    core = {
        "schema": ROLLOVER_REPORT_SCHEMA,
        "status": status,
        "rollover_id": value.get("rollover_id"),
        "predecessor_thread_id": predecessor_id,
        "successor_thread_id": successor_value.get("thread_id") or resolved_thread_id,
        "trigger_type": trigger_type,
        "checkpoint_sha256": checkpoint_sha,
        "creation_attempt_count": creation_value.get("attempt_count"),
        "second_creation_call_permitted": False,
        "matching_candidate_count": len(matching_candidates),
        "successor_verified": successor_verified,
        "predecessor_terminal": predecessor_terminal,
        "lease_owner_thread_id": lease_value.get("owner_thread_id"),
        "lease_version": version,
        "continuity_outcome": continuity,
        "capacity_outcome": capacity_outcome,
        "context_outcome": context_outcome,
        "supervisor_follow_required": status == "ROLLOVER_COMPLETE",
        "automatic_rollover_permitted": False,
        "next_action": checkpoint.get("next_action"),
        "issues": sorted(issues),
        "evidence_tier": "submitted",
    }
    return {**core, "receipt_sha256": _sha256(core)}


def transfer_execution_lease(lease_path: str | Path, request: Any) -> dict[str, Any]:
    """Atomically transfer a durable execution lease after terminal observation.

    The sidecar lock serializes readers performing the compare-and-swap. The
    lease itself is replaced atomically only after all closed request and
    predecessor-terminal gates pass.
    """

    issues: list[str] = []
    value = request if isinstance(request, Mapping) else {}
    _exact(
        request,
        {
            "schema",
            "expected_owner_thread_id",
            "expected_version",
            "successor_thread_id",
            "checkpoint_sha256",
            "predecessor_observation",
        },
        "lease_transfer",
        issues,
    )
    if value.get("schema") != LEASE_TRANSFER_SCHEMA:
        _issue(issues, "lease_transfer:schema_invalid")
    for field in ("expected_owner_thread_id", "successor_thread_id"):
        if not _identifier(value.get(field)):
            _issue(issues, f"lease_transfer:{field}_invalid")
    if value.get("expected_owner_thread_id") == value.get("successor_thread_id"):
        _issue(issues, "lease_transfer:owner_identity_not_changed")
    if type(value.get("expected_version")) is not int or value["expected_version"] < 1:
        _issue(issues, "lease_transfer:expected_version_invalid")
    checkpoint_sha = value.get("checkpoint_sha256")
    if not isinstance(checkpoint_sha, str) or _SHA256.fullmatch(checkpoint_sha) is None:
        _issue(issues, "lease_transfer:checkpoint_sha256_invalid")
    observation = value.get("predecessor_observation")
    _exact(
        observation,
        {"status", "thread_id", "frozen", "source_pointer"},
        "lease_transfer.predecessor_observation",
        issues,
    )
    observation_value = observation if isinstance(observation, Mapping) else {}
    if observation_value.get("status") != "terminal":
        _issue(issues, "lease_transfer:predecessor_not_terminal")
    if observation_value.get("thread_id") != value.get("expected_owner_thread_id"):
        _issue(issues, "lease_transfer:predecessor_identity_mismatch")
    if observation_value.get("frozen") is not True:
        _issue(issues, "lease_transfer:predecessor_not_frozen")
    if not _text(observation_value.get("source_pointer")):
        _issue(issues, "lease_transfer:source_pointer_invalid")
    if issues:
        return {
            "schema": "orch-dork/execution-lease-transfer-report/v1",
            "status": "FAIL",
            "transferred": False,
            "issues": sorted(issues),
        }

    target = Path(lease_path).expanduser().resolve()
    lock_path = target.with_name(target.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            current = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {
                "schema": "orch-dork/execution-lease-transfer-report/v1",
                "status": "FAIL",
                "transferred": False,
                "issues": ["lease:unreadable:" + type(exc).__name__],
            }
        lease_issues: list[str] = []
        _exact(
            current,
            {
                "schema",
                "version",
                "owner_thread_id",
                "checkpoint_sha256",
                "status",
                "predecessor_thread_id",
                "successor_thread_id",
                "terminal_source_pointer",
            },
            "lease",
            lease_issues,
        )
        if not isinstance(current, Mapping) or current.get("schema") != LEASE_SCHEMA:
            _issue(lease_issues, "lease:schema_invalid")
        if (
            current.get("status") == "active_successor"
            and current.get("owner_thread_id") == value.get("successor_thread_id")
            and current.get("version") == value.get("expected_version") + 1
            and current.get("checkpoint_sha256") == checkpoint_sha
        ):
            return {
                "schema": "orch-dork/execution-lease-transfer-report/v1",
                "status": "ALREADY_TRANSFERRED",
                "transferred": True,
                "lease": dict(current),
                "issues": [],
            }
        if current.get("owner_thread_id") != value.get("expected_owner_thread_id"):
            _issue(lease_issues, "lease:owner_conflict")
        if current.get("version") != value.get("expected_version"):
            _issue(lease_issues, "lease:version_conflict")
        current_status = current.get("status")
        if current_status not in {"active_predecessor", "active_successor"}:
            _issue(lease_issues, "lease:status_conflict")
        if current_status == "active_predecessor":
            if current.get("checkpoint_sha256") != checkpoint_sha:
                _issue(lease_issues, "lease:checkpoint_mismatch")
            if current.get("predecessor_thread_id") != value.get("expected_owner_thread_id"):
                _issue(lease_issues, "lease:predecessor_mismatch")
            if current.get("successor_thread_id") not in {None, value.get("successor_thread_id")}:
                _issue(lease_issues, "lease:successor_conflict")
        elif current_status == "active_successor":
            if current.get("successor_thread_id") != value.get("expected_owner_thread_id"):
                _issue(lease_issues, "lease:successor_predecessor_mismatch")
        if lease_issues:
            return {
                "schema": "orch-dork/execution-lease-transfer-report/v1",
                "status": "CONFLICT",
                "transferred": False,
                "lease": dict(current),
                "issues": sorted(lease_issues),
            }
        next_lease = {
            "schema": LEASE_SCHEMA,
            "version": value["expected_version"] + 1,
            "owner_thread_id": value["successor_thread_id"],
            "checkpoint_sha256": checkpoint_sha,
            "status": "active_successor",
            "predecessor_thread_id": value["expected_owner_thread_id"],
            "successor_thread_id": value["successor_thread_id"],
            "terminal_source_pointer": observation_value["source_pointer"],
        }
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=target.name + ".",
            suffix=".tmp",
            dir=str(target.parent),
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as temporary:
                json.dump(next_lease, temporary, indent=2, sort_keys=True)
                temporary.write("\n")
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_name, target)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
        return {
            "schema": "orch-dork/execution-lease-transfer-report/v1",
            "status": "PASS",
            "transferred": True,
            "lease": next_lease,
            "issues": [],
        }


def _read_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON: {path}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provider-free Orch Dork coordination-efficiency governor")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-plan")
    validate.add_argument("plan")
    waves = sub.add_parser("run-waves")
    waves.add_argument("program")
    replan = sub.add_parser("evaluate-replan")
    replan.add_argument("program")
    active = sub.add_parser("run-active-controller")
    active.add_argument("program")
    limits = sub.add_parser("evaluate-limits")
    limits.add_argument("program")
    profile = sub.add_parser("evaluate-profile")
    profile.add_argument("program")
    efficiency = sub.add_parser("evaluate-efficiency")
    efficiency.add_argument("program")
    budget = sub.add_parser("evaluate-budget")
    budget.add_argument("program")
    recovery = sub.add_parser("evaluate-recovery")
    recovery.add_argument("program")
    graph = sub.add_parser("qualify-graph")
    graph.add_argument("program")
    rollover = sub.add_parser("evaluate-rollover")
    rollover.add_argument("program")
    transfer = sub.add_parser("transfer-lease")
    transfer.add_argument("lease")
    transfer.add_argument("request")
    convert = sub.add_parser("convert-v1")
    convert.add_argument("plan")
    convert.add_argument("--plan-id", required=True)
    convert.add_argument("--root-thread-id", required=True)
    convert.add_argument("--authority-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-plan":
            result = validate_logical_plan(_read_json(args.plan))
        elif args.command == "run-waves":
            result = run_wave_program(_read_json(args.program))
        elif args.command == "evaluate-replan":
            result = evaluate_replan_program(_read_json(args.program))
        elif args.command == "run-active-controller":
            result = run_active_controller(_read_json(args.program))
        elif args.command == "evaluate-limits":
            result = evaluate_limit_policy(_read_json(args.program))
        elif args.command == "evaluate-profile":
            result = evaluate_profile_lifecycle(_read_json(args.program))
        elif args.command == "evaluate-efficiency":
            result = evaluate_efficiency_program(_read_json(args.program))
        elif args.command == "evaluate-budget":
            result = evaluate_budget_program(_read_json(args.program))
        elif args.command == "evaluate-recovery":
            result = evaluate_recovery_program(_read_json(args.program))
        elif args.command == "qualify-graph":
            result = qualify_execution_graph(_read_json(args.program))
        elif args.command == "evaluate-rollover":
            result = evaluate_root_rollover(_read_json(args.program))
        elif args.command == "transfer-lease":
            result = transfer_execution_lease(args.lease, _read_json(args.request))
        else:
            result = logical_plan_from_v1(
                _read_json(args.plan),
                plan_id=args.plan_id,
                root_thread_id=args.root_thread_id,
                authority_id=args.authority_id,
            )
    except ValueError as exc:
        print(json.dumps({"status": "FAIL", "issues": [str(exc)]}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    successful = {"PASS", "ATOMIC_SOL", "DRAINED"}
    return 0 if result.get("status", "PASS") in successful else 2


if __name__ == "__main__":
    raise SystemExit(main())
