#!/usr/bin/env python3
"""Deterministic root-governed revisions of one finite logical DAG.

This controller is deliberately provider-free.  Workers may submit the
existing typed decomposition proposal, but only the current Sol/root may
approve it and only this controller may make the mechanically bound successor
effective.  It executes no plan and performs no persistence or provider work.
Proposal token allocations are reservations: they affect explicit projected
totals, but approval alone never turns them into observed token consumption.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
import re
from typing import Any

import orch_dork_decomposition as decomposition
import orch_dork_efficiency_governor as governor
import orch_dork_ownership as ownership


PROGRAM_SCHEMA = "orch-dork/adaptive-finite-dag-program/v1"
REPORT_SCHEMA = "orch-dork/adaptive-finite-dag-report/v1"
# PlanPatchRequestV1 is the controller vocabulary for the already-shipped,
# mechanically closed worker transaction.  Reusing its wire schema keeps one
# proposal validator and makes workers proposers rather than plan authorities.
PLAN_PATCH_REQUEST_V1_SCHEMA = decomposition.PROPOSAL_SCHEMA

MAX_LOGICAL_DEPTH = 2
MAX_NODE_RETRIES = 2
MAX_ACTIVE_REVISIONS = 3

_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")

_PROGRAM_FIELDS = {
    "schema",
    "controller_id",
    "current_plan",
    "decomposition_proposal",
    "proposal_approval",
    "limits",
    "consumption",
    "revision_history",
    "termination",
    "verification",
}
_LIMIT_FIELDS = {
    "max_logical_depth",
    "max_node_retries",
    "max_active_revisions",
    "max_nodes",
    "max_sol_ingress_tokens",
    "max_total_tokens",
}
_CONSUMPTION_FIELDS = {
    "logical_depth",
    "active_revisions",
    "node_retries",
    "completed_node_ids",
    "running_node_ids",
    "failed_node_ids",
    "sol_ingress_tokens",
    "total_tokens",
}
_HISTORY_FIELDS = {"revision", "plan_sha256", "source_pointer"}
_DISPOSITION_FIELDS = {"status", "decided_by", "role", "source_pointer"}
_APPROVAL_FIELDS = {
    "status",
    "approved_by",
    "approver_role",
    "proposal_sha256",
    "base_plan_sha256",
    "source_pointer",
}


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_of(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, fields: set[str], path: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, path + ":not_object")
        return False
    for field in sorted(fields - set(value)):
        _issue(issues, path + ":missing:" + field)
    for field in sorted(set(value) - fields):
        _issue(issues, path + ":unknown:" + str(field))
    return set(value) == fields


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 4096


def _nonnegative_integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def _positive_integer(value: Any) -> bool:
    return type(value) is int and value > 0


def _string_list(value: Any, path: str, issues: list[str]) -> list[str]:
    if not isinstance(value, list):
        _issue(issues, path + ":not_array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not _identifier(item):
            _issue(issues, f"{path}[{index}]:invalid")
        else:
            result.append(item)
    if len(result) != len(set(result)):
        _issue(issues, path + ":duplicates")
    return result


def _validate_limits(value: Any, issues: list[str]) -> dict[str, int]:
    limits = dict(value) if isinstance(value, Mapping) else {}
    _exact(value, _LIMIT_FIELDS, "limits", issues)
    for field in sorted(_LIMIT_FIELDS):
        if not _positive_integer(limits.get(field)):
            _issue(issues, "limits:" + field + "_invalid")
    if _positive_integer(limits.get("max_logical_depth")) and limits["max_logical_depth"] > MAX_LOGICAL_DEPTH:
        _issue(issues, "limits:max_logical_depth_exceeds_controller_max")
    if _positive_integer(limits.get("max_node_retries")) and limits["max_node_retries"] > MAX_NODE_RETRIES:
        _issue(issues, "limits:max_node_retries_exceeds_controller_max")
    if _positive_integer(limits.get("max_active_revisions")) and limits["max_active_revisions"] > MAX_ACTIVE_REVISIONS:
        _issue(issues, "limits:max_active_revisions_exceeds_controller_max")
    return limits


def _validate_consumption(
    value: Any,
    limits: Mapping[str, Any],
    worker_ids: set[str],
    issues: list[str],
) -> dict[str, Any]:
    consumption = dict(value) if isinstance(value, Mapping) else {}
    _exact(value, _CONSUMPTION_FIELDS, "consumption", issues)
    for field in ("logical_depth", "active_revisions", "sol_ingress_tokens", "total_tokens"):
        if not _nonnegative_integer(consumption.get(field)):
            _issue(issues, "consumption:" + field + "_invalid")
    retries = consumption.get("node_retries")
    if not isinstance(retries, Mapping):
        _issue(issues, "consumption.node_retries:not_object")
        retries = {}
    for node_id, count in sorted(retries.items(), key=lambda item: str(item[0])):
        if node_id not in worker_ids:
            _issue(issues, "consumption.node_retries:unknown_node:" + str(node_id))
        if not _nonnegative_integer(count):
            _issue(issues, "consumption.node_retries:invalid_count:" + str(node_id))
        elif _positive_integer(limits.get("max_node_retries")) and count > limits["max_node_retries"]:
            _issue(issues, "limits:node_retries_exceeded:" + str(node_id))

    status_sets: list[set[str]] = []
    for field in ("completed_node_ids", "running_node_ids", "failed_node_ids"):
        identifiers = _string_list(consumption.get(field), "consumption." + field, issues)
        for node_id in identifiers:
            if node_id not in worker_ids:
                _issue(issues, "consumption." + field + ":unknown_node:" + node_id)
        status_sets.append(set(identifiers))
    if any(status_sets[left] & status_sets[right] for left in range(3) for right in range(left + 1, 3)):
        _issue(issues, "consumption:node_status_overlap")

    comparisons = (
        ("logical_depth", "max_logical_depth"),
        ("active_revisions", "max_active_revisions"),
        ("sol_ingress_tokens", "max_sol_ingress_tokens"),
        ("total_tokens", "max_total_tokens"),
    )
    for consumed, maximum in comparisons:
        if _nonnegative_integer(consumption.get(consumed)) and _positive_integer(limits.get(maximum)):
            if consumption[consumed] > limits[maximum]:
                _issue(issues, "limits:" + consumed + "_exceeded")
    return consumption


def _validate_history(
    value: Any,
    current_plan: Mapping[str, Any],
    active_revisions: Any,
    issues: list[str],
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _issue(issues, "revision_history:not_array")
        return []
    history: list[dict[str, Any]] = []
    previous = 0
    for index, item in enumerate(value):
        path = f"revision_history[{index}]"
        _exact(item, _HISTORY_FIELDS, path, issues)
        entry = dict(item) if isinstance(item, Mapping) else {}
        revision = entry.get("revision")
        if not _positive_integer(revision):
            _issue(issues, path + ":revision_invalid")
        elif revision != previous + 1:
            _issue(issues, path + ":revision_not_contiguous")
            previous = revision
        else:
            previous = revision
        digest = entry.get("plan_sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            _issue(issues, path + ":plan_sha256_invalid")
        if not _text(entry.get("source_pointer")):
            _issue(issues, path + ":source_pointer_invalid")
        history.append(entry)
    if _nonnegative_integer(active_revisions) and len(history) != active_revisions:
        _issue(issues, "revision_history:active_revision_count_mismatch")
    if history:
        if history[-1].get("revision") != current_plan.get("revision"):
            _issue(issues, "revision_history:current_revision_mismatch")
        if history[-1].get("plan_sha256") != sha256_of(dict(current_plan)):
            _issue(issues, "revision_history:current_plan_sha256_mismatch")
    else:
        _issue(issues, "revision_history:empty")
    return history


def _validate_dispositions(
    termination: Any,
    verification: Any,
    *,
    controller_id: Any,
    root_id: Any,
    issues: list[str],
) -> str:
    _exact(termination, _DISPOSITION_FIELDS, "termination", issues)
    _exact(verification, _DISPOSITION_FIELDS, "verification", issues)
    term = termination if isinstance(termination, Mapping) else {}
    verify = verification if isinstance(verification, Mapping) else {}
    term_status = term.get("status")
    verify_status = verify.get("status")
    if term_status not in {"running", "succeeded", "failed"}:
        _issue(issues, "termination:status_invalid")
    if verify_status not in {"pending", "passed", "failed"}:
        _issue(issues, "verification:status_invalid")

    if term_status == "running":
        if any(term.get(field) is not None for field in ("decided_by", "role", "source_pointer")):
            _issue(issues, "termination:running_must_be_undecided")
    elif term_status in {"succeeded", "failed"}:
        if term.get("role") != "controller" or term.get("decided_by") != controller_id:
            _issue(issues, "termination:not_controller_decided")
        if not _text(term.get("source_pointer")):
            _issue(issues, "termination:source_pointer_invalid")

    if verify_status == "pending":
        if any(verify.get(field) is not None for field in ("decided_by", "role", "source_pointer")):
            _issue(issues, "verification:pending_must_be_undecided")
    elif verify_status in {"passed", "failed"}:
        if verify.get("role") != "sol" or verify.get("decided_by") != root_id:
            _issue(issues, "verification:not_root_sol_decided")
        if not _text(verify.get("source_pointer")):
            _issue(issues, "verification:source_pointer_invalid")
        if term_status != "succeeded":
            _issue(issues, "verification:terminal_success_required")

    if term_status == "succeeded" and verify_status == "passed":
        return "ACCEPTED"
    if term_status == "failed" or verify_status == "failed":
        return "REJECTED"
    return "PENDING"


def _validate_approval(
    value: Any,
    *,
    proposal_sha256: str,
    current_plan_sha256: str,
    root_id: Any,
    issues: list[str],
) -> dict[str, Any]:
    approval = dict(value) if isinstance(value, Mapping) else {}
    _exact(value, _APPROVAL_FIELDS, "approval", issues)
    if approval.get("status") != "approved":
        _issue(issues, "approval:not_approved")
    if approval.get("approver_role") != "sol" or approval.get("approved_by") != root_id:
        _issue(issues, "approval:not_current_root_sol")
    if approval.get("proposal_sha256") != proposal_sha256:
        _issue(issues, "approval:proposal_sha256_mismatch")
    if approval.get("base_plan_sha256") != current_plan_sha256:
        _issue(issues, "approval:base_plan_sha256_mismatch")
    if not _text(approval.get("source_pointer")):
        _issue(issues, "approval:source_pointer_invalid")
    return approval


def _validate_child_scopes(
    proposal: Mapping[str, Any],
    current_plan: Mapping[str, Any],
    issues: list[str],
) -> None:
    parent_id = proposal.get("parent_node_id")
    workers = current_plan.get("workers") if isinstance(current_plan.get("workers"), list) else []
    parent = next(
        (
            item
            for item in workers
            if isinstance(item, Mapping) and item.get("id") == parent_id
        ),
        None,
    )
    if not isinstance(parent, Mapping):
        return
    parent_scopes: list[Mapping[str, Any]] = []
    for raw in parent.get("owned_resources", []):
        try:
            parent_scopes.append(ownership.normalize_resource(raw))
        except Exception:
            _issue(issues, "scope:parent_owned_resource_invalid:" + str(raw))
    children = proposal.get("children") if isinstance(proposal.get("children"), list) else []
    for child_index, child in enumerate(children):
        if not isinstance(child, Mapping):
            continue
        for field in ("read_set", "expected_write_set"):
            entries = child.get(field) if isinstance(child.get(field), list) else []
            for entry_index, raw in enumerate(entries):
                try:
                    resource = ownership.normalize_resource(raw)
                except Exception:
                    _issue(issues, f"scope:children[{child_index}].{field}[{entry_index}]:invalid")
                    continue
                if not any(ownership.resource_contains(scope, resource) for scope in parent_scopes):
                    _issue(
                        issues,
                        f"scope:children[{child_index}].{field}[{entry_index}]:outside_parent",
                    )


def _validate_proposal_parent_state(
    proposal: Mapping[str, Any],
    current_plan: Mapping[str, Any],
    consumption: Mapping[str, Any],
    issues: list[str],
) -> None:
    """Require a live parent whose original predecessor closure is complete."""

    parent_id = proposal.get("parent_node_id")
    workers = current_plan.get("workers") if isinstance(current_plan.get("workers"), list) else []
    parent = next(
        (
            item
            for item in workers
            if isinstance(item, Mapping) and item.get("id") == parent_id
        ),
        None,
    )
    if not isinstance(parent, Mapping) or not isinstance(parent_id, str):
        return
    completed = set(consumption.get("completed_node_ids", []))
    failed = set(consumption.get("failed_node_ids", []))
    if parent_id in completed:
        _issue(issues, "proposal_gate:parent_completed:" + parent_id)
    if parent_id in failed:
        _issue(issues, "proposal_gate:parent_failed:" + parent_id)
    dependencies = parent.get("dependencies") if isinstance(parent.get("dependencies"), list) else []
    for predecessor_id in sorted(
        item for item in dependencies if isinstance(item, str) and item not in completed
    ):
        _issue(issues, "proposal_gate:parent_predecessor_incomplete:" + predecessor_id)


def _validate_proposal_budget(
    proposal: Mapping[str, Any],
    limits: Mapping[str, Any],
    consumption: Mapping[str, Any],
    issues: list[str],
) -> None:
    budget = proposal.get("budget") if isinstance(proposal.get("budget"), Mapping) else {}
    evidence = proposal.get("evidence") if isinstance(proposal.get("evidence"), Mapping) else {}
    executor_tokens = budget.get("executor_tokens")
    child_tokens = budget.get("child_tokens")
    wall_minutes = budget.get("wall_clock_minutes")
    if _nonnegative_integer(executor_tokens) and _nonnegative_integer(consumption.get("sol_ingress_tokens")):
        if _positive_integer(limits.get("max_sol_ingress_tokens")) and (
            consumption["sol_ingress_tokens"] + executor_tokens > limits["max_sol_ingress_tokens"]
        ):
            _issue(issues, "limits:proposal_sol_ingress_budget_exceeded")
    if (
        _nonnegative_integer(executor_tokens)
        and _nonnegative_integer(child_tokens)
        and _nonnegative_integer(consumption.get("total_tokens"))
        and _positive_integer(limits.get("max_total_tokens"))
        and consumption["total_tokens"] + executor_tokens + child_tokens > limits["max_total_tokens"]
    ):
        _issue(issues, "limits:proposal_total_token_budget_exceeded")
    remaining_minutes = evidence.get("budget_remaining_minutes")
    if (
        isinstance(wall_minutes, (int, float))
        and not isinstance(wall_minutes, bool)
        and isinstance(remaining_minutes, (int, float))
        and not isinstance(remaining_minutes, bool)
        and wall_minutes > remaining_minutes
    ):
        _issue(issues, "limits:proposal_exceeds_parent_remaining_budget")


def _ready_nodes(plan: Mapping[str, Any], consumption: Mapping[str, Any], *, terminal: bool) -> list[str]:
    if terminal:
        return []
    completed = set(consumption.get("completed_node_ids", []))
    unavailable = completed | set(consumption.get("running_node_ids", [])) | set(consumption.get("failed_node_ids", []))
    ready: list[str] = []
    workers = plan.get("workers") if isinstance(plan.get("workers"), list) else []
    for item in workers:
        if not isinstance(item, Mapping) or not isinstance(item.get("id"), str):
            continue
        node_id = item["id"]
        dependencies = item.get("dependencies") if isinstance(item.get("dependencies"), list) else []
        if node_id not in unavailable and set(dependencies) <= completed:
            ready.append(node_id)
    return sorted(ready)


def _validate_terminal_completion(
    plan: Mapping[str, Any],
    consumption: Mapping[str, Any],
    termination: Mapping[str, Any],
    verification: Mapping[str, Any],
    issues: list[str],
) -> None:
    if termination.get("status") != "succeeded":
        return
    if verification.get("status") != "passed":
        _issue(issues, "termination:final_verification_not_passed")
    completed = set(consumption.get("completed_node_ids", []))
    running = set(consumption.get("running_node_ids", []))
    failed = set(consumption.get("failed_node_ids", []))
    workers = plan.get("workers") if isinstance(plan.get("workers"), list) else []
    required = sorted(
        str(item.get("id"))
        for item in workers
        if isinstance(item, Mapping)
        and isinstance(item.get("id"), str)
        and item.get("optional") is False
    )
    for node_id in required:
        if node_id in failed:
            _issue(issues, "termination:required_node_failed:" + node_id)
        elif node_id in running:
            _issue(issues, "termination:required_node_running:" + node_id)
        elif node_id not in completed:
            _issue(issues, "termination:required_node_incomplete:" + node_id)


def _seal(report: dict[str, Any]) -> dict[str, Any]:
    sealed = deepcopy(report)
    sealed["report_sha256"] = sha256_of(report)
    return sealed


def evaluate_adaptive_finite_dag(program: Any) -> dict[str, Any]:
    """Evaluate one closed adaptive revision transaction without side effects."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(program, _PROGRAM_FIELDS, "program", issues)
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    controller_id = value.get("controller_id")
    if not _identifier(controller_id):
        _issue(issues, "program:controller_id_invalid")

    current_plan = value.get("current_plan") if isinstance(value.get("current_plan"), Mapping) else {}
    current_report = governor.validate_logical_plan(current_plan)
    if current_report.get("status") != "PASS":
        for item in current_report.get("issues", []):
            _issue(issues, "current_plan:" + str(item))
    current_plan_copy = deepcopy(dict(current_plan))
    active_sha = sha256_of(current_plan_copy)
    workers = current_plan.get("workers") if isinstance(current_plan.get("workers"), list) else []
    worker_ids = {
        str(item.get("id"))
        for item in workers
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }

    limits = _validate_limits(value.get("limits"), issues)
    if _positive_integer(limits.get("max_nodes")) and len(workers) > limits["max_nodes"]:
        _issue(issues, "limits:max_nodes_exceeded")
    consumption = _validate_consumption(value.get("consumption"), limits, worker_ids, issues)
    effective_consumption = deepcopy(consumption)
    projected_sol_ingress_tokens = (
        consumption.get("sol_ingress_tokens")
        if _nonnegative_integer(consumption.get("sol_ingress_tokens"))
        else None
    )
    projected_total_tokens = (
        consumption.get("total_tokens")
        if _nonnegative_integer(consumption.get("total_tokens"))
        else None
    )
    history = _validate_history(
        value.get("revision_history"),
        current_plan,
        consumption.get("active_revisions"),
        issues,
    )
    planner = current_plan.get("planner") if isinstance(current_plan.get("planner"), Mapping) else {}
    final_acceptance = _validate_dispositions(
        value.get("termination"),
        value.get("verification"),
        controller_id=controller_id,
        root_id=planner.get("root_thread_id"),
        issues=issues,
    )

    proposal = value.get("decomposition_proposal")
    approval = value.get("proposal_approval")
    decision = "NO_PROPOSAL"
    effective_plan = current_plan_copy
    effective_history = deepcopy(history)
    if proposal is None:
        if approval is not None:
            _issue(issues, "approval:present_without_proposal")
    else:
        decision = "PROPOSAL_REJECTED"
        proposal_value = proposal if isinstance(proposal, Mapping) else {}
        try:
            proposal_sha = decomposition.sha256_of(dict(proposal_value))
        except (TypeError, ValueError):
            proposal_sha = ""
            _issue(issues, "proposal:canonicalization_failed")
        proposal_report = decomposition.validate_decomposition_proposal(
            proposal,
            parent_plan=current_plan,
        )
        if proposal_report.get("status") != "PASS":
            for item in proposal_report.get("issues", []):
                _issue(issues, "proposal_gate:" + str(item))
        approval_value = _validate_approval(
            approval,
            proposal_sha256=proposal_sha,
            current_plan_sha256=active_sha,
            root_id=planner.get("root_thread_id"),
            issues=issues,
        )
        _validate_proposal_parent_state(proposal_value, current_plan, consumption, issues)
        _validate_child_scopes(proposal_value, current_plan, issues)
        _validate_proposal_budget(proposal_value, limits, consumption, issues)
        depth = consumption.get("logical_depth")
        if (
            _nonnegative_integer(depth)
            and _positive_integer(limits.get("max_logical_depth"))
            and depth + 1 > limits["max_logical_depth"]
        ):
            _issue(issues, "limits:logical_depth_exceeded_by_proposal")
        active_revisions = consumption.get("active_revisions")
        if (
            _nonnegative_integer(active_revisions)
            and _positive_integer(limits.get("max_active_revisions"))
            and active_revisions + 1 > limits["max_active_revisions"]
        ):
            _issue(issues, "limits:active_revisions_exceeded_by_proposal")

        if not issues:
            binding = decomposition.bind_replan_revision(
                current_plan,
                proposal_value,
                proposal_report,
            )
            if binding.get("status") != "PASS":
                for item in binding.get("issues", []):
                    _issue(issues, "binding:" + str(item))
            else:
                raw_successor = binding.get("successor_plan")
                retained = decomposition.verify_retained_content(binding, raw_successor)
                if retained.get("status") != "PASS":
                    for item in retained.get("issues", []):
                        _issue(issues, "retained:" + str(item))
                candidate = deepcopy(dict(raw_successor))
                if (
                    _positive_integer(limits.get("max_nodes"))
                    and candidate.get("logical_worker_count", 0) > limits["max_nodes"]
                ):
                    _issue(issues, "limits:max_nodes_exceeded_by_proposal")
                successor_report = governor.validate_logical_plan(candidate)
                if successor_report.get("status") != "PASS":
                    for item in successor_report.get("issues", []):
                        _issue(issues, "successor_plan:" + str(item))
                final_retained = decomposition.verify_retained_content(binding, candidate)
                if final_retained.get("status") != "PASS":
                    for item in final_retained.get("issues", []):
                        _issue(issues, "retained:" + str(item))
                if not issues:
                    effective_plan = candidate
                    effective_sha = sha256_of(effective_plan)
                    effective_consumption["logical_depth"] += 1
                    effective_consumption["active_revisions"] += 1
                    effective_consumption["running_node_ids"] = [
                        node_id
                        for node_id in effective_consumption["running_node_ids"]
                        if node_id != proposal_value.get("parent_node_id")
                    ]
                    budget = proposal_value["budget"]
                    projected_sol_ingress_tokens = (
                        effective_consumption["sol_ingress_tokens"]
                        + budget["executor_tokens"]
                    )
                    projected_total_tokens = (
                        effective_consumption["total_tokens"]
                        + budget["executor_tokens"]
                        + budget["child_tokens"]
                    )
                    effective_history.append(
                        {
                            "revision": effective_plan["revision"],
                            "plan_sha256": effective_sha,
                            "source_pointer": approval_value["source_pointer"],
                        }
                    )
                    decision = "REVISION_BOUND"
        if decision != "REVISION_BOUND":
            approval_is_current_root_sol = (
                isinstance(approval, Mapping)
                and approval.get("status") == "approved"
                and approval.get("approver_role") == "sol"
                and approval.get("approved_by") == planner.get("root_thread_id")
            )
            if not approval_is_current_root_sol:
                decision = "PROPOSAL_UNAPPROVED"
            elif "proposal_gate:proposal:base_revision_mismatch" in issues or (
                "approval:base_plan_sha256_mismatch" in issues
            ):
                decision = "PROPOSAL_STALE"
            elif "approval:proposal_sha256_mismatch" in issues:
                decision = "PROPOSAL_TAMPERED"
            elif any(item.startswith("scope:") for item in issues):
                decision = "SCOPE_VIOLATION"
            elif any(item.startswith("limits:") for item in issues):
                decision = "LIMIT_EXCEEDED"

    termination = value.get("termination") if isinstance(value.get("termination"), Mapping) else {}
    verification = value.get("verification") if isinstance(value.get("verification"), Mapping) else {}
    _validate_terminal_completion(
        effective_plan,
        effective_consumption,
        termination,
        verification,
        issues,
    )
    if termination.get("status") == "succeeded" and issues:
        final_acceptance = "REJECTED"
    ready = _ready_nodes(
        effective_plan,
        effective_consumption,
        terminal=termination.get("status") != "running",
    )
    report = {
        "schema": REPORT_SCHEMA,
        "plan_patch_request_schema": PLAN_PATCH_REQUEST_V1_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "decision": decision if not issues or proposal is not None else "PROGRAM_REJECTED",
        "issues": sorted(issues),
        "active_plan": current_plan_copy,
        "active_plan_sha256": active_sha,
        "active_revision": current_plan.get("revision"),
        "effective_plan": effective_plan,
        "effective_plan_sha256": sha256_of(effective_plan),
        "effective_revision": effective_plan.get("revision"),
        "effective_consumption": effective_consumption,
        "projected_sol_ingress_tokens": projected_sol_ingress_tokens,
        "projected_total_tokens": projected_total_tokens,
        "token_allocation_semantics": "reservation_not_consumption",
        "revision_history": effective_history,
        "ready_nodes": ready,
        "termination_status": termination.get("status"),
        "verification_status": verification.get("status"),
        "final_acceptance": final_acceptance,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return _seal(report)


# A descriptive alias for callers that frame the same seam as a controller.
run_adaptive_finite_dag_controller = evaluate_adaptive_finite_dag
