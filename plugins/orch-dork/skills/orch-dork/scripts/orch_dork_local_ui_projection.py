"""Bounded one-way browser projections of the watcher's existing records."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import orch_dork_governed_run_watcher as watcher
import orch_dork_live_view as live_view


def _cost(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {"billing": "unknown", "actual_cost": "unknown"}
    # This summary is already a closed projection of observed token counts,
    # never a provider transcript, raw task body, or dollar estimate.
    return {key: value[key] for key in ("schema", "billing", "actual_cost", "cap", "per_role",
                                        "estimate", "usage_status", "threads_without_usage", "text")
            if key in value}


def _node_state(lane: Mapping[str, Any]) -> tuple[str, str]:
    state = lane.get("worker_status")
    aliases = {"running": "active", "inProgress": "active",
               "interrupted": "cancelled", "errored": "failed"}
    state = aliases.get(state, state)
    if state in live_view.NODE_STATES and lane.get("worker_thread_id"):
        return state, "observed"
    return "planned", "unknown"


def project_run(run_id: str, state: Mapping[str, Any], *, request: Mapping[str, Any] | None = None,
                claim: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Keep the canonical source digest, and explicitly name missing facts.

    The caller reads only the watcher's known files and validates their seals.
    The projection is never accepted as a claim, grant, run input, or receipt.
    No task bodies, control messages, check output, or native arguments escape.
    """

    record = state.get("record") or {}
    progress = state.get("progress") or {}
    status = state.get("status") or {}
    facts = record or progress
    plan = (claim or {}).get("plan") or {}
    label = (record.get("verdict") or {}).get("label")
    digest = record.get("record_sha256") or progress.get("progress_sha256") or status.get("status_sha256")
    digest = digest or (claim or {}).get("claim_sha256")
    unknowns = []
    issues = []
    if state.get("state") in ("UNREADABLE", "UNKNOWN"):
        issues.append("run_record_unavailable")
    if digest is None:
        unknowns.append("canonical_source_not_observed")
    root_id = facts.get("governed_thread_id") or status.get("governed_thread_id")
    requested_model = (request or {}).get("model") or facts.get("model")
    observed_model = facts.get("observed_model")
    if observed_model is None:
        unknowns.append("root_model_not_observed")
    if observed_model is not None and requested_model is not None and observed_model != requested_model:
        issues.append("root:model_differs_from_plan")
    root_state = {watcher.VERIFIED: "completed", watcher.FAILED_CHECKS: "failed",
                  watcher.INTERRUPTED: "blocked", watcher.STOPPED: "cancelled",
                  watcher.REFUSED: "blocked"}.get(label)
    if root_state is None:
        root_state = {"RUNNING": "active", "CHECKING": "integrating",
                      "AWAITING_REVISION": "waiting", "STARTING": "planned"}.get(state.get("state"), "planned")
    if not root_id:
        unknowns.append("root_task_not_observed")
    nodes = [{"id": "root", "objective": "Governed root", "state": root_state,
              "planned_model": requested_model, "observed_model": observed_model,
              "evidence_class": ("contradictory" if "root:model_differs_from_plan" in issues
                                 else "observed" if root_id else "submitted"),
              "evidence_tier": "runtime-observed" if root_id else "submitted"}]
    observed_lanes = {row.get("id"): row for row in facts.get("lanes") or [] if isinstance(row, Mapping)}
    planned_lanes = (request or {}).get("lanes") or facts.get("lanes") or []
    edges = []
    for lane in planned_lanes:
        lane_id = lane.get("id")
        if not isinstance(lane_id, str):
            continue
        observed = observed_lanes.get(lane_id) or {}
        node_state, evidence_class = _node_state(observed)
        if evidence_class == "unknown":
            unknowns.append("lane:" + lane_id + ":state_not_observed")
        if observed.get("overclaim") is True:
            evidence_class = "contradictory"
            issues.append("lane:" + lane_id + ":overclaim")
        worker_model = (request or {}).get("worker_model") or facts.get("worker_model")
        actual_model = observed.get("observed_model")
        if actual_model is None:
            unknowns.append("lane:" + lane_id + ":model_not_observed")
        elif worker_model is not None and actual_model != worker_model:
            evidence_class = "contradictory"
            issues.append("lane:" + lane_id + ":model_differs_from_plan")
        nodes.append({"id": lane_id, "objective": "Lane " + lane_id, "state": node_state,
                      "planned_model": worker_model, "observed_model": actual_model,
                      "evidence_class": evidence_class,
                      "evidence_tier": "runtime-observed" if observed.get("worker_thread_id") else "submitted"})
        spawned = bool(observed.get("worker_thread_id"))
        closed = observed.get("worker_closed") is True
        edges.extend([
            {"id": "spawn:" + lane_id, "from": "root", "to": lane_id,
             "state": "observed" if spawned else "planned",
             "evidence_class": "observed" if spawned else "submitted",
             "evidence_tier": "runtime-observed" if spawned else "submitted"},
            {"id": "join:" + lane_id, "from": lane_id, "to": "root",
             "state": "released" if closed else ("active" if spawned else "planned"),
             "evidence_class": "observed" if closed else "unknown",
             "evidence_tier": "runtime-observed" if closed else "submitted"},
        ])
    cross_check = record.get("cross_check") or {}
    if cross_check.get("status") == "DISAGREED":
        issues.append("owner_and_hooks_disagree")
    contradictions = [item for item in issues if item.endswith((":overclaim", ":model_differs_from_plan"))
                      or item == "owner_and_hooks_disagree"]
    tier = "runtime-observed" if facts else "submitted"
    graph = {"root": {"id": "root", "task_id": root_id,
                      "planned_model": requested_model, "observed_model": observed_model},
             "nodes": nodes, "edges": edges, "canonical_digest": digest, "evidence_tier": tier,
             "plan_digest": facts.get("plan_sha256") or plan.get("plan_sha256"),
             "issues": issues, "unknowns": unknowns, "contradictions": contradictions,
             "raw_evidence": "Host-local governed run record; authoritative if this view disagrees.",
             "minimum_states": sorted(live_view.NODE_STATES),
             "evidence_classes": sorted(live_view.EVIDENCE_CLASSES)}
    return {"schema": "orch-dork/local-ui-run/v1", "run_id": run_id, "state": state.get("state"),
            "verdict": label, "reason": (record.get("verdict") or {}).get("reason"),
            "steered_by_you": bool((record.get("verdict") or {}).get("steered_by_you") or progress.get("steers")),
            "cost": _cost(record.get("cost")), "revision": facts.get("revision", 1),
            "location": facts.get("location") or status.get("location"),
            "canonical_digest": digest, "evidence_tier": tier, "graph": graph,
            "issues": issues, "unknowns": unknowns,
            "project": Path((request or {}).get("project_root") or record.get("project_root") or "unknown").name,
            "started_at": record.get("started_at") or facts.get("started_at"),
            "ended_at": record.get("ended_at")}


def dashboard_row(run: Mapping[str, Any]) -> dict[str, Any]:
    return {key: run.get(key) for key in ("run_id", "state", "verdict", "project", "started_at",
                                         "ended_at", "cost", "canonical_digest")}


def plan_view(request: Mapping[str, Any], plan: Mapping[str, Any]) -> dict[str, Any]:
    """A submitted preview of the frozen plan; it grants no approval."""

    digest = plan["plan_sha256"]
    view = project_run("plan-" + digest, {"state": "AWAITING_APPROVAL"},
                       request=request, claim={"plan": plan})
    view["canonical_digest"] = digest
    view["graph"]["canonical_digest"] = digest
    view["unknowns"].remove("canonical_source_not_observed")
    view["graph"]["raw_evidence"] = "Frozen plan; approval remains in the requesting chat."
    return view
