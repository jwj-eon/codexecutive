#!/usr/bin/env python3
"""Event-driven ready-queue evaluation (north star P2).

A node becomes runnable the moment its dependencies are satisfied; nothing
waits for a nominal wave barrier.  This evaluator is deterministic and
read-only: given declared nodes and observed results it reports what is
dispatchable now, in what priority order, and what is transitively blocked
by failure.  It launches nothing and never touches live capacity.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from typing import Any

PROGRAM_SCHEMA = "orch-dork/ready-queue-program/v1"
REPORT_SCHEMA = "orch-dork/ready-queue-report/v1"

STATUSES = {"pending", "running", "completed", "failed", "cancelled", "timed_out"}
FAILED_STATUSES = {"failed", "cancelled", "timed_out"}

_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")

NODE_FIELDS = {
    "id",
    "dependencies",
    "predicted_minutes",
    "downstream_unblocked",
    "critical_path_weight",
    "confidence",
    "write_overlap_risk",
    "relay_cost_minutes",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, keys: set[str], label: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return False
    for key in sorted(keys - set(value)):
        _issue(issues, label + ":missing:" + str(key))
    for key in sorted(set(value) - keys):
        _issue(issues, label + ":unknown:" + str(key))
    return set(value) == keys


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def evaluate_ready_queue(program: Any) -> dict[str, Any]:
    """Report dispatchable, waiting, running, blocked, and completed nodes."""

    issues: list[str] = []
    value = program if isinstance(program, Mapping) else {}
    _exact(value, {"schema", "nodes", "results", "free_slots", "now_revision"}, "program", issues)
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    free_slots = value.get("free_slots")
    if type(free_slots) is not int or free_slots < 0:
        _issue(issues, "program:free_slots_invalid")
        free_slots = 0
    now_revision = value.get("now_revision")
    if type(now_revision) is not int or now_revision < 1:
        _issue(issues, "program:now_revision_invalid")

    raw_nodes = value.get("nodes")
    if not isinstance(raw_nodes, list):
        _issue(issues, "nodes:not_array")
        raw_nodes = []
    node_ids: list[str] = []
    dependencies: dict[str, list[str]] = {}
    priorities: dict[str, float] = {}
    for index, raw in enumerate(raw_nodes):
        label = f"nodes[{index}]"
        if not _exact(raw, NODE_FIELDS, label, issues):
            continue
        node_id = raw.get("id")
        if not isinstance(node_id, str) or _IDENTIFIER.fullmatch(node_id) is None:
            _issue(issues, label + ":id_invalid")
            continue
        if node_id in dependencies:
            _issue(issues, "nodes:duplicate_ids")
            continue
        node_ids.append(node_id)
        deps = raw.get("dependencies")
        if not isinstance(deps, list) or any(not isinstance(d, str) for d in deps):
            _issue(issues, label + ".dependencies:not_array")
            deps = []
        if node_id in deps:
            _issue(issues, f"nodes:{node_id}:self_dependency")
        dependencies[node_id] = list(deps)
        predicted = raw.get("predicted_minutes")
        if not _number(predicted) or predicted <= 0:
            _issue(issues, label + ":predicted_minutes_invalid")
            predicted = 1.0
        downstream = raw.get("downstream_unblocked")
        if type(downstream) is not int or downstream < 0:
            _issue(issues, label + ":downstream_unblocked_invalid")
            downstream = 0
        cpw = raw.get("critical_path_weight")
        if not _number(cpw) or cpw < 0:
            _issue(issues, label + ":critical_path_weight_invalid")
            cpw = 0.0
        confidence = raw.get("confidence")
        if not _number(confidence) or not 0 <= confidence <= 1:
            _issue(issues, label + ":confidence_invalid")
            confidence = 0.0
        risk = raw.get("write_overlap_risk")
        if not _number(risk) or not 0 <= risk <= 1:
            _issue(issues, label + ":write_overlap_risk_invalid")
            risk = 1.0
        relay = raw.get("relay_cost_minutes")
        if not _number(relay) or relay < 0:
            _issue(issues, label + ":relay_cost_minutes_invalid")
            relay = 0.0
        priority = (1 + downstream) * (0.5 + cpw) * confidence / (predicted + relay + 1)
        priority *= 1 - 0.5 * risk
        priorities[node_id] = round(priority, 6)

    known = set(node_ids)
    for node_id, deps in dependencies.items():
        for dep in deps:
            if dep not in known:
                _issue(issues, f"nodes:{node_id}:unknown_dependency:{dep}")

    indegree = {node_id: 0 for node_id in known}
    for node_id, deps in dependencies.items():
        for dep in deps:
            if dep in indegree:
                indegree[node_id] += 1
    queue = sorted(n for n, d in indegree.items() if d == 0)
    order: list[str] = []
    remaining = dict(indegree)
    while queue:
        current = queue.pop(0)
        order.append(current)
        for node_id, deps in dependencies.items():
            if current in deps:
                remaining[node_id] -= 1
                if remaining[node_id] == 0:
                    queue.append(node_id)
        queue.sort()
    if len(order) != len(known):
        cycle = sorted(known - set(order))
        _issue(issues, "nodes:cycle:" + ",".join(cycle))

    raw_results = value.get("results")
    if not isinstance(raw_results, list):
        _issue(issues, "results:not_array")
        raw_results = []
    statuses = {node_id: "pending" for node_id in known}
    for index, raw in enumerate(raw_results):
        label = f"results[{index}]"
        if not _exact(raw, {"node_id", "status"}, label, issues):
            continue
        node_id = raw.get("node_id")
        status = raw.get("status")
        if node_id not in known:
            _issue(issues, label + ":unknown_node")
            continue
        if status not in STATUSES:
            _issue(issues, label + ":status_invalid")
            continue
        statuses[str(node_id)] = str(status)

    if issues:
        core = {
            "schema": REPORT_SCHEMA,
            "status": "FAIL",
            "issues": sorted(set(issues)),
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
        return {**core, "report_sha256": _sha256(core)}

    failed = {n for n, s in statuses.items() if s in FAILED_STATUSES}
    completed = sorted(n for n, s in statuses.items() if s == "completed")
    blocked_by: dict[str, set[str]] = {n: set() for n in known}
    changed = True
    while changed:
        changed = False
        for node_id, deps in dependencies.items():
            before = set(blocked_by[node_id])
            for dep in deps:
                if dep in failed:
                    blocked_by[node_id].add(dep)
                blocked_by[node_id].update(blocked_by.get(dep, set()))
            if blocked_by[node_id] != before:
                changed = True
    blocked = [
        {"node_id": node_id, "failed_ancestor_ids": sorted(ancestors)}
        for node_id, ancestors in sorted(blocked_by.items())
        if ancestors and statuses[node_id] not in FAILED_STATUSES and statuses[node_id] != "completed"
    ]
    blocked_ids = {item["node_id"] for item in blocked}
    completed_set = set(completed)
    ready = [
        {"id": node_id, "priority": priorities[node_id]}
        for node_id in sorted(known)
        if statuses[node_id] == "pending"
        and node_id not in blocked_ids
        and set(dependencies[node_id]) <= completed_set
    ]
    ready.sort(key=lambda item: (-item["priority"], item["id"]))
    running = sorted(n for n, s in statuses.items() if s == "running")
    pending_unready = sorted(
        n
        for n, s in statuses.items()
        if s == "pending" and n not in blocked_ids and not set(dependencies[n]) <= completed_set
    )
    failed_list = sorted(failed)
    core = {
        "schema": REPORT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "now_revision": now_revision,
        "free_slots": free_slots,
        "ready": ready,
        "dispatch_now": ready[:free_slots],
        "ready_waiting": ready[free_slots:],
        "running": running,
        "blocked": blocked,
        "pending_unready": pending_unready,
        "completed": completed,
        "failed": failed_list,
        "counts": {
            "total": len(known),
            "ready": len(ready),
            "running": len(running),
            "blocked": len(blocked),
            "pending_unready": len(pending_unready),
            "completed": len(completed),
            "failed": len(failed_list),
        },
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "report_sha256": _sha256(core)}
