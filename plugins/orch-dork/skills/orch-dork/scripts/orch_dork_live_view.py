#!/usr/bin/env python3
"""Provider-free live graph projection for Orch Dork.

The input is a frozen planned graph and a complete append-only event prefix.
This module renders only closed structural facts, telemetry, and stable source
pointers. It never reads task/session bodies or reconstructs private reasoning.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence


PROGRAM_SCHEMA = "orch-dork/live-view-program/v1"
PLAN_SCHEMA = "orch-dork/live-view-plan/v1"
REPORT_SCHEMA = "orch-dork/live-view-report/v1"
POLICY_VERSION = "live-view-policy/v1"

NODE_STATES = {
    "planned",
    "active",
    "waiting",
    "completed",
    "failed",
    "cancelled",
    "timed_out",
    "unreleased",
    "released",
    "integrating",
    "blocked",
}
EDGE_STATES = {"planned", "observed", "active", "satisfied", "released", "blocked", "failed"}
EVIDENCE_CLASSES = {"observed", "inferred", "submitted", "unknown", "contradictory"}
EVIDENCE_TIERS = {"submitted", "runtime-observed", "sealed-runtime"}
EVENT_TYPES = {
    "root.observed",
    "node.observed",
    "node.state",
    "edge.state",
    "ownership.state",
    "verification.state",
    "release.observed",
    "metrics.observed",
    "usage.observed",
    "qualification.observed",
}
FORBIDDEN_KEYS = {
    "conversation",
    "messages",
    "prompt",
    "raw_session_body",
    "reasoning",
    "private_reasoning",
    "chain_of_thought",
    "credentials",
    "password",
    "authorization_secret",
    "access_token",
    "api_key",
}
RAW_USAGE_DIMENSIONS = (
    "uncached_input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_tokens",
)

_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


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


def _issue(issues: list[str], issue: str) -> None:
    if issue not in issues:
        issues.append(issue)


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


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 4096


def _optional_pointer(value: Any, path: str, issues: list[str]) -> str | None:
    if value is None:
        return None
    if not _text(value):
        _issue(issues, f"{path}:invalid")
        return None
    return str(value)


def _string_list(value: Any, path: str, issues: list[str], *, empty: bool = True) -> list[str]:
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
            result.append(str(item).strip())
    if len(result) != len(set(result)):
        _issue(issues, f"{path}:duplicates")
    return result


def _reject_forbidden_keys(value: Any, path: str, issues: list[str]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in FORBIDDEN_KEYS:
                _issue(issues, f"privacy:forbidden_field:{path}.{key}")
            _reject_forbidden_keys(item, f"{path}.{key}", issues)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_forbidden_keys(item, f"{path}[{index}]", issues)


def _usage_fact(value: Any, path: str, issues: list[str]) -> dict[str, Any]:
    _exact(value, {"status", *RAW_USAGE_DIMENSIONS, "reason", "source_pointer"}, path, issues)
    item = value if isinstance(value, Mapping) else {}
    if item.get("status") == "known":
        for dimension in RAW_USAGE_DIMENSIONS:
            amount = item.get(dimension)
            if type(amount) is not int or amount < 0:
                _issue(issues, f"{path}:{dimension}_invalid")
        if item.get("reason") is not None:
            _issue(issues, f"{path}:known_has_reason")
    elif item.get("status") == "unknown":
        if any(item.get(dimension) is not None for dimension in RAW_USAGE_DIMENSIONS):
            _issue(issues, f"{path}:unknown_has_values")
        if not _text(item.get("reason")):
            _issue(issues, f"{path}:unknown_reason_invalid")
    else:
        _issue(issues, f"{path}:status_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, f"{path}:source_pointer_invalid")
    return dict(item)


def _scalar_fact(value: Any, path: str, unit: str, issues: list[str]) -> dict[str, Any]:
    _exact(value, {"status", "value", "unit", "reason", "source_pointer"}, path, issues)
    item = value if isinstance(value, Mapping) else {}
    if item.get("unit") != unit:
        _issue(issues, f"{path}:unit_invalid")
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


def _validate_plan(plan: Any, issues: list[str]) -> tuple[dict[str, Any], str, dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    _exact(
        plan,
        {"schema", "plan_id", "revision", "plan_sha256", "root", "nodes", "edges", "source_pointer"},
        "plan",
        issues,
    )
    value = plan if isinstance(plan, Mapping) else {}
    if value.get("schema") != PLAN_SCHEMA:
        _issue(issues, "plan:schema_invalid")
    if not _identifier(value.get("plan_id")):
        _issue(issues, "plan:plan_id_invalid")
    if type(value.get("revision")) is not int or value.get("revision", 0) < 1:
        _issue(issues, "plan:revision_invalid")
    if not _text(value.get("source_pointer")):
        _issue(issues, "plan:source_pointer_invalid")

    root = value.get("root")
    _exact(root, {"root_id", "model", "effort", "task_pointer"}, "plan.root", issues)
    root_value = root if isinstance(root, Mapping) else {}
    for field in ("root_id", "model", "effort"):
        if not _identifier(root_value.get(field)):
            _issue(issues, f"plan.root:{field}_invalid")
    _optional_pointer(root_value.get("task_pointer"), "plan.root.task_pointer", issues)

    nodes_value = value.get("nodes")
    if not isinstance(nodes_value, list) or not nodes_value:
        _issue(issues, "plan.nodes:not_nonempty_array")
        nodes_value = []
    nodes: dict[str, dict[str, Any]] = {}
    for index, node in enumerate(nodes_value):
        path = f"plan.nodes[{index}]"
        _exact(
            node,
            {"node_id", "objective", "model", "effort", "owned_resources", "checks", "task_pointer"},
            path,
            issues,
        )
        item = node if isinstance(node, Mapping) else {}
        node_id = item.get("node_id")
        if not _identifier(node_id) or node_id in nodes:
            _issue(issues, f"{path}:node_id_invalid_or_duplicate")
        elif isinstance(node_id, str):
            nodes[node_id] = dict(item)
        for field in ("objective", "model", "effort"):
            if not _text(item.get(field)):
                _issue(issues, f"{path}:{field}_invalid")
        _string_list(item.get("owned_resources"), f"{path}.owned_resources", issues)
        _string_list(item.get("checks"), f"{path}.checks", issues)
        _optional_pointer(item.get("task_pointer"), f"{path}.task_pointer", issues)

    edges_value = value.get("edges")
    if not isinstance(edges_value, list):
        _issue(issues, "plan.edges:not_array")
        edges_value = []
    edges: dict[str, dict[str, Any]] = {}
    for index, edge in enumerate(edges_value):
        path = f"plan.edges[{index}]"
        _exact(edge, {"edge_id", "type", "source", "target"}, path, issues)
        item = edge if isinstance(edge, Mapping) else {}
        edge_id = item.get("edge_id")
        if not _identifier(edge_id) or edge_id in edges:
            _issue(issues, f"{path}:edge_id_invalid_or_duplicate")
        elif isinstance(edge_id, str):
            edges[edge_id] = dict(item)
        if item.get("type") not in {"dependency", "artifact", "release", "integration"}:
            _issue(issues, f"{path}:type_invalid")
        if item.get("source") not in nodes:
            _issue(issues, f"{path}:source_unknown")
        if item.get("target") not in nodes:
            _issue(issues, f"{path}:target_unknown")

    plan_sha = value.get("plan_sha256")
    plan_core = {key: item for key, item in value.items() if key != "plan_sha256"}
    computed_sha = _sha256(plan_core)
    if plan_sha != computed_sha:
        _issue(issues, "plan:plan_sha256_mismatch")
    return dict(root_value), computed_sha, nodes, edges


def _validate_event(
    event: Any,
    index: int,
    node_ids: set[str],
    edge_ids: set[str],
    root_id: str | None,
    event_ids: set[str],
    issues: list[str],
) -> dict[str, Any]:
    path = f"stream.events[{index}]"
    _exact(
        event,
        {"seq", "event_id", "type", "node_id", "edge_id", "evidence_class", "evidence_tier", "source_pointer", "payload"},
        path,
        issues,
    )
    item = event if isinstance(event, Mapping) else {}
    if item.get("seq") != index + 1:
        _issue(issues, f"{path}:sequence_invalid")
    event_id = item.get("event_id")
    if not _identifier(event_id) or event_id in event_ids:
        _issue(issues, f"{path}:event_id_invalid_or_duplicate")
    elif isinstance(event_id, str):
        event_ids.add(event_id)
    event_type = item.get("type")
    if event_type not in EVENT_TYPES:
        _issue(issues, f"{path}:type_invalid")
    evidence_class = item.get("evidence_class")
    evidence_tier = item.get("evidence_tier")
    if evidence_class not in EVIDENCE_CLASSES:
        _issue(issues, f"{path}:evidence_class_invalid")
    if evidence_tier not in EVIDENCE_TIERS:
        _issue(issues, f"{path}:evidence_tier_invalid")
    if evidence_class == "submitted" and evidence_tier != "submitted":
        _issue(issues, f"{path}:submitted_tier_mismatch")
    if evidence_class == "observed" and evidence_tier == "submitted":
        _issue(issues, f"{path}:observed_tier_mismatch")
    if not _text(item.get("source_pointer")):
        _issue(issues, f"{path}:source_pointer_invalid")

    node_id = item.get("node_id")
    edge_id = item.get("edge_id")
    node_types = {"node.observed", "node.state", "ownership.state", "verification.state"}
    if event_type in node_types:
        if node_id not in node_ids:
            _issue(issues, f"{path}:node_id_unknown")
        if edge_id is not None:
            _issue(issues, f"{path}:unexpected_edge_id")
    elif event_type == "edge.state":
        if edge_id not in edge_ids:
            _issue(issues, f"{path}:edge_id_unknown")
        if node_id is not None:
            _issue(issues, f"{path}:unexpected_node_id")
    elif event_type == "release.observed":
        if edge_id not in edge_ids:
            _issue(issues, f"{path}:edge_id_unknown")
        if node_id is not None:
            _issue(issues, f"{path}:unexpected_node_id")
    elif node_id is not None or edge_id is not None:
        _issue(issues, f"{path}:unexpected_node_or_edge_id")

    payload = item.get("payload")
    if event_type == "root.observed":
        _exact(payload, {"root_id", "model", "effort", "task_pointer"}, f"{path}.payload", issues)
        payload_value = payload if isinstance(payload, Mapping) else {}
        for field in ("root_id", "model", "effort"):
            if not _identifier(payload_value.get(field)):
                _issue(issues, f"{path}.payload:{field}_invalid")
        _optional_pointer(payload_value.get("task_pointer"), f"{path}.payload.task_pointer", issues)
    elif event_type == "node.observed":
        _exact(payload, {"worker_id", "model", "effort", "task_pointer"}, f"{path}.payload", issues)
        payload_value = payload if isinstance(payload, Mapping) else {}
        for field in ("worker_id", "model", "effort"):
            if not _identifier(payload_value.get(field)):
                _issue(issues, f"{path}.payload:{field}_invalid")
        _optional_pointer(payload_value.get("task_pointer"), f"{path}.payload.task_pointer", issues)
    elif event_type == "node.state":
        _exact(payload, {"state"}, f"{path}.payload", issues)
        payload_value = payload if isinstance(payload, Mapping) else {}
        if payload_value.get("state") not in NODE_STATES - {"planned"}:
            _issue(issues, f"{path}.payload:state_invalid")
    elif event_type == "edge.state":
        _exact(payload, {"state"}, f"{path}.payload", issues)
        payload_value = payload if isinstance(payload, Mapping) else {}
        if payload_value.get("state") not in EDGE_STATES - {"planned"}:
            _issue(issues, f"{path}.payload:state_invalid")
    elif event_type == "ownership.state":
        _exact(payload, {"resource", "state"}, f"{path}.payload", issues)
        payload_value = payload if isinstance(payload, Mapping) else {}
        if not _text(payload_value.get("resource")):
            _issue(issues, f"{path}.payload:resource_invalid")
        if payload_value.get("state") not in {"owned", "unreleased", "released", "violation"}:
            _issue(issues, f"{path}.payload:state_invalid")
    elif event_type == "verification.state":
        _exact(payload, {"check_id", "outcome"}, f"{path}.payload", issues)
        payload_value = payload if isinstance(payload, Mapping) else {}
        if not _text(payload_value.get("check_id")):
            _issue(issues, f"{path}.payload:check_id_invalid")
        if payload_value.get("outcome") not in {"PASS", "FAIL", "UNKNOWN", "PENDING"}:
            _issue(issues, f"{path}.payload:outcome_invalid")
    elif event_type == "release.observed":
        _exact(
            payload,
            {"from_node_id", "to_node_id", "owner_worker_id", "target_worker_id"},
            f"{path}.payload",
            issues,
        )
        payload_value = payload if isinstance(payload, Mapping) else {}
        for field in ("from_node_id", "to_node_id"):
            if payload_value.get(field) not in node_ids:
                _issue(issues, f"{path}.payload:{field}_unknown")
        for field in ("owner_worker_id", "target_worker_id"):
            if not _identifier(payload_value.get(field)):
                _issue(issues, f"{path}.payload:{field}_invalid")
    elif event_type == "metrics.observed":
        _exact(payload, {"wall_time", "maximum_overlap"}, f"{path}.payload", issues)
        payload_value = payload if isinstance(payload, Mapping) else {}
        _scalar_fact(payload_value.get("wall_time"), f"{path}.payload.wall_time", "milliseconds", issues)
        _scalar_fact(payload_value.get("maximum_overlap"), f"{path}.payload.maximum_overlap", "workers", issues)
    elif event_type == "usage.observed":
        _exact(payload, {"subject_id", "usage"}, f"{path}.payload", issues)
        payload_value = payload if isinstance(payload, Mapping) else {}
        if payload_value.get("subject_id") not in node_ids | ({root_id} if root_id else set()):
            _issue(issues, f"{path}.payload:subject_id_unknown")
        _usage_fact(payload_value.get("usage"), f"{path}.payload.usage", issues)
    elif event_type == "qualification.observed":
        _exact(payload, {"status", "issues", "unknowns", "report_pointer"}, f"{path}.payload", issues)
        payload_value = payload if isinstance(payload, Mapping) else {}
        if payload_value.get("status") not in {"ACTIVE", "PASS", "FAIL", "BLOCKED", "UNKNOWN"}:
            _issue(issues, f"{path}.payload:status_invalid")
        _string_list(payload_value.get("issues"), f"{path}.payload.issues", issues)
        _string_list(payload_value.get("unknowns"), f"{path}.payload.unknowns", issues)
        _optional_pointer(payload_value.get("report_pointer"), f"{path}.payload.report_pointer", issues)
    return dict(item)


def _markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _link(label: str, pointer: str | None) -> str:
    if pointer is None:
        return "unavailable"
    safe_label = label.replace("[", "(").replace("]", ")")
    safe_pointer = pointer.replace(" ", "%20")
    return f"[{safe_label}]({safe_pointer})"


def _render_mermaid(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> str:
    identifiers = {node["node_id"]: f"n{index}" for index, node in enumerate(nodes)}
    lines = ["flowchart LR"]
    for node in nodes:
        key = identifiers[node["node_id"]]
        state = node["state"]
        label = f"{node['node_id']}<br/>{state}<br/>{node['evidence_class']}"
        lines.append(f'  {key}["{label}"]')
        lines.append(f"  class {key} state_{state}")
    for edge in edges:
        source = identifiers.get(edge["source"])
        target = identifiers.get(edge["target"])
        if source is None or target is None:
            continue
        if edge["state"] == "planned":
            lines.append(f"  {source} -.-> {target}")
        else:
            lines.append(f"  {source} --> {target}")
    colors = {
        "planned": "#e5e7eb",
        "active": "#bfdbfe",
        "waiting": "#fde68a",
        "completed": "#bbf7d0",
        "failed": "#fecaca",
        "cancelled": "#d1d5db",
        "timed_out": "#fed7aa",
        "unreleased": "#ddd6fe",
        "released": "#c7d2fe",
        "integrating": "#a5f3fc",
        "blocked": "#fca5a5",
    }
    for state, color in colors.items():
        lines.append(f"  classDef state_{state} fill:{color},stroke:#374151,color:#111827")
    return "\n".join(lines)


def _render_markdown(
    view_id: Any,
    cursor: int,
    stream_status: Any,
    root: dict[str, Any],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    metrics: dict[str, Any],
    release_order: list[dict[str, Any]],
    qualification: dict[str, Any],
    navigation: list[dict[str, str]],
) -> str:
    lines = [
        "# Orch Dork live graph",
        "",
        f"View `{view_id}` at append-only cursor `{cursor}` (`{stream_status}`).",
        "",
        "```mermaid",
        _render_mermaid(nodes, edges),
        "```",
        "",
        "## Planned and observed workers",
        "",
        "| Node | State | Planned identity | Observed identity | Ownership | Verification | Evidence |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for node in nodes:
        planned = f"{node['planned_model']}/{node['planned_effort']}"
        observed = "unknown"
        if node.get("observed_worker_id"):
            observed = f"{node['observed_worker_id']} {node.get('observed_model')}/{node.get('observed_effort')}"
        ownership = ", ".join(f"{row['resource']}={row['state']}" for row in node["ownership"]) or "none"
        checks = ", ".join(f"{row['check_id']}={row['outcome']}" for row in node["verification"]) or "none"
        evidence = f"{node['evidence_class']} / {node['evidence_tier']}"
        lines.append(
            "| "
            + " | ".join(
                _markdown_escape(value)
                for value in (node["node_id"], node["state"], planned, observed, ownership, checks, evidence)
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Root and telemetry",
            "",
            f"Root: `{root.get('planned_root_id')}` planned `{root.get('planned_model')}/{root.get('planned_effort')}`; "
            f"observed `{root.get('observed_root_id') or 'unknown'}` `{root.get('observed_model') or 'unknown'}/{root.get('observed_effort') or 'unknown'}`.",
            "",
            f"Wall time: `{metrics['wall_time'].get('value')}` ms ({metrics['wall_time'].get('status')}); "
            f"maximum overlap: `{metrics['maximum_overlap'].get('value')}` workers ({metrics['maximum_overlap'].get('status')}).",
            "",
            "Token split: "
            + (", ".join(
                f"`{row['subject_id']}`={row['total_tokens'] if row['status'] == 'known' else 'unknown'}"
                for row in metrics["token_split"]
            ) or "none"),
            "",
            "Release order: "
            + (" → ".join(f"`{row['from_node_id']}`→`{row['to_node_id']}`" for row in release_order) or "none"),
            "",
            f"Qualification: `{qualification.get('status')}`; issues `{len(qualification.get('issues', []))}`; unknowns `{len(qualification.get('unknowns', []))}`.",
            "",
            "## Navigation",
            "",
        ]
    )
    for item in navigation:
        lines.append(f"- {_link(item['label'], item['pointer'])}")
    lines.extend(
        [
            "",
            "## Evidence certainty",
            "",
            "`observed` is runtime-backed, `submitted` is declared, `inferred` is derived, "
            "`unknown` is missing, and `contradictory` is a failure. Stable source pointers are shown above.",
            "",
            "Private chain-of-thought is unavailable and is neither displayed nor inferred.",
        ]
    )
    return "\n".join(lines) + "\n"


def project_live_view(program: Any) -> dict[str, Any]:
    """Validate and project one append-only live orchestration snapshot."""

    issues: list[str] = []
    contradictions: list[str] = []
    unknowns: list[str] = []
    _reject_forbidden_keys(program, "$", issues)
    _exact(program, {"schema", "view_id", "mode", "policy_version", "plan", "previous", "stream"}, "program", issues)
    value = program if isinstance(program, Mapping) else {}
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    if not _identifier(value.get("view_id")):
        _issue(issues, "program:view_id_invalid")
    if value.get("mode") not in {"advisory", "governed"}:
        _issue(issues, "program:mode_invalid")
    if value.get("policy_version") != POLICY_VERSION:
        _issue(issues, "program:policy_version_invalid")

    root_plan, plan_sha, planned_nodes, planned_edges = _validate_plan(value.get("plan"), issues)
    previous = value.get("previous")
    _exact(previous, {"cursor", "events_sha256", "source_pointer"}, "previous", issues)
    previous_value = previous if isinstance(previous, Mapping) else {}
    previous_cursor = previous_value.get("cursor")
    if type(previous_cursor) is not int or previous_cursor < 0:
        _issue(issues, "previous:cursor_invalid")
        previous_cursor = 0
    previous_sha = previous_value.get("events_sha256")
    if not isinstance(previous_sha, str) or _SHA256.fullmatch(previous_sha) is None:
        _issue(issues, "previous:events_sha256_invalid")
    if not _text(previous_value.get("source_pointer")):
        _issue(issues, "previous:source_pointer_invalid")

    stream = value.get("stream")
    _exact(stream, {"status", "events", "source_pointer"}, "stream", issues)
    stream_value = stream if isinstance(stream, Mapping) else {}
    if stream_value.get("status") not in {"open", "closed"}:
        _issue(issues, "stream:status_invalid")
    if not _text(stream_value.get("source_pointer")):
        _issue(issues, "stream:source_pointer_invalid")
    events_value = stream_value.get("events")
    if not isinstance(events_value, list):
        _issue(issues, "stream.events:not_array")
        events_value = []
    events: list[dict[str, Any]] = []
    event_ids: set[str] = set()
    for index, event in enumerate(events_value):
        events.append(
            _validate_event(
                event,
                index,
                set(planned_nodes),
                set(planned_edges),
                root_plan.get("root_id") if isinstance(root_plan.get("root_id"), str) else None,
                event_ids,
                issues,
            )
        )
    if previous_cursor > len(events):
        _issue(issues, "previous:cursor_ahead_of_stream")
    elif previous_sha != _sha256(events[:previous_cursor]):
        _issue(issues, "stream:append_only_prefix_mismatch")
    events_sha = _sha256(events)

    root_view = {
        "planned_root_id": root_plan.get("root_id"),
        "planned_model": root_plan.get("model"),
        "planned_effort": root_plan.get("effort"),
        "planned_task_pointer": root_plan.get("task_pointer"),
        "observed_root_id": None,
        "observed_model": None,
        "observed_effort": None,
        "observed_task_pointer": None,
        "evidence_class": "submitted",
        "evidence_tier": "submitted",
        "source_pointer": (value.get("plan") or {}).get("source_pointer") if isinstance(value.get("plan"), Mapping) else None,
    }
    node_views: dict[str, dict[str, Any]] = {
        node_id: {
            "node_id": node_id,
            "objective": node.get("objective"),
            "state": "planned",
            "planned_model": node.get("model"),
            "planned_effort": node.get("effort"),
            "planned_owned_resources": list(node.get("owned_resources", [])),
            "planned_checks": list(node.get("checks", [])),
            "planned_task_pointer": node.get("task_pointer"),
            "observed_worker_id": None,
            "observed_model": None,
            "observed_effort": None,
            "observed_task_pointer": None,
            "ownership": [],
            "verification": [],
            "evidence_class": "submitted",
            "evidence_tier": "submitted",
            "source_pointer": (value.get("plan") or {}).get("source_pointer") if isinstance(value.get("plan"), Mapping) else None,
        }
        for node_id, node in planned_nodes.items()
    }
    edge_views: dict[str, dict[str, Any]] = {
        edge_id: {
            **edge,
            "state": "planned",
            "evidence_class": "submitted",
            "evidence_tier": "submitted",
            "source_pointer": (value.get("plan") or {}).get("source_pointer") if isinstance(value.get("plan"), Mapping) else None,
        }
        for edge_id, edge in planned_edges.items()
    }
    metrics = {
        "wall_time": {"status": "unknown", "value": None, "unit": "milliseconds", "reason": "not_observed", "source_pointer": stream_value.get("source_pointer")},
        "maximum_overlap": {"status": "unknown", "value": None, "unit": "workers", "reason": "not_observed", "source_pointer": stream_value.get("source_pointer")},
        "token_split": [],
    }
    usage_by_subject: dict[str, dict[str, Any]] = {}
    release_order: list[dict[str, Any]] = []
    qualification = {
        "status": "UNKNOWN",
        "issues": [],
        "unknowns": ["qualification_not_observed"],
        "report_pointer": None,
        "evidence_class": "unknown",
        "evidence_tier": "submitted",
        "source_pointer": stream_value.get("source_pointer"),
    }
    evidence_counts = {name: 0 for name in EVIDENCE_CLASSES}
    navigation: list[dict[str, str]] = []
    if root_plan.get("task_pointer"):
        navigation.append({"kind": "root_task", "label": "root task", "pointer": str(root_plan["task_pointer"])})
    for node_id, node in planned_nodes.items():
        if node.get("task_pointer"):
            navigation.append({"kind": "planned_child_task", "label": f"planned child {node_id}", "pointer": str(node["task_pointer"])})

    for event in events:
        event_type = event.get("type")
        evidence_class = event.get("evidence_class")
        evidence_tier = event.get("evidence_tier")
        source_pointer = event.get("source_pointer")
        payload = event.get("payload") if isinstance(event.get("payload"), Mapping) else {}
        if evidence_class in evidence_counts:
            evidence_counts[str(evidence_class)] += 1
        if evidence_class == "unknown":
            unknowns.append(f"event:{event.get('event_id')}")
        if evidence_class == "contradictory":
            contradictions.append(f"event:{event.get('event_id')}:declared_contradiction")
        if _text(source_pointer):
            navigation.append({"kind": "source_evidence", "label": f"evidence {event.get('event_id')}", "pointer": str(source_pointer)})

        if event_type == "root.observed":
            root_view.update(
                {
                    "observed_root_id": payload.get("root_id"),
                    "observed_model": payload.get("model"),
                    "observed_effort": payload.get("effort"),
                    "observed_task_pointer": payload.get("task_pointer"),
                    "evidence_class": evidence_class,
                    "evidence_tier": evidence_tier,
                    "source_pointer": source_pointer,
                }
            )
            for field, planned_field in (("root_id", "root_id"), ("model", "model"), ("effort", "effort")):
                if payload.get(field) != root_plan.get(planned_field):
                    contradictions.append(f"root:{field}_mismatch")
            if payload.get("task_pointer"):
                navigation.append({"kind": "root_task", "label": "observed root task", "pointer": str(payload["task_pointer"])})
        elif event_type == "node.observed" and event.get("node_id") in node_views:
            node = node_views[str(event["node_id"])]
            node.update(
                {
                    "observed_worker_id": payload.get("worker_id"),
                    "observed_model": payload.get("model"),
                    "observed_effort": payload.get("effort"),
                    "observed_task_pointer": payload.get("task_pointer"),
                    "evidence_class": evidence_class,
                    "evidence_tier": evidence_tier,
                    "source_pointer": source_pointer,
                }
            )
            for field in ("model", "effort"):
                if payload.get(field) != node.get(f"planned_{field}"):
                    contradictions.append(f"node:{event.get('node_id')}:{field}_mismatch")
            if payload.get("task_pointer"):
                navigation.append({"kind": "child_task", "label": f"child task {event.get('node_id')}", "pointer": str(payload["task_pointer"])})
        elif event_type == "node.state" and event.get("node_id") in node_views:
            node_views[str(event["node_id"])].update(
                {
                    "state": payload.get("state"),
                    "evidence_class": evidence_class,
                    "evidence_tier": evidence_tier,
                    "source_pointer": source_pointer,
                }
            )
        elif event_type == "edge.state" and event.get("edge_id") in edge_views:
            edge_views[str(event["edge_id"])].update(
                {
                    "state": payload.get("state"),
                    "evidence_class": evidence_class,
                    "evidence_tier": evidence_tier,
                    "source_pointer": source_pointer,
                }
            )
        elif event_type == "ownership.state" and event.get("node_id") in node_views:
            node_views[str(event["node_id"])]["ownership"].append(
                {
                    "resource": payload.get("resource"),
                    "state": payload.get("state"),
                    "evidence_class": evidence_class,
                    "evidence_tier": evidence_tier,
                    "source_pointer": source_pointer,
                }
            )
            if payload.get("state") == "violation":
                contradictions.append(f"ownership:{event.get('node_id')}:{payload.get('resource')}:violation")
        elif event_type == "verification.state" and event.get("node_id") in node_views:
            node_views[str(event["node_id"])]["verification"].append(
                {
                    "check_id": payload.get("check_id"),
                    "outcome": payload.get("outcome"),
                    "evidence_class": evidence_class,
                    "evidence_tier": evidence_tier,
                    "source_pointer": source_pointer,
                }
            )
        elif event_type == "release.observed":
            release_order.append(
                {
                    "seq": event.get("seq"),
                    "edge_id": event.get("edge_id"),
                    "from_node_id": payload.get("from_node_id"),
                    "to_node_id": payload.get("to_node_id"),
                    "owner_worker_id": payload.get("owner_worker_id"),
                    "target_worker_id": payload.get("target_worker_id"),
                    "evidence_class": evidence_class,
                    "evidence_tier": evidence_tier,
                    "source_pointer": source_pointer,
                }
            )
        elif event_type == "metrics.observed":
            metrics["wall_time"] = dict(payload.get("wall_time", {}))
            metrics["maximum_overlap"] = dict(payload.get("maximum_overlap", {}))
        elif event_type == "usage.observed":
            subject_id = payload.get("subject_id")
            fact = dict(payload.get("usage", {}))
            if isinstance(subject_id, str):
                usage_by_subject[subject_id] = {
                    "subject_id": subject_id,
                    **fact,
                    "total_tokens": (
                        sum(int(fact.get(dimension, 0)) for dimension in RAW_USAGE_DIMENSIONS)
                        if fact.get("status") == "known"
                        else None
                    ),
                    "evidence_class": evidence_class,
                    "evidence_tier": evidence_tier,
                    "event_source_pointer": source_pointer,
                }
        elif event_type == "qualification.observed":
            qualification = {
                **dict(payload),
                "evidence_class": evidence_class,
                "evidence_tier": evidence_tier,
                "source_pointer": source_pointer,
            }
            if payload.get("report_pointer"):
                navigation.append({"kind": "qualification_report", "label": "qualification report", "pointer": str(payload["report_pointer"])})

    metrics["token_split"] = [usage_by_subject[key] for key in sorted(usage_by_subject)]
    for metric_name in ("wall_time", "maximum_overlap"):
        if metrics[metric_name].get("status") == "unknown":
            unknowns.append(f"metric:{metric_name}:{metrics[metric_name].get('reason')}")
    for row in metrics["token_split"]:
        if row.get("status") == "unknown":
            unknowns.append(f"usage:{row.get('subject_id')}:{row.get('reason')}")
    if qualification.get("status") == "UNKNOWN":
        unknowns.extend(f"qualification:{item}" for item in qualification.get("unknowns", []))
    if stream_value.get("status") == "closed":
        for node_id, node in node_views.items():
            if node.get("observed_worker_id") is None:
                unknowns.append(f"node:{node_id}:not_observed")

    navigation_unique: list[dict[str, str]] = []
    seen_navigation: set[tuple[str, str]] = set()
    for item in navigation:
        key = (item["label"], item["pointer"])
        if key not in seen_navigation:
            seen_navigation.add(key)
            navigation_unique.append(item)

    nodes = [node_views[key] for key in sorted(node_views)]
    edges = [edge_views[key] for key in sorted(edge_views)]
    markdown = _render_markdown(
        value.get("view_id"),
        len(events),
        stream_value.get("status"),
        root_view,
        nodes,
        edges,
        metrics,
        release_order,
        qualification,
        navigation_unique,
    )
    if issues:
        status = "FAIL"
    elif contradictions:
        status = "FAIL"
    elif unknowns:
        status = "UNKNOWN"
    else:
        status = "PASS"
    core = {
        "schema": REPORT_SCHEMA,
        "status": status,
        "view_id": value.get("view_id"),
        "mode": value.get("mode"),
        "policy_version": value.get("policy_version"),
        "plan_sha256": plan_sha,
        "cursor": len(events),
        "previous_cursor": previous_cursor,
        "events_sha256": events_sha,
        "append_only_verified": not any(issue.startswith("stream:append_only") or issue.startswith("previous:cursor") for issue in issues),
        "stream_status": stream_value.get("status"),
        "root": root_view,
        "nodes": nodes,
        "edges": edges,
        "metrics": metrics,
        "release_order": release_order,
        "qualification": qualification,
        "evidence_classes": ["observed", "inferred", "submitted", "unknown", "contradictory"],
        "evidence_counts": evidence_counts,
        "navigation": navigation_unique,
        "issues": sorted(issues),
        "unknowns": sorted(set(unknowns)),
        "contradictions": sorted(set(contradictions)),
        "privacy": {
            "private_reasoning_included": False,
            "chain_of_thought_available": False,
            "raw_session_bodies_read": False,
            "forbidden_fields": sorted(FORBIDDEN_KEYS),
        },
        "markdown": markdown,
        "evidence_tier": "submitted-projection",
    }
    return {**core, "report_sha256": _sha256(core)}


def _read_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a provider-free Orch Dork live view")
    parser.add_argument("program")
    args = parser.parse_args(argv)
    try:
        result = project_live_view(_read_json(args.program))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "issues": [str(exc)]}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") in {"PASS", "UNKNOWN"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
