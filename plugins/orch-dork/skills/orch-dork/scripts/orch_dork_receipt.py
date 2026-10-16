#!/usr/bin/env python3
"""Render and verify a user-facing receipt from a sealed evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

try:  # Works both as a sibling script and when imported by a test module.
    from orch_dork_bundle import (
        BUNDLE_SCHEMA,
        BundleError,
        credential_paths,
        json_sha256,
        read_bundle,
    )
except ImportError:  # pragma: no cover - exercised by direct file loading.
    _bundle_path = Path(__file__).with_name("orch_dork_bundle.py")
    _spec = importlib.util.spec_from_file_location("orch_dork_bundle", _bundle_path)
    _bundle = importlib.util.module_from_spec(_spec)
    assert _spec.loader is not None
    _spec.loader.exec_module(_bundle)
    BUNDLE_SCHEMA = _bundle.BUNDLE_SCHEMA
    BundleError = _bundle.BundleError
    credential_paths = _bundle.credential_paths
    json_sha256 = _bundle.json_sha256
    read_bundle = _bundle.read_bundle

try:  # Works both as a sibling script and when imported by a test module.
    import orch_dork_worker_default as worker_default
except ImportError:  # pragma: no cover - exercised by direct file loading.
    _worker_default_path = Path(__file__).with_name("orch_dork_worker_default.py")
    _worker_default_spec = importlib.util.spec_from_file_location(
        "orch_dork_worker_default", _worker_default_path
    )
    worker_default = importlib.util.module_from_spec(_worker_default_spec)
    assert _worker_default_spec.loader is not None
    # Publish before executing, so any module loaded later reuses this exact
    # instance instead of executing the file again. Two instances would each
    # carry their own governed-default state, and a pin applied to one would
    # silently not reach a validator holding the other.
    sys.modules.setdefault("orch_dork_worker_default", worker_default)
    _worker_default_spec.loader.exec_module(worker_default)


RECEIPT_SCHEMA = "orch-dork/receipt/v1"
REPORT_SCHEMA = "orch-dork/report/v1"
PLAN_SCHEMA = "orch-dork/plan/v1"
ADAPTER_VERSION = "orch-dork-bundle/0.1.0"
EVIDENCE_TIERS = {"submitted", "runtime-observed", "sealed-runtime"}


def subagent_model():
    """The governed worker model, resolved when it is used."""

    return worker_default.configured_worker_model()


def subagent_effort():
    """The governed worker effort, resolved when it is used."""

    return worker_default.configured_worker_effort()


# Compatibility aliases for the v1 wire schema, which still uses `children`.
child_model = subagent_model
child_effort = subagent_effort
REPORT_STATES = {
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


class ReceiptError(ValueError):
    """Raised when receipt inputs are incomplete or contradictory."""


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _json_from_candidates(parsed: Mapping[str, Any], *names: str) -> Any:
    # `names` is an explicit precedence list.  Bundle manifests sort entries
    # lexically, so scanning parsed insertion order could otherwise select
    # `qualification.json` before the preferred `verification.json` (or any
    # analogous alias pair) simply because of its filename.  Resolve one
    # requested basename at a time and reject duplicate basenames.
    for name in names:
        matches = [value for path, value in parsed.items() if Path(path).name == name]
        if len(matches) > 1:
            raise ReceiptError("duplicate bundle candidate: %s" % name)
        if matches:
            return matches[0]
    return None


def _submitted_trace_path(path: str) -> bool:
    """Identify normalized/model-authored trace files by basename, not path."""
    # Normalize separators and version suffixes so names such as
    # ``normalized-trace-v1.json`` cannot bypass the raw-V1 custody boundary.
    stem = re.sub(r"[^a-z0-9]+", "_", Path(path).stem.lower()).strip("_")
    exact = {
        "trace",
        "submitted_trace",
        "normalized_trace",
        "events",
        "submitted_events",
        "normalized_events",
        "runtime_evidence",
        "runtime_events",
        "canonical_events",
        "canonical_trace",
        "normalized_evidence",
    }
    if stem in exact:
        return True
    return any(
        stem.startswith(prefix + "_")
        for prefix in (
            "trace",
            "submitted_trace",
            "normalized_trace",
            "events",
            "submitted_events",
            "normalized_events",
            "runtime_evidence",
            "runtime_events",
            "canonical_events",
            "canonical_trace",
            "normalized_evidence",
        )
    )


def _v2_source_surface_identity(value: Any) -> dict[str, Any]:
    """Validate and copy the native-V2 source binding emitted by the adapter.

    A source binding is deliberately kept separate from the canonical event
    stream.  It identifies which native collaboration surface produced the
    events, but it is not itself accepted as event evidence.  Keeping this
    small closed shape in the receipt lets callers distinguish a V2 receipt
    from a V1 receipt after the adapter has normalized both to the same event
    contract.
    """
    identity = _require_mapping(value, "source_surface_identity")
    name = identity.get("name", identity.get("source_surface"))
    adapter_version = identity.get("adapter_version")
    raw_schema = identity.get("raw_schema")
    if not _nonempty(name) or not _nonempty(adapter_version) or not _nonempty(raw_schema):
        raise ReceiptError("source_surface_identity requires name, adapter_version, and raw_schema")
    if name != "native-v2":
        raise ReceiptError("source_surface_identity is not native-v2")
    if raw_schema != "orch-dork/raw-native-v2":
        raise ReceiptError("source_surface_identity raw schema is invalid")
    result = dict(identity)
    result.setdefault("name", name)
    result.setdefault("source_surface", name)
    return result


def _check_source_surface(
    source_surface: str | None,
    identities: Mapping[str, Any] | None,
    events: list[dict[str, Any]] | None,
) -> None:
    """Ensure a V2 receipt does not silently mix native surfaces."""
    if source_surface != "native-v2":
        return
    if identities is not None:
        root = identities.get("root")
        if isinstance(root, Mapping) and root.get("source_surface") not in (None, source_surface):
            raise ReceiptError("source surface contradicts root identity")
        children = identities.get("children")
        if isinstance(children, list):
            for child in children:
                if isinstance(child, Mapping) and child.get("source_surface") not in (None, source_surface):
                    raise ReceiptError("source surface contradicts child identity")
    if events is not None:
        for event in events:
            if event.get("source_surface") != source_surface:
                raise ReceiptError("source surface is missing or contradictory in event evidence")


def _check_source_references(source_surface: str | None, references: list[Any] | None) -> None:
    """Reject source references that claim a different native surface."""
    if source_surface != "native-v2" or references is None:
        return
    for reference in references:
        if isinstance(reference, Mapping) and reference.get("source_surface") not in (None, source_surface):
            raise ReceiptError("source reference surface contradicts native V2")


def _as_events(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, Mapping):
        value = value.get("events", [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ReceiptError("evidence events are required as an array of objects")
    return value


def _candidate_value(value: Any, parsed: Mapping[str, Any], *names: str) -> Any:
    """Use an explicit caller value, including empty values, without fallback."""
    return _json_from_candidates(parsed, *names) if value is None else value


def _event_type(event: Mapping[str, Any]) -> str:
    return str(event.get("type") or event.get("event") or "")


def _event_seq(event: Mapping[str, Any], fallback: int) -> int:
    return event.get("seq") if type(event.get("seq")) is int else fallback


def _terminal_from_events(events: list[dict[str, Any]]) -> tuple[str, list[str]]:
    terminals = []
    for index, event in enumerate(events, 1):
        event_type = _event_type(event)
        if event_type in {"run.completed", "terminal.completed"}:
            terminals.append(("completed", _event_seq(event, index)))
        elif event_type in {"run.failed", "terminal.failed"}:
            terminals.append(("failed", _event_seq(event, index)))
        elif event_type in {"run.cancelled", "terminal.cancelled"}:
            terminals.append(("cancelled", _event_seq(event, index)))
        elif event_type in {"run.timed_out", "terminal.timed_out"}:
            terminals.append(("timed_out", _event_seq(event, index)))
        elif event_type in {"run.blocked", "terminal.blocked"}:
            terminals.append(("blocked", _event_seq(event, index)))
    issues = []
    if len(terminals) > 1:
        issues.append("lifecycle:multiple_terminal_events")
    return (terminals[0][0] if terminals else "", issues)


def _lane_states(plan: Mapping[str, Any], events: list[dict[str, Any]]) -> dict[str, str]:
    lanes = plan.get("lanes", []) if isinstance(plan, Mapping) else []
    states = {lane.get("id"): "planned" for lane in lanes if isinstance(lane, Mapping) and _nonempty(lane.get("id"))}
    spawned: set[str] = set()
    completed: set[str] = set()
    released: set[str] = set()
    failed: set[str] = set()
    for event in events:
        lane = event.get("lane_id")
        event_type = _event_type(event)
        if lane not in states:
            continue
        if event_type in {"child.spawned", "lane.started"}:
            spawned.add(lane)
        elif event_type == "lane.completed":
            if event.get("status") == "completed":
                completed.add(lane)
            else:
                failed.add(lane)
        elif event_type == "lane.released":
            released.add(lane)
    for lane in states:
        if lane in failed:
            states[lane] = "failed"
        elif lane in released:
            states[lane] = "released"
        elif lane in completed:
            states[lane] = "completed"
        elif lane in spawned:
            states[lane] = "active"
    return states


def derive_report(
    plan: Mapping[str, Any],
    events: list[dict[str, Any]],
    *,
    terminal_state: str | None = None,
    qualification: Mapping[str, Any] | None = None,
    evidence_tier: str = "submitted",
) -> dict[str, Any]:
    """Derive stable user-facing states without relying on a provider."""
    states = _lane_states(plan, events)
    event_types = {_event_type(event) for event in events}
    derived_terminal, issues = _terminal_from_events(events)
    overall = terminal_state or derived_terminal
    if terminal_state is not None and terminal_state not in REPORT_STATES:
        issues.append("lifecycle:terminal_state_invalid")
    if overall not in REPORT_STATES or overall in {"planned", "active", "waiting", "released", "integrating", "unreleased"}:
        if "integrator.started" in event_types:
            overall = "integrating"
        elif "lane.released" in event_types:
            overall = "released"
        elif events:
            overall = "active"
        else:
            overall = "planned"
    if terminal_state and derived_terminal and terminal_state != derived_terminal:
        issues.append("lifecycle:terminal_state_mismatch")
    if overall == "completed" and states and any(state not in {"completed", "released"} for state in states.values()):
        issues.append("lifecycle:completed_with_incomplete_lane")
    if evidence_tier not in EVIDENCE_TIERS:
        issues.append("evidence:tier_invalid")
    return {
        "schema": REPORT_SCHEMA,
        "state": overall,
        "lane_states": states,
        "terminal": overall in {"completed", "failed", "cancelled", "timed_out", "blocked"},
        "qualification_status": (qualification or {}).get("status", "unknown"),
        "evidence_tier": evidence_tier,
        "issues": sorted(set(issues)),
    }


def report_state(plan: Mapping[str, Any], events: list[dict[str, Any]], **kwargs: Any) -> str:
    """Return only the stable state for callers rendering a compact view."""
    return derive_report(plan, events, **kwargs)["state"]


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptError("%s must be an object" % name)
    return value


def _normalize_identities(
    identities: Any,
    events: list[dict[str, Any]],
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    value = _require_mapping(identities, "identities")
    root = _require_mapping(value.get("root"), "identities.root")
    if not _nonempty(root.get("thread_id")):
        raise ReceiptError("identities.root.thread_id is required")
    if not _nonempty(root.get("model")) or not _nonempty(root.get("effort")):
        raise ReceiptError("identities.root model and effort are required")
    if "depth" in root and (type(root["depth"]) is not int or root["depth"] != 0):
        raise ReceiptError("identities.root depth contradicts the root boundary")
    planned_root = _require_mapping(plan.get("root"), "plan.root")
    if root.get("model") != planned_root.get("model") or root.get("effort") != planned_root.get("effort"):
        raise ReceiptError("root effective model/effort contradicts governed routing")
    planned_root_context = planned_root.get("context_policy")
    if planned_root_context is not None and root.get("context_policy") != planned_root_context:
        raise ReceiptError("root context policy contradicts governed routing")
    planned_children = plan.get("children")
    planned_children = planned_children if isinstance(planned_children, Mapping) else {}
    expected_child_model = planned_children.get("model", child_model())
    expected_child_effort = planned_children.get("effort", child_effort())
    expected_child_context = planned_children.get("context_policy")
    planned_lanes = plan.get("lanes")
    planned_lane_ids: set[str] | None = None
    if planned_lanes is not None:
        if not isinstance(planned_lanes, list):
            raise ReceiptError("plan.lanes must be an array")
        planned_lane_ids = set()
        for lane in planned_lanes:
            if not isinstance(lane, Mapping) or not _nonempty(lane.get("id")):
                raise ReceiptError("plan lane ids are required")
            lane_id = str(lane["id"])
            if lane_id in planned_lane_ids:
                raise ReceiptError("plan contains duplicate lane ids")
            planned_lane_ids.add(lane_id)
    children = value.get("children")
    if isinstance(children, Mapping):
        children_list = []
        for lane_id, child in children.items():
            child_value = dict(_require_mapping(child, "identities.children.%s" % lane_id))
            child_value.setdefault("lane_id", lane_id)
            children_list.append(child_value)
        children = children_list
    if not isinstance(children, list):
        raise ReceiptError("identities.children must be an array")
    normalized_children = []
    seen_lane_ids: set[str] = set()
    seen_child_ids: set[str] = set()
    for child in children:
        child_value = _require_mapping(child, "identities.children[]")
        if not _nonempty(child_value.get("thread_id")) or not _nonempty(child_value.get("lane_id")):
            raise ReceiptError("each child needs lane_id and thread_id")
        lane_id = str(child_value["lane_id"])
        thread_id = str(child_value["thread_id"])
        if lane_id in seen_lane_ids:
            raise ReceiptError("identities contain duplicate child lanes")
        if thread_id in seen_child_ids:
            raise ReceiptError("identities contain duplicate child threads")
        seen_lane_ids.add(lane_id)
        seen_child_ids.add(thread_id)
        if not _nonempty(child_value.get("model")) or not _nonempty(child_value.get("effort")):
            raise ReceiptError("each child model and effort are required")
        if "parent_thread_id" in child_value and child_value["parent_thread_id"] is not None and child_value["parent_thread_id"] != root["thread_id"]:
            raise ReceiptError("child parent identity contradicts the root")
        if "depth" in child_value and child_value["depth"] is not None and (type(child_value["depth"]) is not int or child_value["depth"] != 1):
            raise ReceiptError("child depth contradicts the governed graph")
        if child_value.get("model") != expected_child_model or child_value.get("effort") != expected_child_effort:
            raise ReceiptError("child effective model/effort contradicts governed routing")
        if expected_child_context is not None and child_value.get("context_policy") != expected_child_context:
            raise ReceiptError("child context policy contradicts governed routing")
        normalized_children.append(dict(child_value))
    if planned_lane_ids is not None and seen_lane_ids != planned_lane_ids:
        raise ReceiptError("identities child lanes contradict governed plan")
    expected_count = plan.get("children", {}).get("expected_count") if isinstance(plan.get("children"), Mapping) else None
    if type(expected_count) is int and expected_count != len(normalized_children):
        raise ReceiptError("identities child count contradicts governed plan")
    edges = value.get("parent_edges")
    if not isinstance(edges, list):
        edges = [{"parent_thread_id": child.get("parent_thread_id", root["thread_id"]), "child_thread_id": child["thread_id"], "depth": child.get("depth", 1)} for child in normalized_children]
    if not edges or any(not isinstance(edge, Mapping) for edge in edges):
        raise ReceiptError("parent_edges are required")
    edge_tuples: list[tuple[Any, Any, Any]] = []
    for edge in edges:
        parent_id = edge.get("parent_thread_id")
        child_id = edge.get("child_thread_id")
        depth = edge.get("depth")
        if not _nonempty(parent_id) or not _nonempty(child_id) or type(depth) is not int:
            raise ReceiptError("parent edge identity is malformed")
        edge_tuples.append((parent_id, child_id, depth))
    child_ids = {child["thread_id"] for child in normalized_children}
    children_by_id = {child["thread_id"]: child for child in normalized_children}
    if len(edge_tuples) != len(set(edge_tuples)):
        raise ReceiptError("parent edge graph contains duplicate edges")
    if len(edge_tuples) != len(child_ids) or {edge[1] for edge in edge_tuples} != child_ids:
        raise ReceiptError("parent edge graph does not cover every child")
    if any(edge[1] not in child_ids or edge[0] != root["thread_id"] or edge[2] != 1 for edge in edge_tuples):
        raise ReceiptError("parent edge contradicts identity graph")
    for parent_id, child_id, depth in edge_tuples:
        child = children_by_id[child_id]
        if child.get("parent_thread_id") is not None and child.get("parent_thread_id") != parent_id:
            raise ReceiptError("parent edge contradicts child parent identity")
        if child.get("depth") is not None and child.get("depth") != depth:
            raise ReceiptError("parent edge contradicts child depth")
    return {"root": dict(root), "children": normalized_children, "parent_edges": [dict(edge) for edge in edges]}


def _check_event_identities(events: list[dict[str, Any]], identities: Mapping[str, Any]) -> None:
    """Reject an event stream that disagrees with the bound identity graph."""
    root = identities["root"]
    children = {child["lane_id"]: child for child in identities["children"]}
    child_by_thread = {child["thread_id"]: child for child in identities["children"]}
    seen_sequences: list[int] = []
    for event in events:
        if "seq" in event:
            seq = event["seq"]
            if type(seq) is not int or seq < 1:
                raise ReceiptError("event sequence must be a positive integer")
            seen_sequences.append(seq)
        event_type = _event_type(event)
        if event_type == "root.started":
            identity_field = {"root_thread_id": "root_thread_id", "task_id": "root_thread_id"}
            for field in ("root_thread_id", "task_id", "model", "effort"):
                expected = root["thread_id"] if field in identity_field else root[field]
                if field in event and event[field] != expected:
                    raise ReceiptError("event contradicts root identity: %s" % field)
            for field in ("context_policy", "depth"):
                if field in event and field in root and event[field] != root[field]:
                    raise ReceiptError("event contradicts root identity: %s" % field)
        if event_type == "child.spawned":
            child = children.get(event.get("lane_id"))
            if child is None:
                raise ReceiptError("event references an unknown child lane")
            expected = {
                "child_thread_id": child["thread_id"],
                "task_id": child["thread_id"],
                "parent_thread_id": child.get("parent_thread_id", root["thread_id"]),
                "parent_task_id": child.get("parent_thread_id", root["thread_id"]),
                "depth": child.get("depth", 1),
                "model": child["model"],
                "effort": child["effort"],
            }
            if "context_policy" in child:
                expected["context_policy"] = child["context_policy"]
            for field, value in expected.items():
                if field in event and event[field] != value:
                    raise ReceiptError("event contradicts child identity: %s" % field)
        if event_type in {"lane.started", "lane.verified", "lane.completed", "lane.terminal", "lane.released"}:
            lane = event.get("lane_id")
            child = children.get(lane)
            if child is None:
                raise ReceiptError("event references an unknown child lane")
            for field in ("task_id", "child_thread_id"):
                if field in event and event[field] != child["thread_id"]:
                    raise ReceiptError("event contradicts child identity: %s" % field)
            expected_fields = {
                "parent_thread_id": child.get("parent_thread_id", root["thread_id"]),
                "parent_task_id": child.get("parent_thread_id", root["thread_id"]),
                "depth": child.get("depth", 1),
                "model": child.get("model"),
                "effort": child.get("effort"),
            }
            if "context_policy" in child:
                expected_fields["context_policy"] = child["context_policy"]
            for field, expected in expected_fields.items():
                if field in event and expected is not None and event[field] != expected:
                    raise ReceiptError("event contradicts child identity: %s" % field)
        if event_type in {"integrator.started", "integrator.validated", "integrator.completed"}:
            child_id = event.get("child_thread_id", event.get("task_id"))
            if child_id is not None and child_id not in child_by_thread:
                raise ReceiptError("event references an unknown integrator child")
        if event_type in {
            "run.completed", "run.failed", "run.cancelled", "run.timed_out", "run.blocked",
            "terminal.completed", "terminal.failed", "terminal.cancelled", "terminal.timed_out", "terminal.blocked",
        }:
            for field in ("root_thread_id", "task_id"):
                if field in event and event[field] != root["thread_id"]:
                    raise ReceiptError("event contradicts root identity: %s" % field)
        if event_type == "root.tool" and "task_id" in event and event["task_id"] != root["thread_id"]:
            raise ReceiptError("event contradicts root identity: task_id")
    if seen_sequences and (len(seen_sequences) != len(set(seen_sequences)) or seen_sequences != sorted(seen_sequences)):
        raise ReceiptError("event sequence is not strictly increasing")


def _normalize_usage(usage: Any) -> dict[str, Any]:
    value = dict(_require_mapping(usage, "usage"))
    if value.get("exact") is not True:
        raise ReceiptError("usage must explicitly be exact")
    if credential_paths(value):
        raise ReceiptError("credentials are forbidden in usage evidence")
    found = 0

    def validate_numbers(item: Any, path: str) -> None:
        nonlocal found
        if isinstance(item, Mapping):
            for key, child in item.items():
                key_text = str(key)
                child_path = "%s.%s" % (path, key_text) if path else key_text
                if key_text.endswith("_tokens"):
                    if type(child) is not int or child < 0:
                        raise ReceiptError("%s must be a non-negative integer" % child_path)
                    found += 1
                validate_numbers(child, child_path)
        elif isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                validate_numbers(child, "%s[%d]" % (path, index))

    validate_numbers(value, "usage")
    if not found:
        raise ReceiptError("exact usage components are missing")
    return value


def _load_bundle_input(bundle: Any) -> dict[str, Any]:
    if isinstance(bundle, (str, Path)):
        try:
            return read_bundle(bundle)
        except BundleError as exc:
            raise ReceiptError(str(exc)) from exc
    if not isinstance(bundle, Mapping):
        raise ReceiptError("bundle must be a sealed bundle path or loaded bundle")
    return dict(bundle)


def _load_sibling_module(name: str) -> Any:
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ReceiptError("runtime adapter unavailable: %s" % name)
    module = importlib.util.module_from_spec(spec)
    # Dataclasses and the observer's sibling import both require the module to
    # be visible during execution, as it would be for a normal import.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _runtime_identities(graph: Mapping[str, Any]) -> dict[str, Any]:
    root = _require_mapping(graph.get("root"), "runtime graph.root")
    children = graph.get("children")
    if not isinstance(children, list):
        raise ReceiptError("runtime graph.children must be an array")
    return {
        "root": {
            "thread_id": root.get("task_id"),
            "model": root.get("model"),
            "effort": root.get("effort"),
            "context_policy": root.get("context_policy"),
            "depth": root.get("depth", 0),
        },
        "children": [
            {
                "lane_id": child.get("lane_id"),
                "thread_id": child.get("task_id"),
                "parent_thread_id": child.get("parent_task_id"),
                "depth": child.get("depth", 1),
                "model": child.get("model"),
                "effort": child.get("effort"),
                "context_policy": child.get("context_policy"),
            }
            for child in children
        ],
    }


def _runtime_usage(usage_report: Mapping[str, Any], graph: Mapping[str, Any]) -> dict[str, Any]:
    components = usage_report.get("components")
    combined = usage_report.get("combined")
    if not isinstance(components, Mapping) or not isinstance(combined, Mapping):
        raise ReceiptError("runtime usage report is incomplete")
    root = graph.get("root")
    root_id = root.get("task_id") if isinstance(root, Mapping) else None
    children: dict[str, Any] = {}
    for child in graph.get("children", []):
        if isinstance(child, Mapping) and child.get("task_id") in components:
            children[child["task_id"]] = dict(components[child["task_id"]])
    if root_id not in components or combined.get("attributed_total_tokens") is None:
        raise ReceiptError("runtime usage lacks exact root or combined attribution")
    return {
        "exact": True,
        "root": dict(components[root_id]),
        "children": children,
        "raw_total_tokens": combined.get("raw_total_tokens"),
        "total_tokens": combined.get("attributed_total_tokens"),
        "copied_history_tokens": combined.get("copied_history_tokens"),
        "source_refs": list(usage_report.get("source_refs", [])),
    }


def _v2_raw_candidates(parsed: Mapping[str, Any]) -> tuple[Any, Any, Any]:
    """Return raw-native-V2, raw usage, and frozen plan evidence.

    V2 has several native transport spellings in the wild.  The basename
    allow-list keeps this lookup explicit; importantly, it never treats a
    normalized event/trace file as raw evidence.
    """
    raw_names = {
        "raw-v2.json",
        "raw_v2.json",
        "raw-native-v2.json",
        "raw_native_v2.json",
        "native-v2.json",
        "native_v2.json",
        "raw-runtime-v2.json",
        "raw_runtime_v2.json",
    }
    usage_names = {
        "raw-usage-v2.json",
        "raw_usage_v2.json",
        "raw-native-v2-usage.json",
        "raw_native_v2_usage.json",
        "usage-raw-v2.json",
        "usage_raw_v2.json",
        # Some native captures carry usage in the primary raw file.  This
        # candidate is intentionally only a separate file, never a parsed
        # normalized report.
        "raw-usage.json",
        "raw_usage.json",
        "usage-runtime-v2.json",
        "usage_runtime_v2.json",
    }
    plan_names = {"plan.json", "frozen_plan.json"}

    def pick(names: set[str]) -> Any:
        for path, value in parsed.items():
            if Path(path).name in names:
                return value
        return None

    return pick(raw_names), pick(usage_names), pick(plan_names)


def _source_references(
    refs: Any,
    *,
    source_surface: str | None = None,
    kind: str = "runtime-record",
) -> list[Any]:
    """Normalize adapter references without discarding native source identity."""
    if not isinstance(refs, list):
        return []
    normalized: list[Any] = []
    for ref in refs:
        if isinstance(ref, Mapping):
            value = dict(ref)
            value.setdefault("kind", kind)
            if source_surface is not None:
                value.setdefault("source_surface", source_surface)
            normalized.append(value)
        elif isinstance(ref, str) and ref.strip():
            value: dict[str, Any] = {"kind": kind, "ref": ref}
            if source_surface is not None:
                value["source_surface"] = source_surface
            normalized.append(value)
    return normalized


def _v2_usage_report(
    observation: Mapping[str, Any],
    raw: Any,
    raw_usage: Any,
    graph: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Select exact V2 usage evidence, reusing the V1 attribution contract."""
    report = observation.get("usage")
    if isinstance(report, Mapping):
        return report
    # A V2 observer may intentionally leave usage on a sibling raw file.  The
    # V1 usage adapter is surface-neutral after raw records are selected; wrap
    # the records in its accepted raw envelope rather than allowing a
    # normalized/model-authored report through.
    usage_value = raw_usage
    if usage_value is None and isinstance(raw, Mapping):
        usage_value = raw.get("usage")
    if usage_value is None:
        raise ReceiptError("raw V2 usage evidence is required")
    if isinstance(usage_value, Mapping) and isinstance(usage_value.get("usage"), list):
        values = usage_value["usage"]
    elif isinstance(usage_value, list):
        values = usage_value
    else:
        raise ReceiptError("raw V2 usage evidence must be an array")
    usage_adapter = _load_sibling_module("orch_dork_usage")
    usage_report = usage_adapter.attribute_usage(
        {"schema": "orch-dork/raw-classic-v1", "usage": values},
        graph,
    )
    return usage_report


def build_receipt_from_v1_bundle(bundle: Any) -> dict[str, Any]:
    """Reconstruct a sealed receipt from raw classic-V1 records.

    This path intentionally accepts only raw runtime records and a frozen plan;
    a submitted normalized trace is neither read nor accepted as a substitute.
    The V1 observer and usage adapter independently produce the graph and exact
    attribution before the common receipt binder is called.
    """
    loaded = _load_bundle_input(bundle)
    parsed = loaded.get("parsed", {})
    if not isinstance(parsed, Mapping):
        raise ReceiptError("bundle parsed evidence is unavailable")
    if any(_submitted_trace_path(path) for path in parsed):
        raise ReceiptError("submitted trace is forbidden for raw V1 receipt reconstruction")
    raw = _json_from_candidates(parsed, "raw-v1.json", "raw_v1.json", "raw-runtime.json", "raw-evidence.json")
    raw_usage = _json_from_candidates(parsed, "raw-usage.json", "raw_usage.json", "usage-raw.json", "usage-runtime.json")
    plan = _json_from_candidates(parsed, "plan.json", "frozen_plan.json")
    if raw is None or raw_usage is None or plan is None:
        raise ReceiptError("raw V1 records, raw usage, and plan are required")
    observer = _load_sibling_module("orch_dork_v1_observer")
    usage_adapter = _load_sibling_module("orch_dork_usage")
    observation = observer.observe_v1(raw, plan)
    if observation.get("status") != "PASS":
        raise ReceiptError("raw V1 observation failed: " + ", ".join(observation.get("issues", [])))
    graph = _require_mapping(observation.get("graph"), "runtime observation graph")
    usage_report = usage_adapter.attribute_usage(raw_usage, graph)
    if usage_report.get("status") != "PASS":
        raise ReceiptError("raw usage attribution failed: " + ", ".join(usage_report.get("issues", [])))
    runtime_identities = _runtime_identities(graph)
    runtime_usage = _runtime_usage(usage_report, graph)
    source_references = [
        {"kind": "runtime-record", **ref}
        for ref in observation.get("source_refs", [])
    ] + [
        {"kind": "usage-record", **ref}
        for ref in usage_report.get("source_refs", [])
    ]
    verification = {
        "status": "PASS",
        "kind": "raw-runtime-reconstruction",
        "observer_status": observation.get("status"),
        "usage_status": usage_report.get("status"),
        "source_refs": source_references,
    }
    qualification = {
        "status": "PASS",
        "kind": "runtime-reconstruction",
        "evidence_tier": "runtime-observed",
        "issues": [],
    }
    adapter_version = "%s+%s" % (observer.ADAPTER_VERSION, usage_adapter.USAGE_ADAPTER_VERSION)
    lifecycle = {
        "root_thread_id": runtime_identities["root"]["thread_id"],
        "terminal_state": "completed",
        "raw_record_count": observation.get("raw_record_count"),
        "event_count": len(observation.get("events", [])),
    }
    return build_receipt(
        loaded,
        plan=plan,
        identities=runtime_identities,
        events=observation.get("events"),
        lifecycle=lifecycle,
        verification=verification,
        usage=runtime_usage,
        terminal_state="completed",
        source_references=source_references,
        adapter_version=adapter_version,
        qualification=qualification,
    )


def build_receipt_from_v2_bundle(bundle: Any) -> dict[str, Any]:
    """Reconstruct a sealed receipt from native-V2 runtime evidence.

    Native V2 and classic V1 have different source records, but both adapters
    emit the same ``orch-dork/runtime-evidence/v1`` graph/events contract.
    This function performs only the V2 source selection and identity binding;
    custody, canonical identity, lifecycle, usage, and tamper checks remain in
    :func:`build_receipt` and :func:`verify_receipt`.
    """
    loaded = _load_bundle_input(bundle)
    parsed = loaded.get("parsed", {})
    if not isinstance(parsed, Mapping):
        raise ReceiptError("bundle parsed evidence is unavailable")
    # Never permit a model-authored normalized stream to participate in raw
    # V2 reconstruction.  This check is intentionally independent of the
    # adapter so a future adapter cannot weaken the custody boundary.
    if any(_submitted_trace_path(path) for path in parsed):
        raise ReceiptError("submitted trace is forbidden for raw V2 receipt reconstruction")
    raw, raw_usage, plan = _v2_raw_candidates(parsed)
    if raw is None:
        # Permit an explicitly schema-bound filename while still rejecting all
        # trace/events spellings above.  The schema, not a caller-provided
        # normalized report, is the authority for this fallback.
        for path, value in parsed.items():
            if isinstance(value, Mapping) and value.get("schema") == "orch-dork/raw-native-v2":
                raw = value
                break
    if raw is None or plan is None:
        raise ReceiptError("raw V2 records and plan are required")
    if not isinstance(raw, Mapping) or raw.get("schema") != "orch-dork/raw-native-v2":
        raise ReceiptError("raw V2 schema is invalid")
    # Load the shared usage adapter first so the native observer's provider-
    # free inline usage path can import it by its canonical sibling name.
    usage_adapter = _load_sibling_module("orch_dork_usage")
    observer = _load_sibling_module("orch_dork_v2_observer")
    observe = getattr(observer, "observe_v2", None)
    if not callable(observe):
        raise ReceiptError("runtime adapter unavailable: observe_v2")
    observation = observe(raw, plan)
    if not isinstance(observation, Mapping) or observation.get("status") != "PASS":
        issues = observation.get("issues", []) if isinstance(observation, Mapping) else []
        if not isinstance(issues, list):
            issues = [str(issues)]
        raise ReceiptError("raw V2 observation failed: " + ", ".join(str(issue) for issue in issues))
    if observation.get("normalized_schema") not in (None, "orch-dork/runtime-evidence/v1"):
        raise ReceiptError("raw V2 normalized schema is invalid")
    source_surface = observation.get("source_surface")
    if source_surface != "native-v2":
        raise ReceiptError("raw V2 source surface is missing or invalid")
    source_identity = _v2_source_surface_identity(observation.get("source_surface_identity"))
    graph = _require_mapping(observation.get("graph"), "runtime V2 graph")
    events = _as_events(observation.get("events"))
    # Every event produced by the native adapter must retain its source
    # surface.  Silently dropping that field would conflate V1 and V2 receipts
    # even though their canonical event types are shared.
    for event in events:
        if event.get("source_surface") != source_surface:
            raise ReceiptError("raw V2 event source surface is missing or contradictory")
    usage_report = _v2_usage_report(observation, raw, raw_usage, graph)
    if usage_report.get("status") != "PASS":
        issues = usage_report.get("issues", [])
        if not isinstance(issues, list):
            issues = [str(issues)]
        raise ReceiptError("raw V2 usage attribution failed: " + ", ".join(str(issue) for issue in issues))
    runtime_identities = _runtime_identities(graph)
    # Graph identity fields are V1-compatible by design; add the V2 source
    # binding alongside them so a receipt never loses which native surface
    # established each task identity.
    runtime_identities["root"]["source_surface"] = source_surface
    for child in runtime_identities["children"]:
        child["source_surface"] = source_surface
    runtime_usage = _runtime_usage(usage_report, graph)
    source_references = _source_references(observation.get("source_refs"), source_surface=source_surface)
    source_references += _source_references(
        usage_report.get("source_refs"),
        source_surface=source_surface,
        kind="usage-record",
    )
    if not source_references:
        raise ReceiptError("raw V2 source references are required")
    derived_terminal, terminal_issues = _terminal_from_events(events)
    if terminal_issues or not derived_terminal:
        raise ReceiptError("raw V2 terminal evidence is incomplete or contradictory")
    verification = {
        "status": "PASS",
        "kind": "raw-runtime-reconstruction",
        "observer_status": observation.get("status"),
        "usage_status": usage_report.get("status"),
        "source_surface": source_surface,
        "source_surface_identity": source_identity,
        "source_refs": source_references,
    }
    qualification = {
        "status": "PASS",
        "kind": "runtime-reconstruction",
        "evidence_tier": "runtime-observed",
        "source_surface": source_surface,
        "source_surface_identity": source_identity,
        "issues": [],
    }
    usage_adapter_version = usage_report.get("adapter_version")
    if not _nonempty(usage_adapter_version):
        usage_adapter_version = getattr(usage_adapter, "USAGE_ADAPTER_VERSION", None)
    adapter_version = "%s+%s" % (
        source_identity["adapter_version"],
        usage_adapter_version or "unknown-usage",
    )
    root = _require_mapping(graph.get("root"), "runtime V2 graph.root")
    lifecycle = {
        "root_thread_id": runtime_identities["root"]["thread_id"],
        "terminal_state": derived_terminal,
        "raw_record_count": observation.get("raw_record_count"),
        "event_count": len(events),
        "source_surface": source_surface,
        "source_surface_identity": source_identity,
    }
    if root.get("terminal") is not None and root.get("terminal") != derived_terminal:
        raise ReceiptError("raw V2 root terminal state contradicts event evidence")
    return build_receipt(
        loaded,
        plan=plan,
        identities=runtime_identities,
        events=events,
        lifecycle=lifecycle,
        verification=verification,
        usage=runtime_usage,
        terminal_state=derived_terminal,
        source_references=source_references,
        adapter_version=adapter_version,
        qualification=qualification,
        source_surface=source_surface,
        source_surface_identity=source_identity,
    )


def build_receipt(
    bundle: Any,
    *,
    plan: Mapping[str, Any] | None = None,
    identities: Mapping[str, Any] | None = None,
    events: list[dict[str, Any]] | None = None,
    lifecycle: Mapping[str, Any] | None = None,
    verification: Mapping[str, Any] | None = None,
    usage: Mapping[str, Any] | None = None,
    terminal_state: str | None = None,
    source_references: list[Any] | None = None,
    adapter_version: str | None = None,
    qualification: Mapping[str, Any] | None = None,
    source_surface: str | None = None,
    source_surface_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the complete receipt binding all externally observable evidence."""
    loaded = _load_bundle_input(bundle)
    manifest = _require_mapping(loaded.get("manifest"), "bundle.manifest")
    parsed = loaded.get("parsed", {})
    if not isinstance(parsed, Mapping):
        parsed = {}
    plan = _candidate_value(plan, parsed, "plan.json", "frozen_plan.json")
    identities = _candidate_value(identities, parsed, "identities.json", "identity.json")
    event_value = _candidate_value(events, parsed, "events.json", "trace.json", "lifecycle_events.json")
    lifecycle = _candidate_value(lifecycle, parsed, "lifecycle.json")
    if lifecycle is None:
        lifecycle = {}
    verification = _candidate_value(verification, parsed, "verification.json", "qualification.json")
    usage = _candidate_value(usage, parsed, "usage.json", "tokens.json")
    source_references = _candidate_value(source_references, parsed, "sources.json", "source_references.json")
    adapter_value = _json_from_candidates(parsed, "adapter.json", "runtime_adapter.json")
    if adapter_version is None and isinstance(adapter_value, Mapping):
        adapter_version = adapter_value.get("version")
    if source_surface is None and isinstance(adapter_value, Mapping):
        source_surface = adapter_value.get("source_surface")
    if source_surface_identity is None and isinstance(adapter_value, Mapping) and isinstance(adapter_value.get("source_surface_identity"), Mapping):
        source_surface_identity = adapter_value.get("source_surface_identity")
    qualification = _candidate_value(qualification, parsed, "qualification.json", "report.json")
    if source_surface is None:
        source_surface_value = _json_from_candidates(parsed, "source_surface.json", "surface.json")
        if isinstance(source_surface_value, str):
            source_surface = source_surface_value
        elif isinstance(source_surface_value, Mapping):
            source_surface = source_surface_value.get("source_surface", source_surface_value.get("name"))
    if source_surface_identity is None:
        source_surface_identity_value = _json_from_candidates(parsed, "source_surface_identity.json", "surface_identity.json")
        if isinstance(source_surface_identity_value, Mapping):
            source_surface_identity = source_surface_identity_value
    plan = _require_mapping(plan, "plan")
    if plan.get("schema") != PLAN_SCHEMA:
        raise ReceiptError("plan schema is invalid")
    normalized_events = _as_events(event_value)
    normalized_identities = _normalize_identities(identities, normalized_events, plan)
    _check_event_identities(normalized_events, normalized_identities)
    usage_value = _normalize_usage(usage)
    if not _nonempty(adapter_version):
        raise ReceiptError("runtime adapter version is required")
    if not isinstance(source_references, list) or not source_references:
        raise ReceiptError("source references are required")
    if any(not isinstance(item, (str, Mapping)) or (isinstance(item, str) and not item.strip()) for item in source_references):
        raise ReceiptError("source references must be non-empty strings or objects")
    if credential_paths({"plan": plan, "identities": normalized_identities, "events": normalized_events, "usage": usage_value, "sources": source_references}):
        raise ReceiptError("credentials are forbidden in receipt evidence")
    normalized_source_identity: dict[str, Any] | None = None
    if source_surface is not None:
        if not _nonempty(source_surface):
            raise ReceiptError("source surface must be a non-empty string")
        if source_surface == "native-v2":
            normalized_source_identity = _v2_source_surface_identity(source_surface_identity)
        elif source_surface_identity is not None:
            if not isinstance(source_surface_identity, Mapping):
                raise ReceiptError("source surface identity must be an object")
            normalized_source_identity = dict(source_surface_identity)
    elif source_surface_identity is not None:
        raise ReceiptError("source surface identity requires a source surface")
    _check_source_surface(source_surface, normalized_identities, normalized_events)
    _check_source_references(source_surface, source_references)
    if credential_paths({"source_surface": source_surface, "source_surface_identity": normalized_source_identity}):
        raise ReceiptError("credentials are forbidden in source identity")
    metadata = manifest.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise ReceiptError("bundle metadata must be an object")
    evidence_tier = metadata.get("evidence_tier", "submitted")
    if evidence_tier not in EVIDENCE_TIERS:
        raise ReceiptError("invalid evidence tier")
    bundle_verification = loaded.get("verification")
    if not isinstance(bundle_verification, Mapping) or bundle_verification.get("verified") is not True:
        raise ReceiptError("receipt requires verified bundle custody")
    qualification_value = dict(qualification or {})
    if qualification_value.get("status") not in {"PASS", "FAIL"}:
        raise ReceiptError("qualification report status is required and must be PASS or FAIL")
    verification_value = _require_mapping(verification, "verification")
    if verification_value.get("status") not in {"PASS", "FAIL", "unknown"}:
        raise ReceiptError("verification report status is required")
    report = derive_report(plan, normalized_events, terminal_state=terminal_state, qualification=qualification_value, evidence_tier=evidence_tier)
    if report["issues"]:
        raise ReceiptError("contradictory lifecycle evidence: " + ", ".join(report["issues"]))
    explicit_terminal = terminal_state or report["state"]
    if explicit_terminal not in REPORT_STATES:
        raise ReceiptError("invalid terminal/report state")
    lifecycle_value = dict(_require_mapping(lifecycle, "lifecycle"))
    lifecycle_value.setdefault("event_count", len(normalized_events))
    lifecycle_value.setdefault("terminal_state", explicit_terminal)
    if lifecycle_value.get("terminal_state") != explicit_terminal:
        raise ReceiptError("lifecycle terminal state contradicts event evidence")
    adapter_record: dict[str, Any] = {"version": adapter_version}
    if source_surface is not None:
        adapter_record["source_surface"] = source_surface
    if normalized_source_identity is not None:
        adapter_record["source_surface_identity"] = normalized_source_identity
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "bundle": {"schema": BUNDLE_SCHEMA, "bundle_id": manifest.get("bundle_id"), "manifest_sha256": bundle_verification.get("manifest_sha256")},
        "evidence_tier": evidence_tier,
        "plan": {"value": dict(plan), "sha256": json_sha256(plan)},
        "identities": normalized_identities,
        "effective_model_effort": {"root": {"model": normalized_identities["root"]["model"], "effort": normalized_identities["root"]["effort"]}, "children": [{"lane_id": child["lane_id"], "model": child["model"], "effort": child["effort"]} for child in normalized_identities["children"]]},
        "lifecycle": lifecycle_value,
        "events": normalized_events,
        "verification": dict(verification_value),
        "qualification": qualification_value,
        "report": report,
        "terminal_state": explicit_terminal,
        "source_references": list(source_references),
        "adapter": adapter_record,
        "usage": usage_value,
    }
    if source_surface is not None:
        receipt["source_surface"] = source_surface
    if normalized_source_identity is not None:
        receipt["source_surface_identity"] = normalized_source_identity
    return receipt


def verify_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Check shape *and* all receipt cross-field contracts.

    A receipt is a derived artifact, so checking only its top-level shape is
    insufficient: callers could otherwise edit identities, events, routing,
    lifecycle, or the user-facing report while retaining a superficially valid
    plan hash. Re-run the same provider-free normalizers used during
    generation and compare deterministic derived fields.
    """
    issues: list[str] = []
    if not isinstance(receipt, Mapping):
        raise ReceiptError("receipt must be an object")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        issues.append("receipt:schema_invalid")
    evidence_tier = receipt.get("evidence_tier")
    if evidence_tier not in EVIDENCE_TIERS:
        issues.append("receipt:evidence_tier_invalid")
    if credential_paths(receipt):
        issues.append("receipt:credentials_present")
    for required in (
        "bundle", "plan", "identities", "effective_model_effort", "events", "lifecycle",
        "verification", "qualification", "report", "terminal_state", "source_references", "adapter", "usage",
    ):
        if required not in receipt:
            issues.append("receipt:missing:%s" % required)

    bundle = receipt.get("bundle")
    if not isinstance(bundle, Mapping) or bundle.get("schema") != BUNDLE_SCHEMA or not _nonempty(bundle.get("bundle_id")):
        issues.append("receipt:bundle_invalid")
    elif not isinstance(bundle.get("manifest_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", bundle["manifest_sha256"]):
        issues.append("receipt:bundle_manifest_hash_invalid")

    plan_value: Mapping[str, Any] | None = None
    plan_record = receipt.get("plan")
    if isinstance(plan_record, Mapping):
        candidate_plan = plan_record.get("value")
        plan_hash = plan_record.get("sha256")
        if not isinstance(candidate_plan, Mapping):
            issues.append("receipt:plan_invalid")
        else:
            plan_value = candidate_plan
            if candidate_plan.get("schema") != PLAN_SCHEMA:
                issues.append("receipt:plan_schema_invalid")
            if not isinstance(plan_hash, str) or plan_hash != json_sha256(candidate_plan):
                issues.append("receipt:plan_hash_mismatch")
    else:
        issues.append("receipt:plan_invalid")

    normalized_events: list[dict[str, Any]] | None = None
    try:
        normalized_events = _as_events(receipt.get("events"))
    except ReceiptError:
        issues.append("receipt:events_invalid")

    identities = receipt.get("identities")
    normalized_identities: dict[str, Any] | None = None
    if not isinstance(identities, Mapping) or not isinstance(identities.get("root"), Mapping) or not isinstance(identities.get("children"), list) or not isinstance(identities.get("parent_edges"), list):
        issues.append("receipt:identities_invalid")
    elif plan_value is not None and normalized_events is not None:
        try:
            normalized_identities = _normalize_identities(identities, normalized_events, plan_value)
            _check_event_identities(normalized_events, normalized_identities)
            if dict(identities) != normalized_identities:
                issues.append("receipt:identities_not_canonical")
        except ReceiptError as exc:
            issues.append("receipt:identity_contract:" + str(exc))

    effective = receipt.get("effective_model_effort")
    if not isinstance(effective, Mapping) or not isinstance(effective.get("root"), Mapping) or not isinstance(effective.get("children"), list):
        issues.append("receipt:effective_model_effort_invalid")
    elif normalized_identities is not None:
        expected_effective = {
            "root": {
                "model": normalized_identities["root"]["model"],
                "effort": normalized_identities["root"]["effort"],
            },
            "children": [
                {"lane_id": child["lane_id"], "model": child["model"], "effort": child["effort"]}
                for child in normalized_identities["children"]
            ],
        }
        if dict(effective) != expected_effective:
            issues.append("receipt:effective_model_effort_mismatch")

    lifecycle = receipt.get("lifecycle")
    if not isinstance(lifecycle, Mapping):
        issues.append("receipt:lifecycle_invalid")
    else:
        terminal_state = receipt.get("terminal_state")
        if "terminal_state" not in lifecycle or lifecycle.get("terminal_state") != terminal_state:
            issues.append("receipt:lifecycle_terminal_mismatch")
        if "event_count" in lifecycle and (type(lifecycle["event_count"]) is not int or normalized_events is None or lifecycle["event_count"] != len(normalized_events)):
            issues.append("receipt:lifecycle_event_count_invalid")
        if normalized_identities is not None and "root_thread_id" in lifecycle and lifecycle.get("root_thread_id") != normalized_identities["root"]["thread_id"]:
            issues.append("receipt:lifecycle_root_mismatch")

    verification = receipt.get("verification")
    if not isinstance(verification, Mapping) or verification.get("status") not in {"PASS", "FAIL", "unknown"}:
        issues.append("receipt:verification_invalid")
    qualification = receipt.get("qualification")
    if not isinstance(qualification, Mapping) or qualification.get("status") not in {"PASS", "FAIL"}:
        issues.append("receipt:qualification_invalid")

    report = receipt.get("report")
    if not isinstance(report, Mapping):
        issues.append("receipt:report_invalid")
    else:
        if report.get("issues") not in (None, []):
            issues.append("receipt:report_has_issues")
        if report.get("state") != receipt.get("terminal_state"):
            issues.append("receipt:report_state_mismatch")
        if plan_value is not None and normalized_events is not None and isinstance(qualification, Mapping) and evidence_tier in EVIDENCE_TIERS and receipt.get("terminal_state") in REPORT_STATES:
            expected_report = derive_report(
                plan_value,
                normalized_events,
                terminal_state=receipt["terminal_state"],
                qualification=qualification,
                evidence_tier=evidence_tier,
            )
            if expected_report["issues"]:
                issues.extend("receipt:derived_report:" + issue for issue in expected_report["issues"])
            if dict(report) != expected_report:
                issues.append("receipt:report_mismatch")

    adapter = receipt.get("adapter")
    if not isinstance(adapter, Mapping) or not _nonempty(adapter.get("version")):
        issues.append("receipt:adapter_invalid")
    receipt_surface = receipt.get("source_surface")
    receipt_surface_identity = receipt.get("source_surface_identity")
    adapter_surface = adapter.get("source_surface") if isinstance(adapter, Mapping) else None
    adapter_surface_identity = adapter.get("source_surface_identity") if isinstance(adapter, Mapping) else None
    if receipt_surface is not None or adapter_surface is not None or receipt_surface_identity is not None or adapter_surface_identity is not None:
        if receipt_surface != adapter_surface:
            issues.append("receipt:source_surface_mismatch")
        if receipt_surface != "native-v2":
            issues.append("receipt:source_surface_invalid")
        try:
            normalized_surface_identity = _v2_source_surface_identity(receipt_surface_identity)
            if not isinstance(adapter_surface_identity, Mapping) or dict(adapter_surface_identity) != normalized_surface_identity:
                issues.append("receipt:source_surface_identity_mismatch")
        except ReceiptError as exc:
            issues.append("receipt:source_surface_identity_invalid:" + str(exc))
        try:
            _check_source_surface(receipt_surface, normalized_identities, normalized_events)
        except ReceiptError as exc:
            issues.append("receipt:source_surface_contract:" + str(exc))
    elif isinstance(adapter, Mapping) and adapter.get("source_surface_identity") is not None:
        issues.append("receipt:source_surface_identity_without_surface")
    sources = receipt.get("source_references")
    if not isinstance(sources, list) or not sources or any(not isinstance(item, (str, Mapping)) or (isinstance(item, str) and not item.strip()) for item in sources):
        issues.append("receipt:sources_invalid")
    else:
        try:
            _check_source_references(receipt_surface, sources)
        except ReceiptError as exc:
            issues.append("receipt:source_reference_contract:" + str(exc))
    try:
        _normalize_usage(receipt.get("usage"))
    except ReceiptError:
        issues.append("receipt:usage_invalid")
    if receipt.get("terminal_state") not in REPORT_STATES:
        issues.append("receipt:terminal_state_invalid")
    if issues:
        raise ReceiptError("invalid receipt: " + ", ".join(sorted(set(issues))))
    digest = hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"schema": RECEIPT_SCHEMA, "status": "PASS", "verified": True, "receipt_sha256": digest, "state": receipt["terminal_state"], "evidence_tier": receipt["evidence_tier"]}


generate_receipt = build_receipt
render_receipt = build_receipt
generate_v1_receipt = build_receipt_from_v1_bundle
generate_v2_receipt = build_receipt_from_v2_bundle


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    generate = subparsers.add_parser("generate")
    generate.add_argument("bundle", nargs="?")
    generate.add_argument("--bundle", dest="bundle_option")
    generate.add_argument("--output", "-o")
    generate_v1 = subparsers.add_parser("generate-v1")
    generate_v1.add_argument("bundle", nargs="?")
    generate_v1.add_argument("--bundle", dest="bundle_option")
    generate_v1.add_argument("--output", "-o")
    generate_v2 = subparsers.add_parser("generate-v2")
    generate_v2.add_argument("bundle", nargs="?")
    generate_v2.add_argument("--bundle", dest="bundle_option")
    generate_v2.add_argument("--output", "-o")
    verify = subparsers.add_parser("verify")
    verify.add_argument("receipt")
    args = parser.parse_args(argv)
    command = args.command or "generate"
    try:
        if command == "verify":
            receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
            result = verify_receipt(receipt)
        else:
            bundle_path = getattr(args, "bundle_option", None) or getattr(args, "bundle", None)
            if not bundle_path:
                parser.error("generate requires a bundle path")
            if command == "generate-v1":
                result_value = build_receipt_from_v1_bundle(bundle_path)
            elif command == "generate-v2":
                result_value = build_receipt_from_v2_bundle(bundle_path)
            else:
                result_value = build_receipt(bundle_path)
            verify_receipt(result_value)
            result = result_value
            output = getattr(args, "output", None)
            if output:
                Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, BundleError, ReceiptError) as exc:
        print(json.dumps({"schema": RECEIPT_SCHEMA, "status": "FAIL", "verified": False, "issues": [str(exc)]}, indent=2, sort_keys=True))
        return 2
    if not getattr(args, "output", None) or command == "verify":
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


main = _main


if __name__ == "__main__":
    raise SystemExit(_main())
