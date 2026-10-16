#!/usr/bin/env python3
"""Normalize the classic-V1 runtime surface into observable graph evidence.

The adapter deliberately accepts a small, provider-free record format.  It does
not infer sessions from tool names or from a submitted trace.  Every accepted
record must have a unique source reference, and every graph edge is bound to a
raw record before it is emitted.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import math
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping, Optional


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


ADAPTER_NAME = "classic-v1"
ADAPTER_VERSION = "classic-v1-observer/1.0"
NORMALIZED_SCHEMA = "orch-dork/runtime-evidence/v1"
RAW_SCHEMA = "orch-dork/raw-classic-v1"
REASONING_EFFORTS = {"low", "medium", "high", "xhigh", "max", "ultra"}
CHILD_CONTEXT_POLICY = "none"


def subagent_model():
    """The governed worker model, resolved when it is used."""

    return worker_default.configured_worker_model()


def subagent_effort():
    """The governed worker effort, resolved when it is used."""

    return worker_default.configured_worker_effort()


# Compatibility aliases for the v1 wire schema, which still uses `children`.
child_model = subagent_model
child_effort = subagent_effort


class V1ObservationError(ValueError):
    """Raised by :func:`require_observation` for non-qualifying evidence."""

    def __init__(self, report: Mapping[str, Any]):
        self.report = dict(report)
        super().__init__("classic-v1 observation failed: " + ", ".join(report["issues"]))


@dataclass(frozen=True)
class SourceRef:
    """Stable, non-secret reference to one raw runtime record."""

    record_id: str
    position: int

    def as_dict(self) -> dict[str, Any]:
        return {"record_id": self.record_id, "position": self.position}


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _record_type(record: Mapping[str, Any]) -> Optional[str]:
    value = record.get("type", record.get("kind"))
    if not _nonempty(value):
        return None
    aliases = {
        "session_start": "session.started",
        "session.started": "session.started",
        "session_end": "session.completed",
        "session.completed": "session.completed",
        "session.failed": "session.failed",
        "session.cancelled": "session.cancelled",
        "session.timed_out": "session.timed_out",
        "child.spawned": "child.spawned",
        "collaboration.spawned": "child.spawned",
        "collaboration.call": "child.spawned",
        "child.completed": "child.completed",
        "collaboration.completed": "child.completed",
        "collaboration.result": "child.completed",
        "verification.completed": "verification.completed",
        "lane.verified": "verification.completed",
        "root.tool": "root.tool",
        "session.compacted": "session.compacted",
    }
    return aliases.get(value.strip())


def _source_ref(record: Mapping[str, Any], position: int) -> Optional[SourceRef]:
    value = record.get("source_ref", record.get("source"))
    if isinstance(value, str) and value.strip():
        return SourceRef(value.strip(), position)
    if isinstance(value, Mapping):
        record_id = value.get("record_id", value.get("id", value.get("ref")))
        if _nonempty(record_id):
            return SourceRef(record_id.strip(), position)
    return None


def _task_id(record: Mapping[str, Any], *names: str) -> Optional[str]:
    for name in names:
        value = record.get(name)
        if _nonempty(value):
            return value.strip()
    return None


def _timestamp(record: Mapping[str, Any]) -> Optional[float | int]:
    value = record.get("timestamp", record.get("time"))
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _metadata(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "model": record.get("model"),
        "effort": record.get("effort", record.get("reasoning_effort")),
        "context_policy": record.get("context_policy"),
        "depth": record.get("depth"),
        "parent_task_id": _task_id(record, "parent_task_id", "parent_thread_id", "parent_id"),
    }


def _plan_expectations(plan: Optional[Mapping[str, Any]], issues: list[str]) -> tuple[Optional[str], set[str]]:
    if plan is None:
        return None, set()
    if not isinstance(plan, Mapping):
        issues.append("plan:not_object")
        return None, set()
    decision = plan.get("decision")
    mode = decision.get("mode") if isinstance(decision, Mapping) else None
    if mode != "orchestrated":
        issues.append("plan:mode_not_orchestrated")
    root = plan.get("root")
    if not isinstance(root, Mapping):
        issues.append("plan:root_not_object")
    else:
        if not _nonempty(root.get("model")):
            issues.append("plan:root_model_invalid")
        if not _nonempty(root.get("effort")):
            issues.append("plan:root_effort_invalid")
    children = plan.get("children")
    if not isinstance(children, Mapping):
        issues.append("plan:children_not_object")
    else:
        # The native subagent route is a policy invariant, not a value that a
        # submitted plan can weaken.  The plan validator reports the same
        # contradiction, while the raw observer must fail independently too.
        if "model" in children and children.get("model") != child_model():
            issues.append("plan:child_model_invalid")
        if "effort" in children and children.get("effort") != child_effort():
            issues.append("plan:child_effort_invalid")
        if "context_policy" in children and children.get("context_policy") != CHILD_CONTEXT_POLICY:
            issues.append("plan:child_context_policy_invalid")
    lanes = plan.get("lanes")
    if not isinstance(lanes, list):
        issues.append("plan:lanes_not_array")
        return mode, set()
    lane_ids: set[str] = set()
    for lane in lanes:
        lane_id = lane.get("id") if isinstance(lane, Mapping) else None
        if not _nonempty(lane_id):
            issues.append("plan:lane_id_invalid")
        elif lane_id.strip() in lane_ids:
            issues.append("plan:duplicate_lane:%s" % lane_id.strip())
        else:
            lane_ids.add(lane_id.strip())
    expected = children.get("expected_count") if isinstance(children, Mapping) else None
    if expected is not None and type(expected) is not int:
        issues.append("plan:expected_count_invalid")
    elif isinstance(expected, int) and expected != len(lane_ids):
        issues.append("plan:lane_count_mismatch")
    return mode, lane_ids


def _empty_report(issues: Iterable[str], *, raw_records: int = 0) -> dict[str, Any]:
    issues = list(issues)
    return {
        "schema": NORMALIZED_SCHEMA,
        "adapter": {"name": ADAPTER_NAME, "version": ADAPTER_VERSION},
        "evidence_tier": "runtime-observed",
        "status": "FAIL" if issues else "PASS",
        "issues": sorted(set(issues)),
        "source_refs": [],
        "events": [],
        "graph": {"root": None, "children": []},
        "raw_record_count": raw_records,
    }


def observe_v1(raw: Mapping[str, Any] | Iterable[Mapping[str, Any]], plan: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
    """Reconstruct a classic-V1 graph from raw records.

    The returned object is always a report.  ``status`` is ``FAIL`` whenever
    any required identity, edge, lifecycle, routing, verification, terminal,
    source, or plan-boundary evidence is missing or contradictory.
    """

    issues: list[str] = []
    if isinstance(raw, Mapping):
        if raw.get("schema") not in (None, RAW_SCHEMA):
            issues.append("raw:schema_invalid")
        records = raw.get("records", raw.get("events"))
        if not isinstance(records, list):
            issues.append("raw:records_not_array")
            records = []
    elif isinstance(raw, Iterable) and not isinstance(raw, (str, bytes)):
        records = list(raw)
    else:
        records = []
        issues.append("raw:not_object_or_array")

    mode, planned_lanes = _plan_expectations(plan, issues)
    planned_root = plan.get("root") if isinstance(plan, Mapping) else None
    planned_root = planned_root if isinstance(planned_root, Mapping) else {}
    planned_children = plan.get("children") if isinstance(plan, Mapping) else None
    planned_children = planned_children if isinstance(planned_children, Mapping) else {}
    # Never let an untrusted plan replace the mandatory native subagent route.
    # If a plan contains route fields, _plan_expectations has already recorded
    # any contradiction; the raw records are still checked against constants.
    expected_child_model = child_model()
    expected_child_effort = child_effort()
    expected_child_context = CHILD_CONTEXT_POLICY
    report = _empty_report(issues, raw_records=len(records))
    issues = list(report["issues"])
    if not records:
        issues.append("raw:no_records")

    refs: list[SourceRef] = []
    seen_refs: set[str] = set()
    typed: list[tuple[int, Mapping[str, Any], str, SourceRef]] = []
    for position, record in enumerate(records):
        if not isinstance(record, Mapping):
            issues.append("record[%d]:not_object" % position)
            continue
        ref = _source_ref(record, position)
        if ref is None:
            issues.append("record[%d]:source_ref_missing" % position)
            continue
        if ref.record_id in seen_refs:
            issues.append("source:duplicate:%s" % ref.record_id)
        seen_refs.add(ref.record_id)
        refs.append(ref)
        event_type = _record_type(record)
        if event_type is None:
            issues.append("record[%d]:type_invalid" % position)
            continue
        if ("timestamp" in record or "time" in record) and _timestamp(record) is None:
            issues.append("record[%d]:timestamp_invalid" % position)
        typed.append((position, record, event_type, ref))

    sessions: dict[str, dict[str, Any]] = {}
    session_events: dict[tuple[str, str], list[tuple[int, Mapping[str, Any], SourceRef]]] = {}
    spawns: list[tuple[int, Mapping[str, Any], SourceRef]] = []
    verifications: list[tuple[int, Mapping[str, Any], SourceRef]] = []
    root_tools: list[tuple[int, Mapping[str, Any], SourceRef]] = []
    compactions: list[tuple[int, Mapping[str, Any], SourceRef]] = []

    for position, record, event_type, ref in typed:
        if event_type == "child.spawned":
            spawns.append((position, record, ref))
            continue
        if event_type == "verification.completed":
            verifications.append((position, record, ref))
            continue
        if event_type == "root.tool":
            root_tools.append((position, record, ref))
            continue
        if event_type == "session.compacted":
            compactions.append((position, record, ref))
            continue
        task_id = _task_id(record, "task_id", "session_id", "thread_id", "root_task_id", "root_thread_id")
        if task_id is None:
            issues.append("record[%d]:task_id_missing" % position)
            continue
        session_events.setdefault((task_id, event_type), []).append((position, record, ref))
        if event_type == "session.started":
            if task_id in sessions:
                issues.append("session:duplicate_start:%s" % task_id)
                continue
            metadata = _metadata(record)
            sessions[task_id] = {
                "task_id": task_id,
                "parent_task_id": metadata["parent_task_id"],
                "depth": metadata["depth"],
                "model": metadata["model"],
                "effort": metadata["effort"],
                "context_policy": metadata["context_policy"],
                "started_at": _timestamp(record),
                "start_ref": ref.as_dict(),
                "terminal": None,
                "terminal_at": None,
                "terminal_ref": None,
                "_start_position": position,
                "_terminal_position": None,
                "verification": [],
                "source_refs": [ref.as_dict()],
            }
        elif task_id in sessions:
            session = sessions[task_id]
            session["source_refs"].append(ref.as_dict())
            if event_type in {"session.completed", "session.failed", "session.cancelled", "session.timed_out"}:
                if session["terminal"] is not None:
                    issues.append("session:duplicate_terminal:%s" % task_id)
                session["terminal"] = event_type.removeprefix("session.")
                session["terminal_at"] = _timestamp(record)
                session["terminal_ref"] = ref.as_dict()
                session["_terminal_position"] = position
        else:
            issues.append("session:event_before_start:%s:%s" % (task_id, event_type))

    root_ids = [task_id for task_id, session in sessions.items() if session["parent_task_id"] in (None, "")]
    if len(root_ids) != 1:
        issues.append("graph:root_count:%d" % len(root_ids))
    root_id = root_ids[0] if len(root_ids) == 1 else None
    if root_id is not None:
        root = sessions[root_id]
        if type(root["depth"]) is not int or root["depth"] != 0:
            issues.append("graph:root_depth_invalid")
        _check_routing(
            root,
            planned_root.get("model"),
            planned_root.get("effort"),
            "root",
            issues,
            require_exact=bool(planned_root),
            context_policy=planned_root.get("context_policy"),
        )
    else:
        root = None

    if root is not None and root.get("_start_position") is not None:
        root_start_position = root["_start_position"]
        for position, _, _ in spawns + verifications + root_tools + compactions:
            if position < root_start_position:
                issues.append("lifecycle:root_start_not_before_event")
        for task_id, session in sessions.items():
            if task_id == root_id:
                continue
            if session.get("_start_position") is not None and session["_start_position"] < root_start_position:
                issues.append("lifecycle:root_start_not_before_child:%s" % task_id)
            if session.get("_terminal_position") is not None and session["_terminal_position"] < root_start_position:
                issues.append("lifecycle:root_start_not_before_child:%s" % task_id)

    children: dict[str, dict[str, Any]] = {}
    spawn_by_lane: dict[str, tuple[int, Mapping[str, Any], SourceRef]] = {}
    spawn_by_child: dict[str, str] = {}
    for position, record, ref in spawns:
        lane_id = _task_id(record, "lane_id", "lane")
        child_id = _task_id(record, "child_task_id", "child_thread_id", "task_id", "session_id")
        parent_id = _task_id(record, "parent_task_id", "parent_thread_id", "parent_id")
        if lane_id is None:
            issues.append("spawn[%d]:lane_id_missing" % position)
        if child_id is None:
            issues.append("spawn[%d]:child_id_missing" % position)
        if parent_id is None:
            issues.append("spawn[%d]:parent_id_missing" % position)
        if lane_id is None or child_id is None:
            continue
        if lane_id in spawn_by_lane:
            issues.append("graph:duplicate_spawn_lane:%s" % lane_id)
        spawn_by_lane[lane_id] = (position, record, ref)
        if child_id in spawn_by_child:
            issues.append("graph:duplicate_child_identity:%s" % child_id)
        else:
            spawn_by_child[child_id] = lane_id
        if parent_id != root_id:
            issues.append("graph:parent_mismatch:%s" % lane_id)
        session = sessions.get(child_id)
        if session is None:
            issues.append("graph:missing_child_session:%s" % lane_id)
            session = {
                "task_id": child_id,
                "parent_task_id": parent_id,
                "depth": record.get("depth"),
                "model": record.get("model"),
                "effort": record.get("effort", record.get("reasoning_effort")),
                "context_policy": record.get("context_policy"),
                "started_at": None,
                "start_ref": None,
                "terminal": None,
                "terminal_at": None,
                "terminal_ref": None,
                "_spawn_position": position,
                "_start_position": None,
                "_terminal_position": None,
                "verification": [],
                "source_refs": [],
            }
        else:
            if session["parent_task_id"] != parent_id:
                issues.append("graph:session_parent_mismatch:%s" % lane_id)
            for field in ("model", "effort", "depth", "context_policy"):
                spawn_value = record.get(field, record.get("reasoning_effort") if field == "effort" else None)
                if spawn_value is not None and session.get(field) is not None and spawn_value != session.get(field):
                    issues.append("graph:spawn_session_%s_mismatch:%s" % (field, lane_id))
        child = dict(session)
        child["lane_id"] = lane_id
        child["_spawn_position"] = position
        child["spawn_ref"] = ref.as_dict()
        child["source_refs"] = list(child.get("source_refs", [])) + [ref.as_dict()]
        children[lane_id] = child
        spawn_identity = {
            "model": record.get("model"),
            "effort": record.get("effort", record.get("reasoning_effort")),
            "context_policy": record.get("context_policy"),
        }
        _check_routing(
            spawn_identity,
            expected_child_model,
            expected_child_effort,
            "spawn:%s" % lane_id,
            issues,
            context_policy=expected_child_context,
        )
        _check_routing(
            child,
            expected_child_model,
            expected_child_effort,
            lane_id,
            issues,
            context_policy=expected_child_context,
        )
        if type(child.get("depth")) is not int or child.get("depth") != 1:
            issues.append("graph:depth_invalid:%s" % lane_id)
        if type(record.get("depth")) is not int or record.get("depth") != 1:
            issues.append("graph:spawn_depth_invalid:%s" % lane_id)
        if child.get("parent_task_id") != root_id:
            issues.append("graph:parent_mismatch:%s" % lane_id)

    if root_id is not None:
        for task_id, session in sessions.items():
            if task_id == root_id:
                continue
            if session["parent_task_id"] != root_id:
                issues.append("graph:nested_or_orphan_session:%s" % task_id)
        if len(children) != len(sessions) - 1:
            issues.append("graph:unspawned_session")

    if planned_lanes:
        for lane_id in sorted(planned_lanes - set(spawn_by_lane)):
            issues.append("graph:missing_spawn:%s" % lane_id)
        for lane_id in sorted(set(spawn_by_lane) - planned_lanes):
            issues.append("graph:extra_child:%s" % lane_id)
        expected_count = plan.get("children", {}).get("expected_count") if isinstance(plan, Mapping) and isinstance(plan.get("children"), Mapping) else None
        if isinstance(expected_count, int) and len(spawn_by_lane) != expected_count:
            issues.append("graph:spawn_count:%d!=%d" % (len(spawn_by_lane), expected_count))
    elif mode == "orchestrated":
        issues.append("plan:lane_boundary_missing")

    seen_verifications: set[tuple[str, str]] = set()
    for position, record, ref in verifications:
        task_id = _task_id(record, "task_id", "child_task_id", "child_thread_id", "session_id", "thread_id")
        lane_id = _task_id(record, "lane_id", "lane")
        passed = record.get("passed")
        if lane_id is not None and lane_id not in children:
            issues.append("verification[%d]:unknown_lane:%s" % (position, lane_id))
            # Do not attach a verification to an unrecognized lane.  In
            # particular, never index children with an arbitrary submitted
            # lane ID; malformed evidence must produce a report, not a crash.
            continue
        if lane_id is not None and task_id is not None and children[lane_id]["task_id"] != task_id:
            issues.append("verification:identity_mismatch:%s" % lane_id)
        if task_id is None and lane_id in children:
            task_id = children[lane_id]["task_id"]
        if task_id is None:
            issues.append("verification[%d]:task_id_missing" % position)
            continue
        resolved_lane = lane_id or next((key for key, child in children.items() if child["task_id"] == task_id), None)
        if resolved_lane is None:
            issues.append("verification[%d]:unknown_child:%s" % (position, task_id))
            continue
        key = (resolved_lane, task_id)
        if key in seen_verifications:
            issues.append("verification:duplicate:%s" % resolved_lane)
        seen_verifications.add(key)
        if passed is not True:
            issues.append("verification:not_passed:%s" % resolved_lane)
        children[resolved_lane]["verification"].append({
            "passed": passed,
            "timestamp": _timestamp(record),
            "source_ref": ref.as_dict(),
            "_position": position,
        })

    for position, record, ref in compactions:
        task_id = _task_id(record, "task_id", "session_id", "thread_id")
        if task_id is None:
            issues.append("compaction[%d]:task_id_missing" % position)
        elif task_id not in sessions:
            issues.append("compaction:unknown_session:%s" % task_id)

    for lane_id, child in children.items():
        if len(child["verification"]) != 1:
            issues.append("verification:count:%s:%d" % (lane_id, len(child["verification"])))
        if child["terminal"] is None:
            issues.append("lifecycle:terminal_missing:%s" % lane_id)
        elif child["terminal"] != "completed":
            issues.append("lifecycle:terminal_not_completed:%s" % lane_id)
        start_position = child.get("_start_position")
        spawn_position = child.get("_spawn_position")
        terminal_position = child.get("_terminal_position")
        if spawn_position is not None and start_position is not None and start_position <= spawn_position:
            issues.append("lifecycle:session_start_not_after_spawn:%s" % lane_id)
        if start_position is not None and terminal_position is not None and terminal_position <= start_position:
            issues.append("lifecycle:terminal_not_after_start:%s" % lane_id)
        if spawn_position is not None and terminal_position is not None and terminal_position <= spawn_position:
            issues.append("lifecycle:terminal_not_after_spawn:%s" % lane_id)
        spawn = spawn_by_lane.get(lane_id)
        spawn_timestamp = _timestamp(spawn[1]) if spawn is not None else None
        if spawn_timestamp is not None and child.get("started_at") is not None and child["started_at"] <= spawn_timestamp:
            issues.append("lifecycle:session_start_not_after_spawn:%s" % lane_id)
        if child.get("started_at") is not None and child.get("terminal_at") is not None and child["terminal_at"] <= child["started_at"]:
            issues.append("lifecycle:terminal_not_after_start:%s" % lane_id)
        if spawn_timestamp is not None and child.get("terminal_at") is not None and child["terminal_at"] <= spawn_timestamp:
            issues.append("lifecycle:terminal_not_after_spawn:%s" % lane_id)
        if child["verification"]:
            for verification in child["verification"]:
                if start_position is not None and verification.get("_position") is not None and verification["_position"] <= start_position:
                    issues.append("lifecycle:verification_not_after_start:%s" % lane_id)
                if terminal_position is not None and verification.get("_position") is not None and verification["_position"] >= terminal_position:
                    issues.append("lifecycle:verification_not_before_terminal:%s" % lane_id)
                if verification.get("timestamp") is not None and child.get("terminal_at") is not None and verification["timestamp"] >= child["terminal_at"]:
                    issues.append("lifecycle:verification_not_before_terminal:%s" % lane_id)
                if verification.get("timestamp") is not None and child.get("started_at") is not None and verification["timestamp"] <= child["started_at"]:
                    issues.append("lifecycle:verification_not_after_start:%s" % lane_id)

    if root is not None and root.get("_terminal_position") is not None:
        for lane_id, child in children.items():
            child_terminal = child.get("_terminal_position")
            if child_terminal is not None and root["_terminal_position"] <= child_terminal:
                issues.append("lifecycle:root_terminal_before_child:%s" % lane_id)
            if child.get("terminal_at") is not None and root.get("terminal_at") is not None and root["terminal_at"] <= child["terminal_at"]:
                issues.append("lifecycle:root_terminal_timestamp_before_child:%s" % lane_id)
        for position, _, _ in spawns + root_tools + compactions:
            if position > root["_terminal_position"]:
                issues.append("lifecycle:root_terminal_not_last")
        for task_id, session in sessions.items():
            if task_id != root_id and session.get("_start_position") is not None and session["_start_position"] > root["_terminal_position"]:
                issues.append("lifecycle:root_terminal_not_last")

    if root is not None:
        if root["terminal"] is None:
            issues.append("lifecycle:root_terminal_missing")
        elif root["terminal"] != "completed":
            issues.append("lifecycle:root_terminal_not_completed")
        for position, record, ref in root_tools:
            task_id = _task_id(record, "task_id", "session_id", "thread_id")
            if task_id is None:
                issues.append("root:tool_identity_missing:%s" % ref.record_id)
            elif task_id != root_id:
                issues.append("root:tool_identity_mismatch:%s" % ref.record_id)
            category = record.get("category")
            if category not in {"coordination", "implementation"}:
                issues.append("root:tool_category_invalid:%s" % ref.record_id)
            if category == "implementation":
                issues.append("root:implementation_tool:%s" % record.get("name", "unknown"))

    events = _normalized_events(root, children, spawns, verifications, root_tools, compactions)
    graph = {
        "root": _public_session(root) if root is not None else None,
        "children": [_public_session(children[lane]) for lane in sorted(children)],
    }
    usage_report = None
    if isinstance(raw, Mapping) and "usage" in raw:
        # Keep the observer and attribution surfaces coherent without making
        # usage a guessed zero when the raw surface did not provide it.
        try:
            from orch_dork_usage import attribute_usage

            usage_report = attribute_usage(raw, graph)
            if usage_report["status"] != "PASS":
                issues.extend("usage:" + issue for issue in usage_report["issues"])
        except ImportError:
            issues.append("usage:adapter_unavailable")
    report.update({
        "status": "FAIL" if issues else "PASS",
        "issues": sorted(set(issues)),
        "source_refs": [ref.as_dict() for ref in refs],
        "events": events,
        "graph": graph,
        "compaction_records": [ref.as_dict() for _, _, ref in compactions],
    })
    if usage_report is not None:
        report["usage"] = usage_report
    return report


def _check_routing(
    session: Mapping[str, Any],
    model: Optional[str],
    effort: Optional[str],
    label: str,
    issues: list[str],
    *,
    require_exact: bool = True,
    context_policy: Optional[str] = None,
) -> None:
    if require_exact and session.get("model") != model:
        issues.append("routing:model_invalid:%s" % label)
    if require_exact and session.get("effort") != effort:
        issues.append("routing:effort_invalid:%s" % label)
    if not _nonempty(session.get("model")) or not _nonempty(session.get("effort")):
        issues.append("routing:missing:%s" % label)
    elif session.get("effort") not in REASONING_EFFORTS:
        issues.append("routing:effort_invalid:%s" % label)
    if context_policy is not None and session.get("context_policy") != context_policy:
        issues.append("routing:context_policy_invalid:%s" % label)
    if not _nonempty(session.get("context_policy")):
        issues.append("routing:context_policy_missing:%s" % label)


def _public_session(session: Optional[Mapping[str, Any]]) -> Optional[dict[str, Any]]:
    if session is None:
        return None
    return {key: value for key, value in session.items() if key != "source_refs" and not key.startswith("_")} | {
        "source_refs": list(session.get("source_refs", []))
    }


def _normalized_events(root: Optional[Mapping[str, Any]], children: Mapping[str, Mapping[str, Any]], spawns: list[Any], verifications: list[Any], root_tools: list[Any], compactions: list[Any]) -> list[dict[str, Any]]:
    """Emit only raw-bound events, preserving their source-record order."""

    rows: list[tuple[int, int, dict[str, Any]]] = []
    missing_position = 10**12
    if root is not None:
        rows.append((root.get("_start_position", missing_position), 0, {
            "type": "root.started",
            "task_id": root["task_id"],
            "parent_task_id": root["parent_task_id"],
            "depth": root["depth"] if root["depth"] is not None else 0,
            "model": root["model"],
            "effort": root["effort"],
            "context_policy": root["context_policy"],
            "timestamp": root["started_at"],
            "source_ref": root["start_ref"],
        }))
    for _, record, ref in sorted(spawns, key=lambda item: item[0]):
        rows.append((ref.position, 1, {
            "type": "child.spawned",
            "lane_id": _task_id(record, "lane_id", "lane"),
            "task_id": _task_id(record, "child_task_id", "child_thread_id", "task_id", "session_id"),
            "parent_task_id": _task_id(record, "parent_task_id", "parent_thread_id", "parent_id"),
            "depth": record.get("depth"),
            "model": record.get("model"),
            "effort": record.get("effort", record.get("reasoning_effort")),
            "context_policy": record.get("context_policy"),
            "timestamp": _timestamp(record),
            "source_ref": ref.as_dict(),
        }))
    for lane_id in sorted(children):
        child = children[lane_id]
        for verification in child["verification"]:
            source_ref = verification.get("source_ref")
            rows.append((verification.get("_position", source_ref.get("position", missing_position) if isinstance(source_ref, Mapping) else missing_position), 2, {
                "type": "lane.verified",
                "lane_id": lane_id,
                "task_id": child["task_id"],
                "passed": verification.get("passed"),
                "source_ref": source_ref,
            }))
        if child["terminal"] is not None:
            rows.append((child.get("_terminal_position", missing_position), 3, {
                "type": "lane.completed" if child["terminal"] == "completed" else "lane.terminal",
                "lane_id": lane_id,
                "task_id": child["task_id"],
                "status": child["terminal"],
                "timestamp": child["terminal_at"],
                "source_ref": child["terminal_ref"],
            }))
    for _, record, ref in sorted(root_tools, key=lambda item: item[0]):
        rows.append((ref.position, 4, {
            "type": "root.tool",
            "task_id": _task_id(record, "task_id", "session_id", "thread_id"),
            "name": record.get("name"),
            "category": record.get("category"),
            "source_ref": ref.as_dict(),
        }))
    for _, record, ref in sorted(compactions, key=lambda item: item[0]):
        rows.append((ref.position, 5, {
            "type": "session.compacted",
            "task_id": _task_id(record, "task_id", "session_id", "thread_id"),
            "timestamp": _timestamp(record),
            "source_ref": ref.as_dict(),
        }))
    if root is not None and root.get("terminal") is not None:
        rows.append((root.get("_terminal_position", missing_position), 6, {
            "type": "run.completed" if root["terminal"] == "completed" else "run.terminal",
            "task_id": root["task_id"],
            "status": root["terminal"],
            "timestamp": root["terminal_at"],
            "source_ref": root["terminal_ref"],
        }))
    rows.sort(key=lambda row: (row[0], row[1]))
    return [{"seq": sequence, **event} for sequence, (_, _, event) in enumerate(rows, 1)]


def require_observation(raw: Mapping[str, Any] | Iterable[Mapping[str, Any]], plan: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
    report = observe_v1(raw, plan)
    if report["status"] != "PASS":
        raise V1ObservationError(report)
    return report


class V1Observer:
    """Reusable state-free observer for provider-free classic-V1 records."""

    adapter_name = ADAPTER_NAME
    adapter_version = ADAPTER_VERSION

    def observe(self, raw: Mapping[str, Any] | Iterable[Mapping[str, Any]], plan: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
        return observe_v1(raw, plan)

    normalize = observe


normalize_v1 = observe_v1
normalize_classic_v1 = observe_v1
reconstruct_v1 = observe_v1
normalize_runtime_records = observe_v1
observe = observe_v1
ClassicV1Observer = V1Observer


__all__ = [
    "ADAPTER_NAME",
    "ADAPTER_VERSION",
    "CHILD_CONTEXT_POLICY",
    "NORMALIZED_SCHEMA",
    "RAW_SCHEMA",
    "V1ObservationError",
    "V1Observer",
    "ClassicV1Observer",
    "child_effort",
    "child_model",
    "normalize_classic_v1",
    "normalize_runtime_records",
    "normalize_v1",
    "observe",
    "observe_v1",
    "reconstruct_v1",
    "require_observation",
    "subagent_effort",
    "subagent_model",
]
