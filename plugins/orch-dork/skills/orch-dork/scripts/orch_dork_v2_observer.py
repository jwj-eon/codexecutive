#!/usr/bin/env python3
"""Observe the native V2 collaboration runtime without a provider.

V2 is a different collaboration surface from the classic V1 tools.  In V2 a
spawn is a call/receipt pair, waits can time out and be repeated, and a child
may complete through a notification which is delivered after the wait that
started it.  This adapter accepts those raw records and emits the same small
+event vocabulary used by :mod:`orch_dork_v1_observer`.

The adapter is intentionally conservative.  A record is a collaboration call
only when the raw record identifies the V2 collaboration surface (or uses the
explicit ``collaboration.*`` record type).  A normal tool called
``spawn_agent`` or ``collaboration.spawn`` therefore remains a root tool and
cannot manufacture a child.  No model-authored trace is consumed here.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import json
import math
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping, Optional


def _load_sibling(name: str):
    """Load a sibling when this module itself was loaded by file path."""

    existing = sys.modules.get(name)
    if existing is not None:
        # Reuse the instance another loader already executed. Re-executing the
        # file would produce a second module object with its own module-level
        # state, so a governed default pinned through one instance would not
        # apply to a validator holding the other.
        return existing
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


ADAPTER_NAME = "native-v2"
ADAPTER_VERSION = "native-v2-observer/1.0"
RAW_SCHEMA = "orch-dork/raw-native-v2"
NORMALIZED_SCHEMA = "orch-dork/runtime-evidence/v1"
SOURCE_SURFACE = "native-v2"
SOURCE_SURFACE_IDENTITY = {
    "name": SOURCE_SURFACE,
    "source_surface": SOURCE_SURFACE,
    "adapter_version": ADAPTER_VERSION,
    "raw_schema": RAW_SCHEMA,
}


def subagent_model():
    """The governed worker model, resolved when it is used."""

    return worker_default.configured_worker_model()


def subagent_effort():
    """The governed worker effort, resolved when it is used."""

    return worker_default.configured_worker_effort()


child_model = subagent_model  # Compatibility names used by the V1 adapter.
child_effort = subagent_effort
CHILD_CONTEXT_POLICY = "none"
REASONING_EFFORTS = {"low", "medium", "high", "xhigh", "max", "ultra"}


class V2ObservationError(ValueError):
    """Raised by :func:`require_observation` for non-qualifying evidence."""

    def __init__(self, report: Mapping[str, Any]):
        self.report = dict(report)
        super().__init__("native-v2 observation failed: " + ", ".join(report["issues"]))


@dataclass(frozen=True)
class SourceRef:
    """A stable reference to one raw source record."""

    record_id: str
    position: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "position": self.position,
            "source_surface": SOURCE_SURFACE,
        }


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _timestamp(record: Mapping[str, Any]) -> Optional[float | int]:
    value = record.get("timestamp", record.get("time"))
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _source_ref(record: Mapping[str, Any], position: int) -> Optional[SourceRef]:
    value = record.get("source_ref", record.get("source"))
    if isinstance(value, str) and value.strip():
        return SourceRef(value.strip(), position)
    if isinstance(value, Mapping):
        record_id = value.get("record_id", value.get("id", value.get("ref")))
        if _nonempty(record_id):
            return SourceRef(record_id.strip(), position)
    return None


def _record_type(record: Mapping[str, Any]) -> Optional[str]:
    value = record.get("type", record.get("kind", record.get("event_type", record.get("event"))))
    if not _nonempty(value):
        return None
    value = value.strip().lower()
    aliases = {
        "session_start": "session.started",
        "start": "session.started",
        "session.started": "session.started",
        "session.start": "session.started",
        "thread.started": "session.started",
        "task.started": "session.started",
        "session_created": "session.started",
        "session_end": "session.completed",
        "end": "session.completed",
        "session.completed": "session.completed",
        "session.complete": "session.completed",
        "thread.completed": "session.completed",
        "task.completed": "session.completed",
        "session.done": "session.completed",
        "session.failed": "session.failed",
        "thread.failed": "session.failed",
        "session.cancelled": "session.cancelled",
        "session.canceled": "session.cancelled",
        "session.timed_out": "session.timed_out",
        "session.timeout": "session.timed_out",
        "thread.timed_out": "session.timed_out",
        "child.spawned": "collaboration.call",
        "collaboration.call": "collaboration.call",
        "collaboration_call": "collaboration.call",
        "call": "collaboration.call",
        "collaboration.result": "collaboration.receipt",
        "collaboration.receipt": "collaboration.receipt",
        "collaboration_result": "collaboration.receipt",
        "receipt": "collaboration.receipt",
        "wait.result": "collaboration.receipt",
        "wait.receipt": "collaboration.receipt",
        "wait.completed": "collaboration.receipt",
        "wait.timed_out": "collaboration.receipt",
        "child.notification": "child.notification",
        "child.completed": "child.notification",
        "collaboration.notification": "child.notification",
        "notification": "child.notification",
        "async.child.completed": "child.notification",
        "notification.child_completed": "child.notification",
        "verification.completed": "verification.completed",
        "lane.verified": "verification.completed",
        "root.tool": "root.tool",
        "tool.call": "root.tool",
        "tool.result": "root.tool",
        "session.compacted": "session.compacted",
        "compaction": "session.compacted",
    }
    return aliases.get(value)


def _maps(record: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    """Yield nested V2 call/receipt maps, never arbitrary text."""

    for key in (
        "arguments",
        "call",
        "params",
        "payload",
        "data",
        "result",
        "response",
        "value",
        "return_value",
        "output",
        "receipt",
        "notification",
        "details",
    ):
        value = record.get(key)
        if isinstance(value, Mapping):
            yield value
        elif isinstance(value, str) and value.lstrip().startswith("{"):
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, Mapping):
                yield parsed


def _value(record: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in record and record[name] is not None:
            return record[name]
    for nested in _maps(record):
        for name in names:
            if name in nested and nested[name] is not None:
                return nested[name]
    return None


def _task_id(record: Mapping[str, Any], *names: str) -> Optional[str]:
    # Explicit names are intentionally checked before generic task/thread IDs;
    # a V2 receipt often has a parent task and child task in the same payload.
    for name in names:
        value = _value(record, name)
        if _nonempty(value):
            return value.strip()
    return None


def _call_id(record: Mapping[str, Any]) -> Optional[str]:
    return _task_id(record, "call_id", "request_id", "receipt_id", "operation_id", "invocation_id")


def _operation(record: Mapping[str, Any]) -> Optional[str]:
    values = [
        _value(record, "operation"),
        _value(record, "action"),
        _value(record, "method"),
        _value(record, "tool_name"),
        _value(record, "call_name"),
        _value(record, "operation_name"),
        _value(record, "call_type"),
        _value(record, "collaboration_operation"),
        _value(record, "name"),
    ]
    value = next((item for item in values if item is not None), None)
    if _nonempty(value) and value.strip().lower() in {"call", "invoke", "collaboration.call", "collaboration_call"}:
        value = next((item for item in values[1:] if item is not None), value)
    if isinstance(value, Mapping):
        value = value.get("name", value.get("operation", value.get("method")))
    if not _nonempty(value):
        return None
    return value.strip().lower()


def _normal_operation(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    # Dynamic call sites commonly use namespace-qualified method names.
    return value.replace("\\", "/").replace("-", "_").replace(".", "_").replace("/", "_")


def _is_v2_surface(record: Mapping[str, Any], event_type: Optional[str]) -> bool:
    explicit_surface = False
    if event_type in {"collaboration.call", "collaboration.receipt", "child.notification"}:
        # An explicit contradictory surface must not be hidden by the record
        # type.  Bare collaboration.* types are accepted as V2 because the
        # source type itself is the native seam.
        explicit_surface = any(name in record for name in ("source_surface", "surface", "runtime_surface", "adapter"))
    for name in ("source_surface", "surface", "runtime_surface", "adapter"):
        value = record.get(name)
        if isinstance(value, Mapping):
            value = value.get("name", value.get("surface"))
        if _nonempty(value):
            return value.strip().lower() in {
                "v2",
                "native-v2",
                "native_v2",
                "collaboration-v2",
                "codex-v2",
            }
    return event_type in {"collaboration.call", "collaboration.receipt", "child.notification"} and not explicit_surface


def _is_spawn(operation: Optional[str]) -> bool:
    op = _normal_operation(operation)
    return op in {
        "spawn",
        "spawn_agent",
        "spawn_subagent",
        "create_child",
        "create_child_task",
        "child_spawn",
        "collaboration_spawn",
        "collaboration_spawn_agent",
    }


def _is_wait(operation: Optional[str]) -> bool:
    op = _normal_operation(operation)
    return op in {
        "wait",
        "wait_agent",
        "wait_for_child",
        "wait_for_task",
        "wait_for_agents",
        "collaboration_wait",
        "collaboration_wait_agent",
        "collaboration_wait_for_child",
        "collaboration_wait_for_task",
    }


def _is_send_or_control(operation: Optional[str]) -> bool:
    op = _normal_operation(operation)
    return op in {
        "send_message",
        "followup_task",
        "list_agents",
        "interrupt_agent",
        "steer",
        "release",
    }


def _status(record: Mapping[str, Any]) -> Optional[str]:
    value = _value(record, "status", "state", "outcome", "terminal", "notification_type", "completion_state")
    if value is None:
        raw_type = record.get("type", record.get("kind", record.get("event_type")))
        if _nonempty(raw_type) and raw_type.strip().lower() in {"child.completed", "child.complete", "notification.child_completed"}:
            return "completed"
    if isinstance(value, bool):
        return "completed" if value else "failed"
    return value.strip().lower() if _nonempty(value) else None


def _is_timeout(record: Mapping[str, Any]) -> bool:
    status = _status(record)
    if status in {"timeout", "timed_out", "timed-out", "wait_timeout", "deadline_exceeded"}:
        return True
    value = _value(record, "timed_out", "timeout", "timedOut")
    return value is True


def _is_compact(record: Mapping[str, Any]) -> bool:
    value = _value(record, "compact", "compacted", "is_compact", "is_compacted", "compact_output", "compact_result", "is_compact_output")
    return isinstance(value, Mapping) or value is True or _status(record) in {"compacted", "compact"}


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
        "normalized_schema": NORMALIZED_SCHEMA,
        "adapter": {
            "name": ADAPTER_NAME,
            "version": ADAPTER_VERSION,
            "source_surface": SOURCE_SURFACE,
            "source_surface_identity": dict(SOURCE_SURFACE_IDENTITY),
        },
        "source_surface": SOURCE_SURFACE,
        "source_surface_identity": dict(SOURCE_SURFACE_IDENTITY),
        "evidence_tier": "runtime-observed",
        "status": "FAIL" if issues else "PASS",
        "issues": sorted(set(issues)),
        "source_refs": [],
        "events": [],
        "graph": {"root": None, "children": []},
        "waits": [],
        "notifications": [],
        "compact_outputs": [],
        "raw_record_count": raw_records,
    }


def _collect_records(raw: Mapping[str, Any] | Iterable[Mapping[str, Any]], issues: list[str]) -> list[Mapping[str, Any]]:
    if isinstance(raw, Mapping):
        schema = raw.get("schema")
        allowed = {None, RAW_SCHEMA, "orch-dork/raw-v2", "orch-dork/native-v2", "native-v2"}
        if schema not in allowed:
            issues.append("raw:schema_invalid")
        surface = raw.get("source_surface", raw.get("surface"))
        if isinstance(surface, Mapping):
            surface = surface.get("name", surface.get("source_surface", surface.get("surface")))
        if surface is not None and (not _nonempty(surface) or surface.strip().lower() not in {"v2", "native-v2", "native_v2", "collaboration-v2", "codex-v2"}):
            issues.append("raw:source_surface_invalid")
        records = raw.get("records", raw.get("events"))
        if isinstance(records, list):
            # A V2 raw bundle may also expose denormalized indexes.  The
            # canonical records array remains authoritative when present.
            return list(records)
        # Accept the native split surface while retaining caller order within
        # each source array.  Missing source references remain a hard failure.
        combined: list[Mapping[str, Any]] = []
        defaults = {
            "collaboration_calls": "collaboration.call",
            "calls": "collaboration.call",
            "collaboration_receipts": "collaboration.receipt",
            "receipts": "collaboration.receipt",
            "child_notifications": "child.notification",
            "notifications": "child.notification",
            "async_notifications": "child.notification",
            "child_events": "child.notification",
            "tools": "root.tool",
        }
        for key in (
            "sessions",
            "collaboration_calls",
            "calls",
            "collaboration_receipts",
            "receipts",
            "child_notifications",
            "notifications",
            "async_notifications",
            "child_events",
            "tools",
        ):
            value = raw.get(key)
            if value is None:
                continue
            if not isinstance(value, list):
                issues.append("raw:%s_not_array" % key)
                continue
            for item in value:
                if isinstance(item, Mapping) and key in defaults and not _nonempty(item.get("type", item.get("kind", item.get("event_type")))):
                    copied = dict(item)
                    copied["type"] = defaults[key]
                    combined.append(copied)
                else:
                    combined.append(item)
        if not combined:
            issues.append("raw:records_not_array")
        return combined
    if isinstance(raw, Iterable) and not isinstance(raw, (str, bytes)):
        return list(raw)
    issues.append("raw:not_object_or_array")
    return []


def _metadata(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "model": _value(record, "model"),
        "effort": _value(record, "effort", "reasoning_effort"),
        "context_policy": _value(record, "context_policy", "fork_context_policy"),
        "depth": _value(record, "depth", "task_depth"),
        "parent_task_id": _task_id(record, "parent_task_id", "parent_thread_id", "parent_id"),
    }


def _check_routing(
    value: Mapping[str, Any],
    model: Optional[str],
    effort: Optional[str],
    label: str,
    issues: list[str],
    *,
    context_policy: Optional[str] = None,
    require_exact: bool = True,
) -> None:
    if require_exact and value.get("model") != model:
        issues.append("routing:model_invalid:%s" % label)
    if require_exact and value.get("effort") != effort:
        issues.append("routing:effort_invalid:%s" % label)
    if not _nonempty(value.get("model")) or not _nonempty(value.get("effort")):
        issues.append("routing:missing:%s" % label)
    elif value.get("effort") not in REASONING_EFFORTS:
        issues.append("routing:effort_invalid:%s" % label)
    if context_policy is not None and value.get("context_policy") != context_policy:
        issues.append("routing:context_policy_invalid:%s" % label)
    if not _nonempty(value.get("context_policy")):
        issues.append("routing:context_policy_missing:%s" % label)


def _public_session(session: Optional[Mapping[str, Any]]) -> Optional[dict[str, Any]]:
    if session is None:
        return None
    return {
        key: value
        for key, value in session.items()
        if key != "source_refs" and not key.startswith("_")
    } | {"source_refs": list(session.get("source_refs", []))}


def observe_v2(
    raw: Mapping[str, Any] | Iterable[Mapping[str, Any]],
    plan: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """Reconstruct a native-V2 graph from raw sessions and call receipts.

    The function is state-free and always returns a report.  Any ambiguity or
    contradiction leaves the report in ``FAIL``; no child or completion is
    synthesized from a tool name, a compact summary, or a submitted trace.
    """

    issues: list[str] = []
    records = _collect_records(raw, issues)
    mode, planned_lanes = _plan_expectations(plan, issues)
    planned_root = plan.get("root") if isinstance(plan, Mapping) else None
    planned_root = planned_root if isinstance(planned_root, Mapping) else {}
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
        # A plain tool.call is deliberately an ordinary root tool.  It may
        # carry a collaboration-looking name but is not a native V2 call.
        if event_type == "root.tool" and record.get("type", record.get("kind")) not in {
            "root.tool",
            "tool.call",
            "tool.result",
        } and not _is_v2_surface(record, event_type):
            event_type = "root.tool"
        if event_type is None:
            issues.append("record[%d]:type_invalid" % position)
            continue
        if ("timestamp" in record or "time" in record) and _timestamp(record) is None:
            issues.append("record[%d]:timestamp_invalid" % position)
        if event_type in {"collaboration.call", "collaboration.receipt", "child.notification"} and not _is_v2_surface(record, event_type):
            issues.append("record[%d]:source_surface_invalid" % position)
            continue
        typed.append((position, record, event_type, ref))

    sessions: dict[str, dict[str, Any]] = {}
    spawns: list[dict[str, Any]] = []
    waits: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    notifications: list[dict[str, Any]] = []
    verifications: list[tuple[int, Mapping[str, Any], SourceRef]] = []
    root_tools: list[tuple[int, Mapping[str, Any], SourceRef]] = []
    compactions: list[tuple[int, Mapping[str, Any], SourceRef]] = []
    call_by_id: dict[str, dict[str, Any]] = {}

    for position, record, event_type, ref in typed:
        if event_type == "session.compacted":
            compactions.append((position, record, ref))
            continue
        if event_type == "verification.completed":
            verifications.append((position, record, ref))
            continue
        if event_type == "root.tool":
            root_tools.append((position, record, ref))
            continue
        if event_type == "collaboration.call":
            operation = _operation(record)
            if operation is None:
                issues.append("collaboration[%d]:operation_missing" % position)
                continue
            call_id = _call_id(record)
            if call_id is not None and call_id in call_by_id:
                issues.append("collaboration:duplicate_call:%s" % call_id)
            call = {
                "position": position,
                "record": record,
                "ref": ref,
                "operation": operation,
                "call_id": call_id,
                "timestamp": _timestamp(record),
                "task_id": _task_id(record, "task_id", "root_task_id", "thread_id", "session_id"),
                "child_id": _task_id(record, "child_task_id", "child_thread_id", "child_id", "target_task_id", "target_thread_id"),
                "lane_id": _task_id(record, "lane_id", "lane"),
                "parent_id": _task_id(record, "parent_task_id", "parent_thread_id", "parent_id"),
                "receipt": None,
            }
            if call_id is not None:
                call_by_id[call_id] = call
            if _is_spawn(operation):
                spawns.append(call)
            elif _is_wait(operation):
                waits.append(call)
            elif not _is_send_or_control(operation):
                # Unknown dynamic collaboration operations are not silently
                # treated as ordinary tools: they are visible contradictions.
                issues.append("collaboration:operation_invalid:%s" % operation)
                waits.append(call)
            else:
                # send/follow-up/list/interrupt are coordination calls; retain
                # them as root tools but never create a child edge.
                waits.append(call)
            continue
        if event_type == "collaboration.receipt":
            call_id = _call_id(record)
            receipt = {
                "position": position,
                "record": record,
                "ref": ref,
                "call_id": call_id,
                "status": _status(record),
                "timestamp": _timestamp(record),
                "compact": _is_compact(record),
                "child_id": _task_id(record, "child_task_id", "child_thread_id", "child_id", "target_task_id", "target_thread_id"),
                "lane_id": _task_id(record, "lane_id", "lane"),
            }
            receipts.append(receipt)
            if call_id is None:
                issues.append("receipt[%d]:call_id_missing" % position)
            elif call_id not in call_by_id:
                issues.append("receipt:unknown_call:%s" % call_id)
            else:
                if call_by_id[call_id].get("receipt") is not None:
                    issues.append("receipt:duplicate_call:%s" % call_id)
                call_by_id[call_id]["receipt"] = receipt
                if call_by_id[call_id] in waits:
                    call_by_id[call_id]["receipt"] = receipt
            continue
        if event_type == "child.notification":
            task_id = _task_id(record, "child_task_id", "child_thread_id", "task_id", "thread_id", "session_id")
            status = _status(record)
            notification = {
                "position": position,
                "record": record,
                "ref": ref,
                "task_id": task_id,
                "lane_id": _task_id(record, "lane_id", "lane"),
                "status": status,
                "timestamp": _timestamp(record),
                "call_id": _call_id(record),
            }
            notifications.append(notification)
            if task_id is None:
                issues.append("notification[%d]:task_id_missing" % position)
            if status not in {"completed", "complete", "success", "succeeded", "done"}:
                issues.append("notification[%d]:status_not_completed" % position)
            continue

        task_id = _task_id(record, "task_id", "session_id", "thread_id", "root_task_id", "root_thread_id")
        if task_id is None:
            issues.append("record[%d]:task_id_missing" % position)
            continue
        metadata = _metadata(record)
        if event_type == "session.started":
            if task_id in sessions:
                issues.append("session:duplicate_start:%s" % task_id)
                continue
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
                "completion_source": None,
                "notification_ref": None,
                "_start_position": position,
                "_terminal_position": None,
                "_spawn_position": None,
                "verification": [],
                "source_refs": [ref.as_dict()],
            }
        elif task_id in sessions:
            session = sessions[task_id]
            session["source_refs"].append(ref.as_dict())
            if event_type in {"session.completed", "session.failed", "session.cancelled", "session.timed_out"}:
                terminal = event_type.removeprefix("session.")
                if session["terminal"] is None:
                    session["terminal"] = terminal
                    session["terminal_at"] = _timestamp(record)
                    session["terminal_ref"] = ref.as_dict()
                    session["completion_source"] = "session"
                    session["_terminal_position"] = position
                elif session["terminal"] != terminal:
                    issues.append("session:terminal_contradiction:%s" % task_id)
                else:
                    # A notification and the native session terminal are two
                    # raw confirmations of one completion, not two children.
                    session["source_refs"].append(ref.as_dict())
        else:
            issues.append("session:event_before_start:%s:%s" % (task_id, event_type))

    # Attach receipts to the corresponding call, and expose waits in a stable
    # shape.  A timeout is an ordinary wait outcome, never an implicit child
    # terminal.  Repeated waits have distinct call IDs and are retained.
    wait_rows: list[dict[str, Any]] = []
    for call in waits:
        operation = call["operation"]
        receipt = call.get("receipt")
        target = call.get("child_id")
        if target is None and receipt is not None:
            target = receipt.get("child_id")
        if _is_wait(operation):
            if target is None:
                issues.append("wait[%d]:target_missing" % call["position"])
        if receipt is None:
            # Native control calls such as send_message do not require a
            # receipt.  Waits do: otherwise a timed-out/complete state cannot
            # be distinguished from a missing response.
            inline_status = _status(call["record"])
            inline_timeout = _is_timeout(call["record"])
            if _is_wait(operation) and not inline_timeout and inline_status is None:
                issues.append("wait[%d]:receipt_missing" % call["position"])
            status = inline_status
            if inline_timeout and status is None:
                status = "timed_out"
            compact = False
            receipt_ref = None
        else:
            status = receipt.get("status")
            compact = receipt.get("compact", False)
            receipt_ref = receipt["ref"].as_dict()
            if _is_wait(operation) and status is None and not _is_timeout(receipt["record"]):
                issues.append("wait[%d]:status_missing" % call["position"])
        wait_rows.append({
            "call_id": call.get("call_id"),
            "operation": operation,
            "task_id": call.get("task_id"),
            "target_task_id": target,
            "status": status,
            "timed_out": bool(receipt and _is_timeout(receipt["record"])),
            "compact": bool(compact),
            "call_ref": call["ref"].as_dict(),
            "receipt_ref": receipt_ref,
            "timestamp": call.get("timestamp"),
        })

    # A receipt that is compact but not tied to a wait is still evidence of a
    # compaction result; keep it in the report and normalized event stream.
    compact_outputs: list[dict[str, Any]] = []
    for receipt in receipts:
        if receipt["compact"]:
            owner_call = call_by_id.get(receipt.get("call_id"))
            compact_outputs.append({
                "call_id": receipt.get("call_id"),
                "task_id": _task_id(receipt["record"], "task_id", "thread_id", "session_id", "root_task_id") or (owner_call.get("task_id") if owner_call else None),
                "status": receipt.get("status"),
                "timestamp": receipt.get("timestamp"),
                "output": _value(receipt["record"], "output", "result", "compact_output", "compact_result"),
                "source_ref": receipt["ref"].as_dict(),
            })

    # Resolve spawn IDs from receipts when the dynamic call only returned the
    # child identity in its compact result.
    children: dict[str, dict[str, Any]] = {}
    spawn_by_lane: dict[str, dict[str, Any]] = {}
    spawn_by_child: dict[str, str] = {}
    root_ids = [task_id for task_id, session in sessions.items() if session["parent_task_id"] in (None, "")]
    if len(root_ids) != 1:
        issues.append("graph:root_count:%d" % len(root_ids))
    root_id = root_ids[0] if len(root_ids) == 1 else None
    root = sessions.get(root_id) if root_id is not None else None
    if root is not None:
        if type(root.get("depth")) is not int or root.get("depth") != 0:
            issues.append("graph:root_depth_invalid")
        _check_routing(root, planned_root.get("model"), planned_root.get("effort"), "root", issues, context_policy=planned_root.get("context_policy"), require_exact=bool(planned_root))

    for spawn in spawns:
        receipt = spawn.get("receipt")
        if spawn.get("child_id") is None and receipt is not None:
            spawn["child_id"] = receipt.get("child_id")
        if spawn.get("lane_id") is None and receipt is not None:
            spawn["lane_id"] = receipt.get("lane_id")
        lane_id = spawn.get("lane_id")
        child_id = spawn.get("child_id")
        parent_id = spawn.get("parent_id") or spawn.get("task_id")
        if lane_id is None:
            issues.append("spawn[%d]:lane_id_missing" % spawn["position"])
        if child_id is None:
            issues.append("spawn[%d]:child_id_missing" % spawn["position"])
        if parent_id is None:
            issues.append("spawn[%d]:parent_id_missing" % spawn["position"])
        if lane_id is None or child_id is None:
            continue
        if lane_id in spawn_by_lane:
            issues.append("graph:duplicate_spawn_lane:%s" % lane_id)
        spawn_by_lane[lane_id] = spawn
        if child_id in spawn_by_child:
            issues.append("graph:duplicate_child_identity:%s" % child_id)
        else:
            spawn_by_child[child_id] = lane_id
        if root_id is not None and parent_id != root_id:
            issues.append("graph:parent_mismatch:%s" % lane_id)
        session = sessions.get(child_id)
        if session is None:
            issues.append("graph:missing_child_session:%s" % lane_id)
            session = {
                "task_id": child_id,
                "parent_task_id": parent_id,
                "depth": _value(spawn["record"], "depth", "task_depth"),
                "model": _value(spawn["record"], "model"),
                "effort": _value(spawn["record"], "effort", "reasoning_effort"),
                "context_policy": _value(spawn["record"], "context_policy", "fork_context_policy"),
                "started_at": None,
                "start_ref": None,
                "terminal": None,
                "terminal_at": None,
                "terminal_ref": None,
                "completion_source": None,
                "notification_ref": None,
                "_start_position": None,
                "_terminal_position": None,
                "_spawn_position": spawn["position"],
                "verification": [],
                "source_refs": [],
            }
        else:
            if session.get("parent_task_id") != parent_id:
                issues.append("graph:session_parent_mismatch:%s" % lane_id)
            for field in ("model", "effort", "depth", "context_policy"):
                spawn_value = _value(spawn["record"], field, "reasoning_effort" if field == "effort" else field)
                if spawn_value is not None and session.get(field) is not None and spawn_value != session.get(field):
                    issues.append("graph:spawn_session_%s_mismatch:%s" % (field, lane_id))
        child = dict(session)
        child["lane_id"] = lane_id
        child["_spawn_position"] = spawn["position"]
        child["spawn_ref"] = spawn["ref"].as_dict()
        child["source_refs"] = list(child.get("source_refs", [])) + [spawn["ref"].as_dict()]
        children[lane_id] = child
        identity = {
            "model": _value(spawn["record"], "model"),
            "effort": _value(spawn["record"], "effort", "reasoning_effort"),
            "context_policy": _value(spawn["record"], "context_policy", "fork_context_policy"),
        }
        _check_routing(identity, child_model(), child_effort(), "spawn:%s" % lane_id, issues, context_policy=CHILD_CONTEXT_POLICY)
        _check_routing(child, child_model(), child_effort(), lane_id, issues, context_policy=CHILD_CONTEXT_POLICY)
        if type(child.get("depth")) is not int or child.get("depth") != 1:
            issues.append("graph:depth_invalid:%s" % lane_id)
        spawn_depth = _value(spawn["record"], "depth", "task_depth")
        if type(spawn_depth) is not int or spawn_depth != 1:
            issues.append("graph:spawn_depth_invalid:%s" % lane_id)
        if root_id is not None and child.get("parent_task_id") != root_id:
            issues.append("graph:parent_mismatch:%s" % lane_id)

    if root_id is not None:
        for task_id, session in sessions.items():
            if task_id != root_id and session.get("parent_task_id") != root_id:
                issues.append("graph:nested_or_orphan_session:%s" % task_id)
        if len(children) != len(sessions) - 1:
            issues.append("graph:unspawned_session")
    if planned_lanes:
        for lane_id in sorted(planned_lanes - set(spawn_by_lane)):
            issues.append("graph:missing_spawn:%s" % lane_id)
        for lane_id in sorted(set(spawn_by_lane) - planned_lanes):
            issues.append("graph:extra_child:%s" % lane_id)
        expected_count = (plan.get("children") or {}).get("expected_count") if isinstance(plan, Mapping) and isinstance(plan.get("children"), Mapping) else None
        if isinstance(expected_count, int) and len(spawn_by_lane) != expected_count:
            issues.append("graph:spawn_count:%d!=%d" % (len(spawn_by_lane), expected_count))
    elif mode == "orchestrated":
        issues.append("plan:lane_boundary_missing")

    # Notifications are asynchronous terminal evidence.  They are never
    # inferred from a wait call or compact output.  A session terminal may
    # confirm the same status; a contradiction fails closed.
    for notification in notifications:
        task_id = notification.get("task_id")
        lane_id = notification.get("lane_id")
        resolved_lane = lane_id if lane_id in children else spawn_by_child.get(task_id)
        if resolved_lane is None:
            issues.append("notification:unknown_child:%s" % (task_id or "missing"))
            continue
        if task_id is not None and children[resolved_lane].get("task_id") != task_id:
            issues.append("notification:identity_mismatch:%s" % resolved_lane)
        child = children[resolved_lane]
        if child.get("notification_ref") is not None:
            issues.append("notification:duplicate:%s" % resolved_lane)
        completed_statuses = {"completed", "complete", "success", "succeeded", "done"}
        if notification.get("status") not in completed_statuses:
            # Preserve an explicit failed/cancelled/timed-out notification as
            # terminal evidence; a later session.completed then becomes a
            # visible contradiction instead of silently repairing it.
            bad_status = notification.get("status") or "failed"
            if bad_status in {"timed_out", "timed-out", "timeout"}:
                bad_status = "timed_out"
            elif bad_status in {"cancelled", "canceled"}:
                bad_status = "cancelled"
            else:
                bad_status = "failed"
            if child.get("_terminal_position") is None or notification["position"] < child["_terminal_position"]:
                child["terminal"] = bad_status
                child["terminal_at"] = notification.get("timestamp")
                child["terminal_ref"] = notification["ref"].as_dict()
                child["completion_source"] = "notification"
                child["notification_ref"] = notification["ref"].as_dict()
                child["_terminal_position"] = notification["position"]
            else:
                issues.append("notification:terminal_contradiction:%s" % resolved_lane)
        elif child.get("terminal") is None:
            child["terminal"] = "completed"
            child["terminal_at"] = notification.get("timestamp")
            child["terminal_ref"] = notification["ref"].as_dict()
            child["completion_source"] = "notification"
            child["notification_ref"] = notification["ref"].as_dict()
            child["_terminal_position"] = notification["position"]
        elif child.get("terminal") != "completed":
            issues.append("notification:terminal_contradiction:%s" % resolved_lane)
        else:
            # The notification may be the actual completion observed before a
            # later session.completed confirmation.  Bind the canonical
            # terminal event to the earliest raw completion source.
            if child.get("_terminal_position") is None or notification["position"] < child["_terminal_position"]:
                child["terminal_at"] = notification.get("timestamp")
                child["terminal_ref"] = notification["ref"].as_dict()
                child["completion_source"] = "notification"
                child["_terminal_position"] = notification["position"]
            child["notification_ref"] = notification["ref"].as_dict()
        child.setdefault("source_refs", []).append(notification["ref"].as_dict())

    # Verification identity and lifecycle checks.
    seen_verifications: set[tuple[str, str]] = set()
    for position, record, ref in verifications:
        task_id = _task_id(record, "task_id", "child_task_id", "child_thread_id", "session_id", "thread_id")
        lane_id = _task_id(record, "lane_id", "lane")
        if lane_id is not None and lane_id not in children:
            issues.append("verification[%d]:unknown_lane:%s" % (position, lane_id))
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
        passed = record.get("passed")
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

    # Root tool identity/category includes V2 waits, while similarly named
    # ordinary tools remain ordinary and cannot add graph edges.
    for call in waits:
        record = call["record"]
        root_tools.append((call["position"], record, call["ref"]))
    if root is not None:
        for position, record, ref in root_tools:
            task_id = _task_id(record, "task_id", "root_task_id", "session_id", "thread_id")
            # A wait record may carry only the parent in ``parent_task_id``.
            if task_id is None:
                task_id = _task_id(record, "parent_task_id", "parent_thread_id")
            if task_id is None:
                issues.append("root:tool_identity_missing:%s" % ref.record_id)
            elif task_id != root_id:
                issues.append("root:tool_identity_mismatch:%s" % ref.record_id)
            category = record.get("category", "coordination")
            if category not in {"coordination", "implementation"}:
                issues.append("root:tool_category_invalid:%s" % ref.record_id)
            if category == "implementation":
                issues.append("root:implementation_tool:%s" % record.get("name", _operation(record) or "unknown"))

    # Child shape and ordering.  A notification is a valid terminal source,
    # including when no session.completed record exists.
    for lane_id, child in children.items():
        if len(child.get("verification", [])) != 1:
            issues.append("verification:count:%s:%d" % (lane_id, len(child.get("verification", []))))
        if child.get("terminal") is None:
            issues.append("lifecycle:terminal_missing:%s" % lane_id)
        elif child.get("terminal") != "completed":
            issues.append("lifecycle:terminal_not_completed:%s" % lane_id)
        spawn_position = child.get("_spawn_position")
        start_position = child.get("_start_position")
        terminal_position = child.get("_terminal_position")
        if spawn_position is not None and start_position is not None and start_position <= spawn_position:
            issues.append("lifecycle:session_start_not_after_spawn:%s" % lane_id)
        if start_position is not None and terminal_position is not None and terminal_position <= start_position:
            issues.append("lifecycle:terminal_not_after_start:%s" % lane_id)
        if spawn_position is not None and terminal_position is not None and terminal_position <= spawn_position:
            issues.append("lifecycle:terminal_not_after_spawn:%s" % lane_id)
        spawn = spawn_by_lane.get(lane_id)
        spawn_timestamp = _timestamp(spawn["record"]) if spawn is not None else None
        if spawn_timestamp is not None and child.get("started_at") is not None and child["started_at"] <= spawn_timestamp:
            issues.append("lifecycle:session_start_not_after_spawn:%s" % lane_id)
        if child.get("started_at") is not None and child.get("terminal_at") is not None and child["terminal_at"] <= child["started_at"]:
            issues.append("lifecycle:terminal_not_after_start:%s" % lane_id)
        if spawn_timestamp is not None and child.get("terminal_at") is not None and child["terminal_at"] <= spawn_timestamp:
            issues.append("lifecycle:terminal_not_after_spawn:%s" % lane_id)
        for verification in child.get("verification", []):
            if start_position is not None and verification.get("_position") is not None and verification["_position"] <= start_position:
                issues.append("lifecycle:verification_not_after_start:%s" % lane_id)
            if terminal_position is not None and verification.get("_position") is not None and verification["_position"] >= terminal_position:
                issues.append("lifecycle:verification_not_before_terminal:%s" % lane_id)
            if verification.get("timestamp") is not None and child.get("started_at") is not None and verification["timestamp"] <= child["started_at"]:
                issues.append("lifecycle:verification_not_after_start:%s" % lane_id)
            if verification.get("timestamp") is not None and child.get("terminal_at") is not None and verification["timestamp"] >= child["terminal_at"]:
                issues.append("lifecycle:verification_not_before_terminal:%s" % lane_id)

    if root is not None and root.get("_start_position") is not None:
        for spawn in spawns:
            if spawn["position"] < root["_start_position"]:
                issues.append("lifecycle:root_start_not_before_event")
        for collection in (waits, notifications):
            for row in collection:
                if row["position"] < root["_start_position"]:
                    issues.append("lifecycle:root_start_not_before_event")
        for task_id, session in sessions.items():
            if task_id != root_id and session.get("_start_position") is not None and session["_start_position"] < root["_start_position"]:
                issues.append("lifecycle:root_start_not_before_child:%s" % task_id)

    if root is not None:
        if root.get("terminal") is None:
            issues.append("lifecycle:root_terminal_missing")
        elif root.get("terminal") != "completed":
            issues.append("lifecycle:root_terminal_not_completed")
        if root.get("_terminal_position") is not None:
            for lane_id, child in children.items():
                if child.get("_terminal_position") is not None and root["_terminal_position"] <= child["_terminal_position"]:
                    issues.append("lifecycle:root_terminal_before_child:%s" % lane_id)
                if root.get("terminal_at") is not None and child.get("terminal_at") is not None and root["terminal_at"] <= child["terminal_at"]:
                    issues.append("lifecycle:root_terminal_timestamp_before_child:%s" % lane_id)
            # No raw source record may follow the root terminal.  This catches
            # late contradictory notifications and reordered receipts.
            for position, _, _, _ in typed:
                if position > root["_terminal_position"]:
                    issues.append("lifecycle:root_terminal_not_last")

    events = _normalized_events(root, children, spawns, verifications, root_tools, compactions, compact_outputs, SOURCE_SURFACE)
    graph = {
        "root": _public_session(root),
        "children": [_public_session(children[lane]) for lane in sorted(children)],
    }

    usage_report = None
    if isinstance(raw, Mapping) and "usage" in raw:
        try:
            from orch_dork_usage import attribute_usage

            usage_value = raw.get("usage")
            # The token adapter is surface-neutral but deliberately rejects a
            # native-V2 envelope.  Wrap only the raw usage array; never pass a
            # normalized report or alter the caller's evidence.
            usage_input = {
                "schema": "orch-dork/raw-classic-v1",
                "usage": usage_value,
            }
            usage_report = attribute_usage(usage_input, graph)
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
        "waits": wait_rows,
        "notifications": [
            {
                "task_id": row.get("task_id"),
                "lane_id": row.get("lane_id"),
                "status": row.get("status"),
                "source_ref": row["ref"].as_dict(),
            }
            for row in notifications
        ],
        "compact_outputs": compact_outputs,
        "compaction_records": [ref.as_dict() for _, _, ref in compactions],
    })
    if usage_report is not None:
        report["usage"] = usage_report
    return report


def _normalized_events(
    root: Optional[Mapping[str, Any]],
    children: Mapping[str, Mapping[str, Any]],
    spawns: list[Mapping[str, Any]],
    verifications: list[tuple[int, Mapping[str, Any], SourceRef]],
    root_tools: list[tuple[int, Mapping[str, Any], SourceRef]],
    compactions: list[tuple[int, Mapping[str, Any], SourceRef]],
    compact_outputs: list[Mapping[str, Any]],
    source_surface: str,
) -> list[dict[str, Any]]:
    rows: list[tuple[int, int, dict[str, Any]]] = []
    missing = 10**12
    if root is not None:
        rows.append((root.get("_start_position", missing), 0, {
            "type": "root.started",
            "task_id": root["task_id"],
            "parent_task_id": root.get("parent_task_id"),
            "depth": root.get("depth") if root.get("depth") is not None else 0,
            "model": root.get("model"),
            "effort": root.get("effort"),
            "context_policy": root.get("context_policy"),
            "timestamp": root.get("started_at"),
            "source_ref": root.get("start_ref"),
            "source_surface": source_surface,
        }))
    for spawn in sorted(spawns, key=lambda value: value["position"]):
        rows.append((spawn["position"], 1, {
            "type": "child.spawned",
            "lane_id": spawn.get("lane_id"),
            "task_id": spawn.get("child_id"),
            "parent_task_id": spawn.get("parent_id") or spawn.get("task_id"),
            "depth": _value(spawn["record"], "depth", "task_depth"),
            "model": _value(spawn["record"], "model"),
            "effort": _value(spawn["record"], "effort", "reasoning_effort"),
            "context_policy": _value(spawn["record"], "context_policy", "fork_context_policy"),
            "timestamp": spawn.get("timestamp"),
            "call_id": spawn.get("call_id"),
            "source_ref": spawn["ref"].as_dict(),
            "source_surface": source_surface,
        }))
    for lane_id in sorted(children):
        child = children[lane_id]
        for verification in child.get("verification", []):
            rows.append((verification.get("_position", missing), 2, {
                "type": "lane.verified",
                "lane_id": lane_id,
                "task_id": child["task_id"],
                "passed": verification.get("passed"),
                "source_ref": verification.get("source_ref"),
                "source_surface": source_surface,
            }))
        if child.get("terminal") is not None:
            rows.append((child.get("_terminal_position", missing), 3, {
                "type": "lane.completed" if child.get("terminal") == "completed" else "lane.terminal",
                "lane_id": lane_id,
                "task_id": child["task_id"],
                "status": child.get("terminal"),
                "timestamp": child.get("terminal_at"),
                "completion_source": child.get("completion_source"),
                "notification_ref": child.get("notification_ref"),
                "source_ref": child.get("terminal_ref"),
                "source_surface": source_surface,
            }))
    for position, record, ref in sorted(root_tools, key=lambda value: value[0]):
        rows.append((position, 4, {
            "type": "root.tool",
            "task_id": _task_id(record, "task_id", "root_task_id", "session_id", "thread_id") or _task_id(record, "parent_task_id", "parent_thread_id"),
            "name": _operation(record) or record.get("name"),
            "category": record.get("category", "coordination"),
            "source_ref": ref.as_dict(),
            "source_surface": source_surface,
        }))
    for position, record, ref in sorted(compactions, key=lambda value: value[0]):
        rows.append((position, 5, {
            "type": "session.compacted",
            "task_id": _task_id(record, "task_id", "session_id", "thread_id"),
            "timestamp": _timestamp(record),
            "source_ref": ref.as_dict(),
            "source_surface": source_surface,
        }))
    for compact in compact_outputs:
        source_ref = compact.get("source_ref")
        if not isinstance(source_ref, Mapping):
            continue
        rows.append((source_ref.get("position", missing), 5, {
            "type": "session.compacted",
            "task_id": compact.get("task_id"),
            "status": compact.get("status"),
            "timestamp": compact.get("timestamp"),
            "source_ref": dict(source_ref),
            "source_surface": source_surface,
        }))
    if root is not None and root.get("terminal") is not None:
        rows.append((root.get("_terminal_position", missing), 6, {
            "type": "run.completed" if root.get("terminal") == "completed" else "run.terminal",
            "task_id": root["task_id"],
            "status": root.get("terminal"),
            "timestamp": root.get("terminal_at"),
            "source_ref": root.get("terminal_ref"),
            "source_surface": source_surface,
        }))
    rows.sort(key=lambda row: (row[0], row[1]))
    return [{"seq": index, **event} for index, (_, _, event) in enumerate(rows, 1)]


def require_observation(
    raw: Mapping[str, Any] | Iterable[Mapping[str, Any]],
    plan: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    report = observe_v2(raw, plan)
    if report["status"] != "PASS":
        raise V2ObservationError(report)
    return report


class V2Observer:
    """Reusable, state-free native-V2 observer."""

    adapter_name = ADAPTER_NAME
    adapter_version = ADAPTER_VERSION
    source_surface = SOURCE_SURFACE

    def observe(self, raw: Mapping[str, Any] | Iterable[Mapping[str, Any]], plan: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
        return observe_v2(raw, plan)

    normalize = observe


normalize_v2 = observe_v2
normalize_native_v2 = observe_v2
normalize_runtime_records = observe_v2
reconstruct_v2 = observe_v2
observe = observe_v2
NativeV2Observer = V2Observer


__all__ = [
    "ADAPTER_NAME",
    "ADAPTER_VERSION",
    "CHILD_CONTEXT_POLICY",
    "NORMALIZED_SCHEMA",
    "RAW_SCHEMA",
    "SOURCE_SURFACE",
    "SOURCE_SURFACE_IDENTITY",
    "V2ObservationError",
    "V2Observer",
    "NativeV2Observer",
    "child_effort",
    "child_model",
    "normalize_native_v2",
    "normalize_runtime_records",
    "normalize_v2",
    "observe",
    "observe_v2",
    "reconstruct_v2",
    "require_observation",
    "subagent_effort",
    "subagent_model",
]
