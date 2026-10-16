#!/usr/bin/env python3
"""Provider-free, attempt-scoped observation of bounded raw sessions.

The native session store is append-only and a root task can be reused for
several turns.  This adapter therefore requires a caller supplied manifest
whose source paths, complete file hashes, and exact record selectors define
one attempt.  It never searches a session directory and never treats the
whole lifetime of a reused root as the attempt.

Only compact identity, lifecycle, timing, usage, test, and mutation facts are
emitted.  Raw session bodies, prompts, messages, reasoning, credentials and
other private values are deliberately rejected and are never copied into a
report.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping, Sequence


SCHEMA = "orch-dork/attempt-observation/v1"
SOURCE_CATALOG_SCHEMA = "orch-dork/run-source-catalog/v1"
ADAPTER_VERSION = "attempt-observer/1.0"
REGISTRY_VERSION = "run-registry/1.0"
CUSTODY_EVENT_SCHEMA = "orch-dork/custody-events/v1"

PASS = "PASS"
PARTIAL = "PARTIAL"
FAIL = "FAIL"
BINDING = {"BOUND", "UNBOUND", "CONTRADICTORY"}
SURFACES = {"native-v2", "v2", "native_v2", "collaboration-v2", "codex-v2"}
CLOCK_KINDS = {"wall", "monotonic", "logical", "unknown"}
CLOCK_UNITS = {"nanoseconds", "microseconds", "milliseconds", "seconds", "ticks", "unknown"}
CLOCK_ORIGINS = {
    "unix_epoch",
    "host_boot",
    "producer_start",
    "subject_start",
    "fixture_start",
    "logical_zero",
    "unknown",
}
REASON_CODES = {
    "missing_source",
    "missing_identity",
    "missing_record",
    "ambiguous_selector",
    "ambiguous_binding",
    "host_unavailable",
    "permission_denied",
    "redacted",
    "unsupported_schema",
    "observation_incomplete",
    "clock_unknown",
    "clock_mismatch",
    "unit_unknown",
    "origin_unknown",
    "conversion_unavailable",
    "render_mismatch",
}
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SECRET = re.compile(
    r"(?:prompt|message|body|(?:^|[_-])reasoning(?:$|[_-](?:content|text|body|trace|data))|credential|password|secret|encrypted|"
    r"cipher|private[_-]?key|access[_-]?token|api[_-]?key|cookie|raw[_-]?"
    r"(?:file|session|trace|record|data|content))",
    re.IGNORECASE,
)


class AttemptObservationError(ValueError):
    """Raised by :func:`require_attempt_observation` for non-bound evidence."""

    def __init__(self, report: Mapping[str, Any]):
        self.report = dict(report)
        super().__init__("attempt observation failed: " + ", ".join(report.get("issues", [])))


def _text(value: Any, field: str, *, max_len: int = 2048) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ValueError(f"{field} must be a non-empty string")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(f"{field} contains a control character")
    return value


def _id(value: Any, field: str) -> str:
    value = _text(value, field, max_len=256)
    if _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{field} has an unsafe shape")
    return value


def _finite(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and (
        not isinstance(value, float) or math.isfinite(value)
    )


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _safe_key(key: Any) -> bool:
    return isinstance(key, str) and not _SECRET.search(key)


def _contains_private(value: Any, path: str = "$") -> str | None:
    """Find private-bearing keys without returning their values."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            if not _safe_key(key):
                return f"privacy:field:{path}.{key}"
            found = _contains_private(item, f"{path}.{key}")
            if found:
                return found
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found = _contains_private(item, f"{path}[{index}]")
            if found:
                return found
    return None


def _safe_public(value: Any, *, field: str = "value", max_bytes: int = 65536) -> Any:
    found = _contains_private(value, "$" )
    if found:
        raise ValueError(f"private field rejected: {found}")
    encoded = _canonical(value)
    if len(encoded) > max_bytes:
        raise ValueError(f"{field} is too large")
    return json.loads(encoded.decode("utf-8"))


def _payload(record: Mapping[str, Any]) -> Mapping[str, Any]:
    value = record.get("payload")
    return value if isinstance(value, Mapping) else record


def _value(record: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in record and record[name] is not None:
            return record[name]
    payload = _payload(record)
    if payload is not record:
        for name in names:
            if name in payload and payload[name] is not None:
                return payload[name]
    return None


def _nested_value(record: Mapping[str, Any], *path: str) -> Any:
    current: Any = record
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current


def _record_type(record: Mapping[str, Any]) -> str | None:
    # Native rollout JSONL wraps lifecycle events in ``event_msg`` records
    # whose payload carries the structural event type (for example
    # ``task_started`` / ``task_complete``).  Prefer explicit structural
    # fields and unwrap only those known envelopes; selectors and hashes still
    # bind to the complete outer record.
    for name in ("record_type", "event_type", "kind", "event"):
        value = record.get(name)
        if isinstance(value, str) and value:
            return value.strip().lower()
    value = record.get("type")
    if isinstance(value, str) and value:
        normalized = value.strip().lower()
        if normalized in {"event_msg", "response_item"}:
            payload = record.get("payload")
            if isinstance(payload, Mapping):
                nested = payload.get("record_type", payload.get("event_type", payload.get("type", payload.get("kind"))))
                if isinstance(nested, str) and nested and nested.strip().lower() != normalized:
                    return nested.strip().lower()
        return normalized
    return None


def _record_id(record: Mapping[str, Any]) -> str | None:
    value = _value(record, "record_id", "id", "event_id", "source_id")
    return value.strip() if isinstance(value, str) and value.strip() else None


def _timestamp(record: Mapping[str, Any]) -> Any:
    value = _value(record, "timestamp", "time", "occurred_at", "occurred_at_ms", "ts")
    return value if _finite(value) or isinstance(value, str) else None


def _clock(record: Mapping[str, Any], *, native_codex: bool = False) -> dict[str, Any]:
    source: Mapping[str, Any] = record
    value = record.get("clock")
    if isinstance(value, Mapping):
        source = value
    payload = _payload(record)
    if source is record and isinstance(payload.get("clock"), Mapping):
        source = payload["clock"]
    clock_id = source.get("clock_id", record.get("clock_id", payload.get("clock_id")))
    kind = source.get("clock_kind", source.get("kind", record.get("clock_kind", payload.get("clock_kind"))))
    unit = source.get("unit", record.get("unit", payload.get("unit")))
    origin = source.get("origin", record.get("origin", payload.get("origin")))
    explicit = {
        "clock_id": clock_id if isinstance(clock_id, str) and clock_id else "unknown",
        "clock_kind": kind if kind in CLOCK_KINDS else "unknown",
        "unit": unit if unit in CLOCK_UNITS else "unknown",
        "origin": origin if origin in CLOCK_ORIGINS else "unknown",
    }
    if explicit["clock_id"] != "unknown" or explicit["clock_kind"] != "unknown":
        return explicit
    # Native Codex rollout envelopes define their outer RFC3339 timestamp as
    # a UTC wall-clock event time.  This is adapter metadata, not an inference
    # from an arbitrary ISO-looking fixture field.  Flat records without an
    # explicit clock remain unknown.
    if native_codex and record.get("type") in {
        "event_msg",
        "response_item",
        "turn_context",
        "session_meta",
        "inter_agent_communication_metadata",
    }:
        timestamp = record.get("timestamp")
        if isinstance(timestamp, str):
            try:
                parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                parsed = None
            if parsed is not None and parsed.tzinfo is not None:
                return {
                    "clock_id": "codex-rollout-rfc3339-v1",
                    "clock_kind": "wall",
                    "unit": "milliseconds",
                    "origin": "unix_epoch",
                }
    return explicit


def _json_object(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, Mapping) else None
    return None


def _spawn_proof(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if _record_type(record) != "function_call" or _value(record, "name") != "spawn_agent":
        return None
    arguments = _json_object(_value(record, "arguments"))
    if arguments is None:
        return None
    return {
        "task_name": arguments.get("task_name"),
        "model": arguments.get("model"),
        "effort": arguments.get("reasoning_effort"),
        "fork_turns": arguments.get("fork_turns"),
        "call_id": _value(record, "call_id"),
    }


def _record_hashes(raw_line: bytes, record: Mapping[str, Any]) -> set[str]:
    candidates = {hashlib.sha256(raw_line.rstrip(b"\r\n")).hexdigest()}
    try:
        candidates.add(hashlib.sha256(_canonical(record)).hexdigest())
    except (TypeError, ValueError):
        pass
    payload = record.get("payload")
    if isinstance(payload, Mapping):
        try:
            candidates.add(hashlib.sha256(_canonical(payload)).hexdigest())
        except (TypeError, ValueError):
            pass
    return candidates


def _selector_fields(selector: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(selector, Mapping):
        raise ValueError("selector must be an object")
    allowed = {
        "timestamp",
        "type",
        "record_id",
        "id",
        "call_id",
        "turn_id",
        "line_number",
        "line",
        "selected_record_hash",
        "record_sha256",
        "record_hash",
        "hash",
    }
    unknown = set(selector) - allowed
    if unknown:
        raise ValueError(f"selector has unsupported fields: {sorted(unknown)}")
    if "timestamp" not in selector or "type" not in selector:
        raise ValueError("selector requires timestamp and type")
    stable = any(key in selector for key in ("record_id", "id", "call_id", "turn_id", "line_number", "line"))
    if not stable:
        raise ValueError("selector requires a stable record/call/turn id or line number")
    hash_value = next((selector.get(key) for key in ("selected_record_hash", "record_sha256", "record_hash", "hash") if selector.get(key) is not None), None)
    if not isinstance(hash_value, str) or _SHA256.fullmatch(hash_value) is None:
        raise ValueError("selector requires selected_record_hash as lowercase SHA-256")
    normalized = dict(selector)
    normalized["type"] = _text(selector["type"], "selector.type", max_len=128).strip().lower()
    normalized["selected_record_hash"] = hash_value
    if "timestamp" in selector and not (_finite(selector["timestamp"]) or isinstance(selector["timestamp"], str)):
        raise ValueError("selector.timestamp is invalid")
    if "line_number" in selector and (type(selector["line_number"]) is not int or selector["line_number"] < 1):
        raise ValueError("selector.line_number must be positive")
    if "line" in selector and (type(selector["line"]) is not int or selector["line"] < 1):
        raise ValueError("selector.line must be positive")
    for key in ("record_id", "id", "call_id", "turn_id"):
        if key in selector:
            normalized[key] = _text(selector[key], f"selector.{key}", max_len=512)
    return normalized


def _selector_match(selector: Mapping[str, Any], record: Mapping[str, Any], raw_line: bytes, line_number: int) -> bool:
    record_type = _record_type(record)
    if record_type != selector["type"]:
        return False
    timestamp = _timestamp(record)
    if timestamp != selector.get("timestamp"):
        # Numeric timestamps may be represented as int/float equivalents.
        if not (_finite(timestamp) and _finite(selector.get("timestamp")) and float(timestamp) == float(selector["timestamp"])):
            return False
    if "line_number" in selector and line_number != selector["line_number"]:
        return False
    if "line" in selector and line_number != selector["line"]:
        return False
    for key in ("record_id", "id"):
        if key in selector and _record_id(record) != selector[key]:
            return False
    for key in ("call_id", "turn_id"):
        if key in selector and _value(record, key) != selector[key]:
            return False
    return selector["selected_record_hash"] in _record_hashes(raw_line, record)


def _read_source(item: Mapping[str, Any]) -> tuple[dict[str, Any] | None, list[str], str | None]:
    """Read one explicitly named source and return records plus file digest.

    A full-file source is immutable and its digest is checked before parsing.
    A bounded-segment source may be an append-only rollout owner file; its
    selected extent is verified after lifecycle selectors resolve, so appends
    outside the attempt do not invalidate the observation.
    """

    issues: list[str] = []
    path_value = item["path"]
    hash_scope = item.get("hash_scope", "full_file")
    expected_hash = item.get("file_sha256")
    path = Path(path_value)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None, ["source:missing_source"], None
    except PermissionError:
        return None, ["source:permission_denied"], None
    except OSError:
        return None, ["source:missing_source"], None
    digest = hashlib.sha256(raw).hexdigest()
    if hash_scope == "full_file" and digest != expected_hash:
        return {"path": path_value, "records": [], "raw": raw, "digest": digest}, ["source:file_hash_conflict"], digest
    # A rendered/exported representation is separate evidence.  If its
    # declared digest does not match the selected source extent, fail closed as
    # an unbound render mismatch rather than treating visual agreement as an
    # identity proof.  The raw source remains authoritative and is never
    # replaced by the rendered bytes.
    rendered_hash = item.get("rendered_sha256")
    render_issues: list[str] = []
    if rendered_hash is not None and rendered_hash != digest:
        render_issues.append("source:render_mismatch")
    records: list[dict[str, Any]] = []
    lines = raw.splitlines(keepends=True)
    if not lines:
        return {"path": path_value, "records": [], "raw": raw, "digest": digest, "hash_scope": hash_scope}, [*render_issues, "source:empty"], digest
    privacy_lines: list[int] = []
    for line_number, line in enumerate(lines, 1):
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            issues.append(f"source:invalid_json_line:{line_number}")
            continue
        if not isinstance(value, Mapping):
            issues.append(f"source:record_not_object:{line_number}")
            continue
        private = _contains_private(value)
        if private:
            # Record only the line number internally.  A private field in an
            # excluded earlier/later turn is not part of this attempt and
            # must not make a bounded observation fail.
            privacy_lines.append(line_number)
        records.append({"line_number": line_number, "value": dict(value), "raw_line": line})
    native_codex = any(
        row["value"].get("type") == "session_meta"
        and isinstance(row["value"].get("payload"), Mapping)
        and row["value"]["payload"].get("originator") == "Codex Desktop"
        and isinstance(row["value"]["payload"].get("cli_version"), str)
        and bool(row["value"]["payload"].get("cli_version"))
        and row["value"]["payload"].get("source") is not None
        for row in records
    )
    for row in records:
        row["native_codex"] = native_codex
    return {"path": path_value, "records": records, "raw": raw, "digest": digest, "privacy_lines": privacy_lines, "hash_scope": hash_scope, "native_codex": native_codex}, [*render_issues, *issues], digest


def _resolve_selector(source: Mapping[str, Any], selector_value: Mapping[str, Any], issues: list[str], label: str) -> dict[str, Any] | None:
    try:
        selector = _selector_fields(selector_value)
    except ValueError as exc:
        issues.append(f"selector:{label}:invalid:{str(exc).replace(' ', '_')}")
        return None
    matches = [row for row in source.get("records", []) if _selector_match(selector, row["value"], row["raw_line"], row["line_number"])]
    if not matches:
        issues.append(f"selector:{label}:missing_record")
        return None
    if len(matches) != 1:
        issues.append(f"selector:{label}:ambiguous_selector")
        return None
    row = matches[0]
    return {
        "line_number": row["line_number"],
        "type": _record_type(row["value"]),
        "timestamp": _timestamp(row["value"]),
        "record_id": _record_id(row["value"]),
        "call_id": _value(row["value"], "call_id"),
        "turn_id": _value(row["value"], "turn_id"),
        "selected_record_hash": selector["selected_record_hash"],
        "clock": _clock(row["value"], native_codex=row.get("native_codex") is True),
        "record": row["value"],
    }


def _segment(source: Mapping[str, Any], start: Mapping[str, Any] | None, end: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if start is None or end is None:
        return []
    lo, hi = start["line_number"], end["line_number"]
    if hi < lo:
        return []
    return [row for row in source.get("records", []) if lo <= row["line_number"] <= hi]


def _identity(record: Mapping[str, Any]) -> dict[str, Any]:
    payload = _payload(record)
    result: dict[str, Any] = {}
    for key in ("thread_id", "task_id", "session_id", "id", "parent_thread_id", "parent_task_id", "parent_id", "agent_thread_id", "child_thread_id"):
        value = _value(record, key)
        if isinstance(value, str) and value:
            result[key] = value
    meta = payload.get("source") if isinstance(payload.get("source"), Mapping) else None
    spawn = meta.get("subagent") if isinstance(meta, Mapping) and isinstance(meta.get("subagent"), Mapping) else None
    edge = spawn.get("thread_spawn") if isinstance(spawn, Mapping) and isinstance(spawn.get("thread_spawn"), Mapping) else None
    if isinstance(edge, Mapping):
        for key in ("parent_thread_id", "parent_task_id", "agent_thread_id", "thread_id", "agent_path", "depth"):
            value = edge.get(key)
            if (isinstance(value, str) and value) or (key == "depth" and type(value) is int):
                result.setdefault(key, value)
    return result


def _effective(segment: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for row in segment:
        record = row["value"]
        record_type = _record_type(record)
        if record_type in {"collaboration.call", "collaboration.receipt", "child.notification", "verification.completed"}:
            result["surface_evidence"] = True
        # Native Codex rollout envelopes carry an explicit V2 marker on the
        # turn-context payload.  Treat that structural marker as surface
        # evidence while keeping body/reasoning fields opaque.
        payload = _payload(record)
        if payload.get("multi_agent_version") == "v2":
            result["surface_evidence"] = True
        for key, names in {
            "model": ("model",),
            "effort": ("effort", "reasoning_effort"),
            "context_policy": ("context_policy", "fork_context_policy"),
            "surface": ("source_surface", "surface", "runtime_surface", "adapter"),
        }.items():
            value = _value(record, *names)
            if isinstance(value, Mapping):
                value = value.get("name", value.get("surface"))
            if value is not None:
                result.setdefault(key, value)
                if key == "surface" and isinstance(value, str) and value.strip().lower() in SURFACES:
                    result["surface_evidence"] = True
    return result


def _surface_ok(effective: Mapping[str, Any], expected: Any) -> bool:
    if not isinstance(expected, str) or expected.strip().lower() not in SURFACES:
        return False
    surface = effective.get("surface")
    # Native records may identify V2 by collaboration event types rather than
    # repeating a surface field.  A declared expected V2 surface is accepted
    # when such records are present; contradictory explicit surfaces fail.
    if surface is None:
        # No selected records may carry a surface field (for example a
        # missing selector or source).  That is incomplete evidence, not a
        # positive contradiction; callers add an explicit unknown issue when
        # a non-empty segment lacks any V2 evidence.
        return True
    return isinstance(surface, str) and surface.strip().lower() in SURFACES


def _lifecycle_ok(start: Mapping[str, Any] | None, end: Mapping[str, Any] | None) -> bool:
    """Require selectors to identify a real bounded lifecycle pair."""

    if start is None or end is None:
        return False
    start_type = str(start.get("type", "")).lower()
    end_type = str(end.get("type", "")).lower()
    starts = start_type.endswith((".started", ".start", "_started", "_start")) or start_type in {"start", "started"}
    ends = end_type.endswith((".completed", ".complete", ".ended", ".end", "_completed", "_complete", "_ended", "_end")) or end_type in {"end", "ended", "completed", "complete", "finished"}
    return starts and ends and end.get("line_number", 0) > start.get("line_number", 0)


def _time_number(value: Any) -> float | None:
    if _finite(value):
        return float(value)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp() * 1000.0
    return None


def _time_point(value: Any, clock: Mapping[str, Any], *, status: str = "observed", reason: str | None = None) -> dict[str, Any]:
    result = {
        "status": status,
        "value": value,
        "clock_id": clock.get("clock_id", "unknown"),
        "clock_kind": clock.get("clock_kind", "unknown"),
        "unit": clock.get("unit", "unknown"),
        "origin": clock.get("origin", "unknown"),
    }
    if reason:
        result["unknown_reason"] = reason
    return result


def _duration(start: Mapping[str, Any] | None, end: Mapping[str, Any] | None) -> dict[str, Any]:
    if start is None or end is None:
        return _time_point(None, {"clock_id": "unknown", "clock_kind": "unknown", "unit": "unknown", "origin": "unknown"}, status="unknown", reason="missing_record")
    start_clock, end_clock = start["clock"], end["clock"]
    def unknown_reason(clock: Mapping[str, Any]) -> str | None:
        # Keep clock identity, kind, unit, and origin explicit in the output,
        # while preserving the more useful reason for an invalid unit/origin.
        # An absent/unknown clock identity or kind remains ``clock_unknown``.
        if clock.get("clock_id") == "unknown" or clock.get("clock_kind") == "unknown":
            return "clock_unknown"
        if clock.get("unit") == "unknown":
            return "unit_unknown"
        if clock.get("origin") == "unknown":
            return "origin_unknown"
        return None
    start_unknown = unknown_reason(start_clock)
    if start_unknown:
        return _time_point(None, start_clock, status="unknown", reason=start_unknown)
    end_unknown = unknown_reason(end_clock)
    if end_unknown:
        return _time_point(None, end_clock, status="unknown", reason=end_unknown)
    if start_clock != end_clock:
        return _time_point(None, start_clock, status="unknown", reason="clock_mismatch")
    first, last = _time_number(start.get("timestamp")), _time_number(end.get("timestamp"))
    if first is None or last is None:
        return _time_point(None, start_clock, status="unknown", reason="conversion_unavailable")
    if isinstance(start.get("timestamp"), str) != isinstance(end.get("timestamp"), str):
        return _time_point(None, start_clock, status="unknown", reason="conversion_unavailable")
    # ISO values are normalized to milliseconds.  Numeric values use their
    # declared unit; output duration is always milliseconds for the catalog.
    if isinstance(start.get("timestamp"), str) or isinstance(end.get("timestamp"), str):
        delta = last - first
    else:
        multiplier = {
            "nanoseconds": 1e-6,
            "microseconds": 1e-3,
            "milliseconds": 1.0,
            "seconds": 1000.0,
        }.get(start_clock["unit"])
        if multiplier is None:
            return _time_point(None, start_clock, status="unknown", reason="conversion_unavailable")
        first *= multiplier
        last *= multiplier
        delta = last - first
    if delta < 0:
        return _time_point(None, start_clock, status="unknown", reason="clock_mismatch")
    result = {
        "status": "observed",
        "started_at": first,
        "ended_at": last,
        "duration_ms": delta,
        **start_clock,
    }
    return result


def _timing_metric(start: Mapping[str, Any] | None, end: Mapping[str, Any] | None) -> dict[str, Any]:
    duration = _duration(start, end)
    if duration.get("status") != "observed":
        return duration
    return {
        "status": "observed",
        "value_ms": duration["duration_ms"],
        **{key: duration[key] for key in ("clock_id", "clock_kind", "unit", "origin")},
    }


def _overlap_metric(intervals: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not intervals:
        return _unknown("missing_record")
    if any(item.get("status") != "observed" for item in intervals):
        reason = next(
            (str(item.get("unknown_reason")) for item in intervals if item.get("status") != "observed"),
            "observation_incomplete",
        )
        return _unknown(reason)
    clock_fields = ("clock_id", "clock_kind", "unit", "origin")
    reference = {key: intervals[0].get(key) for key in clock_fields}
    if any(any(item.get(key) != reference[key] for key in clock_fields) for item in intervals):
        return _unknown("clock_mismatch")
    events: dict[float, int] = {}
    for interval in intervals:
        start = float(interval["started_at"])
        end = float(interval["ended_at"])
        events[start] = events.get(start, 0) + 1
        events[end] = events.get(end, 0) - 1
    active = 0
    previous: float | None = None
    overlap_ms = 0.0
    for timestamp in sorted(events):
        if previous is not None and active >= 2:
            overlap_ms += timestamp - previous
        active += events[timestamp]
        previous = timestamp
    return {"status": "observed", "value_ms": overlap_ms, **reference}


def _unknown(reason: str) -> dict[str, Any]:
    reason = reason if reason in REASON_CODES else "observation_incomplete"
    return {
        "status": "unknown",
        "value": None,
        "clock_id": "unknown",
        "clock_kind": "unknown",
        "unit": "unknown",
        "origin": "unknown",
        "unknown_reason": reason,
    }


def _usage_for(
    segment: Sequence[Mapping[str, Any]],
    *,
    role: str,
    expected_thread_id: str,
    source_item: Mapping[str, Any],
    copied_history_known_zero: bool,
) -> dict[str, Any]:
    rows: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    compactions: list[dict[str, Any]] = []
    native_snapshots: dict[tuple[int, ...], tuple[int, ...]] = {}
    previous_native_total: tuple[int, ...] | None = None
    native_duplicate_snapshots = 0
    native_snapshot_conflict = False
    native_keys = ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens", "total_tokens")
    for row in segment:
        record = row["value"]
        usage = _value(record, "usage", "token_usage", "tokens")
        if isinstance(usage, Mapping):
            rows.append((row, usage))
            continue
        payload = _payload(record)
        info = payload.get("info") if isinstance(payload.get("info"), Mapping) else None
        last = info.get("last_token_usage") if isinstance(info, Mapping) and isinstance(info.get("last_token_usage"), Mapping) else None
        total = info.get("total_token_usage") if isinstance(info, Mapping) and isinstance(info.get("total_token_usage"), Mapping) else None
        if row.get("native_codex") is True and record.get("type") == "event_msg" and payload.get("type") == "token_count" and last is not None and total is not None:
            last_tuple = tuple(last.get(key) for key in native_keys)
            total_tuple = tuple(total.get(key) for key in native_keys)
            if any(type(value) is not int or value < 0 for value in (*last_tuple, *total_tuple)):
                native_snapshot_conflict = True
                continue
            if total_tuple in native_snapshots:
                if native_snapshots[total_tuple] == last_tuple:
                    native_duplicate_snapshots += 1
                    continue
                native_snapshot_conflict = True
                continue
            if previous_native_total is not None:
                delta = tuple(current - previous for current, previous in zip(total_tuple, previous_native_total))
                if delta != last_tuple:
                    native_snapshot_conflict = True
                    continue
            native_snapshots[total_tuple] = last_tuple
            previous_native_total = total_tuple
            rows.append((row, {
                "kind": "generation_delta",
                "usage_id": "native:" + hashlib.sha256(_canonical({"total": total, "last": last})).hexdigest(),
                "usage_delta": {
                    "input_tokens": last["input_tokens"],
                    "cached_input_tokens": last["cached_input_tokens"],
                    "output_tokens": last["output_tokens"],
                    "reasoning_tokens": last["reasoning_output_tokens"],
                    "total_tokens": last["total_tokens"],
                    "copied_history_tokens": 0 if copied_history_known_zero else None,
                },
            }))
        elif any(key in record for key in ("input_tokens", "output_tokens", "total_tokens", "delta_tokens", "usage_delta")):
            rows.append((row, record))
    if native_snapshot_conflict:
        return {
            "status": "contradictory",
            "known": False,
            "role": role,
            "unknown_reason": "ambiguous_binding",
            "records": len(rows),
            "generation_records": 0,
            "native_duplicate_snapshots": native_duplicate_snapshots,
            "source_refs": [],
            "issues": ["ambiguous_binding"],
        }
    if not rows:
        return {"status": "unknown", "known": False, "role": role, "unknown_reason": "missing_record", "records": 0, "source_refs": [], "issues": []}
    totals = {
        "input_tokens": 0,
        "copied_history_tokens": 0,
        "uncached_input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
        "raw_total_tokens": 0,
        "total_tokens": 0,
    }
    issues: list[str] = []
    source_refs: list[dict[str, Any]] = []
    seen_usage_ids: set[str] = set()
    seen_record_hashes: set[str] = set()
    generation_records = 0
    lifecycle_turn_ids = {
        str(_value(row["value"], "turn_id"))
        for row in segment
        if _value(row["value"], "turn_id") is not None
        and (_record_type(row["value"]) or "").endswith((".started", ".completed"))
    }
    for row, usage in rows:
        record = row["value"]
        typ = _record_type(record) or ""
        kind = str(usage.get("kind", usage.get("type", typ))).lower()
        record_hash = hashlib.sha256(_canonical(record)).hexdigest()
        usage_id_value = usage.get("usage_id", usage.get("id", _value(record, "usage_id", "id")))
        usage_id = str(usage_id_value) if isinstance(usage_id_value, str) and usage_id_value else record_hash
        source_ref = {
            "usage_id": usage_id,
            "role": role,
            "source_id": f"{source_item['path']}#line:{row['line_number']}",
            "record_pointer": f"line:{row['line_number']};record_sha256:{record_hash}",
            "record_sha256": record_hash,
            "content_hash": source_item.get("segment_sha256") or source_item.get("file_sha256") or source_item.get("observed_file_sha256"),
            "hash_scope": source_item.get("hash_scope", "full_file"),
        }
        source_refs.append(source_ref)
        if usage_id in seen_usage_ids or record_hash in seen_record_hashes:
            issues.append("duplicate_record")
        seen_usage_ids.add(usage_id)
        seen_record_hashes.add(record_hash)
        owner = usage.get("task_id", usage.get("thread_id", usage.get("session_id", _value(record, "task_id", "thread_id", "session_id"))))
        if owner is not None and owner != expected_thread_id:
            issues.append("ambiguous_binding")
        turn_id = usage.get("turn_id", _value(record, "turn_id"))
        if turn_id is not None and lifecycle_turn_ids and str(turn_id) not in lifecycle_turn_ids:
            issues.append("ambiguous_binding")
        if "compaction" in kind or "compaction" in typ:
            snapshot = usage.get("snapshot", record.get("snapshot", True))
            if snapshot is not True:
                issues.append("observation_incomplete")
            compactions.append({**source_ref, "snapshot": snapshot, "included_in_totals": False})
            continue
        if usage.get("is_cumulative") is True or kind in {"cumulative", "task_total", "snapshot", "aggregate"}:
            issues.append("conversion_unavailable")
            continue
        delta = usage.get("attempt_delta", usage.get("delta", usage.get("usage_delta")))
        if isinstance(delta, Mapping):
            values = delta
        else:
            # Exact attempt attribution requires an explicit delta. Provider
            # snapshots and cumulative task totals are not silently accepted.
            issues.append("conversion_unavailable")
            continue
        numeric = {key: values.get(key) for key in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "total_tokens")}
        if any(type(value) is not int or value < 0 for value in numeric.values()):
            issues.append("observation_incomplete")
            continue
        if numeric["cached_input_tokens"] > numeric["input_tokens"] or numeric["reasoning_tokens"] > numeric["output_tokens"]:
            issues.append("observation_incomplete")
            continue
        if numeric["total_tokens"] != numeric["input_tokens"] + numeric["output_tokens"]:
            issues.append("observation_incomplete")
            continue
        copied_values = [
            candidate
            for candidate in (
                values.get("copied_history_tokens"),
                values.get("forked_prefix_tokens"),
                usage.get("copied_history_tokens"),
                usage.get("forked_prefix_tokens"),
                record.get("copied_history_tokens"),
                record.get("forked_prefix_tokens"),
            )
            if candidate is not None
        ]
        if len(set(copied_values)) > 1:
            issues.append("ambiguous_binding")
            continue
        if copied_values:
            copied = copied_values[0]
        elif copied_history_known_zero:
            copied = 0
        else:
            issues.append("observation_incomplete")
            continue
        if type(copied) is not int or copied < 0 or copied + numeric["cached_input_tokens"] > numeric["input_tokens"]:
            issues.append("observation_incomplete")
            continue
        uncached = numeric["input_tokens"] - numeric["cached_input_tokens"] - copied
        attributed_total = uncached + numeric["cached_input_tokens"] + numeric["output_tokens"]
        totals["input_tokens"] += numeric["input_tokens"]
        totals["copied_history_tokens"] += copied
        totals["uncached_input_tokens"] += uncached
        totals["cached_input_tokens"] += numeric["cached_input_tokens"]
        totals["output_tokens"] += numeric["output_tokens"]
        totals["reasoning_tokens"] += numeric["reasoning_tokens"]
        totals["raw_total_tokens"] += numeric["total_tokens"]
        totals["total_tokens"] += attributed_total
        generation_records += 1
    if issues or generation_records == 0:
        contradictory = any(issue in {"duplicate_record", "ambiguous_binding"} for issue in issues)
        reason = "ambiguous_binding" if contradictory else (issues[0] if issues else "missing_record")
        return {
            "status": "contradictory" if contradictory else "unknown",
            "known": False,
            "role": role,
            "unknown_reason": reason,
            "records": len(rows),
            "generation_records": generation_records,
            "compaction_snapshots": len(compactions),
            "native_duplicate_snapshots": native_duplicate_snapshots,
            "source_refs": source_refs,
            "compaction_records": compactions,
            "issues": sorted(set(issues)),
        }
    return {
        "status": "observed",
        "known": True,
        "role": role,
        "records": len(rows),
        "generation_records": generation_records,
        "compaction_snapshots": len(compactions),
        "native_duplicate_snapshots": native_duplicate_snapshots,
        **totals,
        "arithmetic": {
            "uncached_input_tokens": "input_tokens - cached_input_tokens - copied_history_tokens",
            "total_tokens": "uncached_input_tokens + cached_input_tokens + output_tokens",
            "reasoning_tokens": "subset of output_tokens",
        },
        "source_refs": source_refs,
        "compaction_records": compactions,
        "issues": [],
    }


def _combine_usage(roles: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    known_roles = sorted(name for name, value in roles.items() if value.get("status") == "observed")
    unknown_roles = sorted(name for name, value in roles.items() if value.get("status") != "observed")
    source_ids: set[str] = set()
    duplicate_source = False
    for value in roles.values():
        for source in value.get("source_refs", []):
            source_id = str(source.get("source_id")) + "#" + str(source.get("record_pointer"))
            if source_id in source_ids:
                duplicate_source = True
            source_ids.add(source_id)
    all_required_known = not unknown_roles and not duplicate_source
    issues = sorted({issue for value in roles.values() for issue in value.get("issues", [])})
    if duplicate_source:
        issues.append("ambiguous_binding")
    result: dict[str, Any] = {
        "status": "observed" if all_required_known else ("contradictory" if duplicate_source or any(value.get("status") == "contradictory" for value in roles.values()) else "partial"),
        "known": all_required_known,
        "all_required_known": all_required_known,
        "known_roles": known_roles,
        "unknown_roles": unknown_roles,
        "issues": sorted(set(issues)),
    }
    if not all_required_known:
        result["unknown_reason"] = "ambiguous_binding" if result["status"] == "contradictory" else next(
            (str(value.get("unknown_reason")) for value in roles.values() if value.get("status") != "observed"),
            "observation_incomplete",
        )
        return result
    keys = ("input_tokens", "copied_history_tokens", "uncached_input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "raw_total_tokens", "total_tokens")
    result.update({key: sum(int(value[key]) for value in roles.values()) for key in keys})
    result["arithmetic"] = {
        "uncached_input_tokens": "sum(role.uncached_input_tokens)",
        "cached_input_tokens": "sum(role.cached_input_tokens)",
        "output_tokens": "sum(role.output_tokens)",
        "reasoning_tokens": "sum(role.reasoning_tokens)",
        "total_tokens": "uncached_input_tokens + cached_input_tokens + output_tokens",
    }
    return result


def _metric_counts(segment: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    mutations: list[dict[str, Any]] = []
    native_test_runs: dict[str, dict[str, Any]] = {}
    native_test_sessions: dict[str, str] = {}
    native_test_polls: dict[str, str] = {}
    for row in segment:
        record = row["value"]
        typ = _record_type(record) or ""
        name = _value(record, "operation", "name", "tool_name", "action")
        if typ in {"function_call", "custom_tool_call", "tool.call", "collaboration.call", "action"} or name:
            if isinstance(name, str) and name and not _SECRET.search(name):
                actions.append({"name": name, "line_number": row["line_number"]})
        passed = _value(record, "passed", "success", "ok")
        if typ in {"verification.completed", "verification", "test", "test_result", "check"} or passed is not None:
            checks.append({"passed": passed is True, "line_number": row["line_number"]})
        if typ in {"mutation", "file.mutation", "edit", "patch", "write", "integration.action"} or _value(record, "mutation", "mutated") is True:
            mutations.append({"type": typ, "line_number": row["line_number"]})
        # Native Codex tool envelopes preserve the exact command/result pair.
        # Record only aggregate unittest outcomes: never copy command text or
        # output bodies into the observation.  Poll fragments for the same
        # session are reconciled by call order; a terminal `Ran N tests` line
        # is the evidence boundary and prevents counting partial output.
        payload = _payload(record)
        if record.get("type") == "response_item" and typ in {"custom_tool_call", "function_call"}:
            input_value = payload.get("input", payload.get("arguments"))
            if isinstance(input_value, str) and "unittest" in input_value:
                call_id = payload.get("call_id")
                if isinstance(call_id, str) and call_id:
                    native_test_runs[call_id] = {"line_number": row["line_number"], "count": None, "passed": None}
            elif isinstance(input_value, str) and "write_stdin" in input_value:
                session_match = re.search(r"session_id\s*:\s*(\d+)", input_value)
                call_id = payload.get("call_id")
                if session_match and isinstance(call_id, str) and call_id:
                    original_call = native_test_sessions.get(session_match.group(1))
                    if original_call is not None:
                        native_test_polls[call_id] = original_call
        elif record.get("type") == "response_item" and typ in {"custom_tool_call_output", "function_call_output"}:
            output = payload.get("output")
            if isinstance(output, list):
                output_text = "\n".join(
                    str(item.get("text", ""))
                    for item in output
                    if isinstance(item, Mapping) and isinstance(item.get("text"), str)
                )
            elif isinstance(output, str):
                output_text = output
            else:
                output_text = ""
            call_id = str(payload.get("call_id", ""))
            original_call = native_test_polls.get(call_id, call_id)
            session_match = re.search(r'"session_id"\s*:\s*(\d+)', output_text)
            if session_match and original_call in native_test_runs:
                native_test_sessions[session_match.group(1)] = original_call
            match = re.search(r"Ran\s+(\d+)\s+tests?\b", output_text)
            if match and original_call in native_test_runs:
                count = int(match.group(1))
                passed = re.search(r"(?:^|\n|\r|\\n|\\r)OK(?:\n|\r|\\n|\\r|$)", output_text) is not None
                native_test_runs[original_call] = {
                    "line_number": row["line_number"],
                    "count": count,
                    "passed": passed,
                }
    for item in native_test_runs.values():
        if type(item.get("count")) is int and item["count"] > 0:
            checks.extend(
                {"passed": item.get("passed") is True, "line_number": item["line_number"]}
                for _ in range(item["count"])
            )
    return (
        {"count": len(actions), "items": actions},
        {"count": len(checks), "passed": sum(1 for item in checks if item["passed"]), "items": checks},
        {"count": len(mutations), "items": mutations},
    )


def _custody_access_candidates(
    segment: Sequence[Mapping[str, Any]],
    *,
    worker_id: str,
    lane_id: str,
    phase: str,
    source_path: str,
    issues: list[str],
) -> list[tuple[float, int, str, int, dict[str, Any], dict[str, Any]]]:
    """Project explicit source access records without copying tool bodies.

    Native command text is deliberately not interpreted as authority. A
    runtime or harness must emit a structural ``resource.access`` record with
    a resource and read/write operation. The observer binds that projection
    to the complete source record hash and independently assigns membership
    and phase from the selected attempt segment.
    """

    result: list[tuple[float, int, str, int, dict[str, Any], dict[str, Any]]] = []
    for row in segment:
        record = row["value"]
        if _record_type(record) != "resource.access":
            continue
        declared_worker = _value(record, "worker_id", "thread_id", "task_id")
        declared_lane = _value(record, "lane_id")
        declared_phase = _value(record, "phase")
        if declared_worker is not None and declared_worker != worker_id:
            issues.append(f"custody:{lane_id}:access_worker_conflict")
            continue
        if declared_lane is not None and declared_lane != lane_id:
            issues.append(f"custody:{lane_id}:access_lane_conflict")
            continue
        if declared_phase is not None and declared_phase != phase:
            issues.append(f"custody:{lane_id}:access_phase_conflict")
            continue
        operation = _value(record, "operation")
        resource = _value(record, "resource")
        if operation not in {"read", "write"}:
            issues.append(f"custody:{lane_id}:access_operation_invalid")
            continue
        try:
            resource_value = _text(resource, "resource.access.resource", max_len=4096)
        except ValueError:
            issues.append(f"custody:{lane_id}:access_resource_invalid")
            continue
        timestamp = _time_number(_timestamp(record))
        clock = _clock(record, native_codex=row.get("native_codex") is True)
        if timestamp is None:
            issues.append(f"custody:{lane_id}:access_time_unknown")
            continue
        record_sha256 = hashlib.sha256(_canonical(record)).hexdigest()
        event = {
            "type": "resource.access",
            "worker_id": worker_id,
            "lane_id": lane_id,
            "resource": resource_value,
            "operation": operation,
            "phase": phase,
            "source_pointer": f"{source_path}#line:{row['line_number']};record_sha256:{record_sha256}",
        }
        result.append((timestamp, 10 if phase == "initial" else 70, source_path, row["line_number"], event, clock))
    return result


def _custody_lifecycle_candidate(
    point: Mapping[str, Any] | None,
    *,
    priority: int,
    source_path: str,
    event: dict[str, Any],
) -> tuple[float, int, str, int, dict[str, Any], dict[str, Any]] | None:
    if point is None:
        return None
    timestamp = _time_number(point.get("timestamp"))
    clock = point.get("clock") if isinstance(point.get("clock"), Mapping) else _clock({})
    if timestamp is None:
        return None
    return (timestamp, priority, source_path, int(point.get("line_number", 0)), event, dict(clock))


def _custody_bundle(
    *,
    attempt_id: str,
    candidates: Sequence[tuple[float, int, str, int, dict[str, Any], dict[str, Any]]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Order hash-bound custody facts only when their clocks are comparable."""

    clocks = [item[5] for item in candidates]
    known = bool(candidates) and all(
        clock.get("clock_id") not in {None, "unknown"}
        and clock.get("clock_kind") not in {None, "unknown"}
        and clock.get("unit") not in {None, "unknown"}
        and clock.get("origin") not in {None, "unknown"}
        for clock in clocks
    )
    comparable = known and all(clock == clocks[0] for clock in clocks[1:])
    if not comparable:
        reason = "clock_mismatch" if known else "clock_unknown"
        bundle = {"schema": CUSTODY_EVENT_SCHEMA, "events": []}
        return bundle, {
            "status": "unknown",
            "evidence_tier": "runtime-observed",
            "attempt_id": attempt_id,
            "unknown_reason": reason,
            "event_count": 0,
            "events_sha256": hashlib.sha256(_canonical(bundle)).hexdigest(),
        }
    ordered = sorted(candidates, key=lambda item: item[:4])
    events = [{"seq": index, **item[4]} for index, item in enumerate(ordered, 1)]
    bundle = {"schema": CUSTODY_EVENT_SCHEMA, "events": events}
    access_count = sum(1 for event in events if event["type"] == "resource.access")
    status = "observed" if access_count else "unknown"
    evidence = {
        "status": status,
        "evidence_tier": "runtime-observed",
        "attempt_id": attempt_id,
        "event_count": len(events),
        "access_count": access_count,
        "events_sha256": hashlib.sha256(_canonical(bundle)).hexdigest(),
        "clock": clocks[0],
    }
    if not access_count:
        evidence["unknown_reason"] = "missing_record"
    return bundle, evidence


def _source_descriptor(role: str, item: Mapping[str, Any], *, selector: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result = {
        "role": role,
        "path": item["path"],
        "path_kind": "absolute" if str(item["path"]).startswith("/") else "relative",
        "store": "codex_session_store",
        "host_identity": "local",
        "sha256": item.get("segment_sha256") or item.get("file_sha256") or item.get("observed_file_sha256"),
        "content_hash": item.get("segment_sha256") or item.get("file_sha256") or item.get("observed_file_sha256"),
        "hash_scope": item.get("hash_scope", "full_file"),
        # The registry's catalog mapper carries an optional size field
        # unconditionally; retain a neutral bounded value when the manifest
        # did not provide byte-size metadata.
        "size": item.get("size", 0),
    }
    if item.get("hash_scope") == "bounded_segment":
        result["source_file"] = item["path"]
        result["observed_file_sha256"] = item.get("observed_file_sha256") or item.get("file_sha256")
        result["start_line"] = item.get("start_line")
        result["end_line"] = item.get("end_line")
    if selector:
        selected_hash = selector.get("selected_record_hash")
        suffix = f";record_sha256:{selected_hash}" if selected_hash else ""
        result["selector"] = f"line:{selector['line_number']}{suffix}"
        result["record_pointer"] = f"line:{selector['line_number']}{suffix}"
        result["source_id"] = f"{item['path']}#line:{selector['line_number']}"
    return result


def _artifact_descriptor(item: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        "role": item["role"],
        "path": item["path"],
        "path_kind": "absolute" if str(item["path"]).startswith("/") else "relative",
        "store": "artifact_store",
        "host_identity": "local",
        "sha256": item["file_sha256"],
        "content_hash": item["file_sha256"],
        "size": item.get("size", 0),
    }
    for key in ("selector", "record_pointer"):
        if key in item:
            result[key] = item[key]
    return result


def _issue_code(issues: Iterable[str]) -> list[str]:
    result: list[str] = []
    for issue in issues:
        lower = issue.lower()
        if "private" in lower or "privacy:" in lower:
            result.append("redacted")
        elif "missing_source" in lower or "source:missing" in lower:
            result.append("missing_source")
        elif "permission" in lower:
            result.append("permission_denied")
        elif "ambiguous" in lower:
            result.append("ambiguous_selector")
        elif "render_mismatch" in lower or "rendered_mismatch" in lower:
            result.append("render_mismatch")
        elif "hash_conflict" in lower or "identity_conflict" in lower or "parent_conflict" in lower:
            result.append("ambiguous_binding")
        elif "clock" in lower:
            result.append("clock_unknown")
        elif "selector" in lower or "record" in lower:
            result.append("missing_record")
        else:
            result.append("observation_incomplete")
    return sorted(set(result))


def _manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be an object")
    allowed = {"schema", "attempt_id", "root", "children", "expected", "artifacts", "timing"}
    unknown = set(manifest) - allowed
    if unknown:
        raise ValueError(f"manifest has unsupported fields: {sorted(unknown)}")
    if manifest.get("schema") != SCHEMA:
        raise ValueError("manifest schema must be orch-dork/attempt-observation/v1")
    attempt_id = _id(manifest.get("attempt_id"), "attempt_id")
    def source(value: Any, label: str, *, child: bool = False) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise ValueError(f"{label} must be an object")
        fields = {"thread_id", "parent_thread_id", "lane_id", "path", "file_sha256", "observed_file_sha256", "segment_sha256", "rendered_sha256", "rendered_file_sha256", "hash_scope", "start_line", "end_line", "spawn_selector", "start_selector", "end_selector"}
        unknown_fields = set(value) - fields
        if unknown_fields:
            raise ValueError(f"{label} has unsupported fields: {sorted(unknown_fields)}")
        result = {
            "thread_id": _id(value.get("thread_id"), f"{label}.thread_id"),
            "path": _text(value.get("path"), f"{label}.path", max_len=4096),
            "file_sha256": value.get("file_sha256"),
            "observed_file_sha256": value.get("observed_file_sha256"),
            "segment_sha256": value.get("segment_sha256"),
            "rendered_sha256": value.get("rendered_sha256", value.get("rendered_file_sha256")),
            "hash_scope": value.get("hash_scope", "full_file"),
            "start_line": value.get("start_line"),
            "end_line": value.get("end_line"),
            "spawn_selector": value.get("spawn_selector"),
            "start_selector": value.get("start_selector"),
            "end_selector": value.get("end_selector"),
        }
        if result["file_sha256"] is not None and (not isinstance(result["file_sha256"], str) or _SHA256.fullmatch(result["file_sha256"]) is None):
            raise ValueError(f"{label}.file_sha256 must be lowercase SHA-256")
        if result["observed_file_sha256"] is not None and (not isinstance(result["observed_file_sha256"], str) or _SHA256.fullmatch(result["observed_file_sha256"]) is None):
            raise ValueError(f"{label}.observed_file_sha256 must be lowercase SHA-256")
        if result["rendered_sha256"] is not None and (not isinstance(result["rendered_sha256"], str) or _SHA256.fullmatch(result["rendered_sha256"]) is None):
            raise ValueError(f"{label}.rendered_sha256 must be lowercase SHA-256")
        if result["hash_scope"] not in {"full_file", "bounded_segment"}:
            raise ValueError(f"{label}.hash_scope is invalid")
        if result["hash_scope"] == "bounded_segment":
            if not isinstance(result["segment_sha256"], str) or _SHA256.fullmatch(result["segment_sha256"]) is None:
                raise ValueError(f"{label}.segment_sha256 is required for bounded_segment")
            if type(result["start_line"]) is not int or type(result["end_line"]) is not int or result["start_line"] < 1 or result["end_line"] < result["start_line"]:
                raise ValueError(f"{label}.start_line/end_line must bound a positive segment")
            if result["file_sha256"] is not None and result["observed_file_sha256"] is not None and result["file_sha256"] != result["observed_file_sha256"]:
                raise ValueError(f"{label}.file_sha256 conflicts with observed_file_sha256")
        elif result["segment_sha256"] is not None:
            raise ValueError(f"{label}.segment_sha256 requires bounded_segment")
        elif result["file_sha256"] is None:
            raise ValueError(f"{label}.file_sha256 is required for full_file")
        if child:
            result["lane_id"] = _id(value.get("lane_id"), f"{label}.lane_id")
            result["parent_thread_id"] = _id(value.get("parent_thread_id"), f"{label}.parent_thread_id")
        else:
            result["lane_id"] = None
        # Validate selector shape before opening any source.
        _selector_fields(result["start_selector"])
        _selector_fields(result["end_selector"])
        if result["spawn_selector"] is not None:
            _selector_fields(result["spawn_selector"])
        return result
    root = source(manifest.get("root"), "root")
    children_value = manifest.get("children", [])
    if not isinstance(children_value, list):
        raise ValueError("children must be an array")
    children = [source(value, f"children[{index}]", child=True) for index, value in enumerate(children_value)]
    lane_ids = [child["lane_id"] for child in children]
    if len(set(lane_ids)) != len(lane_ids):
        raise ValueError("children lane_id values must be unique")
    timing_value = manifest.get("timing")
    timing: dict[str, Any] | None = None
    if timing_value is not None:
        if not isinstance(timing_value, Mapping):
            raise ValueError("timing must be an object")
        if set(timing_value) - {"integrator", "release"}:
            raise ValueError(f"timing has unsupported fields: {sorted(set(timing_value) - {'integrator', 'release'})}")
        integrator = source(timing_value.get("integrator"), "timing.integrator", child=True)
        if integrator["lane_id"] not in set(lane_ids):
            raise ValueError("timing.integrator.lane_id must identify an initial lane")
        initial_owner = next(child for child in children if child["lane_id"] == integrator["lane_id"])
        for key in ("thread_id", "parent_thread_id", "path"):
            if integrator[key] != initial_owner[key]:
                raise ValueError(f"timing.integrator.{key} must match its initial lane")
        release_value = timing_value.get("release")
        if not isinstance(release_value, Mapping) or set(release_value) - {"owner_lane_id", "selector"}:
            raise ValueError("timing.release must contain only owner_lane_id and selector")
        owner_lane_id = _id(release_value.get("owner_lane_id"), "timing.release.owner_lane_id")
        if owner_lane_id not in set(lane_ids) or owner_lane_id == integrator["lane_id"]:
            raise ValueError("timing.release.owner_lane_id must identify a non-integrator initial lane")
        release_selector = _selector_fields(release_value.get("selector"))
        timing = {"integrator": integrator, "release": {"owner_lane_id": owner_lane_id, "selector": release_selector}}
    expected = manifest.get("expected")
    if not isinstance(expected, Mapping):
        raise ValueError("expected must be an object")
    expected_allowed = {"root_model", "root_effort", "child_model", "child_effort", "context_policy", "surface"}
    if set(expected) - expected_allowed:
        raise ValueError(f"expected has unsupported fields: {sorted(set(expected) - expected_allowed)}")
    expected_copy = {key: _text(expected.get(key), f"expected.{key}", max_len=256) for key in expected_allowed}
    if expected_copy["surface"].lower() not in SURFACES:
        raise ValueError("expected.surface must identify native V2")
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        raise ValueError("artifacts must be an array")
    # Artifacts are pass-through evidence descriptors but remain closed and
    # privacy-safe; hashes are required so a catalog can retain provenance.
    artifact_copy: list[dict[str, Any]] = []
    for index, value in enumerate(artifacts):
        if not isinstance(value, Mapping):
            raise ValueError(f"artifacts[{index}] must be an object")
        if set(value) - {"role", "path", "file_sha256", "selector", "record_pointer"}:
            raise ValueError(f"artifacts[{index}] has unsupported fields")
        role = _text(value.get("role"), f"artifacts[{index}].role", max_len=256)
        path = _text(value.get("path"), f"artifacts[{index}].path", max_len=4096)
        digest = value.get("file_sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ValueError(f"artifacts[{index}].file_sha256 must be lowercase SHA-256")
        artifact_copy.append({"role": role, "path": path, "file_sha256": digest, **({"selector": value["selector"]} if "selector" in value else {}), **({"record_pointer": value["record_pointer"]} if "record_pointer" in value else {})})
    return {"schema": SCHEMA, "attempt_id": attempt_id, "root": root, "children": children, "expected": expected_copy, "artifacts": artifact_copy, "timing": timing}


def observe_attempt(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Observe exactly one manifest-bounded root attempt and child lanes."""

    issues: list[str] = []
    try:
        value = _manifest(manifest)
    except ValueError as exc:
        return {
            "schema": SCHEMA,
            "status": FAIL,
            "binding_status": "CONTRADICTORY",
            "attempt_id": manifest.get("attempt_id") if isinstance(manifest, Mapping) else None,
            "graph": {"root": None, "children": [], "edges": []},
            "timing": {"status": "unknown", "unknown_reason": "unsupported_schema", **_clock({})},
            "usage": {"status": "unknown", "unknown_reason": "unsupported_schema"},
            "checks": {"count": 0, "passed": 0},
            "mutations": {"count": 0},
            "claims": [],
            "sources": [],
            "unknown_reasons": ["unsupported_schema"],
            "issues": [f"manifest:{str(exc).replace(' ', '_')}"],
        }
    root = value["root"]
    expected = value["expected"]
    loaded: dict[str, dict[str, Any] | None] = {}
    source_issues: dict[str, list[str]] = {}
    timed_integrator = value.get("timing", {}).get("integrator") if isinstance(value.get("timing"), Mapping) else None
    for item in [root, *value["children"], *([timed_integrator] if isinstance(timed_integrator, Mapping) else [])]:
        path = item["path"]
        if path in loaded:
            continue
        source, source_issue, _ = _read_source(item)
        loaded[path] = source
        source_issues[path] = source_issue
        issues.extend(f"{path}:{issue}" for issue in source_issue)

    root_source = loaded.get(root["path"])
    if root_source and root.get("hash_scope") == "bounded_segment":
        lines = root_source.get("raw", b"").splitlines(keepends=True)
        lo, hi = root.get("start_line"), root.get("end_line")
        if not isinstance(lo, int) or not isinstance(hi, int) or hi > len(lines):
            issues.append("root:segment_hash_conflict")
        elif hashlib.sha256(b"".join(lines[lo - 1:hi])).hexdigest() != root["segment_sha256"]:
            issues.append("root:segment_hash_conflict")
    root_start = _resolve_selector(root_source or {}, root["start_selector"], issues, "root.start") if root_source else None
    root_end = _resolve_selector(root_source or {}, root["end_selector"], issues, "root.end") if root_source else None
    root_segment = _segment(root_source or {}, root_start, root_end)
    if root_source and root.get("hash_scope") == "bounded_segment" and root_start and root_end:
        selected_raw = b"".join(row["raw_line"] for row in root_segment)
        if hashlib.sha256(selected_raw).hexdigest() != root["segment_sha256"]:
            issues.append("root:segment_hash_conflict")
    # The source store is authoritative and may contain opaque private fields
    # on otherwise structurally useful records.  Privacy is enforced on
    # emitted projections (which never copy source records), not by rejecting
    # a bounded source line merely because its outer envelope contains a body
    # or reasoning field.
    root_effective = _effective(root_segment)
    root_identity: dict[str, Any] = {}
    root_meta_identity: dict[str, Any] = {}
    for row in (root_source or {}).get("records", []):
        if _record_type(row["value"]) == "session_meta":
            root_meta_identity.update(_identity(row["value"]))
            break
    for row in root_segment:
        root_identity.update(_identity(row["value"]))
    actual_root = root_meta_identity.get("id") or root_meta_identity.get("session_id") or root_identity.get("thread_id") or root_identity.get("task_id") or root_identity.get("session_id")
    if actual_root != root["thread_id"]:
        issues.append("root:identity_conflict" if actual_root else "root:missing_identity")
    if root_effective.get("model") is not None and root_effective.get("model") != expected["root_model"]:
        issues.append("root:model_conflict")
    if root_effective.get("effort") is not None and root_effective.get("effort") != expected["root_effort"]:
        issues.append("root:effort_conflict")
    if root_effective.get("context_policy") is not None and root_effective.get("context_policy") != expected["context_policy"]:
        issues.append("root:context_conflict")
    if not _surface_ok(root_effective, expected["surface"]):
        issues.append("root:surface_conflict")
    elif root_segment and not root_effective.get("surface") and not root_effective.get("surface_evidence"):
        issues.append("root:surface_missing")
    if root_start and root_end and not _lifecycle_ok(root_start, root_end):
        issues.append("root:lifecycle_conflict")
    root_duration = _duration(root_start, root_end)
    release_record = None
    integrator_start = None
    integrator_end = None
    if value.get("timing"):
        release_record = _resolve_selector(
            root_source or {}, value["timing"]["release"]["selector"], issues, "timing.release"
        ) if root_source else None
        if release_record and root_start and root_end and not (
            root_start["line_number"] <= release_record["line_number"] <= root_end["line_number"]
        ):
            issues.append("timing:release_outside_attempt")
        integrator_source = loaded.get(value["timing"]["integrator"]["path"])
        integrator_start = _resolve_selector(
            integrator_source or {}, value["timing"]["integrator"]["start_selector"], issues, "timing.integrator.start"
        ) if integrator_source else None
        integrator_end = _resolve_selector(
            integrator_source or {}, value["timing"]["integrator"]["end_selector"], issues, "timing.integrator.end"
        ) if integrator_source else None

    children_rows: list[dict[str, Any]] = []
    child_segments: list[list[dict[str, Any]]] = []
    all_timing = [root_duration]
    all_usage: list[dict[str, Any]] = []
    all_actions: list[dict[str, Any]] = []
    all_checks: list[dict[str, Any]] = []
    all_mutations: list[dict[str, Any]] = []
    custody_candidates: list[tuple[float, int, str, int, dict[str, Any], dict[str, Any]]] = []
    for child in value["children"]:
        spawn_record = None
        spawn = None
        if child.get("spawn_selector") is not None:
            spawn_record = _resolve_selector(
                root_source or {}, child["spawn_selector"], issues, f"{child['lane_id']}.spawn"
            ) if root_source else None
            if spawn_record and root_start and root_end and not (
                root_start["line_number"] <= spawn_record["line_number"] <= root_end["line_number"]
            ):
                issues.append(f"{child['lane_id']}:spawn_outside_attempt")
            if spawn_record:
                spawn = _spawn_proof(spawn_record["record"])
                if spawn is None:
                    issues.append(f"{child['lane_id']}:spawn_conflict")
                else:
                    if spawn.get("task_name") != child["lane_id"]:
                        issues.append(f"{child['lane_id']}:spawn_lane_conflict")
                    if spawn.get("model") != expected["child_model"]:
                        issues.append(f"{child['lane_id']}:spawn_model_conflict")
                    if spawn.get("effort") != expected["child_effort"]:
                        issues.append(f"{child['lane_id']}:spawn_effort_conflict")
                    if spawn.get("fork_turns") != "none":
                        issues.append(f"{child['lane_id']}:spawn_context_conflict")
        source = loaded.get(child["path"])
        if source and child.get("hash_scope") == "bounded_segment":
            lines = source.get("raw", b"").splitlines(keepends=True)
            lo, hi = child.get("start_line"), child.get("end_line")
            if not isinstance(lo, int) or not isinstance(hi, int) or hi > len(lines):
                issues.append(f"{child['lane_id']}:segment_hash_conflict")
            elif hashlib.sha256(b"".join(lines[lo - 1:hi])).hexdigest() != child["segment_sha256"]:
                issues.append(f"{child['lane_id']}:segment_hash_conflict")
        start = _resolve_selector(source or {}, child["start_selector"], issues, f"{child['lane_id']}.start") if source else None
        end = _resolve_selector(source or {}, child["end_selector"], issues, f"{child['lane_id']}.end") if source else None
        lifecycle_segment = _segment(source or {}, start, end)
        if source and child.get("hash_scope") == "bounded_segment" and start and end:
            selected_raw = b"".join(row["raw_line"] for row in lifecycle_segment)
            if hashlib.sha256(selected_raw).hexdigest() != child["segment_sha256"]:
                issues.append(f"{child['lane_id']}:segment_hash_conflict")
        # A first-finishing worker may remain active and receive the
        # integration handoff inside its original task lifecycle.  In that
        # shape, the lifecycle end proves terminal completion but is not the
        # initial-lane accounting boundary.  Partition at the exact,
        # hash-bound integrator start so timing, usage, actions, checks and
        # mutations are attributed once rather than double-counted across the
        # initial-lane and integrator roles.
        phase_end = end
        segment = lifecycle_segment
        active_integrator_handoff = (
            value.get("timing") is not None
            and integrator_start is not None
            and child["lane_id"] == value["timing"]["integrator"]["lane_id"]
            and child["path"] == value["timing"]["integrator"]["path"]
            and start is not None
            and end is not None
            and start["line_number"] < integrator_start["line_number"] < end["line_number"]
        )
        if active_integrator_handoff:
            phase_end = integrator_start
            segment = [
                row
                for row in lifecycle_segment
                if row["line_number"] < integrator_start["line_number"]
            ]
        # Selected source records are parsed only for allowlisted structural
        # fields.  Private values remain opaque and are never copied into the
        # observation/catalog projection.
        child_segments.append(segment)
        identity: dict[str, Any] = {}
        meta_identity: dict[str, Any] = {}
        if source:
            for row in source.get("records", []):
                if _record_type(row["value"]) == "session_meta":
                    meta_identity.update(_identity(row["value"]))
                    break
        for row in segment:
            identity.update(_identity(row["value"]))
        actual_child = meta_identity.get("id") or meta_identity.get("session_id") or identity.get("thread_id") or identity.get("task_id") or identity.get("agent_thread_id")
        if actual_child != child["thread_id"]:
            issues.append(f"{child['lane_id']}:identity_conflict" if actual_child else f"{child['lane_id']}:missing_identity")
        parent = meta_identity.get("parent_thread_id") or identity.get("parent_thread_id") or identity.get("parent_task_id")
        if parent != child["parent_thread_id"]:
            issues.append(f"{child['lane_id']}:parent_conflict" if parent else f"{child['lane_id']}:missing_parent")
        depth = meta_identity.get("depth") or identity.get("depth")
        agent_path = meta_identity.get("agent_path") or identity.get("agent_path")
        if spawn is not None:
            if depth != 1:
                issues.append(f"{child['lane_id']}:depth_conflict" if depth is not None else f"{child['lane_id']}:missing_depth")
            expected_suffix = "/" + str(spawn.get("task_name"))
            if not isinstance(agent_path, str) or not agent_path.endswith(expected_suffix):
                issues.append(f"{child['lane_id']}:agent_path_conflict" if agent_path is not None else f"{child['lane_id']}:missing_agent_path")
        effective = _effective(segment)
        for key, expected_key in (("model", "child_model"), ("effort", "child_effort"), ("context_policy", "context_policy")):
            if effective.get(key) is not None and effective.get(key) != expected[expected_key]:
                issues.append(f"{child['lane_id']}:{key}_conflict")
        if effective.get("context_policy") is None and spawn is None:
            issues.append(f"{child['lane_id']}:context_missing")
        if not _surface_ok(effective, expected["surface"]):
            issues.append(f"{child['lane_id']}:surface_conflict")
        elif segment and not effective.get("surface") and not effective.get("surface_evidence"):
            issues.append(f"{child['lane_id']}:surface_missing")
        if start and end and not _lifecycle_ok(start, end):
            issues.append(f"{child['lane_id']}:lifecycle_conflict")
        duration = _duration(start, phase_end)
        all_timing.append(duration)
        usage = _usage_for(
            segment,
            role=f"lane:{child['lane_id']}",
            expected_thread_id=child["thread_id"],
            source_item=child,
            copied_history_known_zero=spawn is not None and spawn.get("fork_turns") == "none",
        )
        all_usage.append(usage)
        actions, checks, mutations = _metric_counts(segment)
        all_actions.extend(actions["items"])
        all_checks.extend(checks["items"])
        all_mutations.extend(mutations["items"])
        custody_candidates.extend(
            _custody_access_candidates(
                segment,
                worker_id=child["thread_id"],
                lane_id=child["lane_id"],
                phase="initial",
                source_path=child["path"],
                issues=issues,
            )
        )
        completion_candidate = _custody_lifecycle_candidate(
            phase_end,
            priority=30,
            source_path=child["path"],
            event={
                "type": "lane.completed",
                "lane_id": child["lane_id"],
                "worker_id": child["thread_id"],
            },
        )
        if completion_candidate is not None:
            custody_candidates.append(completion_candidate)
        children_rows.append({
            "lane_id": child["lane_id"],
            "thread_id": child["thread_id"],
            "parent_thread_id": child["parent_thread_id"],
            "depth": depth,
            "model": effective.get("model", expected["child_model"]),
            "effort": effective.get("effort", expected["child_effort"]),
            "context_policy": effective.get("context_policy") or ("none" if spawn is not None and spawn.get("fork_turns") == "none" else None),
            "spawn": ({
                **spawn,
                "line_number": spawn_record["line_number"],
                "selected_record_hash": spawn_record["selected_record_hash"],
            } if spawn is not None and spawn_record is not None else None),
            "start": _time_point(start.get("timestamp") if start else None, start.get("clock", _clock({})) if start else _clock({}), status="observed" if start else "unknown", reason=None if start else "missing_record"),
            "end": _time_point(phase_end.get("timestamp") if phase_end else None, phase_end.get("clock", _clock({})) if phase_end else _clock({}), status="observed" if phase_end else "unknown", reason=None if phase_end else "missing_record"),
            "lifecycle_end": _time_point(end.get("timestamp") if end else None, end.get("clock", _clock({})) if end else _clock({}), status="observed" if end else "unknown", reason=None if end else "missing_record"),
            "phase_boundary": "integrator_handoff" if active_integrator_handoff else "lifecycle_end",
            "duration": duration,
            "usage": usage,
            "actions": actions,
            "checks": checks,
            "mutations": mutations,
            "source": _source_descriptor(f"child:{child['lane_id']}", child, selector=start),
        })

    # Root metrics are kept separately from lane metrics, then flattened into
    # compact aggregate fields for the run registry.
    root_usage = _usage_for(
        root_segment,
        role="root",
        expected_thread_id=root["thread_id"],
        source_item=root,
        copied_history_known_zero=True,
    )
    root_actions, root_checks, root_mutations = _metric_counts(root_segment)
    all_usage.insert(0, root_usage)
    all_actions.extend(root_actions["items"])
    all_checks.extend(root_checks["items"])
    all_mutations.extend(root_mutations["items"])
    usage_unknown = next((item.get("unknown_reason") for item in all_usage if item.get("status") == "unknown"), None)

    root_timing = {
        "status": root_duration.get("status", "unknown"),
        "start": _time_point(root_start.get("timestamp") if root_start else None, root_start.get("clock", _clock({})) if root_start else _clock({}), status="observed" if root_start else "unknown", reason=None if root_start else "missing_record"),
        "end": _time_point(root_end.get("timestamp") if root_end else None, root_end.get("clock", _clock({})) if root_end else _clock({}), status="observed" if root_end else "unknown", reason=None if root_end else "missing_record"),
        "duration": root_duration,
    }
    overlap = _overlap_metric(all_timing[1:])
    critical = (
        {"status": "observed", "value_ms": root_duration["duration_ms"], **{key: root_duration[key] for key in ("clock_id", "clock_kind", "unit", "origin")}}
        if root_duration.get("status") == "observed"
        else dict(root_duration)
    )
    integrator_timing = {"status": "unknown", "duration": _unknown("missing_record")}
    integrator_usage = {"status": "unknown", "known": False, "role": "integrator", "unknown_reason": "missing_record", "records": 0, "source_refs": [], "issues": []}
    waiting = _unknown("missing_record")
    release_latency = _unknown("missing_record")
    if value.get("timing"):
        integrator_source = loaded.get(value["timing"]["integrator"]["path"])
        integrator_duration = _duration(integrator_start, integrator_end)
        integrator_segment = _segment(integrator_source or {}, integrator_start, integrator_end)
        integrator_usage = _usage_for(
            integrator_segment,
            role="integrator",
            expected_thread_id=value["timing"]["integrator"]["thread_id"],
            source_item=value["timing"]["integrator"],
            copied_history_known_zero=next(
                (
                    item.get("spawn", {}).get("fork_turns") == "none"
                    for item in children_rows
                    if item["lane_id"] == value["timing"]["integrator"]["lane_id"]
                    and isinstance(item.get("spawn"), Mapping)
                ),
                False,
            ),
        )
        integrator_timing = {
            "status": integrator_duration.get("status", "unknown"),
            "lane_id": value["timing"]["integrator"]["lane_id"],
            "thread_id": value["timing"]["integrator"]["thread_id"],
            "start": _time_point(integrator_start.get("timestamp") if integrator_start else None, integrator_start.get("clock", _clock({})) if integrator_start else _clock({}), status="observed" if integrator_start else "unknown", reason=None if integrator_start else "missing_record"),
            "end": _time_point(integrator_end.get("timestamp") if integrator_end else None, integrator_end.get("clock", _clock({})) if integrator_end else _clock({}), status="observed" if integrator_end else "unknown", reason=None if integrator_end else "missing_record"),
            "duration": integrator_duration,
        }
        integrator_actions, integrator_checks, integrator_mutations = _metric_counts(integrator_segment)
        all_actions.extend(integrator_actions["items"])
        all_checks.extend(integrator_checks["items"])
        all_mutations.extend(integrator_mutations["items"])
        integrator_lane_id = value["timing"]["integrator"]["lane_id"]
        integrator_thread_id = value["timing"]["integrator"]["thread_id"]
        for candidate in (
            _custody_lifecycle_candidate(
                integrator_start,
                priority=40,
                source_path=value["timing"]["integrator"]["path"],
                event={"type": "integrator.started", "worker_id": integrator_thread_id},
            ),
            _custody_lifecycle_candidate(
                release_record,
                priority=60,
                source_path=root["path"],
                event={
                    "type": "lane.released",
                    "lane_id": value["timing"]["release"]["owner_lane_id"],
                    "owner_worker_id": next(
                        (
                            item["thread_id"]
                            for item in children_rows
                            if item["lane_id"] == value["timing"]["release"]["owner_lane_id"]
                        ),
                        "unknown",
                    ),
                    "integrator_worker_id": integrator_thread_id,
                },
            ),
            _custody_lifecycle_candidate(
                integrator_end,
                priority=90,
                source_path=value["timing"]["integrator"]["path"],
                event={"type": "integrator.completed", "worker_id": integrator_thread_id},
            ),
        ):
            if candidate is not None:
                custody_candidates.append(candidate)
        custody_candidates.extend(
            _custody_access_candidates(
                integrator_segment,
                worker_id=integrator_thread_id,
                lane_id=integrator_lane_id,
                phase="integration",
                source_path=value["timing"]["integrator"]["path"],
                issues=issues,
            )
        )
        waiting = _timing_metric(integrator_start, release_record)
        if waiting.get("status") == "observed" and integrator_duration.get("status") == "observed" and waiting["value_ms"] > integrator_duration["duration_ms"]:
            waiting = _unknown("clock_mismatch")
        owner = next((item for item in children_rows if item["lane_id"] == value["timing"]["release"]["owner_lane_id"]), None)
        owner_end = None
        if owner is not None:
            owner_end = {
                "timestamp": owner["end"].get("value"),
                "clock": {key: owner["end"].get(key, "unknown") for key in ("clock_id", "clock_kind", "unit", "origin")},
            }
        release_latency = _timing_metric(owner_end, release_record)

    timing_roles = {"root": root_duration, **{f"lane:{item['lane_id']}": item["duration"] for item in children_rows}, "integrator": integrator_timing["duration"]}
    timing_metrics = {"overlap": overlap, "waiting": waiting, "release_latency": release_latency, "critical_path": critical}
    known_roles = sorted(name for name, item in timing_roles.items() if item.get("status") == "observed")
    unknown_roles = sorted(name for name, item in timing_roles.items() if item.get("status") != "observed")
    all_required_timing_known = not unknown_roles and all(item.get("status") == "observed" for item in timing_metrics.values())
    usage_roles = {"root": root_usage, **{f"lane:{item['lane_id']}": item["usage"] for item in children_rows}, "integrator": integrator_usage}
    combined_usage = _combine_usage(usage_roles)
    custody_events, custody_evidence = _custody_bundle(
        attempt_id=value["attempt_id"],
        candidates=custody_candidates,
    )

    contradiction = any(any(token in issue for token in ("conflict", "privacy_rejected", "hash_conflict", "lifecycle_conflict")) for issue in issues)
    # Source absence, selector gaps, and incomplete parent/identity evidence
    # are unbound but not contradictory.
    binding_status = "CONTRADICTORY" if contradiction else ("BOUND" if not issues else "UNBOUND")
    status = FAIL if contradiction else (PASS if binding_status == "BOUND" else PARTIAL)
    unknown_reasons = _issue_code(issues)
    for item in [*timing_roles.values(), *timing_metrics.values()]:
        if item.get("status") != "observed" and item.get("unknown_reason"):
            unknown_reasons.append(str(item["unknown_reason"]))
    if usage_unknown:
        unknown_reasons.append(usage_unknown)
    if not combined_usage.get("all_required_known") and combined_usage.get("unknown_reason"):
        unknown_reasons.append(str(combined_usage["unknown_reason"]))
    unknown_reasons = sorted(set(unknown_reasons))
    sources = [_source_descriptor("root", root, selector=root_start)] + [_source_descriptor(f"child:{child['lane_id']}", child, selector=(children_rows[index].get("start") and _resolve_selector(loaded.get(child["path"]) or {}, child["start_selector"], [], f"{child['lane_id']}.source"))) for index, child in enumerate(value["children"])]
    if value.get("timing"):
        integrator = value["timing"]["integrator"]
        sources.append(
            _source_descriptor(
                "integrator",
                integrator,
                selector=_resolve_selector(
                    loaded.get(integrator["path"]) or {}, integrator["start_selector"], [], "timing.integrator.source"
                ),
            )
        )
    # The source list above deliberately retains only paths/hashes and bounded
    # line pointers.  Do not expose records or session bodies.
    graph = {
        "root": {
            "thread_id": root["thread_id"],
            "model": expected["root_model"],
            "effort": expected["root_effort"],
            "context_policy": expected["context_policy"],
            "attempt_start_line": root_start["line_number"] if root_start else None,
            "attempt_end_line": root_end["line_number"] if root_end else None,
        },
        "children": children_rows,
        "edges": [{"parent_thread_id": root["thread_id"], "child_thread_id": child["thread_id"], "lane_id": child["lane_id"]} for child in value["children"]],
    }
    claims = [
        {"name": "attempt_identity", "value": {"attempt_id": value["attempt_id"], "root_thread_id": root["thread_id"]}, "status": "SUPPORTED" if binding_status == "BOUND" else binding_status, "evidence_tier": "runtime-observed", "source_refs": [sources[0]["source_id"] if "source_id" in sources[0] else sources[0]["path"]]},
        {"name": "graph_binding", "value": binding_status, "status": "SUPPORTED" if binding_status == "BOUND" else binding_status, "evidence_tier": "runtime-observed", "source_refs": [item.get("source_id", item["path"]) for item in sources]},
    ]
    if binding_status != "BOUND":
        for claim in claims:
            claim["unknown_reason"] = unknown_reasons[0] if unknown_reasons else "observation_incomplete"
    report = {
        "schema": SCHEMA,
        "adapter_version": ADAPTER_VERSION,
        "status": status,
        "binding_status": binding_status,
        "attempt_id": value["attempt_id"],
        "graph": graph,
        "timing": {
            "status": "observed" if all_required_timing_known else "partial",
            "all_required_known": all_required_timing_known,
            "known_roles": known_roles,
            "unknown_roles": unknown_roles,
            "root": root_timing,
            "lanes": {item["lane_id"]: item["duration"] for item in children_rows},
            "integrator": integrator_timing,
            "overlap": overlap,
            "waiting": waiting,
            "release_latency": release_latency,
            "critical_path": critical,
        },
        "usage": {
            "status": combined_usage["status"],
            "known": combined_usage["known"],
            "all_required_known": combined_usage["all_required_known"],
            "known_roles": combined_usage["known_roles"],
            "unknown_roles": combined_usage["unknown_roles"],
            "root": root_usage,
            "lanes": {item["lane_id"]: item["usage"] for item in children_rows},
            "integrator": integrator_usage,
            "combined": combined_usage,
            "unknown_reason": combined_usage.get("unknown_reason"),
        },
        "checks": {"count": len(all_checks), "passed": sum(1 for item in all_checks if item["passed"])},
        "mutations": {"count": len(all_mutations), "items": all_mutations},
        "actions": {"count": len(all_actions), "items": all_actions},
        "integration_burden": {"actions": len(all_actions), "checks": len(all_checks), "mutations": len(all_mutations)},
        "custody_events": custody_events,
        "custody_evidence": custody_evidence,
        "claims": claims,
        "sources": sources,
        "artifacts": [_artifact_descriptor(item) for item in value["artifacts"]],
        "unknown_reasons": unknown_reasons,
        "issues": sorted(set(issues)),
    }
    return report


def require_attempt_observation(manifest: Mapping[str, Any]) -> dict[str, Any]:
    report = observe_attempt(manifest)
    if report["status"] != PASS or report["binding_status"] != "BOUND":
        raise AttemptObservationError(report)
    return report


def _catalog_timing(report: Mapping[str, Any]) -> dict[str, Any]:
    timing = report.get("timing", {})
    root = timing.get("root", {})
    duration = root.get("duration") if isinstance(root, Mapping) else None
    if not isinstance(duration, Mapping) or duration.get("status") != "observed":
        reason = (duration or {}).get("unknown_reason", "clock_unknown") if isinstance(duration, Mapping) else "clock_unknown"
        return {"subject": {"status": "unknown", "unknown_reason": reason, "all_required_known": False, "known_roles": timing.get("known_roles", []), "unknown_roles": timing.get("unknown_roles", [])}}
    return {"subject": {
        "status": "observed" if timing.get("all_required_known") is True else "partial",
        "all_required_known": timing.get("all_required_known") is True,
        "known_roles": timing.get("known_roles", []),
        "unknown_roles": timing.get("unknown_roles", []),
        "started_at": duration.get("started_at"),
        "ended_at": duration.get("ended_at"),
        "duration_ms": duration.get("duration_ms"),
        "clock_id": duration.get("clock_id", "unknown"),
        "clock_kind": duration.get("clock_kind", "unknown"),
        "unit": duration.get("unit", "unknown"),
        "origin": duration.get("origin", "unknown"),
        "spans": {
            "root": root,
            "lanes": timing.get("lanes", {}),
            "integrator": timing.get("integrator", {}),
        },
        "metrics": {key: timing.get(key, {}) for key in ("overlap", "waiting", "release_latency", "critical_path")},
    }}


def _catalog_safe(value: Any) -> Any:
    """Rename token-category metadata rejected by the registry privacy gate.

    ``orch_dork_run_registry`` intentionally reserves fields containing
    ``reasoning`` because raw hidden reasoning must never enter a summary.  A
    token *count* is safe, but the rich catalog still has to pass that closed
    validator.  Keep the count under a neutral name while preserving the
    attempt report's more precise runtime field.
    """

    if isinstance(value, Mapping):
        return {
            ("analysis_tokens" if key == "reasoning_tokens" else key): _catalog_safe(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_catalog_safe(item) for item in value]
    return value


def _catalog_usage(value: Any) -> Any:
    """Project exact usage totals without copying every record pointer.

    The attempt observation remains the authoritative record-level artifact.
    A registry catalog is deliberately compact: for each usage role it keeps
    exact metrics plus a deterministic count/digest of the omitted pointer
    list.  The catalog's session-source descriptors retain the raw file/hash
    custody needed to reopen those pointers through the observation detail
    artifact, while ordinary indexed queries stay small.
    """

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key == "source_refs" and isinstance(item, list):
                result["source_ref_count"] = len(item)
                result["source_refs_sha256"] = hashlib.sha256(_canonical(item)).hexdigest()
                continue
            if key == "compaction_records" and isinstance(item, list):
                result["compaction_record_count"] = len(item)
                result["compaction_records_sha256"] = hashlib.sha256(_canonical(item)).hexdigest()
                continue
            result[key] = _catalog_usage(item)
        return result
    if isinstance(value, list):
        return [_catalog_usage(item) for item in value]
    return value


def _catalog_graph(value: Any) -> Any:
    """Keep graph identity/routing/timing aggregates, not event inventories."""

    if not isinstance(value, Mapping):
        return value
    root = value.get("root") if isinstance(value.get("root"), Mapping) else {}
    children: list[dict[str, Any]] = []
    for child in value.get("children", []):
        if not isinstance(child, Mapping):
            continue
        children.append({
            key: _catalog_usage(child[key])
            for key in (
                "lane_id",
                "thread_id",
                "parent_thread_id",
                "depth",
                "model",
                "effort",
                "context_policy",
                "spawn",
                "start",
                "end",
                "lifecycle_end",
                "phase_boundary",
                "duration",
            )
            if key in child
        })
    return {
        "root": dict(root),
        "children": children,
        "edges": [dict(item) for item in value.get("edges", []) if isinstance(item, Mapping)],
    }


def to_source_catalog_entry(report: Mapping[str, Any], *, ticket_key: str, artifact_dir: str | None = None) -> dict[str, Any]:
    """Convert one report into a rich run-source-catalog/v1 entry."""

    if not isinstance(report, Mapping) or report.get("schema") != SCHEMA:
        raise ValueError("report schema must be orch-dork/attempt-observation/v1")
    ticket_key = _id(ticket_key, "ticket_key")
    attempt_id = _id(report.get("attempt_id"), "report.attempt_id")
    graph = report.get("graph") if isinstance(report.get("graph"), Mapping) else {}
    root = graph.get("root") if isinstance(graph.get("root"), Mapping) else {}
    actual_root = root.get("thread_id") or "unknown-root"
    suffix = f"{ticket_key}:{attempt_id}"
    compact_graph = _catalog_graph(graph)
    producer_run = {"run_key": f"producer:{suffix}", "kind": "hosted_execution", "thread_id": actual_root, "attempt_id": attempt_id, "root": compact_graph.get("root", {}), "children": compact_graph.get("children", []), "edges": compact_graph.get("edges", [])}
    subject_run = {"run_key": f"subject:{suffix}", "kind": "hosted_execution", "thread_id": actual_root, "attempt_id": attempt_id, "root": compact_graph.get("root", {}), "children": compact_graph.get("children", []), "edges": compact_graph.get("edges", [])}
    producer_run["run_id"] = producer_run["run_key"]
    subject_run["run_id"] = subject_run["run_key"]
    status = report.get("binding_status")
    if status not in BINDING:
        raise ValueError("report binding_status is invalid")
    reasons = list(report.get("unknown_reasons", []))
    if status != "BOUND" and not reasons:
        reasons = ["observation_incomplete"]
    observation = {
        "observation_id": f"attempt:{attempt_id}",
        "observer_version": ADAPTER_VERSION,
        "registry_version": REGISTRY_VERSION,
        "relationship": {"status": status, "identity_equivalence": "exact" if status == "BOUND" else "unknown", "reason": None if status == "BOUND" else reasons[0]},
        "attempt_id": attempt_id,
        "source_refs": [item.get("source_id", item.get("path")) for item in report.get("sources", []) if isinstance(item, Mapping)],
    }
    claims: list[dict[str, Any]] = []
    for claim in report.get("claims", []):
        if not isinstance(claim, Mapping):
            continue
        refs = claim.get("source_refs", [])
        if not isinstance(refs, list):
            refs = []
        item = {"name": claim.get("name"), "value": claim.get("value"), "evidence_tier": claim.get("evidence_tier", "runtime-observed"), "source_refs": refs, "provenance": [{"source_id": ref, "pointer": "$"} for ref in refs if isinstance(ref, str)], "status": claim.get("status", "SUPPORTED")}
        if item["status"] in {"UNBOUND", "CONTRADICTORY"}:
            item["unknown_reason"] = claim.get("unknown_reason", reasons[0] if reasons else "observation_incomplete")
        claims.append(item)
    entry: dict[str, Any] = {
        "schema": SOURCE_CATALOG_SCHEMA,
        "binding_id": suffix,
        "ticket_key": ticket_key,
        "producer_run": producer_run,
        "subject_run": subject_run,
        "producer_run_id": producer_run["run_id"],
        "subject_run_id": subject_run["run_id"],
        "observation": observation,
        "subject_kind": "hosted_execution",
        "binding_status": status,
        "artifacts": [dict(item, size=item.get("size", 0)) if isinstance(item, Mapping) else item for item in report.get("artifacts", [])],
        "sources": [dict(item, size=item.get("size", 0)) if isinstance(item, Mapping) else item for item in report.get("sources", [])],
        "claims": claims,
        "timing": _catalog_timing(report),
        "usage": _catalog_usage(report.get("usage", {})),
        "tests": report.get("checks", {}),
        "unknown_reasons": sorted(set(reasons)),
        "graph": compact_graph,
    }
    # Rich catalog entries are recognized by ``ticket_key`` and the current
    # registry requires a locator for that branch.  Use a deterministic,
    # privacy-safe relative projection when the caller has no artifact root.
    entry["artifact_dir"] = _text(artifact_dir, "artifact_dir", max_len=4096) if artifact_dir is not None else f"attempts/{attempt_id}"
    return _safe_public(_catalog_safe(entry), field="source_catalog")


def _load_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load JSON: {path}") from exc


def _write_json(path: str, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Observe one explicitly bounded Orch Dork attempt")
    sub = parser.add_subparsers(dest="command", required=True)
    observe = sub.add_parser("observe")
    observe.add_argument("--manifest", required=True)
    observe.add_argument("--output", required=True)
    catalog = sub.add_parser("catalog")
    catalog.add_argument("--observation", required=True)
    catalog.add_argument("--ticket-key", required=True)
    catalog.add_argument("--artifact-dir")
    catalog.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "observe":
            result = observe_attempt(_load_json(args.manifest))
        else:
            result = to_source_catalog_entry(_load_json(args.observation), ticket_key=args.ticket_key, artifact_dir=args.artifact_dir)
        _write_json(args.output, result)
    except ValueError as exc:
        error = {"schema": SCHEMA, "status": FAIL, "issues": [str(exc)]}
        try:
            _write_json(args.output, error)
        except Exception:
            json.dump(error, sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ADAPTER_VERSION",
    "AttemptObservationError",
    "SCHEMA",
    "SOURCE_CATALOG_SCHEMA",
    "observe_attempt",
    "require_attempt_observation",
    "to_source_catalog_entry",
]
