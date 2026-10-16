#!/usr/bin/env python3
"""Runtime routing verifier for Orch Dork waves (north star P3 runtime side).

Every plan validator in the Orch Dork suite checks what a wave plan
DECLARES. Nothing up to this point checks what the spawned sessions
actually RAN. This module closes that gap: it reads the real Codex
rollout JSONL files that sessions leave behind at
the host session store (rollout JSONL files under the Codex home,
always supplied by the caller as an explicit path) and verifies the
observed model/effort against the frozen plan's declared routing.

The report produced here is the runtime-side complement of the frozen
plan: the plan hash attests what was DECLARED, this report attests what
was OBSERVED. Both must agree for a wave to be trusted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping


WAVE_ROUTING_PROGRAM_SCHEMA = "orch-dork/wave-routing-program/v1"
WAVE_ROUTING_PROGRAM_SCHEMA_V2 = "orch-dork/wave-routing-program/v2"
WAVE_ROUTING_PROGRAM_SCHEMA_V3 = "orch-dork/wave-routing-program/v3"
SESSION_ROUTING_REPORT_SCHEMA = "orch-dork/session-routing/v1"
SESSION_RUNTIME_OBSERVATION_SCHEMA = "orch-dork/session-runtime-observation/v1"
WAVE_ROUTING_REPORT_SCHEMA = "orch-dork/wave-routing-report/v1"
TERMINAL_ABSENCE_STABILITY_SCHEMA = "orch-dork/terminal-absence-stability/v1"

TERMINAL_ABSENCE_GRACE_FLOOR_MS = 5_000

STABLE_ABSENCE = "STABLE_ABSENCE"
UNSTABLE_ABSENCE = "UNSTABLE_ABSENCE"
TERMINAL_APPEARED = "TERMINAL_APPEARED"

MAX_JSON_RECORD_DEPTH = 32
MAX_JSON_RECORD_NODES = 100_000
MAX_JSON_RECORD_BYTES = 16 * 1024 * 1024
MAX_JSON_SCALAR_CHARS = 16 * 1024 * 1024
MAX_ROLLOUT_BYTES = 128 * 1024 * 1024
MAX_ROLLOUT_RECORDS = 20_000
MAX_ROLLOUT_JSON_NODES = 1_000_000

LANE_ROLES = ("worker", "root")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

# Issue 118 (C5): the closed observation-issue vocabulary for
# observe_session_runtime.  Every issue that function can emit is listed
# here; the seeded store-state corpus asserts membership so a new issue
# string cannot appear without a deliberate vocabulary change.
OBSERVATION_ISSUE_VOCABULARY = frozenset(
    {
        "runtime:file_unreadable",
        "runtime:unparseable_records",
        "runtime:session_id_mismatch",
        "observer:invalid",
        "observer:not_independent",
        "routing:no_turn_context",
        "terminal:json_missing",
        "terminal:not_closed_json_object",
        "terminal:schema_missing",
        "terminal:conflicting_records",
        "usage:exact_record_missing",
        "usage:exact_record_invalid",
    }
)


def _canonical(value: Any) -> bytes:
    _validate_bounded_json(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _bounded_utf8_size(value: str) -> int:
    if len(value) > MAX_JSON_SCALAR_CHARS:
        raise ValueError("json scalar bound exceeded")
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise ValueError("invalid unicode scalar") from error


def _validate_bounded_json(value: Any) -> int:
    """Reject cyclic, nonfinite, or excessively large JSON values."""

    stack = [(value, 0)]
    seen_containers: set[int] = set()
    nodes = 0
    scalar_chars = 0
    while stack:
        child, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_RECORD_NODES or depth > MAX_JSON_RECORD_DEPTH:
            raise ValueError("json record bound exceeded")
        if isinstance(child, dict):
            identity = id(child)
            if identity in seen_containers or any(
                    type(key) is not str for key in child):
                raise ValueError("invalid json object")
            seen_containers.add(identity)
            for key in child:
                scalar_chars += _bounded_utf8_size(key)
                if scalar_chars > MAX_JSON_SCALAR_CHARS:
                    raise ValueError("json scalar bound exceeded")
            children = child.values()
            child_count = len(child)
            if nodes + len(stack) + child_count > MAX_JSON_RECORD_NODES:
                raise ValueError("json record bound exceeded")
            stack.extend((item, depth + 1) for item in children)
        elif isinstance(child, (list, tuple)):
            identity = id(child)
            if identity in seen_containers:
                raise ValueError("cyclic json value")
            seen_containers.add(identity)
            child_count = len(child)
            if nodes + len(stack) + child_count > MAX_JSON_RECORD_NODES:
                raise ValueError("json record bound exceeded")
            stack.extend((item, depth + 1) for item in child)
        elif isinstance(child, float) and not math.isfinite(child):
            raise ValueError("non-finite json number")
        elif type(child) is str:
            scalar_chars += _bounded_utf8_size(child)
        elif type(child) is int:
            if child.bit_length() > MAX_JSON_SCALAR_CHARS * 4:
                raise ValueError("json scalar bound exceeded")
            scalar_chars += len(str(child))
        elif child is not None and not isinstance(
                child, (float, bool)):
            raise ValueError("non-json value")
        if scalar_chars > MAX_JSON_SCALAR_CHARS:
            raise ValueError("json scalar bound exceeded")
    return nodes


def _parse_bounded_json(raw: str | bytes, *,
                        limit: int = MAX_JSON_RECORD_BYTES,
                        return_nodes: bool = False) -> Any:
    """Parse one byte-bounded JSON value with unique object keys."""

    if type(raw) is str:
        if len(raw) > limit:
            raise ValueError("json record byte bound exceeded")
        encoded = raw.encode("utf-8")
    elif type(raw) is bytes:
        encoded = raw
    else:
        raise ValueError("json source type invalid")
    if len(encoded) > limit:
        raise ValueError("json record byte bound exceeded")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate json key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("non-finite json number")

    value = json.loads(
        encoded, object_pairs_hook=unique, parse_constant=reject_constant)
    nodes = _validate_bounded_json(value)
    return (value, nodes) if return_nodes else value


def _read_bounded_bytes(path: str, limit: int) -> bytes:
    """Read at most ``limit`` bytes from one caller-selected regular path."""

    flags = os.O_RDONLY | os.O_NONBLOCK
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("regular file required")
        remaining = limit + 1
        chunks = []
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        source = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(source) > limit:
        raise ValueError("file byte bound exceeded")
    return source


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, fields: set[str], path: str, issues: list[str]) -> bool:
    """Reject unknown keys and report missing ones, mirroring repo state."""

    if not isinstance(value, Mapping):
        _issue(issues, f"{path}:not_object")
        return False
    for key in sorted(fields - set(value)):
        _issue(issues, f"{path}:missing:{key}")
    for key in sorted(set(value) - fields):
        _issue(issues, f"{path}:unknown:{key}")
    return set(value) == fields


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _safe_nonempty_json_string(value: Any) -> str | None:
    if type(value) is not str or not value.strip():
        return None
    try:
        _bounded_utf8_size(value)
    except ValueError:
        return None
    return value


def _render(value: Any) -> str:
    """Deterministic issue-string renderer: None becomes 'null'."""

    if value is None:
        return "null"
    return str(value)


def _report_footer(core: dict[str, Any]) -> dict[str, Any]:
    """Attach the provider-free attestation fields and the sealed report sha."""

    attested = {
        **core,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "evidence_tier": "submitted",
    }
    return {**attested, "report_sha256": _sha256(attested)}


def _reasoning_effort(payload: Mapping[str, Any]) -> str | None:
    """Pull collaboration_mode.settings.reasoning_effort, tolerantly."""

    collaboration = payload.get("collaboration_mode")
    if not isinstance(collaboration, Mapping):
        return None
    settings = collaboration.get("settings")
    if not isinstance(settings, Mapping):
        return None
    value = settings.get("reasoning_effort")
    if isinstance(value, str) and value:
        return value
    return None


def _routing_core(
    issues: list[str],
    session_ids: list[str],
    own_session_id: str | None,
    inherited_history: bool,
    turn_contexts: list[dict[str, Any]],
    observed_model: str | None,
    observed_effort: str | None,
    skipped_lines: int,
) -> dict[str, Any]:
    status = "FAIL" if issues else "PASS"
    return {
        "schema": SESSION_ROUTING_REPORT_SCHEMA,
        "status": status,
        "issues": sorted(issues),
        "session_ids": session_ids,
        "own_session_id": own_session_id,
        "inherited_history": inherited_history,
        "turn_contexts": turn_contexts,
        "observed_model": observed_model,
        "observed_effort": observed_effort,
        "skipped_lines": skipped_lines,
    }


def extract_session_routing(path: str, session_id: str | None = None) -> dict[str, Any]:
    """Extract the authoritative routing from a single Codex rollout JSONL.

    A rollout spawned as a full-history fork carries two ``session_meta``
    records (its own id first, then the parent's) and the PARENT's
    ``turn_context`` before the child's own. A no-context spawn has exactly
    one ``session_meta`` and only its own ``turn_context``s. The
    authoritative routing is therefore the LAST ``turn_context`` in the
    file (the session's own most-recent context), and ``inherited_history``
    flags the foreign inherited context (more than one ``session_meta``).

    ``path`` is the caller-provided rollout location; this is the only
    filesystem access in the module. Unparseable JSONL lines are skipped
    and counted in ``skipped_lines``.
    """

    issues: list[str] = []
    try:
        text = _read_bounded_bytes(path, MAX_ROLLOUT_BYTES).decode(
            "utf-8", "strict")
    except (OSError, UnicodeDecodeError, ValueError):
        _issue(issues, "routing:file_unreadable")
        return _report_footer(
            _routing_core(
                issues, [], None, False, [], None, None, 0
            )
        )

    session_ids: list[str] = []
    turn_contexts: list[dict[str, Any]] = []
    skipped_lines = 0
    record_count = 0
    total_nodes = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        record_count += 1
        if record_count > MAX_ROLLOUT_RECORDS:
            skipped_lines += 1
            break
        try:
            record, nodes = _parse_bounded_json(
                line, return_nodes=True)
            total_nodes += nodes
            if total_nodes > MAX_ROLLOUT_JSON_NODES:
                raise ValueError("rollout json node bound exceeded")
        except (json.JSONDecodeError, RecursionError, ValueError):
            skipped_lines += 1
            if total_nodes > MAX_ROLLOUT_JSON_NODES:
                break
            continue
        if not isinstance(record, Mapping):
            skipped_lines += 1
            continue
        record_type = record.get("type")
        payload = record.get("payload")
        if not isinstance(payload, Mapping):
            skipped_lines += 1
            continue
        if record_type == "session_meta":
            sid = payload.get("id")
            if isinstance(sid, str) and sid:
                session_ids.append(sid)
        elif record_type == "turn_context":
            model = payload.get("model")
            turn_contexts.append(
                {
                    "model": model if isinstance(model, str) and model else None,
                    "effort": _reasoning_effort(payload),
                }
            )

    own_session_id = session_ids[0] if session_ids else None
    inherited_history = len(session_ids) > 1
    if turn_contexts:
        observed_model = turn_contexts[-1]["model"]
        observed_effort = turn_contexts[-1]["effort"]
    else:
        observed_model = None
        observed_effort = None
        _issue(issues, "routing:no_turn_context")
    if session_id is not None and own_session_id != session_id:
        _issue(issues, "routing:session_id_mismatch")

    return _report_footer(
        _routing_core(
            issues,
            session_ids,
            own_session_id,
            inherited_history,
            turn_contexts,
            observed_model,
            observed_effort,
            skipped_lines,
        )
    )


def _runtime_observation_footer(core: dict[str, Any]) -> dict[str, Any]:
    attested = {
        **core,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "evidence_tier": "runtime-observed",
    }
    return {**attested, "report_sha256": _sha256(attested)}


def observe_session_runtime(
    path: str,
    *,
    session_id: str,
    observer_id: str,
) -> dict[str, Any]:
    """Observe one closed rollout without retaining prompts or raw messages.

    The adapter binds the exact source bytes, authoritative route, final JSON
    terminal digest, and the final native cumulative token snapshot.  It
    returns only allow-listed facts and hashes.  A caller-supplied tier cannot
    create this receipt.
    """

    try:
        source = _read_bounded_bytes(path, MAX_ROLLOUT_BYTES)
    except (OSError, ValueError):
        source = None
    return build_session_runtime_observation(source, session_id=session_id, observer_id=observer_id)


def build_session_runtime_observation(
    source: bytes | None, *, session_id: str, observer_id: str,
) -> dict[str, Any]:
    """Project one already-read rollout prefix without reopening its path.

    The host reader owns custody. This pure transport constructor preserves
    the historical runtime observation schema and exact source-byte digest.
    """
    issues: list[str] = []
    source_sha256 = None
    skipped_lines = 0
    try:
        if type(source) is not bytes or len(source) > MAX_ROLLOUT_BYTES:
            raise ValueError("invalid bounded source")
        source_sha256 = hashlib.sha256(source).hexdigest()
        text = source.decode("utf-8", "strict")
    except (ValueError, UnicodeDecodeError):
        _issue(issues, "runtime:file_unreadable")
        text = ""

    session_ids: list[str] = []
    contexts: list[dict[str, str | None]] = []
    terminal_candidate: tuple[int, str, str, bytes] | None = None
    last_agent_candidate: tuple[int, str, str, bytes] | None = None
    preceding_agent_for_terminal: tuple[int, str, str, bytes] | None = None
    usage_snapshot: tuple[int, Mapping[str, Any], bytes] | None = None
    tool_calls = 0
    record_count = 0
    total_nodes = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        record_count += 1
        if record_count > MAX_ROLLOUT_RECORDS:
            skipped_lines += 1
            break
        try:
            record, nodes = _parse_bounded_json(
                stripped, return_nodes=True)
            total_nodes += nodes
            if total_nodes > MAX_ROLLOUT_JSON_NODES:
                raise ValueError("rollout json node bound exceeded")
            encoded = _canonical(record)
        except (json.JSONDecodeError, RecursionError, ValueError):
            skipped_lines += 1
            if total_nodes > MAX_ROLLOUT_JSON_NODES:
                break
            continue
        if not isinstance(record, Mapping):
            skipped_lines += 1
            continue
        payload = record.get("payload")
        if not isinstance(payload, Mapping):
            continue
        record_type = record.get("type")
        payload_type = payload.get("type")
        if record_type == "session_meta":
            value = payload.get("id")
            if isinstance(value, str) and value:
                session_ids.append(value)
        elif record_type == "turn_context":
            contexts.append(
                {
                    "model": payload.get("model")
                    if isinstance(payload.get("model"), str)
                    else None,
                    "effort": _reasoning_effort(payload),
                }
            )
        elif record_type == "event_msg" and payload_type == "agent_message":
            message = payload.get("message")
            if isinstance(message, str) and message.strip():
                terminal_candidate = (
                    line_number, str(payload_type), message, encoded)
                last_agent_candidate = terminal_candidate
                preceding_agent_for_terminal = None
        elif record_type == "event_msg" and payload_type == "task_complete":
            message = payload.get("last_agent_message")
            if isinstance(message, str) and message.strip():
                terminal_candidate = (
                    line_number, str(payload_type), message, encoded)
                preceding_agent_for_terminal = last_agent_candidate
        elif record_type == "event_msg" and payload_type == "token_count":
            info = payload.get("info")
            total = (
                info.get("total_token_usage")
                if isinstance(info, Mapping)
                else None
            )
            if isinstance(total, Mapping):
                usage_snapshot = (line_number, total, encoded)
        if (
            record_type == "event_msg"
            and payload_type
            in {
                "function_call",
                "mcp_tool_call_begin",
                "dynamic_tool_call_begin",
                "web_search_begin",
            }
        ) or (
            record_type == "response_item"
            and payload_type
            in {
                "function_call",
                "custom_tool_call",
                "mcp_tool_call",
                "local_shell_call",
                "web_search_call",
            }
        ):
            tool_calls += 1
    if skipped_lines:
        _issue(issues, "runtime:unparseable_records")

    own_session_id = session_ids[0] if session_ids else None
    valid_session_id = _safe_nonempty_json_string(session_id)
    valid_observer_id = _safe_nonempty_json_string(observer_id)
    if own_session_id != valid_session_id:
        _issue(issues, "runtime:session_id_mismatch")
    if valid_observer_id is None:
        _issue(issues, "observer:invalid")
    elif valid_observer_id == valid_session_id:
        _issue(issues, "observer:not_independent")
    if not contexts:
        _issue(issues, "routing:no_turn_context")
    route = {
        "session_id": own_session_id,
        "model": contexts[-1]["model"] if contexts else None,
        "effort": contexts[-1]["effort"] if contexts else None,
        "context_policy": "none" if len(session_ids) == 1 else "inherited",
        "inherited_history": len(session_ids) > 1,
    }

    terminal_json_sha256 = None
    terminal_schema = None
    terminal_record_sha256 = None
    terminal_line = None
    if terminal_candidate is None:
        _issue(issues, "terminal:json_missing")
    else:
        terminal_line, terminal_type, terminal_text, terminal_record = (
            terminal_candidate
        )
        try:
            terminal = _parse_bounded_json(terminal_text)
        except (json.JSONDecodeError, RecursionError, ValueError):
            terminal = None
        if not isinstance(terminal, Mapping):
            _issue(issues, "terminal:not_closed_json_object")
        else:
            terminal_json_sha256 = _sha256(terminal)
            terminal_schema = terminal.get("schema")
            if not isinstance(terminal_schema, str) or not terminal_schema:
                _issue(issues, "terminal:schema_missing")
        terminal_record_sha256 = hashlib.sha256(terminal_record).hexdigest()
        if terminal_type == "task_complete":
            preceding = preceding_agent_for_terminal
            if preceding is not None:
                try:
                    preceding_json = _parse_bounded_json(preceding[2])
                except (json.JSONDecodeError, RecursionError, ValueError):
                    preceding_json = None
                if isinstance(preceding_json, Mapping) and preceding_json != terminal:
                    _issue(issues, "terminal:conflicting_records")

    usage: dict[str, Any]
    usage_record_sha256 = None
    usage_line = None
    if usage_snapshot is None:
        _issue(issues, "usage:exact_record_missing")
        usage = {
            "status": "unknown",
            "input_tokens": None,
            "cached_input_tokens": None,
            "output_tokens": None,
            "reasoning_tokens": None,
            "total_tokens": None,
            "tool_calls": None,
        }
    else:
        usage_line, total, usage_record = usage_snapshot
        values = {
            "input_tokens": total.get("input_tokens"),
            "cached_input_tokens": total.get("cached_input_tokens"),
            "output_tokens": total.get("output_tokens"),
            "reasoning_tokens": total.get("reasoning_output_tokens"),
            "total_tokens": total.get("total_tokens"),
        }
        if (
            any(type(value) is not int or value < 0 for value in values.values())
            or values["cached_input_tokens"] > values["input_tokens"]
            or values["reasoning_tokens"] > values["output_tokens"]
            or values["total_tokens"]
            != values["input_tokens"] + values["output_tokens"]
        ):
            _issue(issues, "usage:exact_record_invalid")
            usage = {
                "status": "unknown",
                **{field: None for field in values},
                "tool_calls": None,
            }
        else:
            usage = {"status": "observed", **values, "tool_calls": tool_calls}
        usage_record_sha256 = hashlib.sha256(usage_record).hexdigest()

    core = {
        "schema": SESSION_RUNTIME_OBSERVATION_SCHEMA,
        "status": "FAIL" if issues else "PASS",
        "issues": sorted(issues),
        "observer_id": valid_observer_id,
        "source_pointer": (
            f"session://{valid_session_id}"
            if valid_session_id is not None else None),
        "source_sha256": source_sha256,
        "route": route,
        "terminal_schema": terminal_schema,
        "terminal_json_sha256": terminal_json_sha256,
        "terminal_record": {
            "line": terminal_line,
            "sha256": terminal_record_sha256,
        },
        "usage": usage,
        "usage_record": {
            "line": usage_line,
            "sha256": usage_record_sha256,
        },
        "skipped_lines": skipped_lines,
    }
    return _runtime_observation_footer(core)


def _valid_routing_report(report: Any) -> bool:
    return (
        isinstance(report, Mapping)
        and report.get("schema") == SESSION_ROUTING_REPORT_SCHEMA
        and report.get("status") == "PASS"
    )


def _stability_sample(
    value: Any, label: str, issues: list[str]
) -> Mapping[str, Any]:
    """Validate one sealed runtime observation used as a stability sample."""

    try:
        _validate_bounded_json(value)
    except (RecursionError, TypeError, ValueError):
        _issue(issues, f"stability.{label}:json_invalid")
        return {}
    if not isinstance(value, Mapping):
        _issue(issues, f"stability.{label}:type_invalid")
        return {}
    if value.get("schema") != SESSION_RUNTIME_OBSERVATION_SCHEMA:
        _issue(issues, f"stability.{label}:schema_invalid")
    sealed = dict(value)
    supplied = sealed.pop("report_sha256", None)
    if not isinstance(supplied, str) or supplied != _sha256(sealed):
        _issue(issues, f"stability.{label}:seal_invalid")
    if not _nonempty_str(value.get("source_sha256")) or (
        isinstance(value.get("source_sha256"), str)
        and _SHA256.fullmatch(value["source_sha256"]) is None
    ):
        _issue(issues, f"stability.{label}:source_sha256_invalid")
    return value


def derive_terminal_absence_stability(
    first: Any,
    second: Any,
    *,
    first_observed_at_ms: int,
    second_observed_at_ms: int,
) -> dict[str, Any]:
    """Classify a missing terminal body from two sealed observations.

    Pure derivation, no I/O and no scoring authority.  The first sample must
    be a FAIL observation whose only issue is ``terminal:json_missing``.  The
    second sample of the same session by the same observer, taken at least
    ``TERMINAL_ABSENCE_GRACE_FLOOR_MS`` later, resolves the write-lag
    hypothesis three ways: identical bytes still missing a terminal is the
    stronger ``STABLE_ABSENCE`` claim, changed bytes still missing a terminal
    is ``UNSTABLE_ABSENCE`` (single-read semantics stand), and a terminal
    present in the second sample is ``TERMINAL_APPEARED`` (the ordinary
    scored path continues with the second observation; nothing here scores).
    """

    issues: list[str] = []
    first_value = _stability_sample(first, "first", issues)
    second_value = _stability_sample(second, "second", issues)
    first_issues = first_value.get("issues")
    if first_value and first_issues != ["terminal:json_missing"]:
        _issue(issues, "stability:first_cause_invalid")
    second_issues = second_value.get("issues")
    if second_value and second_issues not in (
        [],
        ["terminal:json_missing"],
    ):
        _issue(issues, "stability:second_cause_invalid")
    first_route = first_value.get("route")
    second_route = second_value.get("route")
    first_session = (
        first_route.get("session_id") if isinstance(first_route, Mapping) else None
    )
    second_session = (
        second_route.get("session_id")
        if isinstance(second_route, Mapping)
        else None
    )
    if first_value and second_value:
        if (
            not _nonempty_str(first_session)
            or first_session != second_session
            or first_value.get("source_pointer")
            != second_value.get("source_pointer")
        ):
            _issue(issues, "stability:session_mismatch")
        if first_value.get("observer_id") != second_value.get("observer_id"):
            _issue(issues, "stability:observer_mismatch")
    for label, stamp in (
        ("first", first_observed_at_ms),
        ("second", second_observed_at_ms),
    ):
        if type(stamp) is not int or stamp < 0:
            _issue(issues, f"stability:{label}_observed_at_invalid")
    if (
        type(first_observed_at_ms) is int
        and type(second_observed_at_ms) is int
        and first_observed_at_ms >= 0
        and second_observed_at_ms >= 0
    ):
        if second_observed_at_ms < first_observed_at_ms:
            _issue(issues, "stability:ordering_invalid")
        elif (
            second_observed_at_ms - first_observed_at_ms
            < TERMINAL_ABSENCE_GRACE_FLOOR_MS
        ):
            _issue(issues, "stability:grace_floor_not_met")

    first_at_valid = type(first_observed_at_ms) is int and first_observed_at_ms >= 0
    second_at_valid = (
        type(second_observed_at_ms) is int and second_observed_at_ms >= 0
    )
    classification = None
    if not issues:
        if second_issues == []:
            classification = TERMINAL_APPEARED
        elif first_value.get("source_sha256") == second_value.get(
            "source_sha256"
        ):
            classification = STABLE_ABSENCE
        else:
            classification = UNSTABLE_ABSENCE
    interval = (
        second_observed_at_ms - first_observed_at_ms
        if not issues
        else None
    )
    core = {
        "schema": TERMINAL_ABSENCE_STABILITY_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(issues),
        "classification": classification,
        "first": {
            "source_sha256": first_value.get("source_sha256"),
            "report_sha256": first_value.get("report_sha256"),
            "observed_at_ms": first_observed_at_ms if first_at_valid else None,
        },
        "second": {
            "source_sha256": second_value.get("source_sha256"),
            "report_sha256": second_value.get("report_sha256"),
            "observed_at_ms": (
                second_observed_at_ms if second_at_valid else None
            ),
        },
        "session_id": first_session if not issues else None,
        "observer_id": first_value.get("observer_id") if not issues else None,
        "interval_ms": interval,
        "grace_floor_ms": TERMINAL_ABSENCE_GRACE_FLOOR_MS,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "report_sha256": _sha256(core)}


def validate_session_runtime_observation(value: Any) -> dict[str, Any]:
    """Validate the closed seal and minimum runtime facts on an observation."""

    issues: list[str] = []
    try:
        _validate_bounded_json(value)
    except (RecursionError, TypeError, ValueError):
        _issue(issues, "observation:json_invalid")
        value = {}
    required = {
        "schema",
        "status",
        "issues",
        "observer_id",
        "source_pointer",
        "source_sha256",
        "route",
        "terminal_schema",
        "terminal_json_sha256",
        "terminal_record",
        "usage",
        "usage_record",
        "skipped_lines",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "evidence_tier",
        "report_sha256",
    }
    _exact(value, required, "observation", issues)
    report = value if isinstance(value, Mapping) else {}
    if report.get("schema") != SESSION_RUNTIME_OBSERVATION_SCHEMA:
        _issue(issues, "observation:schema_invalid")
    if report.get("status") != "PASS":
        _issue(issues, "observation:not_passing")
    if report.get("issues") != []:
        _issue(issues, "observation:issues_present")
    if report.get("evidence_tier") != "runtime-observed":
        _issue(issues, "observation:tier_invalid")
    if report.get("provider_free") is not True or any(
        type(report.get(field)) is not int or report.get(field) != 0
        for field in ("model_calls", "hosted_calls")
    ):
        _issue(issues, "observation:adapter_boundary_invalid")
    for field in ("source_sha256", "terminal_json_sha256"):
        candidate = report.get(field)
        if not isinstance(candidate, str) or _SHA256.fullmatch(candidate) is None:
            _issue(issues, f"observation:{field}_invalid")
    observer_id = report.get("observer_id")
    if not _nonempty_str(observer_id):
        _issue(issues, "observation:observer_id_invalid")
    route = report.get("route")
    _exact(
        route,
        {
            "session_id",
            "model",
            "effort",
            "context_policy",
            "inherited_history",
        },
        "observation.route",
        issues,
    )
    route_source = route if isinstance(route, Mapping) else {}
    for field in ("session_id", "model", "effort"):
        if not _nonempty_str(route_source.get(field)):
            _issue(issues, f"observation:route_{field}_invalid")
    inherited = route_source.get("inherited_history")
    context_policy = route_source.get("context_policy")
    if (
        type(inherited) is not bool
        or context_policy not in {"none", "inherited"}
        or (context_policy == "inherited") is not inherited
    ):
        _issue(issues, "observation:route_context_invalid")
    if observer_id == route_source.get("session_id"):
        _issue(issues, "observation:observer_not_independent")
    if report.get("source_pointer") != f"session://{route_source.get('session_id')}":
        _issue(issues, "observation:source_pointer_invalid")
    if not _nonempty_str(report.get("terminal_schema")):
        _issue(issues, "observation:terminal_schema_invalid")
    if type(report.get("skipped_lines")) is not int or report.get("skipped_lines") != 0:
        _issue(issues, "observation:skipped_lines_invalid")
    for field in ("terminal_record", "usage_record"):
        record = report.get(field)
        _exact(record, {"line", "sha256"}, f"observation.{field}", issues)
        row = record if isinstance(record, Mapping) else {}
        if type(row.get("line")) is not int or row["line"] < 1:
            _issue(issues, f"observation:{field}_line_invalid")
        digest = row.get("sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            _issue(issues, f"observation:{field}_sha256_invalid")
    usage = report.get("usage")
    _exact(
        usage,
        {
            "status",
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "reasoning_tokens",
            "total_tokens",
            "tool_calls",
        },
        "observation.usage",
        issues,
    )
    if isinstance(usage, Mapping):
        if usage.get("status") != "observed":
            _issue(issues, "observation:exact_usage_required")
        numeric_fields = (
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "reasoning_tokens",
            "total_tokens",
            "tool_calls",
        )
        if any(type(usage.get(field)) is not int or usage[field] < 0 for field in numeric_fields):
            _issue(issues, "observation:usage_components_invalid")
        elif (
            usage["cached_input_tokens"] > usage["input_tokens"]
            or usage["reasoning_tokens"] > usage["output_tokens"]
            or usage["total_tokens"]
            != usage["input_tokens"] + usage["output_tokens"]
        ):
            _issue(issues, "observation:usage_arithmetic_invalid")
    supplied = report.get("report_sha256")
    if not isinstance(supplied, str) or _SHA256.fullmatch(supplied) is None:
        _issue(issues, "observation:report_sha256_invalid")
    sealed = dict(report)
    sealed.pop("report_sha256", None)
    if supplied != _sha256(sealed):
        _issue(issues, "observation:report_sha256_mismatch")
    normalized = dict(report) if not issues else None
    return {
        "schema": "orch-dork/session-runtime-observation-validation/v1",
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": sorted(issues),
        "normalized": normalized,
        "digest": supplied if not issues else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def verify_wave_routing(program: Any) -> dict[str, Any]:
    """Verify observed per-lane routing against a frozen wave plan.

    Pure validation, no I/O. The input is a wave-routing program with the
    exact top-level fields ``{schema, plan_worker_model, plan_worker_effort,
    plan_root_model, plan_root_effort, lanes}``. Each lane carries the
    ``extract_session_routing`` report for its session under
    ``session_routing``; expected routing is plan_worker_* for a worker
    lane and plan_root_* for a root lane. Status is PASS only when every
    lane matches; on PASS the report seals the canonical program with
    ``routing_sha256``.
    """

    issues: list[str] = []
    try:
        _validate_bounded_json(program)
    except (RecursionError, TypeError, ValueError):
        _issue(issues, "program:json_invalid")
        program = {}
    value = program if isinstance(program, Mapping) else {}
    schema = value.get("schema")
    v2 = schema == WAVE_ROUTING_PROGRAM_SCHEMA_V2
    v3 = schema == WAVE_ROUTING_PROGRAM_SCHEMA_V3
    bound = v2 or v3
    top_fields = {
        "schema",
        "plan_worker_model",
        "plan_worker_effort",
        "plan_root_model",
        "plan_root_effort",
        "lanes",
    }
    if bound:
        top_fields.add("expected_members")
    _exact(
        value,
        top_fields,
        "program",
        issues,
    )
    if schema not in {
        WAVE_ROUTING_PROGRAM_SCHEMA,
        WAVE_ROUTING_PROGRAM_SCHEMA_V2,
        WAVE_ROUTING_PROGRAM_SCHEMA_V3,
    }:
        _issue(issues, "program:schema_invalid")

    for field in (
        "plan_worker_model",
        "plan_worker_effort",
        "plan_root_model",
        "plan_root_effort",
    ):
        if not _nonempty_str(value.get(field)):
            _issue(issues, f"program:{field}_invalid")

    expected_by_lane: dict[str, Mapping[str, Any]] = {}
    if bound:
        expected_value = value.get("expected_members")
        if not isinstance(expected_value, list) or not expected_value:
            _issue(issues, "expected_members:invalid")
            expected_value = []
        expected_worker_ids: list[str] = []
        expected_session_ids: list[str] = []
        for index, member in enumerate(expected_value):
            label = f"expected_members[{index}]"
            _exact(
                member,
                {"lane_id", "role", "worker_id", "session_id"},
                label,
                issues,
            )
            if not isinstance(member, Mapping):
                continue
            lane_id = member.get("lane_id")
            if not _nonempty_str(lane_id) or lane_id in expected_by_lane:
                _issue(issues, f"{label}:lane_id_invalid_or_duplicate")
                continue
            if member.get("role") not in LANE_ROLES:
                _issue(issues, f"{label}:role_invalid")
            if not _nonempty_str(member.get("worker_id")):
                _issue(issues, f"{label}:worker_id_invalid")
            else:
                expected_worker_ids.append(str(member["worker_id"]))
            if not _nonempty_str(member.get("session_id")):
                _issue(issues, f"{label}:session_id_invalid")
            else:
                expected_session_ids.append(str(member["session_id"]))
            expected_by_lane[str(lane_id)] = member
        if len(expected_worker_ids) != len(set(expected_worker_ids)):
            _issue(issues, "expected_members:duplicate_worker_ids")
        if len(expected_session_ids) != len(set(expected_session_ids)):
            _issue(issues, "expected_members:duplicate_session_ids")

    lanes_value = value.get("lanes")
    if not isinstance(lanes_value, list):
        _issue(issues, "lanes:not_array")
        lanes_value = []
    if not lanes_value:
        _issue(issues, "lanes:empty")

    lane_ids: list[str] = []
    verified: list[str] = []
    mismatched: list[dict[str, Any]] = []
    for index, lane in enumerate(lanes_value):
        label = f"lanes[{index}]"
        lane_fields = {
            "lane_id",
            "role",
            "session_observation" if v3 else "session_routing",
        }
        if bound:
            lane_fields.update({"worker_id", "session_id"})
        _exact(lane, lane_fields, label, issues)
        if not isinstance(lane, Mapping):
            continue
        if not _nonempty_str(lane.get("lane_id")):
            _issue(issues, f"{label}:lane_id_invalid")
        else:
            lane_ids.append(str(lane["lane_id"]))
        role = lane.get("role")
        if role not in LANE_ROLES:
            _issue(issues, f"{label}:role_invalid")
        report = lane.get("session_observation" if v3 else "session_routing")
        if v3 and not validate_session_runtime_observation(report)["valid"]:
            _issue(issues, f"{label}:runtime_observation_invalid")
            continue
        if not v3 and not _valid_routing_report(report):
            _issue(issues, f"{label}:routing_report_invalid")
            continue
        route_report = report.get("route", {}) if v3 else report
        binding_matched = True
        if bound:
            expected_member = expected_by_lane.get(str(lane.get("lane_id")))
            if expected_member is None:
                _issue(issues, f"routing:unexpected_lane:{lane.get('lane_id')}")
                binding_matched = False
            else:
                for field in ("role", "worker_id", "session_id"):
                    if lane.get(field) != expected_member.get(field):
                        binding_matched = False
                        binding_field = (
                            "session" if field == "session_id" else field
                        )
                        _issue(
                            issues,
                            f"{label}:{binding_field}_binding_mismatch:"
                            f"{_render(expected_member.get(field))}:"
                            f"{_render(lane.get(field))}",
                        )
                observed_session = (
                    route_report.get("session_id")
                    if v3
                    else report.get("own_session_id")
                )
                if observed_session != lane.get("session_id"):
                    _issue(issues, f"{label}:routing_report_session_mismatch")
                    binding_matched = False
        expected_model = (
            value.get("plan_worker_model") if role == "worker"
            else value.get("plan_root_model")
        )
        expected_effort = (
            value.get("plan_worker_effort") if role == "worker"
            else value.get("plan_root_effort")
        )
        observed_model = (
            route_report.get("model") if v3 else report.get("observed_model")
        )
        observed_effort = (
            route_report.get("effort") if v3 else report.get("observed_effort")
        )
        lane_id = str(lane.get("lane_id"))
        lane_matched = binding_matched and (
            role in LANE_ROLES
            and isinstance(expected_model, str)
            and isinstance(expected_effort, str)
        )
        if expected_model is not None and observed_model != expected_model:
            _issue(
                issues,
                f"{label}:model_mismatch:{_render(expected_model)}:{_render(observed_model)}",
            )
            mismatched.append(
                {
                    "lane_id": lane_id,
                    "field": "model",
                    "expected": expected_model,
                    "observed": observed_model,
                }
            )
            lane_matched = False
        if expected_effort is not None and observed_effort != expected_effort:
            _issue(
                issues,
                f"{label}:effort_mismatch:{_render(expected_effort)}:{_render(observed_effort)}",
            )
            mismatched.append(
                {
                    "lane_id": lane_id,
                    "field": "effort",
                    "expected": expected_effort,
                    "observed": observed_effort,
                }
            )
            lane_matched = False
        if (
            role == "worker"
            and isinstance(route_report.get("inherited_history"), bool)
            and route_report.get("inherited_history")
        ):
            _issue(issues, f"{label}:inherited_history_present")
            lane_matched = False
        if lane_matched:
            verified.append(lane_id)

    if len(lane_ids) != len(set(lane_ids)):
        _issue(issues, "lanes:duplicate_ids")
    if bound:
        for lane_id in sorted(set(expected_by_lane) - set(lane_ids)):
            _issue(issues, f"routing:missing_lane:{lane_id}")
        for lane_id in sorted(set(lane_ids) - set(expected_by_lane)):
            _issue(issues, f"routing:unexpected_lane:{lane_id}")

    if issues:
        status = "FAIL"
    elif lane_ids != verified:
        status = "FAIL"
    else:
        status = "PASS"

    worker_lane_ids = [
        str(lane.get("lane_id"))
        for lane in lanes_value
        if isinstance(lane, Mapping) and lane.get("role") == "worker"
    ]
    root_lane_ids = [
        str(lane.get("lane_id"))
        for lane in lanes_value
        if isinstance(lane, Mapping) and lane.get("role") == "root"
    ]
    runtime_observations_complete = status == "PASS" and v3 and bool(lanes_value) and not any(
        "runtime_observation_invalid" in issue for issue in issues
    )
    worker_route_verified = bool(worker_lane_ids) and runtime_observations_complete and all(
        lane_id in verified for lane_id in worker_lane_ids
    )
    root_route_verified = bool(root_lane_ids) and runtime_observations_complete and all(
        lane_id in verified for lane_id in root_lane_ids
    )

    core = {
        "schema": WAVE_ROUTING_REPORT_SCHEMA,
        "status": status,
        "issues": sorted(issues),
        "lane_count": len(lanes_value),
        "expected_lane_count": len(expected_by_lane) if v2 else None,
        "verified": verified,
        "mismatched": mismatched,
        "worker_route_evidence_tier": (
            "runtime-observed"
            if runtime_observations_complete and worker_lane_ids
            else "invalid"
            if v3 and worker_lane_ids
            else "submitted"
            if worker_lane_ids
            else "unobserved"
        ),
        "worker_route_verified": worker_route_verified,
        "root_route_evidence_tier": (
            "runtime-observed"
            if runtime_observations_complete and root_lane_ids
            else "invalid"
            if v3 and root_lane_ids
            else "submitted"
            if root_lane_ids
            else "unobserved"
        ),
        "root_route_verified": root_route_verified,
    }
    if status == "PASS":
        core["routing_sha256"] = _sha256(value)
    return _report_footer(core)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Runtime routing verifier for Orch Dork wave sessions"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    extract = sub.add_parser(
        "extract-session-routing", help="Extract routing from one rollout JSONL"
    )
    extract.add_argument("path")
    extract.add_argument("--session-id", default=None)
    observe = sub.add_parser(
        "observe-session-runtime",
        help="Bind route, typed terminal JSON, and exact usage from one rollout",
    )
    observe.add_argument("path")
    observe.add_argument("--session-id", required=True)
    observe.add_argument("--observer-id", required=True)
    verify = sub.add_parser(
        "verify-wave-routing", help="Verify a wave-routing program"
    )
    verify.add_argument("program")
    args = parser.parse_args(argv)
    if args.command == "extract-session-routing":
        result = extract_session_routing(args.path, args.session_id)
    elif args.command == "observe-session-runtime":
        result = observe_session_runtime(
            args.path,
            session_id=args.session_id,
            observer_id=args.observer_id,
        )
    else:
        try:
            program = _parse_bounded_json(
                _read_bounded_bytes(args.program, MAX_JSON_RECORD_BYTES))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError,
                RecursionError, ValueError) as exc:
            raise SystemExit(f"cannot read program JSON: {exc}") from exc
        result = verify_wave_routing(program)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
