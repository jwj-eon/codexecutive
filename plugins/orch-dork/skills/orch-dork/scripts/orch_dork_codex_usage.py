"""Exact Codex 0.153.4 response deltas from an owning reader's selected window.

The reader supplies complete selected turns and authenticates raw line hashes.
This pure transport does neither. Child thread IDs differ from the root session
ID: the observed session is retained and checked for consistency, not inferred
from the requested thread. No dollars are inferred from token telemetry.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import hashlib
import json
from typing import Any

import orch_dork_hostile_input as hostile

SCHEMA = "orch-dork/codex-token-usage-observation/v1"
TOKEN_FIELDS = ("input_tokens", "cached_input_tokens", "cache_write_input_tokens",
                "output_tokens", "reasoning_output_tokens", "total_tokens")
_ENVELOPE = {"type", "timestamp", "ordinal", "payload"}
_PAYLOAD = {"response_id", "root_turn_id", "session_id", "thread_id", "turn_id",
            "usage", "turn_token_usage", "thread_token_usage"}
_REPORT = {"schema", "status", "issues", "thread_id", "session_id", "turn_ids", "evidence",
           "source_refs", "per_turn", "totals", "provider_free", "cost_usd", "report_sha256"}
_DENIALS = {"usage:input_invalid", "usage:row_invalid", "usage:source_order",
            "usage:native_shape", "usage:mirror_shape"}
_INVALID = (KeyError, TypeError, ValueError, OverflowError, RecursionError)


def _bytes(value: Any) -> bytes:
    profile = hostile.PROFILE
    stack, nodes = [(value, 0)], 0
    while stack:
        child, depth = stack.pop()
        nodes += 1
        if depth > profile.max_depth or nodes > profile.max_nodes:
            raise ValueError("usage:input_invalid")
        if type(child) is dict:
            if len(child) > profile.max_object_keys:
                raise ValueError("usage:input_invalid")
            for key, item in child.items():
                if type(key) is not str or len(key) > profile.max_key_bytes:
                    raise ValueError("usage:input_invalid")
                stack.append((item, depth + 1))
        elif type(child) is list:
            if len(child) > profile.max_array_items:
                raise ValueError("usage:input_invalid")
            stack.extend((item, depth + 1) for item in child)
        elif type(child) is str:
            if len(child) > profile.max_string_bytes:
                raise ValueError("usage:input_invalid")
        elif type(child) not in (int, float, bool, type(None)):
            raise ValueError("usage:input_invalid")
    encoded = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    for part in encoder.iterencode(value):
        chunk = part.encode("utf-8")
        if len(encoded) + len(chunk) > profile.canonical_json_bytes:
            raise ValueError("usage:input_invalid")
        encoded.extend(chunk)
    return hostile.canonicalize_bounded_json(encoded, profile=profile)


def _sha(value: Any) -> str:
    return hashlib.sha256(_bytes(value)).hexdigest()


def _id(value: Any) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= hostile.PROFILE.max_key_bytes and "\x00" not in value


def _digest(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and not set(value) - set("0123456789abcdef")


def _ref(row: Any) -> bool:
    return type(row) is dict and type(row.get("line")) is int and row["line"] > 0 and _digest(row.get("sha256"))


def _envelope(record: Any, kind: str) -> bool:
    if (type(record) is not dict or set(record) != _ENVELOPE or record["type"] != kind
            or type(record["ordinal"]) is not int or record["ordinal"] < 0
            or type(record["timestamp"]) is not str):
        return False
    try:
        return datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _token_shape(value: Any) -> bool:
    return type(value) is dict and set(value) == set(TOKEN_FIELDS) and all(type(value[key]) is int for key in TOKEN_FIELDS)


def _native_shape(record: Any) -> bool:
    if not _envelope(record, "token_usage_record"):
        return False
    p = record["payload"]
    return (type(p) is dict and set(p) == _PAYLOAD
            and all(_id(p[key]) for key in ("response_id", "root_turn_id", "session_id", "thread_id", "turn_id"))
            and all(_token_shape(p[key]) for key in ("usage", "turn_token_usage", "thread_token_usage")))


def _info_shape(info: Any) -> bool:
    return info is None or (type(info) is dict
        and {"last_token_usage", "total_token_usage"} <= set(info) <= {"last_token_usage", "total_token_usage", "model_context_window"}
        and _token_shape(info["last_token_usage"]) and _token_shape(info["total_token_usage"])
        and ("model_context_window" not in info or (type(info["model_context_window"]) is int and info["model_context_window"] >= 0)))


def _denial(issue: str, row: Any = None) -> dict:
    return {"kind": "refusal", "line": row["line"] if _ref(row) else None,
            "sha256": row["sha256"] if _ref(row) else None, "issue": issue}


def _project(records: Any) -> list[dict]:
    try:
        _bytes(records)
        if type(records) is not list:
            raise ValueError("usage:input_invalid")
    except _INVALID:
        return [_denial("usage:input_invalid")]
    evidence, previous_line = [], 0
    for row in records:
        if (not _ref(row) or set(row) != {"line", "sha256", "record"} or type(row["record"]) is not dict):
            evidence.append(_denial("usage:row_invalid", row))
            continue
        if row["line"] <= previous_line:
            evidence.append(_denial("usage:source_order", row))
            continue
        previous_line = row["line"]
        record = row["record"]
        if record.get("type") == "token_usage_record":
            evidence.append({"kind": "token_usage_record", **deepcopy(row)} if _native_shape(record)
                            else _denial("usage:native_shape", row))
        elif (record.get("type") == "event_msg" and type(record.get("payload")) is dict
              and record["payload"].get("type") == "token_count"):
            payload = record["payload"]
            if (not _envelope(record, "event_msg") or not {"type", "info"} <= set(payload) <= {"type", "info", "rate_limits"}
                    or not _info_shape(payload["info"])):
                evidence.append(_denial("usage:mirror_shape", row))
            else:
                evidence.append({"kind": "token_count", "line": row["line"], "sha256": row["sha256"],
                                 "timestamp": record["timestamp"], "ordinal": record["ordinal"], "info": deepcopy(payload["info"])})
    return evidence


def _evidence_shape(evidence: Any) -> None:
    if type(evidence) is not list:
        raise ValueError("invalid evidence")
    for row in evidence:
        if type(row) is not dict:
            raise ValueError("invalid evidence")
        kind = row.get("kind")
        if kind == "refusal":
            if (set(row) != {"kind", "line", "sha256", "issue"} or row["issue"] not in _DENIALS
                    or not (_ref(row) or (row["line"] is None and row["sha256"] is None))):
                raise ValueError("invalid denial")
        elif kind == "token_usage_record":
            if set(row) != {"kind", "line", "sha256", "record"} or not _ref(row) or not _native_shape(row["record"]):
                raise ValueError("invalid native evidence")
        elif kind == "token_count":
            envelope = {"type": "event_msg", "timestamp": row.get("timestamp"), "ordinal": row.get("ordinal"), "payload": {}}
            if (set(row) != {"kind", "line", "sha256", "timestamp", "ordinal", "info"}
                    or not _ref(row) or not _envelope(envelope, "event_msg") or not _info_shape(row["info"])):
                raise ValueError("invalid mirror projection")
        else:
            raise ValueError("invalid evidence kind")


class _Refused(ValueError):
    pass


def _tokens(value: dict) -> None:
    if (any(value[key] < 0 for key in TOKEN_FIELDS)
            or value["total_tokens"] != value["input_tokens"] + value["output_tokens"]
            or value["cached_input_tokens"] > value["input_tokens"]
            or value["reasoning_output_tokens"] > value["output_tokens"]):
        raise _Refused("usage:token_arithmetic")


def _calculate(evidence: list[dict], thread_id: Any, turn_ids: Any) -> tuple[str, list[dict], dict]:
    if not _id(thread_id) or type(turn_ids) is not list or not turn_ids or any(not _id(t) for t in turn_ids) or len(set(turn_ids)) != len(turn_ids):
        raise _Refused("usage:selection_invalid")
    totals = {key: 0 for key in TOKEN_FIELDS}
    turns, responses, session, previous, previous_line = {}, set(), None, None, 0
    for row in evidence:
        if row["kind"] == "refusal":
            raise _Refused(row["issue"])
        if row["line"] <= previous_line:
            raise _Refused("usage:source_order")
        previous_line = row["line"]
        if row["kind"] == "token_count":
            info = row["info"]
            if info is None:
                continue
            if previous is None:
                raise _Refused("usage:mirror_without_delta")
            for key in ("last_token_usage", "total_token_usage"):
                _tokens(info[key])
            if info["last_token_usage"] != previous["usage"] or info["total_token_usage"] != previous["thread_token_usage"]:
                raise _Refused("usage:mirror_mismatch")
            continue
        p = row["record"]["payload"]
        if p["thread_id"] != thread_id or p["turn_id"] not in turn_ids:
            raise _Refused("usage:thread_or_turn_mismatch")
        if session is not None and session != p["session_id"]:
            raise _Refused("usage:session_mismatch")
        session = p["session_id"]
        if p["response_id"] in responses:
            raise _Refused("usage:duplicate_response")
        responses.add(p["response_id"])
        for key in ("usage", "turn_token_usage", "thread_token_usage"):
            _tokens(p[key])
        turn = turns.setdefault(p["turn_id"], {"turn_id": p["turn_id"], "root_turn_id": p["root_turn_id"],
                                               "response_ids": [], "totals": {key: 0 for key in TOKEN_FIELDS}})
        if turn["root_turn_id"] != p["root_turn_id"]:
            raise _Refused("usage:root_turn_mismatch")
        for key in TOKEN_FIELDS:
            turn["totals"][key] += p["usage"][key]
            totals[key] += p["usage"][key]
        turn["response_ids"].append(p["response_id"])
        if turn["totals"] != p["turn_token_usage"]:
            raise _Refused("usage:turn_cumulative_mismatch")
        if previous is None:
            _tokens({key: p["thread_token_usage"][key] - p["usage"][key] for key in TOKEN_FIELDS})
        elif any(p["thread_token_usage"][key] - previous["thread_token_usage"][key] != p["usage"][key] for key in TOKEN_FIELDS):
            raise _Refused("usage:thread_cumulative_mismatch")
        previous = p
    if set(turns) != set(turn_ids):
        raise _Refused("usage:missing_native_delta")
    return session, [turns[t] for t in turn_ids], totals


def _report(evidence: list[dict], thread_id: Any, turn_ids: Any) -> dict:
    _evidence_shape(evidence)
    try:
        session, per_turn, totals = _calculate(evidence, thread_id, turn_ids)
        status, issues = "OBSERVED", []
    except _Refused as error:
        session, per_turn, totals = None, [], None
        status, issues = "REFUSED", [str(error)]
    core = {"schema": SCHEMA, "status": status, "issues": issues, "thread_id": thread_id, "session_id": session,
            "turn_ids": deepcopy(turn_ids), "evidence": deepcopy(evidence),
            "source_refs": [{"line": row["line"], "sha256": row["sha256"], "kind": row["kind"]} for row in evidence if _ref(row)],
            "per_turn": per_turn, "totals": totals, "provider_free": True, "cost_usd": None}
    return {**core, "report_sha256": _sha(core)}


def build_usage_observation(records: Any, *, thread_id: Any, turn_ids: Any) -> dict:
    """Count deltas once; corroborate mirrors without exporting their private data.

    Raw hashes are reader-supplied references, not hashes of reserialized JSON.
    Malformed records get a bounded refusal marker instead of leaking payloads.
    A selected turn must start at its first delta; completeness is reader-owned.
    """
    selected_thread = thread_id if _id(thread_id) else None
    selected_turns = (deepcopy(turn_ids) if type(turn_ids) is list and len(turn_ids) <= hostile.PROFILE.max_array_items
                      and all(_id(t) for t in turn_ids) else [])
    try:
        report = _report(_project(records), selected_thread, selected_turns)
        _bytes(report)
        return report
    except _INVALID:
        return _report([_denial("usage:input_invalid")], selected_thread, selected_turns)


def validate_usage_observation(report: Any) -> dict:
    """Reconstruct compact telemetry transport; establish no raw-source authority."""
    try:
        encoded = _bytes(report)
        if type(report) is not dict or set(report) != _REPORT:
            raise ValueError("invalid report")
        if report["thread_id"] is not None and not _id(report["thread_id"]):
            raise ValueError("invalid thread selector")
        if type(report["turn_ids"]) is not list or any(not _id(t) for t in report["turn_ids"]):
            raise ValueError("invalid turn selector")
        expected = _report(report["evidence"], report["thread_id"], report["turn_ids"])
        if encoded != _bytes(expected):
            raise ValueError("noncanonical report")
    except _INVALID:
        return {"valid": False, "issues": ["usage:report_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


__all__ = ["SCHEMA", "TOKEN_FIELDS", "build_usage_observation", "validate_usage_observation"]
