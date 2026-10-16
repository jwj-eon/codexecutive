"""One closed Codex-host compatibility boundary, with no lifecycle policy.

Transport normalization never edits a controller action or a canonical report.
The caller selects a qualified host profile and supplies complete observations.
This module performs no environment lookup, process creation or network call.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
from datetime import datetime
from pathlib import PurePosixPath

from lifecycle_conformance import reference_values as rv, values

MAX_BYTES = 1_000_000
MAX_STREAM_BYTES = 65536
HOST_PROFILE = rv.freeze({"host": "codex-desktop-functions", "codex_cli": "0.153.4",
                          "os": "Linux", "python": "3.12.3"})
TOOLS = rv.freeze({alias: "multi_agent_v1__" + method
                   for method in ("spawn_agent", "send_input", "wait_agent", "close_agent")
                   for alias in (method, "multi_agent_v1." + method, "multi_agent_v1__" + method)})
HOOKS = ("PreToolUse", "PostToolUse", "SessionStart", "SubagentStop", "Stop")
HOOK_NAMES = {name[0].lower() + name[1:]: name for name in HOOKS} | {name: name for name in HOOKS}
ENVIRONMENT_KEYS = {"HOME", "CODEX_HOME", "ORCH_DORK_APP_SERVER_SOCKET"}
OBSERVATIONS = ("tool_name", "response", "newline_frame", "javascript_globals", "environment",
                "owned_file", "hook_inventory", "session_start", "permission", "pty",
                "completed_mcp_tool_call", "mcp_call_context")


def _refuse(reason: str) -> None:
    raise values.LifecycleContractError("host_adapter:" + reason)


def _json_value(value: object, depth: int = 0) -> None:
    if depth > 16:
        _refuse("depth")
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str or key == "__proto__":
                _refuse("json_key")
            _json_value(child, depth + 1)
    elif type(value) is list:
        for child in value:
            _json_value(child, depth + 1)
    elif type(value) is float:
        if not math.isfinite(value):
            _refuse("json_number")
    elif type(value) not in (str, int, bool, type(None)):
        _refuse("json_type")


def canonical_bytes(value: object) -> bytes:
    """UTF-8 transport identity, preserving JSON scalar types and all fields."""
    _json_value(value)
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError):
        _refuse("json_encoding")
    if len(raw) > MAX_BYTES:
        _refuse("size")
    return raw


def _pairs(pairs: list) -> dict:
    value = {}
    for key, child in pairs:
        if key in value:
            _refuse("duplicate_key")
        value[key] = child
    return value


def decode_response(raw: object) -> dict:
    """Accept a whole mapping or one JSON string; return a detached mapping."""
    if type(raw) is dict:
        encoded = canonical_bytes(raw)
    elif type(raw) is str:
        try:
            encoded = raw.encode("utf-8")
        except UnicodeError:
            _refuse("json_encoding")
        if len(encoded) > MAX_BYTES:
            _refuse("size")
    else:
        _refuse("response_type")
    try:
        value = json.loads(encoded, object_pairs_hook=_pairs,
                           parse_constant=lambda _: _refuse("json_number"))
    except (ValueError, RecursionError):
        _refuse("response_json")
    if type(value) is not dict:
        _refuse("response_type")
    canonical_bytes(value)
    return value


def canonical_tool_name(name: object) -> str:
    if type(name) is not str or name not in TOOLS.to_plain():
        _refuse("tool_name")
    return TOOLS.to_plain()[name]


def completed_mcp_tool_call(raw: object) -> dict:
    """Preserve the complete MCP item; establish no call authority."""
    required = {"type", "id", "server", "tool", "arguments", "result", "error", "status",
                "durationMs", "pluginId", "appContext", "readOnlyHint"}
    value = _compatible_fields(decode_response(raw), required, {"mcpAppUi"})
    if (value["type"] != "mcpToolCall" or value["status"] != "completed" or value["error"] is not None
            or any(type(value[key]) is not str or not value[key] for key in ("id", "server", "tool"))
            or type(value["arguments"]) is not dict or type(value["durationMs"]) is not int
            or value["durationMs"] < 0
            or value["pluginId"] is not None and type(value["pluginId"]) is not str
            or value["appContext"] is not None and type(value["appContext"]) is not dict
            or value["readOnlyHint"] is not None and type(value["readOnlyHint"]) is not bool):
        _refuse("mcp_tool_call")
    result = _required_fields(value["result"], {"_meta", "content", "structuredContent"})
    if (result["_meta"] is not None and type(result["_meta"]) is not dict
            or type(result["content"]) is not list
            or any(type(item) is not dict for item in result["content"])
            or result["structuredContent"] is not None and type(result["structuredContent"]) is not dict):
        _refuse("mcp_tool_call_result")
    return value


def mcp_call_context(raw: object) -> dict:
    """Project native MCP metadata; callers must supply the host request metadata.

    This is a compatibility check, not proof that arbitrary submitted metadata
    came from Codex. Reconciliation must bind the emitted host acknowledgement
    to the exact completed MCP item and turn on the pinned owner.
    """
    top_fields = {"threadId", "callId", "itemId", "progressToken", "x-codex-turn-metadata"}
    context_fields = {
        "auto_review_enabled", "model", "node_repl_auto_review_required", "node_repl_disabled", "reasoning_effort",
        "sandbox", "sandbox_mode", "session_id", "thread_id", "turn_id", "turn_started_at_unix_ms", "workspaces",
    }
    value = _compatible_fields(decode_response(raw), top_fields, {"plugin_id", "sessionId", "windowId"})
    context = _compatible_fields(value["x-codex-turn-metadata"], context_fields, {"codex_version"})
    if (any(type(value[key]) is not str or not value[key] for key in ("threadId", "callId", "itemId"))
            or type(value["progressToken"]) is not int or value["progressToken"] < 0
            or any(key in value and (type(value[key]) is not str or not value[key])
                   for key in ("plugin_id", "sessionId", "windowId"))
            or any(type(context[key]) is not str or not context[key]
                   for key in ("session_id", "thread_id", "turn_id", "model", "reasoning_effort", "sandbox", "sandbox_mode"))
            or "codex_version" in context
            and (type(context["codex_version"]) is not str or not context["codex_version"])
            or any(type(context[key]) is not bool for key in ("auto_review_enabled", "node_repl_auto_review_required", "node_repl_disabled"))
            or value["threadId"] != context["thread_id"] or context["session_id"] != context["thread_id"]
            or type(context["turn_started_at_unix_ms"]) is not int or context["turn_started_at_unix_ms"] < 0
            or type(context["workspaces"]) is not dict
            or any(not _absolute(path) or not _compatible_workspace(row)
                   for path, row in context["workspaces"].items())):
        _refuse("mcp_call_context")
    return {
        "schema": "orch-dork/host-mcp-call-context/v1", "task_id": context["thread_id"],
        "session_id": context["session_id"], "turn_id": context["turn_id"], "tool_call_id": value["callId"],
        "model": context["model"], "effort": context["reasoning_effort"],
        "turn_started_at_unix_ms": context["turn_started_at_unix_ms"],
        "source_meta_sha256": hashlib.sha256(canonical_bytes(value)).hexdigest(),
    }


def decode_bounded_response(raw: object) -> dict:
    """Decode an exact native mapping after bounding its graph and strings."""
    if type(raw) is not dict:
        _refuse("native_record")
    # Bound the object graph before the ordinary canonical transport encodes it.
    # Opaque prompt fields are still input bytes, even though no projection emits them.
    stack, nodes, string_bytes = [raw], 0, 0
    while stack:
        child = stack.pop(); nodes += 1
        if nodes > 4096:
            _refuse("native_record_size")
        if type(child) is dict:
            if len(child) > 256:
                _refuse("native_record_size")
            stack.extend(child.keys()); stack.extend(child.values())
        elif type(child) is list:
            if len(child) > 256:
                _refuse("native_record_size")
            stack.extend(child)
        elif type(child) is str:
            if len(child) > MAX_BYTES:
                _refuse("native_record_size")
            try:
                string_bytes += len(child.encode("utf-8"))
            except UnicodeError:
                _refuse("json_encoding")
            if string_bytes > MAX_BYTES:
                _refuse("native_record_size")
    return decode_response(raw)


def _native_record(raw: object, kind: str) -> tuple[dict, datetime]:
    value = decode_bounded_response(raw)
    _fields(value, {"type", "ordinal", "timestamp", "payload"})
    if (value["type"] != kind or type(value["ordinal"]) is not int or value["ordinal"] < 0
            or type(value["timestamp"]) is not str or type(value["payload"]) is not dict):
        _refuse("native_record")
    try:
        stamp = datetime.fromisoformat(value["timestamp"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("timezone required")
    except ValueError:
        _refuse("native_record_clock")
    return value, stamp


def native_v1_spawn_pair(call: object, result: object, child_metadata: object) -> dict:
    """Bind exact 0.153.4 direct V1 transport without guessing a lane name.

    The owning reader authenticates source bytes, root identity, selected-turn
    membership and order. This pure projection joins the returned child with
    its first-level metadata. Requested model/effort are not observed routing;
    the observer must also verify the child's complete native turn context.
    Hashes here identify canonical records, never original raw JSONL bytes.
    """
    call_value, call_time = _native_record(call, "response_item")
    result_value, result_time = _native_record(result, "response_item")
    child_value, _child_time = _native_record(child_metadata, "session_meta")
    request = _fields(call_value["payload"], {"type", "call_id", "id", "namespace", "name",
                                            "arguments", "internal_chat_message_metadata_passthrough"})
    response = _fields(result_value["payload"], {"type", "call_id", "id", "output",
                                               "internal_chat_message_metadata_passthrough"})
    metadata = _fields(child_value["payload"], {
        "session_id", "id", "parent_thread_id", "timestamp", "cwd", "originator", "cli_version",
        "source", "thread_source", "agent_nickname", "model_provider", "base_instructions",
        "history_mode", "multi_agent_version", "context_window", "git",
    })
    if (request["type"] != "function_call" or response["type"] != "function_call_output"
            or request["namespace"] != "multi_agent_v1" or request["name"] != "spawn_agent"
            or any(type(row[key]) is not str or not row[key] for row in (request, response)
                   for key in ("call_id", "id"))
            or request["call_id"] != response["call_id"]
            or result_value["ordinal"] <= call_value["ordinal"] or result_time < call_time
            or child_value["ordinal"] != 0
            or metadata["cli_version"] != "0.153.4" or metadata["multi_agent_version"] != "v1"
            or metadata["thread_source"] != "subagent"
            or type(request["arguments"]) is not str or type(response["output"]) is not str):
        _refuse("native_v1_spawn_pair")
    arguments = _fields(decode_response(request["arguments"]), {"message", "model", "reasoning_effort", "fork_context"})
    output = _fields(decode_response(response["output"]), {"agent_id", "nickname"})
    if (arguments["fork_context"] is not False
            or any(type(arguments[key]) is not str or not arguments[key] for key in ("message", "model", "reasoning_effort"))
            or any(type(output[key]) is not str or not output[key] for key in ("agent_id", "nickname"))):
        _refuse("native_v1_spawn_arguments")
    source = _fields(metadata["source"], {"subagent"})
    subagent = _fields(source["subagent"], {"thread_spawn"})
    edge = _fields(subagent["thread_spawn"], {"parent_thread_id", "depth", "agent_path", "agent_nickname", "agent_role"})
    if (any(type(metadata[key]) is not str or not metadata[key] for key in ("session_id", "id", "parent_thread_id"))
            or metadata["id"] != output["agent_id"] or metadata["id"] == metadata["session_id"]
            or edge["parent_thread_id"] != metadata["parent_thread_id"] or metadata["parent_thread_id"] != metadata["session_id"]
            or type(edge["depth"]) is not int or edge["depth"] != 1
            or edge["agent_path"] is not None or edge["agent_role"] is not None
            or edge["agent_nickname"] != output["nickname"] or metadata["agent_nickname"] != output["nickname"]):
        _refuse("native_v1_spawn_membership")
    return {
        "schema": "orch-dork/host-native-v1-spawn/v1", "scope": "structural_transport",
        "call_id": request["call_id"], "parent_thread_id": metadata["parent_thread_id"], "worker_id": metadata["id"],
        "model": arguments["model"], "effort": arguments["reasoning_effort"],
        "context_policy": "none", "surface": "native-v1", "depth": 1,
        "canonical_record_sha256": {key: hashlib.sha256(canonical_bytes(value)).hexdigest()
                                    for key, value in (("call", call_value), ("result", result_value), ("child_metadata", child_value))},
    }


def native_v1_turn_window(records: object) -> dict:
    """Project one contiguous completed 0.153.4 V1 turn supplied by its reader.

    Raw line hashes are references supplied by the owning reader. No source
    authenticity, usage amount, expected model or root identity is inferred.
    Unsupported response forms refuse rather than conceal an external action.
    """
    return _native_v1_turn_projection(records)


def native_v1_active_turn_prefix(records: object, *, pending_call_id: str) -> dict:
    """Project the actual unfinished prefix containing one exact pending call.

    The owning host must bind the call to its current tool request. No terminal
    record is created, and a completed-window consumer rejects this schema.
    """
    if type(pending_call_id) is not str or not pending_call_id:
        _refuse("native_active_call")
    return _native_v1_turn_projection(records, pending_call_id=pending_call_id)


def _native_v1_turn_projection(records: object, *, pending_call_id: str | None = None) -> dict:
    if type(records) is not list or not 3 <= len(records) <= 256:
        _refuse("native_turn_window")
    rows, stamps, refs = [], [], []
    for row in records:
        if (type(row) is not dict or set(row) != {"line", "sha256", "record"}
                or type(row["line"]) is not int or row["line"] < 1
                or type(row["sha256"]) is not str or len(row["sha256"]) != 64
                or set(row["sha256"]) - set("0123456789abcdef") or type(row["record"]) is not dict):
            _refuse("native_turn_source")
        kind = row["record"].get("type")
        if kind not in ("event_msg", "response_item", "turn_context", "world_state", "token_usage_record"):
            _refuse("native_turn_record_kind")
        value, stamp = _native_record(row["record"], kind)
        if (value["ordinal"] != row["line"] - 1 or rows and (
                value["ordinal"] != rows[-1]["ordinal"] + 1 or stamp < stamps[-1])):
            _refuse("native_turn_source_order")
        rows.append(value); stamps.append(stamp)
        refs.append({"line": row["line"], "sha256": row["sha256"]})
    start, end = rows[0]["payload"], rows[-1]["payload"]
    _fields(start, {"type", "turn_id", "started_at", "model_context_window", "collaboration_mode_kind"})
    if (rows[0]["type"] != "event_msg" or start["type"] != "task_started"
            or type(start["turn_id"]) is not str or not start["turn_id"]
            or any(type(value) is not int or value < 0 for value in (start["started_at"], start["model_context_window"]))):
        _refuse("native_turn_boundary")
    if pending_call_id is None:
        end_fields = {"type", "turn_id", "started_at", "completed_at", "duration_ms", "last_agent_message"}
        if type(end) is not dict or set(end) not in (end_fields, end_fields | {"time_to_first_token_ms"}):
            _refuse("native_turn_boundary")
        if (rows[-1]["type"] != "event_msg" or end["type"] != "task_complete" or start["turn_id"] != end["turn_id"]
                or any(type(value) is not int or value < 0 for value in (end["started_at"], end["completed_at"], end["duration_ms"]))
                or start["started_at"] != end["started_at"] or end["completed_at"] < end["started_at"]
                or "time_to_first_token_ms" in end and (type(end["time_to_first_token_ms"]) is not int or end["time_to_first_token_ms"] < 0)):
            _refuse("native_turn_boundary")
    context, calls, call_kinds, outputs = None, {}, {}, set()
    for index, value in enumerate(rows[1:-1] if pending_call_id is None else rows[1:], 1):
        payload, kind = value["payload"], value["type"]
        if kind == "event_msg" and payload.get("type") in ("task_started", "task_complete", "turn_aborted", "error"):
            _refuse("native_turn_boundary")
        if kind == "turn_context":
            _fields(payload, {"turn_id", "root_turn_id", "cwd", "workspace_roots", "current_date", "timezone", "approval_policy",
                "approvals_reviewer", "sandbox_policy", "permission_profile", "model", "comp_hash", "personality",
                "collaboration_mode", "multi_agent_version", "realtime_active", "effort", "summary"})
            current = {key: payload[key] for key in ("turn_id", "root_turn_id", "model", "effort", "multi_agent_version")}
            if (any(type(item) is not str or not item for item in current.values())
                    or current["turn_id"] != start["turn_id"] or current["multi_agent_version"] != "v1"
                    or context is not None and current != context):
                _refuse("native_turn_context")
            context = current
        if kind == "response_item":
            if payload.get("type") in ("function_call", "custom_tool_call"):
                custom = payload["type"] == "custom_tool_call"
                fields = {"type", "call_id", "id", "namespace", "name", "internal_chat_message_metadata_passthrough"}
                # Codex's unnamespaced function and custom calls omit this optional
                # field. Project None without inserting it into the source row.
                if "namespace" not in payload:fields.remove("namespace")
                _fields(payload, fields | ({"input", "status"} if custom else {"arguments"}))
                if (any(type(payload[key]) is not str or not payload[key] for key in ("call_id", "id", "name"))
                        or payload.get("namespace") is not None and type(payload["namespace"]) is not str
                        or type(payload["input" if custom else "arguments"]) is not str or payload["call_id"] in calls
                        or custom and payload["status"] != "completed"):
                    _refuse("native_turn_action")
                call_kinds[payload["call_id"]] = payload["type"]
                calls[payload["call_id"]] = {"call_id": payload["call_id"], "name": payload["name"],
                    "namespace": payload.get("namespace"), "source_ref": refs[index]}
            elif payload.get("type") in ("function_call_output", "custom_tool_call_output"):
                _fields(payload, {"type", "call_id", "id", "output", "internal_chat_message_metadata_passthrough"})
                if (type(payload["call_id"]) is not str or payload["call_id"] not in calls
                        or payload["call_id"] in outputs or type(payload["id"]) is not str or not payload["id"]
                        or payload["type"] != call_kinds[payload["call_id"]] + "_output"):
                    _refuse("native_turn_result")
                output = payload["output"]
                if payload["type"] == "custom_tool_call_output":
                    if (type(output) is not list or not output or any(type(item) is not dict
                            or set(item) != {"type", "text"} or item["type"] != "input_text"
                            or type(item["text"]) is not str for item in output)):
                        _refuse("native_turn_result")
                elif type(output) is not str:
                    _refuse("native_turn_result")
                outputs.add(payload["call_id"])
            elif payload.get("type") not in ("message", "reasoning"):
                _refuse("native_turn_unsupported_response")
    if context is None or (pending_call_id is None and outputs != set(calls)):
        _refuse("native_turn_incomplete")
    if pending_call_id is not None:
        if set(calls) - outputs != {pending_call_id} or next(reversed(calls)) != pending_call_id:
            _refuse("native_active_call")
        return {"schema": "orch-dork/host-native-v1-active-turn-prefix/v1", "scope": "structural_transport",
            **{key: context[key] for key in ("turn_id", "root_turn_id", "model", "effort")}, "surface": "native-v1",
            "start": {**refs[0], "timestamp": rows[0]["timestamp"]}, "through": {**refs[-1], "timestamp": rows[-1]["timestamp"]},
            "source_refs": refs, "actions": {"count": len(calls), "items": list(calls.values())},
            "pending_call": deepcopy(calls[pending_call_id])}
    return {"schema": "orch-dork/host-native-v1-turn-window/v1", "scope": "structural_transport",
        **{key: context[key] for key in ("turn_id", "root_turn_id", "model", "effort")}, "surface": "native-v1",
        "start": {**refs[0], "timestamp": rows[0]["timestamp"]}, "end": {**refs[-1], "timestamp": rows[-1]["timestamp"]},
        "native_duration_ms": end["duration_ms"], "source_refs": refs,
        "actions": {"count": len(calls), "items": list(calls.values())}}


def native_v1_root_identity(raw: object) -> dict:
    """Select root session identity without exporting its instructions."""
    value, _ = _native_record(raw, "session_meta")
    fields = {"session_id", "id", "timestamp", "cwd", "originator", "cli_version",
              "source", "model_provider", "base_instructions", "history_mode", "context_window", "git"}
    if "dynamic_tools" in value["payload"]:
        fields.add("dynamic_tools")
        tools = value["payload"]["dynamic_tools"]
        if type(tools) is not list or not 1 <= len(tools) <= 32:
            _refuse("native_root_dynamic_tools")
        names = set()
        for tool in tools:
            required = {"type", "name", "description", "inputSchema"}
            if (type(tool) is not dict or set(tool) not in (required, required | {"deferLoading"})
                    or tool["type"] != "function" or type(tool["name"]) is not str or not 0 < len(tool["name"]) <= 128
                    or tool["name"] in names or type(tool["description"]) is not str or type(tool["inputSchema"]) is not dict
                    or "deferLoading" in tool and type(tool["deferLoading"]) is not bool):
                _refuse("native_root_dynamic_tools")
            names.add(tool["name"])
    metadata = _fields(value["payload"], fields)
    if (value["ordinal"] != 0 or metadata["cli_version"] != "0.153.4"
            or type(metadata["id"]) is not str or not metadata["id"] or metadata["session_id"] != metadata["id"]
            or not _absolute(metadata["cwd"])):
        _refuse("native_root_identity")
    return {"task_id": metadata["id"], "session_id": metadata["session_id"], "cwd": metadata["cwd"],
            "canonical_record_sha256": hashlib.sha256(canonical_bytes(value)).hexdigest()}


def native_v1_child_identity(raw: object) -> dict:
    """Project exact first-level native child metadata without inventing a spawn.

    A current owner selects the child; its retained spawn result establishes
    creation. This projection checks the separate owned rollout identity.
    """
    value, _ = _native_record(raw, "session_meta")
    metadata = _fields(value["payload"], {
        "session_id", "id", "parent_thread_id", "timestamp", "cwd", "originator", "cli_version",
        "source", "thread_source", "agent_nickname", "model_provider", "base_instructions",
        "history_mode", "multi_agent_version", "context_window", "git",
    })
    source = _fields(metadata["source"], {"subagent"})
    edge = _fields(_fields(source["subagent"], {"thread_spawn"})["thread_spawn"],
                   {"parent_thread_id", "depth", "agent_path", "agent_nickname", "agent_role"})
    if (value["ordinal"] != 0 or metadata["cli_version"] != "0.153.4" or metadata["multi_agent_version"] != "v1"
            or metadata["thread_source"] != "subagent"
            or any(type(metadata[key]) is not str or not metadata[key] for key in ("id", "session_id", "parent_thread_id", "agent_nickname"))
            or metadata["id"] == metadata["session_id"] or metadata["session_id"] != metadata["parent_thread_id"]
            or edge["parent_thread_id"] != metadata["parent_thread_id"] or type(edge["depth"]) is not int or edge["depth"] != 1
            or edge["agent_path"] is not None or edge["agent_role"] is not None
            or edge["agent_nickname"] != metadata["agent_nickname"] or not _absolute(metadata["cwd"])):
        _refuse("native_child_identity")
    return {"worker_id": metadata["id"], "parent_thread_id": metadata["parent_thread_id"], "cwd": metadata["cwd"],
            "canonical_record_sha256": hashlib.sha256(canonical_bytes(value)).hexdigest()}


def validate_native_v1_turn_window(value: object) -> dict:
    """Check a safe window projection, not authenticity of its referenced rows."""
    return _validate_native_v1_projection(value, active=False)


def validate_native_v1_active_turn_prefix(value: object) -> dict:
    """Validate retained active transport without claiming current-call custody."""
    return _validate_native_v1_projection(value, active=True)


def _validate_native_v1_projection(value: object, *, active: bool) -> dict:
    try:
        window = decode_bounded_response(value)
        _fields(window, {"schema", "scope", "turn_id", "root_turn_id", "model", "effort", "surface", "start", "source_refs", "actions"}
                         | ({"through", "pending_call"} if active else {"end", "native_duration_ms"}))
        schema = "orch-dork/host-native-v1-active-turn-prefix/v1" if active else "orch-dork/host-native-v1-turn-window/v1"
        if (window["schema"] != schema or window["scope"] != "structural_transport"
                or window["surface"] != "native-v1"
                or any(type(window[key]) is not str or not window[key] for key in ("turn_id", "root_turn_id", "model", "effort"))
                or not active and (type(window["native_duration_ms"]) is not int or window["native_duration_ms"] < 0)
                or type(window["source_refs"]) is not list or not 3 <= len(window["source_refs"]) <= 256):
            _refuse("native_window_projection")
        refs = window["source_refs"]
        for index, ref in enumerate(refs):
            _fields(ref, {"line", "sha256"})
            if (type(ref["line"]) is not int or ref["line"] < 1 or type(ref["sha256"]) is not str
                    or len(ref["sha256"]) != 64 or set(ref["sha256"]) - set("0123456789abcdef")
                    or index and ref["line"] != refs[index-1]["line"] + 1):
                _refuse("native_window_projection")
        clocks = []
        for key, ref in (("start", refs[0]), ("through" if active else "end", refs[-1])):
            edge = _fields(window[key], {"line", "sha256", "timestamp"})
            if (type(edge["line"]) is not int or {name: edge[name] for name in ref} != ref
                    or type(edge["timestamp"]) is not str):
                _refuse("native_window_projection")
            clock = datetime.fromisoformat(edge["timestamp"].replace("Z", "+00:00"))
            if clock.tzinfo is None:
                _refuse("native_window_projection")
            clocks.append(clock)
        actions = _fields(window["actions"], {"count", "items"})
        if (clocks[1] < clocks[0] or type(actions["count"]) is not int or type(actions["items"]) is not list
                or actions["count"] != len(actions["items"])):
            _refuse("native_window_projection")
        previous_line, seen = refs[0]["line"], set()
        for action in actions["items"]:
            _fields(action, {"call_id", "name", "namespace", "source_ref"})
            if (any(type(action[key]) is not str or not action[key] for key in ("call_id", "name"))
                    or action["namespace"] is not None and type(action["namespace"]) is not str
                    or action["call_id"] in seen or action["source_ref"] not in (refs[1:] if active else refs[1:-1])
                    or action["source_ref"]["line"] <= previous_line):
                _refuse("native_window_projection")
            seen.add(action["call_id"]); previous_line = action["source_ref"]["line"]
        if active and (not actions["items"] or window["pending_call"] != actions["items"][-1]):
            _refuse("native_active_call")
    except (KeyError, TypeError, ValueError, RecursionError):
        return {"valid": False, "scope": "structural_transport"}
    return {"valid": True, "scope": "structural_transport"}


def native_v1_runtime_window(rows: object) -> dict:
    """Retain raw-line and canonical-record references without equating them.

    The legacy session-runtime observer seals canonical JSON record bytes.
    Native owned-prefix readers seal raw line bytes. Their line identities join
    through this host-owned projection; neither digest is rewritten in place.
    """
    window = native_v1_turn_window(rows)
    references = [{"line": row["line"], "sha256": hashlib.sha256(canonical_bytes(row["record"])).hexdigest()}
                  for row in rows]
    return {"schema": "orch-dork/host-native-v1-runtime-window/v1", "scope": "structural_transport",
            "native_window": window, "canonical_source_refs": references}


def validate_native_v1_runtime_window(value: object) -> dict:
    """Validate the declared digest map; source custody remains host-owned."""
    try:
        value = decode_bounded_response(value)
        if (set(value) != {"schema", "scope", "native_window", "canonical_source_refs"}
                or value["schema"] != "orch-dork/host-native-v1-runtime-window/v1"
                or value["scope"] != "structural_transport"
                or validate_native_v1_turn_window(value["native_window"])["valid"] is not True):
            raise ValueError("invalid native runtime window")
        references = value["canonical_source_refs"]
        source = value["native_window"]["source_refs"]
        if (type(references) is not list or len(references) != len(source)
                or any(type(ref) is not dict or set(ref) != {"line", "sha256"}
                       or type(ref["line"]) is not int or ref["line"] != raw["line"]
                       or type(ref["sha256"]) is not str or len(ref["sha256"]) != 64
                       or set(ref["sha256"]) - set("0123456789abcdef") for ref, raw in zip(references, source))):
            raise ValueError("invalid canonical record references")
    except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
        return {"valid": False, "issues": ["native_runtime_window:invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def native_v1_worker_action_pair(call: object, result: object) -> dict:
    """Bind a continuation receipt or completed close return, not lane release."""
    call_value, call_time = _native_record(call, "response_item")
    result_value, result_time = _native_record(result, "response_item")
    request = _fields(call_value["payload"], {"type", "call_id", "id", "namespace", "name", "arguments",
                                            "internal_chat_message_metadata_passthrough"})
    response = _fields(result_value["payload"], {"type", "call_id", "id", "output", "internal_chat_message_metadata_passthrough"})
    if (request["type"] != "function_call" or response["type"] != "function_call_output"
            or request["namespace"] != "multi_agent_v1" or request["name"] not in ("send_input", "close_agent")
            or any(type(row[key]) is not str or not row[key] for row in (request, response) for key in ("call_id", "id"))
            or request["call_id"] != response["call_id"] or result_value["ordinal"] <= call_value["ordinal"]
            or result_time < call_time or type(request["arguments"]) is not str or type(response["output"]) is not str):
        _refuse("native_worker_action_pair")
    continuation = request["name"] == "send_input"
    args = _fields(decode_response(request["arguments"]), {"target", "message"} if continuation else {"target"})
    if any(type(value) is not str or not value for value in args.values()):
        _refuse("native_worker_action_arguments")
    output = _fields(decode_response(response["output"]), {"submission_id"} if continuation else {"previous_status"})
    if continuation:
        if type(output["submission_id"]) is not str or not output["submission_id"]:
            _refuse("native_worker_submission")
        fact = {"submission_id": output["submission_id"]}
    else:
        previous = _fields(output["previous_status"], {"completed"})
        if type(previous["completed"]) is not str:
            _refuse("native_worker_close")
        fact = {"previous_status": "completed"}
    return {"kind": "continue" if continuation else "close", "worker_id": args["target"],
            "call_id": request["call_id"], **fact,
            "canonical_record_sha256": {key: hashlib.sha256(canonical_bytes(value)).hexdigest()
                                        for key, value in (("call", call_value), ("result", result_value))}}


def _native_source_fields(value: object) -> dict:
    fields = {"task_id", "session_id", "parent_thread_id", "cli_version", "path", "cwd", "status", "turns"}
    if type(value) is not dict or set(value) != fields:
        _refuse("native_thread_source")
    if (any(type(value[key]) is not str or not 0 < len(value[key]) <= 128 for key in ("task_id", "session_id"))
            or value["parent_thread_id"] is not None and (
                type(value["parent_thread_id"]) is not str or not 0 < len(value["parent_thread_id"]) <= 128)
            or value["cli_version"] != "0.153.4" or value["status"] not in ("idle", "notLoaded", "active")):
        _refuse("native_thread_source")
    # Native thread/read changes sessionId when a child is unloaded: live
    # threads share the root session, stored children report their own ID.
    # Keep that observed value. Rollout session_meta has a separate profile.
    session = (value["parent_thread_id"] if value["parent_thread_id"] is not None
               and value["status"] != "notLoaded" else value["task_id"])
    if value["session_id"] != session or value["parent_thread_id"] == value["task_id"]:
        _refuse("native_thread_session")
    for key in ("path", "cwd"):
        path = value[key]
        if (type(path) is not str or not 0 < len(path) <= 4096 or not path.startswith("/") or "\x00" in path
                or any(part in ("", ".", "..") for part in path.split("/")[1:])):
            _refuse("native_thread_path")
    turns = value["turns"]
    if (type(turns) is not list or not 1 <= len(turns) <= 256
            or any(type(turn) is not dict or set(turn) != {"id", "status"} for turn in turns)
            or any(type(turn["id"]) is not str or not 0 < len(turn["id"]) <= 128
                   or turn["status"] not in ("inProgress", "completed", "failed", "interrupted") for turn in turns)
            or len({turn["id"] for turn in turns}) != len(turns)):
        _refuse("native_thread_turns")
    return decode_response(value)


def native_v1_thread_source(raw: object) -> dict:
    """Project source identity and full turn inventory from a bounded owner RPC.

    The owner authenticates the whole response and retains its hash. Private
    item bodies are deliberately not traversed or exported here. This inventory
    says neither that actions were valid nor that resources were released.
    Current thread model settings cannot attest historical execution routing.
    """
    if type(raw) is not dict or set(raw) != {"thread"} or type(raw["thread"]) is not dict:
        _refuse("native_thread_source")
    thread = raw["thread"]
    required = {"id", "sessionId", "parentThreadId", "cliVersion", "path", "cwd", "status", "turns", "ephemeral"}
    if (not required <= set(thread) or thread["ephemeral"] is not False
            or type(thread["status"]) is not dict or type(thread["turns"]) is not list
            or not 1 <= len(thread["turns"]) <= 256):
        _refuse("native_thread_source")
    status = thread["status"]
    if (set(status) != ({"type", "activeFlags"} if status.get("type") == "active" else {"type"})
            or status.get("type") == "active" and type(status["activeFlags"]) is not list):
        _refuse("native_thread_status")
    turns = []
    for turn in thread["turns"]:
        if (type(turn) is not dict or not {"id", "status", "items", "itemsView"} <= set(turn)
                or turn["itemsView"] != "full" or type(turn["items"]) is not list
                or len(turn["items"]) > 256
                or any(type(item) is not dict for item in turn["items"])):
            _refuse("native_thread_turns")
        turns.append({"id": turn["id"], "status": turn["status"]})
    return _native_source_fields({
        "task_id": thread["id"], "session_id": thread["sessionId"], "parent_thread_id": thread["parentThreadId"],
        "cli_version": thread["cliVersion"], "path": thread["path"], "cwd": thread["cwd"],
        "status": status.get("type"), "turns": turns,
    })


def validate_native_v1_thread_source(value: object) -> dict:
    """Validate the safe source projection; this is not owner authentication."""
    try:
        _native_source_fields(value)
    except (values.LifecycleContractError, TypeError, ValueError, KeyError, RecursionError):
        return {"valid": False, "scope": "structural_transport"}
    return {"valid": True, "scope": "structural_transport"}


def _fields(value: object, fields: set[str]) -> dict:
    if type(value) is not dict or set(value) != fields:
        _refuse("observation_fields")
    canonical_bytes(value)
    return value


def _required_fields(value: object, fields: set[str]) -> dict:
    """Require fields while retaining additive host data for forward compatibility."""
    if type(value) is not dict or not fields.issubset(value):
        _refuse("observation_fields")
    canonical_bytes(value)
    return value


def _compatible_fields(value: object, required: set[str], optional: set[str]) -> dict:
    """Accept the pinned shape plus additive fields observed from newer Codex hosts."""
    value = _required_fields(value, required)
    if not set(value).issubset(required | optional):
        _refuse("observation_fields")
    return value


def _compatible_workspace(value: object) -> bool:
    if type(value) is not dict or not {"has_changes"}.issubset(value):
        return False
    if not set(value).issubset({"has_changes", "associated_remote_urls", "latest_git_commit_hash"}):
        return False
    if type(value["has_changes"]) is not bool:
        return False
    remotes = value.get("associated_remote_urls", {})
    if type(remotes) is not dict or any(type(key) is not str or type(url) is not str for key, url in remotes.items()):
        return False
    commit = value.get("latest_git_commit_hash", "")
    return type(commit) is str


def _absolute(path: object) -> bool:
    return (type(path) is str and path.startswith("/") and "\x00" not in path
            and ".." not in PurePosixPath(path).parts and "//" not in path)


def _environment(raw: object) -> dict:
    value = _fields(raw, {"parent", "child"})
    for item in (value["parent"], value["child"]):
        _fields(item, ENVIRONMENT_KEYS)
        if not all(_absolute(path) for path in item.values()):
            _refuse("environment_path")
    if canonical_bytes(value["parent"]) != canonical_bytes(value["child"]):
        _refuse("environment_forwarding")
    return {"forwarded": True, "environment_sha256": hashlib.sha256(canonical_bytes(value["child"])).hexdigest()}


def _owned_file(raw: object) -> dict:
    value = _fields(raw, {"kind", "owner_uid", "caller_uid", "mode", "symlink"})
    modes = {"file": 0o600, "directory": 0o700, "socket": 0o600}
    if (type(value["kind"]) is not str or value["kind"] not in modes
            or any(type(value[k]) is not int or value[k] < 0 for k in ("owner_uid", "caller_uid", "mode"))
            or value["owner_uid"] != value["caller_uid"] or value["symlink"] is not False
            or value["mode"] != modes[value["kind"]]):
        _refuse("file_custody")
    return {"kind": value["kind"], "same_owner": True, "mode": value["mode"], "symlink": False}


def _hooks(raw: object) -> dict:
    value = _fields(raw, {"hooks"})
    if type(value["hooks"]) is not list or len(value["hooks"]) != 5:
        _refuse("hook_inventory")
    found = []
    for item in value["hooks"]:
        _fields(item, {"eventName", "enabled", "trustStatus"})
        name = item["eventName"]
        if (type(name) is not str or name not in HOOK_NAMES or item["enabled"] is not True
                or item["trustStatus"] != "trusted"):
            _refuse("hook_inventory")
        found.append(HOOK_NAMES[name])
    if sorted(found) != sorted(HOOKS):
        _refuse("hook_inventory")
    return {"enabled_trusted_events": sorted(found)}


def _permission(raw: object) -> dict:
    value = _fields(raw, {"hookSpecificOutput"})
    output = value["hookSpecificOutput"]
    if (type(output) is not dict or not {"hookEventName"} <= set(output)
            or set(output) - {"hookEventName", "permissionDecision", "permissionDecisionReason", "additionalContext"}
            or output["hookEventName"] != "PreToolUse"):
        _refuse("permission_shape")
    if "additionalContext" in output and type(output["additionalContext"]) is not str:
        _refuse("permission_shape")
    if "permissionDecision" not in output:
        if "permissionDecisionReason" in output:
            _refuse("permission_shape")
        return {"hook_disposition": "no_denial", "authority_granted": False}
    if output["permissionDecision"] != "deny":
        _refuse("permission_value")
    if "permissionDecisionReason" in output and type(output["permissionDecisionReason"]) is not str:
        _refuse("permission_shape")
    return {"hook_disposition": "deny", "authority_granted": False}


class CodexHostAdapter:
    """Normalize only fixture-qualified shapes for one exact host profile."""

    def __init__(self, host_profile: object):
        if canonical_bytes(host_profile) != canonical_bytes(HOST_PROFILE.to_plain()):
            _refuse("unqualified_host")

    def execute_current(self, action: object, authority_store: object, transport: object) -> object:
        """Forward one exact controller action and return the raw observation.

        The production adapter supplies its real NativeGrantStore. Its public
        verified authority projection owns the current-action decision; this
        bridge checks byte identity, never creates or advances a grant. The
        transport must invoke the official native tool through normal hooks:
        those hooks retain atomic grant consumption and race protection.
        Exceptions propagate unchanged, with no retry or fallback.
        """
        submitted = decode_response(action)
        declared = submitted.get("action_sha256")
        core = {key: value for key, value in submitted.items() if key != "action_sha256"}
        if (type(declared) is not str or hashlib.sha256(canonical_bytes(core)).hexdigest() != declared
                or "tool_input" not in submitted
                or hashlib.sha256(canonical_bytes(submitted["tool_input"])).hexdigest()
                != submitted.get("tool_input_sha256")):
            _refuse("action_identity")
        canonical_tool_name(submitted.get("tool_name"))
        authority = authority_store.canonical_authority()
        if type(authority) is not dict or authority.get("status") != "VERIFIED":
            _refuse("current_authority")
        lifecycle = authority.get("lifecycle")
        if (type(lifecycle) is not dict or lifecycle.get("expected_binding_status") != "ACTIVE"
                or lifecycle.get("grant_state") != "AUTHORIZED"
                or lifecycle.get("action_sha256") != declared):
            _refuse("current_action")
        return transport(submitted)

    def normalize(self, kind: str, raw: object) -> object:
        if type(kind) is not str or kind not in OBSERVATIONS:
            _refuse("observation_kind")
        if kind == "tool_name":
            return canonical_tool_name(raw)
        if kind == "response":
            return decode_response(raw)
        if kind == "completed_mcp_tool_call":
            return completed_mcp_tool_call(raw)
        if kind == "mcp_call_context":
            return mcp_call_context(raw)
        if kind == "newline_frame":
            if type(raw) is not str or not raw.endswith("\n") or raw.count("\n") != 1:
                _refuse("newline_frame")
            return decode_response(raw)
        if kind == "environment":
            return _environment(raw)
        if kind == "owned_file":
            return _owned_file(raw)
        if kind == "hook_inventory":
            return _hooks(raw)
        if kind == "permission":
            return _permission(raw)
        if kind == "javascript_globals":
            expected = {"tools": "object", "process": "undefined", "console": "undefined",
                        "fetch": "undefined", "Buffer": "undefined", "TextEncoder": "undefined",
                        "JSON": "object", "Promise": "function"}
            if canonical_bytes(raw) != canonical_bytes(expected):
                _refuse("javascript_globals")
            return {"tool_bridge": "tools", "ambient_io": False}
        if kind == "session_start":
            value = _fields(raw, {"source", "first_turn_started"})
            if value["source"] != "startup" or value["first_turn_started"] is not False:
                _refuse("session_start_timing")
            return {"startup_before_first_turn": True}
        value = _fields(raw, {"isatty", "exit_code", "stdout", "stderr", "owned_descendants"})
        if (value["isatty"] is not True or type(value["exit_code"]) is not int
                or value["exit_code"] != 0 or type(value["owned_descendants"]) is not int
                or value["owned_descendants"] != 0
                or any(type(value[k]) is not str for k in ("stdout", "stderr"))):
            _refuse("pty_observation")
        if any(len(value[k].encode("utf-8")) > MAX_STREAM_BYTES for k in ("stdout", "stderr")):
            _refuse("pty_stream_size")
        return decode_response(canonical_bytes(value).decode("utf-8"))
