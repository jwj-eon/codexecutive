"""Join a pinned owner's native two-lane trace without granting final authority.

The qualification producer supplies its sealed identities and expected routes.
This reader discovers paths from that owner, reads owned prefixes, selects the
complete root extent containing both workers and the review turn, and checks the
owner again afterward. It never dispatches a task or infers resource release
from a close return. Legacy manifest observations remain separately replayable.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from lifecycle_conformance import host_adapter as host
import orch_dork_codex_usage as usage
import orch_dork_local_task_runtime as owner
import orch_dork_owned_file as owned
import orch_dork_qualification_progress as progress
import orch_dork_routing_verify as routing
import orch_dork_adaptive_contracts as contracts

SCHEMA = "orch-dork/native-two-lane-attempt-observation/v1"
CHECKPOINT_SCHEMA = "orch-dork/native-worker-checkpoint-observation/v1"
_CHECKPOINT_ARRIVAL_SCHEMA = "orch-dork/native-worker-checkpoint-arrival-observation/v1"
_LANES = ("spec", "standards")
_ISSUES = {"native_attempt:" + name for name in (
    "partial_line", "source_bounds", "source_order", "metadata_missing", "record_outside_turn", "turn_bounds",
    "turn_incomplete", "owner_turn_mismatch", "route_mismatch", "usage_unavailable", "usage_window_mismatch",
    "root_identity_mismatch", "worker_extent_invalid", "root_extent_invalid", "unexpected_worker", "spawn_mismatch",
    "worker_lifecycle_mismatch", "worker_clock_mismatch", "private_root_unavailable", "owner_changed_during_read",
    "source_unavailable", "report_bounds", "owner_sources_unavailable")}


def _digest(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and not set(value) - set("0123456789abcdef")


def _clock(value: Any) -> datetime:
    if type(value) is not str:
        raise ValueError("native_attempt:source_order")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("native_attempt:source_order")
    return stamp


def _native_pairs(rows: list[dict]) -> list[dict]:
    calls, pairs = {}, []
    for row in rows:
        value, payload = row["record"], row["record"]["payload"]
        if value["type"] != "response_item":
            continue
        if payload.get("type") == "function_call" and payload.get("namespace") == "multi_agent_v1":
            calls[payload["call_id"]] = row
        elif payload.get("type") == "function_call_output" and payload.get("call_id") in calls:
            pairs.append({"call": calls[payload["call_id"]], "result": row})
    return pairs


def _expectation(value: Any) -> dict:
    value = host.decode_bounded_response(value)
    if (set(value) != {"owner", "root", "lanes"} or type(value["root"]) is not dict
            or set(value["root"]) != {"model", "effort", "review_turn_id"}
            or type(value["lanes"]) is not dict or set(value["lanes"]) != set(_LANES)):
        raise ValueError("native_attempt:expectation_invalid")
    # The owner observer validates the fixed task and authority identities
    # before connecting. Validate its closed selection here without any I/O.
    selected = value["owner"]
    fields = {"root_task_id", "worker_ids", "owner_identity_sha256", "app_server_argv_sha256", "hook_inventory_report_sha256"}
    if (type(selected) is not dict or set(selected) != fields or type(selected["worker_ids"]) is not dict
            or set(selected["worker_ids"]) != set(_LANES)):
        raise ValueError("native_attempt:expectation_invalid")
    ids = [selected["root_task_id"], *selected["worker_ids"].values()]
    if (any(type(item) is not str or not 0 < len(item) <= 128 for item in ids) or len(set(ids)) != 3
            or any(type(selected[key]) is not str or len(selected[key]) != 64
                   or set(selected[key]) - set("0123456789abcdef") for key in fields - {"root_task_id", "worker_ids"})):
        raise ValueError("native_attempt:expectation_invalid")
    for route in (value["root"], *value["lanes"].values()):
        if (type(route) is not dict or set(route) not in ({"model", "effort"}, {"model", "effort", "review_turn_id"})
                or any(type(item) is not str or not 0 < len(item) <= 128 for item in route.values())):
            raise ValueError("native_attempt:expectation_invalid")
    if any(set(value["lanes"][lane]) != {"model", "effort"} for lane in _LANES):
        raise ValueError("native_attempt:expectation_invalid")
    return value


def _scan(source: dict, private_root: Path, *, retain_runtime: bool = False, retain_raw: bool = False,
          pending_call_id: str | None = None) -> dict:
    snapshot = owned.read_private_rollout(source["path"], private_root=private_root)
    raw = snapshot["raw"]
    if not raw.endswith(b"\n"):
        raise ValueError("native_attempt:partial_line")
    metadata = None
    turns, current = [], []
    offset, line_number, previous_stamp = 0, 0, None
    while offset < len(raw):
        end = raw.find(b"\n", offset)
        line_number += 1
        if end < offset or end - offset > host.MAX_BYTES or line_number > 1 + 256 * 256:
            raise ValueError("native_attempt:source_bounds")
        line = raw[offset:end]
        offset = end + 1
        record = host.decode_bounded_response(host.decode_response(line.decode("utf-8")))
        if (set(record) != {"type", "ordinal", "timestamp", "payload"}
                or type(record["ordinal"]) is not int or record["ordinal"] != line_number - 1
                or type(record["payload"]) is not dict):
            raise ValueError("native_attempt:source_order")
        stamp = _clock(record["timestamp"])
        if previous_stamp is not None and stamp < previous_stamp:
            raise ValueError("native_attempt:source_order")
        previous_stamp = stamp
        row = {"line": line_number, "sha256": hashlib.sha256(line).hexdigest(), "record": record}
        if line_number == 1:
            if record["type"] != "session_meta":
                raise ValueError("native_attempt:metadata_missing")
            metadata = row
            continue
        kind = record["payload"].get("type") if record["type"] == "event_msg" else None
        if not current and kind != "task_started":
            raise ValueError("native_attempt:record_outside_turn")
        current.append(row)
        if len(current) > 256:
            raise ValueError("native_attempt:turn_bounds")
        if kind == "task_complete":
            window = host.native_v1_turn_window(current)
            telemetry = []
            for item in current:
                value, payload = item["record"], item["record"]["payload"]
                if (value["type"] == "token_usage_record"
                        or value["type"] == "event_msg" and payload.get("type") == "token_count"):
                    telemetry.append(item)
            turns.append({"window": window, "native_pairs": _native_pairs(current), "telemetry": telemetry})
            if retain_runtime:
                turns[-1].update(runtime_window=host.native_v1_runtime_window(current),
                                 terminal_text=current[-1]["record"]["payload"]["last_agent_message"])
            current = []
    active = None
    if pending_call_id is not None and current:
        active = {"prefix": host.native_v1_active_turn_prefix(current, pending_call_id=pending_call_id),
                  "native_pairs": _native_pairs(current),
                  "telemetry": [row for row in current if row["record"]["type"] == "token_usage_record"
                      or row["record"]["type"] == "event_msg" and row["record"]["payload"].get("type") == "token_count"]}
    if (current and active is None) or metadata is None or (pending_call_id is not None and active is None):
        raise ValueError("native_attempt:turn_incomplete")
    observed = [{"id": turn["window"]["turn_id"], "status": "completed"} for turn in turns]
    if active is not None:observed.append({"id": active["prefix"]["turn_id"], "status": "inProgress"})
    if observed != source["turns"]:
        raise ValueError("native_attempt:owner_turn_mismatch")
    result = {"metadata": metadata, "turns": turns, "path": source["path"], "file_sha256": snapshot["file_sha256"],
              "custody": snapshot["custody"], "prefix_bytes": snapshot["prefix_bytes"]}
    if retain_runtime or retain_raw:result["raw"] = raw
    if active is not None:result["active"] = active
    return result


def _role(scan: dict, turns: list[dict], *, task_id: str, root_id: str, route: dict) -> dict:
    windows = [turn["window"] for turn in turns]
    if not windows or any(window["model"] != route["model"] or window["effort"] != route["effort"] for window in windows):
        raise ValueError("native_attempt:route_mismatch")
    telemetry = usage.build_usage_observation([row for turn in turns for row in turn["telemetry"]],
                                              thread_id=task_id, turn_ids=[window["turn_id"] for window in windows])
    if telemetry["status"] != "OBSERVED" or telemetry["session_id"] != root_id:
        raise ValueError("native_attempt:usage_unavailable")
    if [turn["root_turn_id"] for turn in telemetry["per_turn"]] != [window["root_turn_id"] for window in windows]:
        raise ValueError("native_attempt:usage_window_mismatch")
    return {key: deepcopy(scan[key]) for key in ("path", "file_sha256", "prefix_bytes", "custody")} | {
        "task_id": task_id, "metadata_source_ref": {key: scan["metadata"][key] for key in ("line", "sha256")},
        "windows": windows, "usage": telemetry}


def _checkpoint_expectation(value: Any) -> dict:
    value = host.decode_bounded_response(value)
    if set(value) != {"sources", "lanes"} or type(value["lanes"]) is not dict or set(value["lanes"]) != set(_LANES):
        raise ValueError("native_checkpoint:expectation_invalid")
    owner._checkpoint_source_expectation(value["sources"])
    for lane in value["lanes"].values():
        if (type(lane) is not dict or set(lane) != {"task_spec_sha256", "model", "effort", "root_turn_id"}
                or not _digest(lane["task_spec_sha256"])
                or any(type(lane[key]) is not str or not 0 < len(lane[key]) <= 128 for key in ("model", "effort", "root_turn_id"))):
            raise ValueError("native_checkpoint:expectation_invalid")
    return value


def _checkpoint_arrival_expectation(value: Any) -> dict:
    value = host.decode_bounded_response(value)
    if type(value) is not dict or set(value) != {"sources", "root", "lanes"}:
        raise ValueError("native_checkpoint_arrival:expectation_invalid")
    checkpoint = _checkpoint_expectation({"sources": value["sources"], "lanes": value["lanes"]})
    root = value["root"]
    if (type(root) is not dict or set(root) != {"model", "effort", "pending_call"}
            or any(type(root[key]) is not str or not 0 < len(root[key]) <= 128 for key in ("model", "effort"))):
        raise ValueError("native_checkpoint_arrival:expectation_invalid")
    call = root["pending_call"]
    if (type(call) is not dict or set(call) != {"call_id", "name", "namespace"}
            or any(type(call[key]) is not str or not 0 < len(call[key]) <= 128 for key in ("call_id", "name"))
            or call["namespace"] is not None
            and (type(call["namespace"]) is not str or not 0 < len(call["namespace"]) <= 128)):
        raise ValueError("native_checkpoint_arrival:expectation_invalid")
    return {"sources": checkpoint["sources"], "root": root, "lanes": checkpoint["lanes"]}


def _checkpoint_worker(expected: dict, lane: str, source: dict, scan: dict, task_spec: dict) -> dict:
    selected = expected["sources"]
    root_id, worker_id = selected["owner"]["root_task_id"], selected["owner"]["worker_ids"][lane]
    route = expected["lanes"][lane]
    identity = host.native_v1_child_identity(scan["metadata"]["record"])
    if (identity["worker_id"] != worker_id or identity["parent_thread_id"] != root_id or identity["cwd"] != source["cwd"]
            or len(scan["turns"]) != 2 or any(turn["window"]["actions"]["count"] != 0 for turn in scan["turns"])):
        raise ValueError("native_checkpoint:worker_identity_or_actions")
    terminal = scan["turns"][-1]
    binding = {"logical_worker_id": lane, "worker_id": worker_id, "observer_id": root_id,
               "turn_id": selected["worker_turn_ids"][lane], **{key: route[key] for key in ("model", "effort", "root_turn_id")}}
    runtime = routing.build_session_runtime_observation(scan["raw"], session_id=worker_id, observer_id=root_id)
    report = progress.build_worker_progress_report(task_spec, binding, host.decode_response(terminal["terminal_text"]),
                                                  terminal["runtime_window"], runtime)
    role = _role(scan, scan["turns"], task_id=worker_id, root_id=root_id, route=route)
    if (runtime["source_sha256"] != scan["file_sha256"]
            or any(runtime["usage"][key] != role["usage"]["totals"][key] for key in ("input_tokens", "output_tokens", "total_tokens"))):
        raise ValueError("native_checkpoint:usage_mismatch")
    return {"progress_report": report, "source": role, "child_identity": identity}


def _check_checkpoint_evidence(expected: dict, evidence: Any, *, lanes: tuple[str, ...] = _LANES,
                               arrival: bool = False) -> None:
    if (type(lanes) is not tuple or not lanes or len(set(lanes)) != len(lanes)
            or any(lane not in _LANES for lane in lanes)
            or type(arrival) is not bool):
        raise ValueError("native_checkpoint:evidence_invalid")
    validator = (owner.validate_worker_checkpoint_arrival_sources if arrival
                 else owner.validate_worker_checkpoint_sources)
    if (type(evidence) is not dict or set(evidence) != {"source_inventory", "source_inventory_after_sha256", "workers"}
            or validator(evidence["source_inventory"])["valid"] is not True):
        raise ValueError("native_checkpoint:evidence_invalid")
    inventory = evidence["source_inventory"]
    if (inventory["status"] != "OBSERVED" or inventory["expectation"] != expected["sources"]
            or evidence["source_inventory_after_sha256"] != inventory["report_sha256"]
            or arrival and inventory["observation"]["completed_lane_ids"] != list(lanes)
            or type(evidence["workers"]) is not dict or set(evidence["workers"]) != set(lanes)):
        raise ValueError("native_checkpoint:evidence_invalid")
    root_id = expected["sources"]["owner"]["root_task_id"]
    root_turns = [t["id"] for t in inventory["observation"]["sources"]["root"]["turns"]]
    for lane in lanes:
        row = evidence["workers"][lane]
        if type(row) is not dict or set(row) != {"progress_report", "source", "child_identity"}:
            raise ValueError("native_checkpoint:evidence_invalid")
        report, source, identity = row["progress_report"], row["source"], row["child_identity"]
        discovered = inventory["observation"]["sources"][lane]
        route = expected["lanes"][lane]
        worker = expected["sources"]["owner"]["worker_ids"][lane]
        binding = {"logical_worker_id": lane, "worker_id": worker, "observer_id": root_id,
                   "turn_id": expected["sources"]["worker_turn_ids"][lane], **{key: route[key] for key in ("model", "effort", "root_turn_id")}}
        if (progress.validate_worker_progress_report(report)["valid"] is not True or report["binding"] != binding
                or report["task_spec"]["task_spec_sha256"] != route["task_spec_sha256"]
                or type(identity) is not dict or set(identity) != {"worker_id", "parent_thread_id", "cwd", "canonical_record_sha256"}
                or identity["worker_id"] != worker or identity["parent_thread_id"] != root_id
                or identity["cwd"] != discovered["cwd"] or not _digest(identity["canonical_record_sha256"])):
            raise ValueError("native_checkpoint:evidence_invalid")
        if (type(source) is not dict or set(source) != {"path", "file_sha256", "prefix_bytes", "custody", "task_id", "metadata_source_ref", "windows", "usage"}
                or source["task_id"] != worker or source["path"] != discovered["path"]
                or source["file_sha256"] != report["runtime_observation"]["source_sha256"]
                or type(source["prefix_bytes"]) is not int or not 0 < source["prefix_bytes"] <= owned.MAX_PRIVATE_ROLLOUT_BYTES):
            raise ValueError("native_checkpoint:evidence_invalid")
        custody = source["custody"]
        if (type(custody) is not dict or set(custody) != {"status", "scope", "owner_uid", "private_root_mode", "file_mode", "device", "inode", "links", "read_passes", "prefix_bytes", "link_identity_checked"}
                or custody["status"] != "observed" or custody["scope"] != "owned_prefix_snapshot" or custody["link_identity_checked"] is not True
                or any(type(custody[k]) is not int or custody[k] < 0 for k in ("owner_uid", "private_root_mode", "file_mode", "device", "inode", "links", "read_passes", "prefix_bytes"))
                or custody["private_root_mode"] > 0o7777 or custody["private_root_mode"] & 0o077
                or custody["file_mode"] > 0o7777 or custody["file_mode"] & 0o002
                or custody["links"] != 1 or custody["read_passes"] != 2 or custody["prefix_bytes"] != source["prefix_bytes"]):
            raise ValueError("native_checkpoint:evidence_invalid")
        metadata, windows, telemetry = source["metadata_source_ref"], source["windows"], source["usage"]
        if (type(metadata) is not dict or set(metadata) != {"line", "sha256"} or type(metadata["line"]) is not int
                or metadata["line"] != 1 or not _digest(metadata["sha256"])
                or type(windows) is not list or len(windows) != 2
                or any(host.validate_native_v1_turn_window(w)["valid"] is not True for w in windows)
                or [w["turn_id"] for w in windows] != [t["id"] for t in discovered["turns"]]
                or windows[1] != report["native_source"]["native_window"]
                or any(w["model"] != route["model"] or w["effort"] != route["effort"] or w["actions"]["count"] != 0
                       or w["root_turn_id"] not in root_turns for w in windows)
                or windows[0]["start"]["line"] != 2 or windows[1]["start"]["line"] != windows[0]["end"]["line"] + 1
                or _clock(windows[1]["start"]["timestamp"]) < _clock(windows[0]["end"]["timestamp"])):
            raise ValueError("native_checkpoint:evidence_invalid")
        if (usage.validate_usage_observation(telemetry)["valid"] is not True or telemetry["status"] != "OBSERVED"
                or telemetry["thread_id"] != worker or telemetry["session_id"] != root_id
                or telemetry["turn_ids"] != [w["turn_id"] for w in windows]
                or [t["root_turn_id"] for t in telemetry["per_turn"]] != [w["root_turn_id"] for w in windows]
                or any({"line": ref["line"], "sha256": ref["sha256"]} not in [r for w in windows for r in w["source_refs"]]
                       for ref in telemetry["source_refs"])
                or any(telemetry["totals"][key] != report["runtime_observation"]["usage"][key]
                       for key in ("input_tokens", "output_tokens", "total_tokens"))):
            raise ValueError("native_checkpoint:evidence_invalid")


def observe_native_worker_checkpoints(expectation: Any, task_specs: Any, *, env: Mapping[str, str] | None = None) -> dict:
    """Read exact idle worker prefixes from the active root's pinned owner.

    This producer checks source custody, native identity, complete checkpoint
    turns, routes and cumulative usage. It grants no continuation or terminal
    authority. The controller must derive the selection and call it itself.
    """
    expected = _checkpoint_expectation(expectation)
    host.decode_bounded_response(task_specs)
    if (set(task_specs) != set(_LANES) or any(contracts.validate_task_spec(task_specs[lane])["valid"] is not True
            or task_specs[lane].get("task_spec_sha256") != expected["lanes"][lane]["task_spec_sha256"] for lane in _LANES)):
        raise ValueError("native_checkpoint:tasks_invalid")
    environment = os.environ if env is None else env
    evidence = None
    try:
        private = environment.get("CODEX_HOME")
        if not private and type(environment.get("HOME")) is str:private = str(Path(environment["HOME"]) / ".codex")
        if type(private) is not str or not private.startswith("/"):
            raise ValueError("native_checkpoint:private_root_unavailable")
        before = owner.observe_worker_checkpoint_sources(expected["sources"], env=environment)
        if owner.validate_worker_checkpoint_sources(before)["valid"] is not True or before["expectation"] != expected["sources"]:
            raise ValueError("native_checkpoint:owner_sources_unavailable")
        if before["status"] != "OBSERVED":
            status, issues = before["status"], ["native_checkpoint:owner_sources_unavailable"]
        else:
            workers = {}
            for lane in _LANES:
                source = before["observation"]["sources"][lane]
                scan = _scan(source, Path(private), retain_runtime=True)
                workers[lane] = _checkpoint_worker(expected, lane, source, scan, task_specs[lane])
            after = owner.observe_worker_checkpoint_sources(expected["sources"], env=environment)
            if host.canonical_bytes(after) != host.canonical_bytes(before):raise ValueError("native_checkpoint:owner_changed_during_read")
            evidence = {"source_inventory": before, "source_inventory_after_sha256": after["report_sha256"], "workers": workers}
            _check_checkpoint_evidence(expected, evidence)
            status, issues = "OBSERVED", []
    except (KeyError, TypeError, ValueError, OSError, RecursionError, OverflowError) as error:
        evidence = None
        status, issues = "REFUSED", [str(error) if str(error) in _CHECKPOINT_ISSUES else "native_checkpoint:source_unavailable"]
    core = {"schema": CHECKPOINT_SCHEMA, "status": status, "issues": issues, "expectation": expected, "evidence": evidence,
            "scope": "owned_native_transport", "continuation_permitted": False, "terminal_claim_permitted": False,
            "provider_free": True, "native_calls": 0, "model_calls": 0, "cost_usd": None}
    try:host.decode_bounded_response({**core, "report_sha256": "0" * 64})
    except ValueError:core.update(status="REFUSED", issues=["native_checkpoint:report_bounds"], evidence=None)
    return {**core, "report_sha256": hashlib.sha256(host.canonical_bytes(core)).hexdigest()}


_CHECKPOINT_ISSUES = {"native_checkpoint:" + name for name in (
    "source_unavailable", "private_root_unavailable", "owner_sources_unavailable", "owner_changed_during_read",
    "evidence_invalid", "worker_identity_or_actions", "usage_mismatch", "report_bounds")}


def validate_native_worker_checkpoint_observation(report: Any) -> dict:
    """Validate full retained checkpoint transport, without live source custody."""
    try:
        value = host.decode_bounded_response(report)
        if (set(value) != {"schema", "status", "issues", "expectation", "evidence", "scope", "continuation_permitted", "terminal_claim_permitted",
                          "provider_free", "native_calls", "model_calls", "cost_usd", "report_sha256"}
                or value["schema"] != CHECKPOINT_SCHEMA or value["scope"] != "owned_native_transport"
                or value["continuation_permitted"] is not False or value["terminal_claim_permitted"] is not False
                or value["provider_free"] is not True or value["cost_usd"] is not None
                or any(type(value[k]) is not int or value[k] != 0 for k in ("native_calls", "model_calls"))
                or value["report_sha256"] != hashlib.sha256(host.canonical_bytes({k:v for k,v in value.items() if k != "report_sha256"})).hexdigest()):
            raise ValueError("invalid transport")
        expected = _checkpoint_expectation(value["expectation"])
        if value["status"] == "OBSERVED":
            if value["issues"] != []:raise ValueError("observed with issues")
            _check_checkpoint_evidence(expected, value["evidence"])
        elif value["status"] in {"PENDING", "REFUSED"}:
            if (value["evidence"] is not None or type(value["issues"]) is not list or len(value["issues"]) != 1
                    or type(value["issues"][0]) is not str or value["issues"][0] not in _CHECKPOINT_ISSUES
                    or value["status"] == "PENDING" and value["issues"] != ["native_checkpoint:owner_sources_unavailable"]):
                raise ValueError("invalid negative transport")
        else:raise ValueError("invalid status")
    except (KeyError, TypeError, ValueError, OSError, RecursionError, OverflowError):
        return {"valid": False, "issues": ["native_checkpoint:report_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def _checkpoint_arrival_spawn_request(call: dict, result: dict) -> dict:
    """Validate a root spawn pair without opening an unfinished child rollout."""
    call_value = host.decode_bounded_response(call)
    result_value = host.decode_bounded_response(result)
    call_fields = {"type", "call_id", "id", "namespace", "name", "arguments",
                   "internal_chat_message_metadata_passthrough"}
    result_fields = {"type", "call_id", "id", "output",
                     "internal_chat_message_metadata_passthrough"}
    request, response = call_value.get("payload"), result_value.get("payload")
    if (call_value.get("type") != "response_item"
            or result_value.get("type") != "response_item"
            or type(request) is not dict or set(request) != call_fields
            or type(response) is not dict or set(response) != result_fields
            or request["type"] != "function_call"
            or response["type"] != "function_call_output"
            or request["namespace"] != "multi_agent_v1"
            or request["name"] != "spawn_agent"
            or any(type(row[key]) is not str or not row[key]
                   for row in (request, response) for key in ("call_id", "id"))
            or request["call_id"] != response["call_id"]
            or type(request["arguments"]) is not str
            or type(response["output"]) is not str
            or _clock(result_value["timestamp"]) < _clock(call_value["timestamp"])):
        raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
    arguments = host.decode_response(request["arguments"])
    output = host.decode_response(response["output"])
    legacy_fields = {"message", "model", "reasoning_effort", "fork_context"}
    current_fields = {
        "task_name", "fork_turns", "message", "model", "reasoning_effort",
    }
    if (type(arguments) is not dict
            or set(arguments) not in (legacy_fields, current_fields)
            or type(output) is not dict or set(output) != {"agent_id", "nickname"}
            or (set(arguments) == legacy_fields
                and arguments["fork_context"] is not False)
            or (set(arguments) == current_fields
                and (arguments["fork_turns"] != "none"
                     or type(arguments["task_name"]) is not str
                     or not arguments["task_name"]))
            or any(type(arguments[key]) is not str or not arguments[key]
                   for key in ("message", "model", "reasoning_effort"))
            or any(type(output[key]) is not str or not output[key]
                   for key in ("agent_id", "nickname"))):
        raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
    return {"kind": "spawn", "worker_id": output["agent_id"],
            "call_id": request["call_id"], "model": arguments["model"],
            "effort": arguments["reasoning_effort"]}


def _checkpoint_arrival_actions(expected: dict, root_scan: dict,
                                worker_scans: dict[str, dict]) -> dict[str, list[dict]]:
    root_id = expected["sources"]["owner"]["root_task_id"]
    by_worker = {worker: lane for lane, worker in expected["sources"]["owner"]["worker_ids"].items()}
    events = {lane: [] for lane in _LANES}
    active = root_scan["active"]
    for pair in active["native_pairs"]:
        call_row, result_row = pair["call"], pair["result"]
        call, result = call_row["record"], result_row["record"]
        name = call["payload"].get("name")
        if name == "spawn_agent":
            request_fact = _checkpoint_arrival_spawn_request(call, result)
            lane = by_worker.get(request_fact["worker_id"])
            if lane is None:
                raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
            if lane in worker_scans:
                fact = {"kind": "spawn", **host.native_v1_spawn_pair(
                    call, result, worker_scans[lane]["metadata"]["record"])}
                if any(fact[key] != request_fact[key]
                       for key in ("kind", "worker_id", "call_id", "model", "effort")):
                    raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
            else:
                fact = request_fact
        elif name in {"send_input", "close_agent"}:
            fact = host.native_v1_worker_action_pair(call, result)
            lane = by_worker.get(fact["worker_id"])
            if lane is None:
                raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
        else:
            raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
        events[lane].append({**fact, "turn_id": active["prefix"]["turn_id"],
            "call_timestamp": call["timestamp"], "result_timestamp": result["timestamp"],
            "source_refs": {key: {field: pair[key][field] for field in ("line", "sha256")}
                            for key in ("call", "result")}})
    for lane, rows in events.items():
        if [row["kind"] for row in rows] != ["spawn", "continue"]:
            raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
        spawn, continued = rows
        route = expected["lanes"][lane]
        if (spawn["worker_id"] != expected["sources"]["owner"]["worker_ids"][lane]
                or spawn["model"] != route["model"] or spawn["effort"] != route["effort"]
                or continued["worker_id"] != spawn["worker_id"]
                or continued["submission_id"] != expected["sources"]["worker_turn_ids"][lane]):
            raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
        if lane in worker_scans and spawn["parent_thread_id"] != root_id:
            raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
    return {lane: events[lane] for lane in worker_scans}


def _checkpoint_arrival_root(expected: dict, inventory: dict, scan: dict,
                             worker_scans: dict[str, dict]) -> dict:
    source = inventory["observation"]["sources"]["root"]
    active = scan["active"]
    if active is None:
        raise ValueError("native_checkpoint_arrival:root_invalid")
    return {
        "source": {**{key: scan[key] for key in ("path", "file_sha256", "prefix_bytes", "custody")},
                   "metadata_source_ref": {key: scan["metadata"][key] for key in ("line", "sha256")}},
        "identity": host.native_v1_root_identity(scan["metadata"]["record"]),
        "windows": [turn["window"] for turn in scan["turns"]],
        "active_prefix": active["prefix"],
        "worker_actions": _checkpoint_arrival_actions(expected, scan, worker_scans),
    }


def _check_checkpoint_arrival_root(expected: dict, inventory: dict, value: Any,
                                   lanes: tuple[str, ...], workers: dict) -> None:
    if (type(value) is not dict
            or set(value) != {"source", "identity", "windows", "active_prefix", "worker_actions"}):
        raise ValueError("native_checkpoint_arrival:root_invalid")
    discovered = inventory["observation"]["sources"]["root"]
    source, identity = value["source"], value["identity"]
    if (type(source) is not dict
            or set(source) != {"path", "file_sha256", "prefix_bytes", "custody", "metadata_source_ref"}
            or source["path"] != discovered["path"] or not _digest(source["file_sha256"])
            or type(source["prefix_bytes"]) is not int or not 0 < source["prefix_bytes"] <= owned.MAX_PRIVATE_ROLLOUT_BYTES
            or type(identity) is not dict
            or set(identity) != {"task_id", "session_id", "cwd", "canonical_record_sha256"}
            or identity["task_id"] != discovered["task_id"] or identity["session_id"] != discovered["task_id"]
            or identity["cwd"] != discovered["cwd"] or not _digest(identity["canonical_record_sha256"])):
        raise ValueError("native_checkpoint_arrival:root_invalid")
    custody, metadata = source["custody"], source["metadata_source_ref"]
    if (type(custody) is not dict
            or set(custody) != {"status", "scope", "owner_uid", "private_root_mode", "file_mode", "device", "inode",
                                "links", "read_passes", "prefix_bytes", "link_identity_checked"}
            or custody["status"] != "observed" or custody["scope"] != "owned_prefix_snapshot"
            or custody["link_identity_checked"] is not True
            or any(type(custody[key]) is not int or custody[key] < 0 for key in (
                "owner_uid", "private_root_mode", "file_mode", "device", "inode", "links", "read_passes", "prefix_bytes"))
            or custody["private_root_mode"] > 0o7777 or custody["private_root_mode"] & 0o077
            or custody["file_mode"] > 0o7777 or custody["file_mode"] & 0o002
            or custody["links"] != 1 or custody["read_passes"] != 2
            or custody["prefix_bytes"] != source["prefix_bytes"]
            or type(metadata) is not dict or set(metadata) != {"line", "sha256"}
            or type(metadata["line"]) is not int or metadata["line"] != 1
            or not _digest(metadata["sha256"])):
        raise ValueError("native_checkpoint_arrival:root_invalid")
    windows, active = value["windows"], value["active_prefix"]
    all_windows = [*windows, active]
    if (type(windows) is not list
            or any(host.validate_native_v1_turn_window(window)["valid"] is not True for window in windows)
            or host.validate_native_v1_active_turn_prefix(active)["valid"] is not True
            or {key: active["pending_call"][key] for key in expected["root"]["pending_call"]}
               != expected["root"]["pending_call"]
            or [window["turn_id"] for window in all_windows] != [turn["id"] for turn in discovered["turns"]]
            or active["turn_id"] != expected["sources"]["root_turn_id"]
            or any(window["root_turn_id"] != window["turn_id"]
                   or window["model"] != expected["root"]["model"]
                   or window["effort"] != expected["root"]["effort"] for window in all_windows)
            or any(later["start"]["line"] != earlier["end"]["line"] + 1
                   or _clock(later["start"]["timestamp"]) < _clock(earlier["end"]["timestamp"])
                   for earlier, later in zip(windows, all_windows[1:]))):
        raise ValueError("native_checkpoint_arrival:root_invalid")
    action_items = active["actions"]["items"]
    if (any(type(item["source_ref"]["line"]) is not int
            or item["source_ref"]["line"] < 1
            or not _digest(item["source_ref"]["sha256"])
            for item in action_items)):
        raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
    native_items = [item for item in action_items
                    if item["namespace"] == "multi_agent_v1"]
    if (len(native_items) != 4
            or sorted((item["namespace"], item["name"])
                      for item in native_items)
               != sorted([("multi_agent_v1", "spawn_agent")] * 2
                         + [("multi_agent_v1", "send_input")] * 2)):
        raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
    actions = value["worker_actions"]
    if type(actions) is not dict or set(actions) != set(lanes):
        raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
    root_id = expected["sources"]["owner"]["root_task_id"]
    for lane in lanes:
        rows = actions[lane]
        if (type(rows) is not list or len(rows) != 2
                or [row.get("kind") for row in rows if type(row) is dict] != ["spawn", "continue"]):
            raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
        spawn, continued = rows
        common = {"kind", "worker_id", "call_id", "canonical_record_sha256", "turn_id",
                  "call_timestamp", "result_timestamp", "source_refs"}
        spawn_extra = {"schema", "scope", "parent_thread_id", "model", "effort", "context_policy", "surface", "depth"}
        if (set(spawn) != common | spawn_extra or set(continued) != common | {"submission_id"}
                or spawn["schema"] != "orch-dork/host-native-v1-spawn/v1"
                or spawn["scope"] != "structural_transport" or spawn["parent_thread_id"] != root_id
                or spawn["worker_id"] != expected["sources"]["owner"]["worker_ids"][lane]
                or spawn["model"] != expected["lanes"][lane]["model"]
                or spawn["effort"] != expected["lanes"][lane]["effort"]
                or spawn["context_policy"] != "none" or spawn["surface"] != "native-v1"
                or type(spawn["depth"]) is not int or spawn["depth"] != 1
                or continued["worker_id"] != spawn["worker_id"]
                or continued["submission_id"] != expected["sources"]["worker_turn_ids"][lane]
                or spawn["turn_id"] != active["turn_id"] or continued["turn_id"] != active["turn_id"]):
            raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
        for event, name in ((spawn, "spawn_agent"), (continued, "send_input")):
            refs, digests = event["source_refs"], event["canonical_record_sha256"]
            if (type(refs) is not dict or set(refs) != {"call", "result"}
                    or any(type(refs[key]) is not dict
                           or set(refs[key]) != {"line", "sha256"}
                           or type(refs[key]["line"]) is not int
                           or refs[key]["line"] < 1
                           or not _digest(refs[key]["sha256"])
                           for key in ("call", "result"))
                    or refs["call"] not in active["source_refs"] or refs["result"] not in active["source_refs"]
                    or refs["result"]["line"] <= refs["call"]["line"]
                    or {"call_id": event["call_id"], "name": name, "namespace": "multi_agent_v1",
                        "source_ref": refs["call"]} not in active["actions"]["items"]
                    or type(digests) is not dict
                    or set(digests) != ({"call", "result", "child_metadata"} if event["kind"] == "spawn" else {"call", "result"})
                    or any(not _digest(digest) for digest in digests.values())
                    or not _clock(active["start"]["timestamp"]) <= _clock(event["call_timestamp"])
                           <= _clock(event["result_timestamp"]) <= _clock(active["through"]["timestamp"])):
                raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
        if spawn["source_refs"]["result"]["line"] >= continued["source_refs"]["call"]["line"]:
            raise ValueError("native_checkpoint_arrival:worker_actions_invalid")
        worker_windows = workers[lane]["source"]["windows"]
        if (len(worker_windows) != 2
                or _clock(spawn["call_timestamp"])
                   > _clock(worker_windows[0]["start"]["timestamp"])
                or _clock(worker_windows[0]["end"]["timestamp"])
                   > _clock(continued["call_timestamp"])
                or _clock(continued["call_timestamp"])
                   > _clock(worker_windows[1]["start"]["timestamp"])):
            raise ValueError("native_checkpoint_arrival:worker_actions_invalid")


def _check_checkpoint_arrival_evidence(expected: dict, evidence: Any) -> None:
    if (type(evidence) is not dict
            or set(evidence) != {"source_inventory", "source_inventory_after_sha256", "root", "workers"}):
        raise ValueError("native_checkpoint_arrival:evidence_invalid")
    inventory = evidence["source_inventory"]
    if (owner.validate_worker_checkpoint_arrival_sources(inventory)["valid"] is not True
            or inventory["status"] != "OBSERVED" or inventory["expectation"] != expected["sources"]):
        raise ValueError("native_checkpoint_arrival:evidence_invalid")
    lanes = tuple(inventory["observation"]["completed_lane_ids"])
    checkpoint = {key: evidence[key] for key in ("source_inventory", "source_inventory_after_sha256", "workers")}
    try:
        _check_checkpoint_evidence({"sources": expected["sources"], "lanes": expected["lanes"]},
                                   checkpoint, lanes=lanes, arrival=True)
        _check_checkpoint_arrival_root(
            expected, inventory, evidence["root"], lanes, evidence["workers"])
    except ValueError as error:
        raise ValueError("native_checkpoint_arrival:evidence_invalid") from error


_CHECKPOINT_ARRIVAL_ISSUES = {"native_checkpoint_arrival:" + name for name in (
    "source_unavailable", "private_root_unavailable", "owner_sources_unavailable",
    "awaiting_checkpoints",
    "owner_changed_during_read", "evidence_invalid", "root_invalid",
    "worker_actions_invalid", "report_bounds")}


def observe_native_worker_checkpoint_arrivals(expectation: Any, task_specs: Any,
                                              *, env: Mapping[str, str] | None = None) -> dict:
    """Read one stable raw checkpoint frontier without inferring chronology."""
    expected = _checkpoint_arrival_expectation(expectation)
    host.decode_bounded_response(task_specs)
    if (set(task_specs) != set(_LANES)
            or any(contracts.validate_task_spec(task_specs[lane])["valid"] is not True
                   or task_specs[lane].get("task_spec_sha256") != expected["lanes"][lane]["task_spec_sha256"]
                   for lane in _LANES)):
        raise ValueError("native_checkpoint_arrival:tasks_invalid")
    environment = os.environ if env is None else env
    evidence = None
    try:
        private = environment.get("CODEX_HOME")
        if not private and type(environment.get("HOME")) is str:
            private = str(Path(environment["HOME"]) / ".codex")
        if type(private) is not str or not private.startswith("/"):
            raise ValueError("native_checkpoint_arrival:private_root_unavailable")
        before = owner.observe_worker_checkpoint_arrival_sources(expected["sources"], env=environment)
        if (owner.validate_worker_checkpoint_arrival_sources(before)["valid"] is not True
                or before["expectation"] != expected["sources"]):
            raise ValueError("native_checkpoint_arrival:owner_sources_unavailable")
        if before["status"] != "OBSERVED":
            status, issues = before["status"], ["native_checkpoint_arrival:awaiting_checkpoints"]
        else:
            completed = tuple(before["observation"]["completed_lane_ids"])
            root_scan = _scan(before["observation"]["sources"]["root"], Path(private),
                              pending_call_id=expected["root"]["pending_call"]["call_id"])
            worker_scans, workers = {}, {}
            checkpoint_expected = {"sources": expected["sources"], "lanes": expected["lanes"]}
            for lane in completed:
                source = before["observation"]["sources"][lane]
                scan = _scan(source, Path(private), retain_runtime=True)
                worker_scans[lane] = scan
                workers[lane] = _checkpoint_worker(checkpoint_expected, lane, source, scan, task_specs[lane])
            root = _checkpoint_arrival_root(expected, before, root_scan, worker_scans)
            after = owner.observe_worker_checkpoint_arrival_sources(expected["sources"], env=environment)
            if host.canonical_bytes(after) != host.canonical_bytes(before):
                raise ValueError("native_checkpoint_arrival:owner_changed_during_read")
            evidence = {"source_inventory": before, "source_inventory_after_sha256": after["report_sha256"],
                        "root": root, "workers": workers}
            _check_checkpoint_arrival_evidence(expected, evidence)
            status, issues = "OBSERVED", []
    except (KeyError, TypeError, ValueError, OSError, RecursionError, OverflowError) as error:
        evidence = None
        issue = str(error)
        status, issues = "REFUSED", [issue if issue in _CHECKPOINT_ARRIVAL_ISSUES
                                     else "native_checkpoint_arrival:source_unavailable"]
    false_fields = {key: False for key in (
        "retained_owner_authentication", "chronology_attested", "capture_authenticated",
        "host_execution_custody", "controller_continuation_authorized", "controller_authority",
        "grant_authority", "progress_authority", "continuation_permitted", "terminal_claim_permitted",
        "execution_attested", "complete_campaign", "release_authorized", "qualification_authorized")}
    core = {"schema": _CHECKPOINT_ARRIVAL_SCHEMA, "status": status, "issues": issues,
            "expectation": expected, "evidence": evidence, "scope": "owned_native_checkpoint_frontier",
            "raw_checkpoint_custody_observed": status == "OBSERVED", **false_fields,
            "provider_free": True, "native_calls": 0, "model_calls": 0, "cost_usd": None}
    try:
        host.decode_bounded_response({**core, "report_sha256": "0" * 64})
    except ValueError:
        core.update(status="REFUSED", issues=["native_checkpoint_arrival:report_bounds"], evidence=None,
                    raw_checkpoint_custody_observed=False)
    return {**core, "report_sha256": hashlib.sha256(host.canonical_bytes(core)).hexdigest()}


def validate_native_worker_checkpoint_arrival_observation(report: Any) -> dict:
    """Validate retained frontier transport without live owner authentication."""
    false_fields = {"retained_owner_authentication", "chronology_attested", "capture_authenticated",
        "host_execution_custody", "controller_continuation_authorized", "controller_authority",
        "grant_authority", "progress_authority", "continuation_permitted", "terminal_claim_permitted",
        "execution_attested", "complete_campaign", "release_authorized", "qualification_authorized"}
    try:
        value = host.decode_bounded_response(report)
        fields = {"schema", "status", "issues", "expectation", "evidence", "scope",
                  "raw_checkpoint_custody_observed", "provider_free", "native_calls", "model_calls",
                  "cost_usd", "report_sha256", *false_fields}
        if (set(value) != fields or value["schema"] != _CHECKPOINT_ARRIVAL_SCHEMA
                or value["scope"] != "owned_native_checkpoint_frontier"
                or any(value[key] is not False for key in false_fields)
                or value["provider_free"] is not True or value["cost_usd"] is not None
                or any(type(value[key]) is not int or value[key] != 0 for key in ("native_calls", "model_calls"))
                or value["report_sha256"] != hashlib.sha256(host.canonical_bytes(
                    {key: item for key, item in value.items() if key != "report_sha256"})).hexdigest()):
            raise ValueError("invalid report")
        expected = _checkpoint_arrival_expectation(value["expectation"])
        if value["status"] == "OBSERVED":
            if value["issues"] != [] or value["raw_checkpoint_custody_observed"] is not True:
                raise ValueError("invalid observed report")
            _check_checkpoint_arrival_evidence(expected, value["evidence"])
        elif value["status"] in {"PENDING", "REFUSED"}:
            if (value["raw_checkpoint_custody_observed"] is not False or value["evidence"] is not None
                    or type(value["issues"]) is not list or len(value["issues"]) != 1
                    or value["issues"][0] not in _CHECKPOINT_ARRIVAL_ISSUES
                    or value["status"] == "PENDING"
                    and value["issues"] != ["native_checkpoint_arrival:awaiting_checkpoints"]):
                raise ValueError("invalid negative report")
        else:
            raise ValueError("invalid status")
    except (KeyError, TypeError, ValueError, OSError, RecursionError, OverflowError):
        return {"valid": False, "issues": ["native_checkpoint_arrival:report_invalid"],
                "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def _join(expected: dict, discovery: dict, scans: dict, *, continuation_count: int = 1) -> dict:
    if type(continuation_count) is not int or continuation_count not in (1, 2):
        raise ValueError("native_attempt:worker_extent_invalid")
    root_id = expected["owner"]["root_task_id"]
    root_identity = host.native_v1_root_identity(scans["root"]["metadata"]["record"])
    if root_identity["task_id"] != root_id or root_identity["cwd"] != discovery["observation"]["sources"]["root"]["cwd"]:
        raise ValueError("native_attempt:root_identity_mismatch")
    root_turns = scans["root"]["turns"]
    root_ids = [turn["window"]["turn_id"] for turn in root_turns]
    first = []
    for lane in _LANES:
        child = scans[lane]["turns"]
        if len(child) != continuation_count + 1 or child[0]["window"]["root_turn_id"] not in root_ids:
            raise ValueError("native_attempt:worker_extent_invalid")
        first.append(root_ids.index(child[0]["window"]["root_turn_id"]))
    selected = root_turns[min(first):]
    selected_ids = [turn["window"]["turn_id"] for turn in selected]
    if (expected["root"]["review_turn_id"] not in selected_ids
            or any(turn["window"]["root_turn_id"] != turn["window"]["turn_id"] for turn in selected)):
        raise ValueError("native_attempt:root_extent_invalid")
    roles = {"root": _role(scans["root"], selected, task_id=root_id, root_id=root_id, route=expected["root"])}
    by_worker = {worker: lane for lane, worker in expected["owner"]["worker_ids"].items()}
    events = {lane: [] for lane in _LANES}
    for turn in selected:
        for pair in turn["native_pairs"]:
            call, result = pair["call"]["record"], pair["result"]["record"]
            if call["payload"]["name"] == "spawn_agent":
                output = host.decode_response(result["payload"]["output"])
                lane = by_worker.get(output.get("agent_id"))
                if lane is None:
                    raise ValueError("native_attempt:unexpected_worker")
                fact = host.native_v1_spawn_pair(call, result, scans[lane]["metadata"]["record"])
                if (fact["parent_thread_id"] != root_id or fact["model"] != expected["lanes"][lane]["model"]
                        or fact["effort"] != expected["lanes"][lane]["effort"]
                        or turn["window"]["turn_id"] != scans[lane]["turns"][0]["window"]["root_turn_id"]):
                    raise ValueError("native_attempt:spawn_mismatch")
                fact = {"kind": "spawn", **fact}
            else:
                fact = host.native_v1_worker_action_pair(call, result)
                lane = by_worker.get(fact["worker_id"])
                if lane is None:
                    raise ValueError("native_attempt:unexpected_worker")
            events[lane].append({**fact, "turn_id": turn["window"]["turn_id"],
                                 "call_timestamp": call["timestamp"], "result_timestamp": result["timestamp"],
                                 "source_refs": {key: {name: pair[key][name] for name in ("line", "sha256")}
                                                 for key in ("call", "result")}})
    for lane in _LANES:
        turns = scans[lane]["turns"]
        kinds = ["spawn", *(["continue"] * continuation_count), "close"]
        if ([event["kind"] for event in events[lane]] != kinds
                or any(turn["window"]["root_turn_id"] not in selected_ids for turn in turns)
                or any(event["submission_id"] != turn["window"]["turn_id"]
                       or event["turn_id"] != turn["window"]["root_turn_id"]
                       for event, turn in zip(events[lane][1:-1], turns[1:]))
                or continuation_count == 2 and any(turn["window"]["actions"]["count"] != 0 for turn in turns)):
            raise ValueError("native_attempt:worker_lifecycle_mismatch")
        if (_clock(events[lane][0]["call_timestamp"]) > _clock(turns[0]["window"]["start"]["timestamp"])
                or any(_clock(turn["window"]["end"]["timestamp"]) > _clock(event["call_timestamp"])
                       for turn, event in zip(turns, events[lane][1:]))
                or continuation_count == 2 and any(_clock(event["call_timestamp"]) > _clock(turn["window"]["start"]["timestamp"])
                                                 for event, turn in zip(events[lane][1:-1], turns[1:]))):
            raise ValueError("native_attempt:worker_clock_mismatch")
        roles[lane] = _role(scans[lane], turns, task_id=expected["owner"]["worker_ids"][lane], root_id=root_id,
                            route=expected["lanes"][lane])
    return {"roles": roles, "worker_events": events, "root_identity": root_identity,
            "root_turn_ids": selected_ids, "root_extent": "first_spawn_turn_through_last_completed_root_turn"}


def observe_native_two_lane_attempt(expectation: Any, *, env: Mapping[str, str] | None = None) -> dict:
    """Observe complete successful native transport; confer no qualification.

    Two child turns are the initial acknowledgement and its one continuation.
    A missing/failed/unknown lifecycle remains unobserved here; a final failure
    closure producer must preserve its own outstanding obligations separately.
    """
    expected = _expectation(expectation)
    environment = os.environ if env is None else env
    evidence = None
    try:
        private = environment.get("CODEX_HOME")
        if not private:
            home = environment.get("HOME")
            if type(home) is not str or not home.startswith("/"):
                raise ValueError("native_attempt:private_root_unavailable")
            private = str(Path(home) / ".codex")
        if type(private) is not str or not private.startswith("/"):
            raise ValueError("native_attempt:private_root_unavailable")
        before = owner.observe_completed_attempt_sources(expected["owner"], env=environment)
        if before["status"] != "OBSERVED":
            status, issues = before["status"], ["native_attempt:owner_sources_unavailable"]
        else:
            scans = {role: _scan(source, Path(private)) for role, source in before["observation"]["sources"].items()}
            joined = _join(expected, before, scans)
            after = owner.observe_completed_attempt_sources(expected["owner"], env=environment)
            if host.canonical_bytes(after) != host.canonical_bytes(before):
                raise ValueError("native_attempt:owner_changed_during_read")
            evidence = {"owner_before": before, "owner_after": after, **joined}
            _check_evidence(expected, evidence)
            status, issues = "OBSERVED", []
    except (KeyError, TypeError, ValueError, OSError, RecursionError, OverflowError) as error:
        evidence = None
        issue = str(error)
        status, issues = "REFUSED", [issue if issue.startswith("native_attempt:") else "native_attempt:source_unavailable"]
    report = {"schema": SCHEMA, "status": status, "issues": issues, "expectation": expected, "evidence": evidence,
              "scope": "owned_native_transport", "qualification_permitted": False, "resource_release_proven": False,
              "provider_free": True, "native_calls": 0, "model_calls": 0, "cost_usd": None}
    try:
        host.decode_bounded_response({**report, "report_sha256": "0" * 64})
    except ValueError:
        report.update(status="REFUSED", issues=["native_attempt:report_bounds"], evidence=None)
    return {**report, "report_sha256": hashlib.sha256(host.canonical_bytes(report)).hexdigest()}


def _check_evidence(expected: dict, evidence: Any, *, continuation_count: int = 1) -> None:
    if type(continuation_count) is not int or continuation_count not in (1, 2):
        raise ValueError("invalid continuation profile")
    if (type(evidence) is not dict or set(evidence) != {"owner_before", "owner_after", "roles", "worker_events", "root_identity", "root_turn_ids", "root_extent"}
            or host.canonical_bytes(evidence["owner_before"]) != host.canonical_bytes(evidence["owner_after"])
            or owner.validate_completed_attempt_sources(evidence["owner_before"])["valid"] is not True):
        raise ValueError("invalid owner observations")
    before = evidence["owner_before"]
    if before["status"] != "OBSERVED" or before["expectation"] != expected["owner"]:
        raise ValueError("invalid owner binding")
    if any(turn["status"] != "completed" for source in before["observation"]["sources"].values() for turn in source["turns"]):
        raise ValueError("incomplete owner turn inventory")
    roles, events = evidence["roles"], evidence["worker_events"]
    if type(roles) is not dict or set(roles) != {"root", *_LANES} or type(events) is not dict or set(events) != set(_LANES):
        raise ValueError("invalid roles")
    root_id = expected["owner"]["root_task_id"]
    identity = evidence["root_identity"]
    if (type(identity) is not dict or set(identity) != {"task_id", "session_id", "cwd", "canonical_record_sha256"}
            or identity["task_id"] != root_id or identity["session_id"] != root_id
            or identity["cwd"] != before["observation"]["sources"]["root"]["cwd"]
            or not _digest(identity["canonical_record_sha256"])):
        raise ValueError("invalid root identity")
    for role, value in roles.items():
        source = before["observation"]["sources"][role]
        if (type(value) is not dict or set(value) != {"path", "file_sha256", "prefix_bytes", "custody", "task_id", "metadata_source_ref", "windows", "usage"}
                or value["task_id"] != source["task_id"] or value["path"] != source["path"] or not _digest(value["file_sha256"])
                or type(value["prefix_bytes"]) is not int or not 0 < value["prefix_bytes"] <= owned.MAX_PRIVATE_ROLLOUT_BYTES):
            raise ValueError("invalid source binding")
        custody = value["custody"]
        if (type(custody) is not dict or set(custody) != {"status", "scope", "owner_uid", "private_root_mode", "file_mode", "device", "inode", "links", "read_passes", "prefix_bytes", "link_identity_checked"}
                or custody["status"] != "observed" or custody["scope"] != "owned_prefix_snapshot"
                or custody["link_identity_checked"] is not True
                or any(type(custody[key]) is not int or custody[key] < 0 for key in (
                    "owner_uid", "private_root_mode", "file_mode", "device", "inode", "links", "read_passes", "prefix_bytes"))
                or custody["private_root_mode"] > 0o7777 or custody["private_root_mode"] & 0o077
                or custody["file_mode"] > 0o7777 or custody["file_mode"] & 0o002
                or custody["links"] != 1 or custody["read_passes"] != 2 or custody["prefix_bytes"] != value["prefix_bytes"]):
            raise ValueError("invalid prefix custody transport")
        metadata = value["metadata_source_ref"]
        if (type(metadata) is not dict or set(metadata) != {"line", "sha256"}
                or type(metadata["line"]) is not int or metadata["line"] != 1 or not _digest(metadata["sha256"])):
            raise ValueError("invalid metadata reference")
        windows = value["windows"]
        route = expected["root"] if role == "root" else expected["lanes"][role]
        if (type(windows) is not list or not 1 <= len(windows) <= 256
                or any(host.validate_native_v1_turn_window(window)["valid"] is not True for window in windows)
                or len({w["turn_id"] for w in windows}) != len(windows)
                or any(w["model"] != route["model"] or w["effort"] != route["effort"] for w in windows)
                or any(b["start"]["line"] != a["end"]["line"] + 1 or _clock(b["start"]["timestamp"]) < _clock(a["end"]["timestamp"])
                       for a, b in zip(windows, windows[1:]))):
            raise ValueError("invalid native windows")
        ids = [w["turn_id"] for w in windows]
        telemetry = value["usage"]
        if (usage.validate_usage_observation(telemetry)["valid"] is not True or telemetry["status"] != "OBSERVED"
                or telemetry["thread_id"] != source["task_id"] or telemetry["session_id"] != root_id or telemetry["turn_ids"] != ids
                or [t["root_turn_id"] for t in telemetry["per_turn"]] != [w["root_turn_id"] for w in windows]):
            raise ValueError("invalid window telemetry")
        refs = [ref for window in windows for ref in window["source_refs"]]
        if any({"line": ref["line"], "sha256": ref["sha256"]} not in refs for ref in telemetry["source_refs"]):
            raise ValueError("telemetry outside selected windows")
        if role != "root" and (len(windows) != continuation_count + 1 or ids != [t["id"] for t in source["turns"]]
                               or continuation_count == 2 and any(w["actions"]["count"] != 0 for w in windows)):
            raise ValueError("invalid worker extent")
    root_windows = roles["root"]["windows"]
    root_ids = [w["turn_id"] for w in root_windows]
    all_root_ids = [t["id"] for t in before["observation"]["sources"]["root"]["turns"]]
    first = min(all_root_ids.index(roles[lane]["windows"][0]["root_turn_id"]) for lane in _LANES)
    if (root_ids != all_root_ids[first:] or root_ids != evidence["root_turn_ids"] or expected["root"]["review_turn_id"] not in root_ids
            or any(w["root_turn_id"] != w["turn_id"] for w in root_windows)
            or evidence["root_extent"] != "first_spawn_turn_through_last_completed_root_turn"):
        raise ValueError("invalid root extent")
    referenced_calls = []
    for lane in _LANES:
        kinds = ["spawn", *(["continue"] * continuation_count), "close"]
        if (type(events[lane]) is not list or len(events[lane]) != len(kinds)
                or [e.get("kind") for e in events[lane] if type(e) is dict] != kinds):
            raise ValueError("invalid worker events")
        child_windows = roles[lane]["windows"]
        for event, kind in zip(events[lane], kinds):
            common = {"kind", "worker_id", "call_id", "canonical_record_sha256", "turn_id", "source_refs", "call_timestamp", "result_timestamp"}
            extra = ({"schema", "scope", "parent_thread_id", "model", "effort", "context_policy", "surface", "depth"} if kind == "spawn"
                     else {"submission_id"} if kind == "continue" else {"previous_status"})
            if (set(event) != common | extra or event["worker_id"] != expected["owner"]["worker_ids"][lane]
                    or type(event["call_id"]) is not str or not event["call_id"] or event["turn_id"] not in root_ids
                    or type(event["source_refs"]) is not dict or set(event["source_refs"]) != {"call", "result"}
                    or type(event["canonical_record_sha256"]) is not dict
                    or set(event["canonical_record_sha256"]) != ({"call", "result", "child_metadata"} if kind == "spawn" else {"call", "result"})
                    or any(not _digest(v) for v in event["canonical_record_sha256"].values())):
                raise ValueError("invalid worker event binding")
            window = root_windows[root_ids.index(event["turn_id"])]
            call, result = (event["source_refs"][key] for key in ("call", "result"))
            if (call not in window["source_refs"][1:-1] or result not in window["source_refs"][1:-1]
                    or type(call["line"]) is not int or type(result["line"]) is not int or result["line"] <= call["line"]
                    or not _clock(window["start"]["timestamp"]) <= _clock(event["call_timestamp"]) <= _clock(event["result_timestamp"]) <= _clock(window["end"]["timestamp"])):
                raise ValueError("invalid worker event source refs")
            action = {"call_id": event["call_id"], "name": {"spawn": "spawn_agent", "continue": "send_input", "close": "close_agent"}[kind],
                      "namespace": "multi_agent_v1", "source_ref": call}
            if action not in window["actions"]["items"]:
                raise ValueError("worker event not observed as action")
            referenced_calls.append(action)
        spawn, *continued, close = events[lane]
        if (spawn["schema"] != "orch-dork/host-native-v1-spawn/v1" or spawn["scope"] != "structural_transport"
                or spawn["parent_thread_id"] != root_id or spawn["context_policy"] != "none" or spawn["surface"] != "native-v1"
                or type(spawn["depth"]) is not int or spawn["depth"] != 1 or spawn["model"] != expected["lanes"][lane]["model"]
                or spawn["effort"] != expected["lanes"][lane]["effort"] or spawn["turn_id"] != child_windows[0]["root_turn_id"]
                or any(event["turn_id"] != window["root_turn_id"] or event["submission_id"] != window["turn_id"]
                       for event, window in zip(continued, child_windows[1:]))
                or close["previous_status"] != "completed"
                or any(before["source_refs"]["result"]["line"] >= after["source_refs"]["call"]["line"]
                       for before, after in zip(events[lane], events[lane][1:]))
                or _clock(spawn["call_timestamp"]) > _clock(child_windows[0]["start"]["timestamp"])
                or any(_clock(window["end"]["timestamp"]) > _clock(event["call_timestamp"])
                       for window, event in zip(child_windows, events[lane][1:]))
                or continuation_count == 2 and any(_clock(event["call_timestamp"]) > _clock(window["start"]["timestamp"])
                                                 for event, window in zip(continued, child_windows[1:]))):
            raise ValueError("invalid lifecycle join")
    native_calls = [action for window in root_windows for action in window["actions"]["items"] if action["namespace"] == "multi_agent_v1"]
    if sorted(native_calls, key=lambda a: a["source_ref"]["line"]) != sorted(referenced_calls, key=lambda a: a["source_ref"]["line"]):
        raise ValueError("unaccounted native calls")


def validate_native_two_lane_attempt_observation(report: Any) -> dict:
    """Validate complete retained transport; do not authenticate caller custody."""
    try:
        value = host.decode_bounded_response(report)
        if (set(value) != {"schema", "status", "issues", "expectation", "evidence", "scope", "qualification_permitted", "resource_release_proven", "provider_free", "native_calls", "model_calls", "cost_usd", "report_sha256"}
                or value["schema"] != SCHEMA or value["scope"] != "owned_native_transport" or value["provider_free"] is not True
                or value["qualification_permitted"] is not False or value["resource_release_proven"] is not False or value["cost_usd"] is not None
                or any(type(value[key]) is not int or value[key] != 0 for key in ("native_calls", "model_calls"))
                or value["report_sha256"] != hashlib.sha256(host.canonical_bytes({k: v for k, v in value.items() if k != "report_sha256"})).hexdigest()):
            raise ValueError("invalid report")
        expected = _expectation(value["expectation"])
        if value["status"] == "OBSERVED":
            if value["issues"] != []:
                raise ValueError("observed issues")
            _check_evidence(expected, value["evidence"])
        elif value["status"] in ("REFUSED", "PENDING"):
            if (value["evidence"] is not None or type(value["issues"]) is not list or len(value["issues"]) != 1
                    or type(value["issues"][0]) is not str or value["issues"][0] not in _ISSUES
                    or value["status"] == "PENDING" and value["issues"] != ["native_attempt:owner_sources_unavailable"]):
                raise ValueError("invalid unobserved result")
        else:
            raise ValueError("invalid status")
    except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
        return {"valid": False, "issues": ["native_attempt:report_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


__all__ = ["SCHEMA", "CHECKPOINT_SCHEMA", "observe_native_two_lane_attempt", "validate_native_two_lane_attempt_observation",
           "observe_native_worker_checkpoints", "validate_native_worker_checkpoint_observation",
           "observe_native_worker_checkpoint_arrivals", "validate_native_worker_checkpoint_arrival_observation"]
