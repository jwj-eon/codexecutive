"""Observe exact worker handoffs from bound runtime records; no authority effects."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

import orch_dork_adaptive_contracts as contracts
import orch_dork_owned_file as owned_file
import orch_dork_route_policy as route_policy
import orch_dork_routing_verify as routing_verify

REPORT_SCHEMA = "orch-dork/qualification-worker-result-observation/v1"
MAX_ROLLOUT_BYTES = 128 * 1024 * 1024
_BINDING_FIELDS = {"logical_worker_id", "worker_id", "model", "effort", "observer_id"}
_REPORT_FIELDS = {"schema", "status", "issues", "binding", "task_spec", "runtime_observation",
                  "handoff_receipt", "read_error", "provider_free", "native_actions", "report_sha256"}
_READ_ERRORS = {"not_found", "unreadable", "source_changed", "record_invalid"}


def _inputs(task_spec: Any, binding: Any) -> tuple[dict, dict]:
    checked = contracts.validate_task_spec(task_spec)
    if (type(task_spec) is not dict or checked.get("valid") is not True
            or type(binding) is not dict or set(binding) != _BINDING_FIELDS
            or any(type(value) is not str or not value for value in binding.values())
            or task_spec.get("id") != binding["logical_worker_id"]
            or binding["observer_id"] == binding["worker_id"]
            or task_spec.get("deliverable", {}).get("schema") != contracts.HANDOFF_RECEIPT_SCHEMA):
        raise ValueError("worker_result:input_invalid")
    return checked, deepcopy(binding)


def _assessment(task_spec: dict, binding: dict, observation: Any, handoff: Any, read_error: Any) -> tuple[str, list[str]]:
    task, _ = _inputs(task_spec, binding)
    if read_error is not None:
        if (read_error not in _READ_ERRORS or handoff is not None
                or (read_error == "not_found" and observation is not None)):
            raise ValueError("worker_result:read_error_invalid")
        return ("PENDING" if read_error == "not_found" else "REFUSED", ["worker_result:" + read_error])
    if (type(observation) is not dict
            or routing_verify.validate_session_runtime_observation(observation).get("valid") is not True):
        return "REFUSED", ["worker_result:runtime_invalid"]
    if observation["observer_id"] != binding["observer_id"]:
        return "REFUSED", ["worker_result:observer_mismatch"]
    route = observation["route"]
    if (route != {"session_id": binding["worker_id"], "model": binding["model"], "effort": binding["effort"],
                  "context_policy": "none", "inherited_history": False}):
        return "REFUSED", ["worker_result:route_mismatch"]
    acknowledgement = route_policy.task_spec_pre_work_receipt(
        logical_lane_id=binding["logical_worker_id"], task_spec_sha256=task["digest"])
    if (observation["terminal_schema"] == route_policy.TASK_SPEC_PRE_WORK_RECEIPT_SCHEMA
            and observation["terminal_json_sha256"] == contracts.json_sha256(acknowledgement)
            and handoff is None):
        return "PENDING", ["worker_result:awaiting_handoff"]
    if (type(handoff) is not dict or observation["terminal_schema"] != contracts.HANDOFF_RECEIPT_SCHEMA
            or observation["terminal_json_sha256"] != contracts.json_sha256(handoff)
            or contracts.validate_handoff_receipt(handoff, task_spec=task_spec).get("valid") is not True):
        return "REFUSED", ["worker_result:handoff_invalid"]
    # OBSERVED means a valid typed disposition was observed. It does not turn a
    # blocked/failed handoff into success, settle capacity, or qualify the run.
    return "OBSERVED", []


def validate_worker_result_report(report: Any) -> dict[str, Any]:
    """Validate the complete observation and exact task/runtime/handoff binding."""
    try:
        if (type(report) is not dict or set(report) != _REPORT_FIELDS or report["schema"] != REPORT_SCHEMA
                or report["provider_free"] is not True or type(report["native_actions"]) is not int
                or report["native_actions"] != 0
                or report["report_sha256"] != contracts.json_sha256({k: v for k, v in report.items() if k != "report_sha256"})):
            raise ValueError("worker_result:report_invalid")
        status, issues = _assessment(report["task_spec"], report["binding"], report["runtime_observation"],
                                     report["handoff_receipt"], report["read_error"])
        if report["status"] != status or report["issues"] != issues:
            raise ValueError("worker_result:disposition_mismatch")
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return {"valid": False, "issues": ["worker_result:report_invalid"]}
    return {"valid": True, "issues": [], "report_sha256": report["report_sha256"]}


def join_bindings(bindings: Any, root_task_id: Any) -> list[dict[str, Any]]:
    """Validate the exact two-lane task/route/worker join owned by a receipt."""
    try:
        specs, lanes = bindings["task_specs"], bindings["lane_bindings"]
        expected = ["spec", "standards"]
        phase = bindings.get("quality_phase")
        if "quality_phase" in bindings and phase not in {"worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification"}:
            raise ValueError("invalid quality phase")
        current_wave = bindings["current_wave_logical_lane_ids"]
        if current_wave == []:
            # Quality work retains the admitted join after a separately proven
            # physical release. This checks receipt transport, not host custody.
            digest = bindings.get("capacity_authority_state_sha256")
            store = bindings.get("capacity_authority_store_id")
            if (phase not in {"worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification"}
                    or bindings.get("capacity_authority_lane_ids") != []
                    or bindings.get("completed_logical_lane_ids") != expected
                    or bindings.get("failed_logical_lane_ids") != []
                    or bindings.get("cancelled_logical_lane_ids") != []
                    or type(digest) is not str or len(digest) != 64 or set(digest) - set("0123456789abcdef")
                    or type(store) is not str or not store.strip()
                    or contracts.json_sha256(bindings.get("all_task_specs")) != contracts.json_sha256(specs)
                    or contracts.json_sha256(bindings.get("all_lane_bindings")) != contracts.json_sha256(lanes)):
                raise ValueError("incomplete released join")
        elif current_wave != expected:
            raise ValueError("invalid current wave")
        if (type(root_task_id) is not str or not root_task_id.strip()
                or type(specs) is not list or type(lanes) is not list
                or [row["logical_worker_id"] for row in specs] != expected
                or [row["logical_worker_id"] for row in lanes] != expected):
            raise ValueError("invalid result join")
        result = []
        for spec, lane in zip(specs, lanes):
            digest = spec["task_spec_sha256"]
            if (type(digest) is not str or len(digest) != 64 or set(digest) - set("0123456789abcdef")
                    or digest != lane["task_spec_sha256"] or lane["worker_id"] != lane["session_id"]):
                raise ValueError("invalid result binding")
            binding = {"logical_worker_id": lane["logical_worker_id"], "worker_id": lane["worker_id"],
                       "model": spec["model"], "effort": spec["effort"], "observer_id": root_task_id}
            if any(type(value) is not str or not value.strip() for value in binding.values()):
                raise ValueError("invalid result route")
            result.append({"binding": binding, "task_spec_sha256": digest})
        if result[0]["binding"]["worker_id"] == result[1]["binding"]["worker_id"]:
            raise ValueError("duplicate worker")
        return result
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("worker_result:join_invalid") from error


def join_decision(reports: Any, *, bindings: Any, root_task_id: Any) -> str:
    """Validate complete observations against the exact task and route bindings."""
    expected_rows = join_bindings(bindings, root_task_id)
    if type(reports) is not list or len(reports) != len(expected_rows):
        raise ValueError("worker_result:reports_invalid")
    for report, expected in zip(reports, expected_rows):
        if (validate_worker_result_report(report).get("valid") is not True
                or report["binding"] != expected["binding"]
                or report["task_spec"]["task_spec_sha256"] != expected["task_spec_sha256"]):
            raise ValueError("worker_result:report_binding_invalid")
    if any(report["status"] == "REFUSED" for report in reports):
        return "WORKER_RESULT_EVIDENCE_REQUIRED"
    if any(report["status"] == "OBSERVED" and report["handoff_receipt"]["disposition"] != "complete"
           for report in reports):
        return "WORKER_RESULTS_FAILED"
    if all(report["status"] == "OBSERVED" for report in reports):
        return "AWAITING_RESULT_AGGREGATION"
    return "AWAITING_WORKER_RESULTS"


def merge_results(previous_reports: Any, current_reports: Any, *, bindings: Any, root_task_id: Any) -> list[dict]:
    """Keep accepted results immutable and never erase an unresolved refusal."""
    join_decision(current_reports, bindings=bindings, root_task_id=root_task_id)
    if previous_reports is None:
        return deepcopy(current_reports)
    join_decision(previous_reports, bindings=bindings, root_task_id=root_task_id)
    merged = []
    for previous, current in zip(previous_reports, current_reports):
        if previous["status"] == "OBSERVED" and previous != current:
            raise ValueError("worker_result:accepted_result_changed")
        keep_previous = (previous["status"] == current["status"] == "PENDING"
                         or previous["status"] == "REFUSED" and current["status"] in {"PENDING", "REFUSED"})
        merged.append(previous if keep_previous else current)
    return deepcopy(merged)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
    value: dict = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def _read_rollout(path: Path, private_root: Path | None, *, verify_only: bool = False) -> bytes:
    if private_root is None:
        if verify_only:
            owned_file.verify_owned_regular_file(path, max_bytes=MAX_ROLLOUT_BYTES)
            return b""
        return owned_file.read_owned_bytes(path, max_bytes=MAX_ROLLOUT_BYTES)
    if not private_root.is_absolute() or not path.is_absolute():
        raise ValueError("absolute private rollout required")
    parts = path.relative_to(private_root).parts
    if not parts or any(part in {".", ".."} for part in parts):
        raise ValueError("private rollout containment required")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptors: list[int] = []
    try:
        directory = os.open(private_root, flags | os.O_DIRECTORY)
        descriptors.append(directory)
        root_stat = os.fstat(directory)
        if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) & 0o077:
            raise ValueError("private owned root required")
        for part in parts[:-1]:
            directory = os.open(part, flags | os.O_DIRECTORY, dir_fd=directory)
            descriptors.append(directory)
            if os.fstat(directory).st_uid != os.getuid():
                raise ValueError("owned rollout ancestor required")
        descriptor = os.open(parts[-1], flags, dir_fd=directory)
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o002 or metadata.st_size > MAX_ROLLOUT_BYTES):
            raise ValueError("private owned rollout required")
        if verify_only:
            return b""
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_ROLLOUT_BYTES + 1)
        if len(raw) > MAX_ROLLOUT_BYTES:
            raise ValueError("private rollout exceeds byte limit")
        return raw
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_terminal(path: Path, observation: dict, private_root: Path | None) -> dict:
    raw = _read_rollout(path, private_root)
    if hashlib.sha256(raw).hexdigest() != observation["source_sha256"]:
        raise ValueError("source_changed")
    line = observation["terminal_record"]["line"]
    if type(line) is not int or line < 1:
        raise ValueError("record_invalid")
    try:
        record = json.loads(raw.splitlines()[line - 1], object_pairs_hook=_unique_pairs)
        if contracts.json_sha256(record) != observation["terminal_record"]["sha256"]:
            raise ValueError("record_invalid")
        payload = record["payload"]
        field = {"agent_message": "message", "task_complete": "last_agent_message"}[payload["type"]]
        terminal = json.loads(payload[field], object_pairs_hook=_unique_pairs)
        if type(terminal) is not dict or contracts.json_sha256(terminal) != observation["terminal_json_sha256"]:
            raise ValueError("record_invalid")
        return terminal
    except (IndexError, KeyError, TypeError, ValueError, UnicodeError) as error:
        raise ValueError("record_invalid") from error


def _result_report(task_spec: dict, binding: dict, observation: Any, handoff: Any, read_error: Any) -> dict:
    status, issues = _assessment(task_spec, binding, observation, handoff, read_error)
    core = {"schema": REPORT_SCHEMA, "status": status, "issues": issues, "binding": deepcopy(binding),
            "task_spec": deepcopy(task_spec), "runtime_observation": deepcopy(observation), "handoff_receipt": deepcopy(handoff),
            "read_error": read_error, "provider_free": True, "native_actions": 0}
    report = {**core, "report_sha256": contracts.json_sha256(core)}
    if validate_worker_result_report(report)["valid"] is not True:
        raise ValueError("worker_result:producer_invalid")
    return report


def build_worker_result_report(task_spec: Any, binding: Any, runtime_observation: Any, handoff: Any) -> dict:
    """Join a typed final from already held source bytes, without reading again.

    The owning reader authenticates custody. A valid failed/blocked handoff
    remains an observed typed result, never an assertion of success or release.
    """
    from lifecycle_conformance.host_adapter import decode_bounded_response
    values = decode_bounded_response({"task":task_spec, "binding":binding, "runtime":runtime_observation, "handoff":handoff})
    report = _result_report(values["task"], values["binding"], values["runtime"], values["handoff"], None)
    if report["status"] != "OBSERVED":
        raise ValueError("worker_result:final_unobserved")
    return report


def observe_worker_result(path: str | Path | None, *, task_spec: dict, binding: dict,
                          private_root: str | Path | None = None) -> dict:
    """Read one exact runtime-bound terminal; preserve its complete JSON value."""
    _inputs(task_spec, binding)
    selected = Path(path) if path is not None else None
    root = Path(private_root) if private_root is not None else None
    observation, handoff, read_error = None, None, None
    if selected is None or not selected.exists():
        read_error = "not_found"
    else:
        try:
            _read_rollout(selected, root, verify_only=True)
            observation = routing_verify.observe_session_runtime(
                str(selected), session_id=binding["worker_id"], observer_id=binding["observer_id"])
            if observation.get("status") == "PASS" and observation.get("terminal_schema") == contracts.HANDOFF_RECEIPT_SCHEMA:
                handoff = _read_terminal(selected, observation, root)
        except OSError:
            read_error = "unreadable"
        except (KeyError, TypeError, ValueError) as error:
            read_error = str(error) if str(error) in _READ_ERRORS else "record_invalid"
    return _result_report(task_spec, binding, observation, handoff, read_error)
