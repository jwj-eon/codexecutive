"""Read exact third-turn handoffs while preserving accepted checkpoint custody."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from lifecycle_conformance import host_adapter as host
import orch_dork_codex_usage as usage
import orch_dork_local_task_runtime as owner
import orch_dork_native_attempt_observer as native
import orch_dork_qualification_progress as progress
import orch_dork_qualification_results as results
import orch_dork_qualification_verification as verification
import orch_dork_routing_verify as routing

SCHEMA = "orch-dork/native-worker-finals/v1"
ARRIVAL_SCHEMA = "orch-dork/native-worker-final-arrivals/v1"
_LANES = ("spec", "standards")
_INVALID = (KeyError, TypeError, ValueError, OSError, RecursionError, OverflowError)
_ISSUES = {"worker_finals:" + name for name in ("sources_unavailable", "owner_changed", "report_bounds")}
_ARRIVAL_FALSE_FIELDS = (
    "retained_owner_authentication", "chronology_attested",
    "capture_authenticated", "host_execution_custody",
    "controller_continuation_authorized", "controller_authority",
    "grant_authority", "progress_authority", "continuation_permitted",
    "terminal_claim_permitted", "execution_attested", "complete_campaign",
    "release_authorized", "qualification_authorized",
)


def _sha(value: Any) -> str:
    return hashlib.sha256(host.canonical_bytes(value)).hexdigest()


def _same(left: Any, right: Any) -> bool:
    return host.canonical_bytes(left) == host.canonical_bytes(right)


def _bytes(value: Any) -> bytes:
    encoded = verification._bounded_bytes(value)
    host.canonical_bytes(value)
    return encoded


def _expectation(value: Any) -> dict:
    value = host.decode_bounded_response(value)
    if set(value) != {"sources", "lanes", "checkpoint_sources_sha256"} or not native._digest(value["checkpoint_sources_sha256"]):
        raise ValueError("invalid final selection")
    native._checkpoint_expectation({key:value[key] for key in ("sources", "lanes")})
    return value


def _sources(expected: dict, bundle: Any) -> dict:
    if type(bundle) is not dict or set(bundle) != {"coordinator", "workers"} or _sha(bundle) != expected["checkpoint_sources_sha256"]:
        raise ValueError("different retained sources")
    root = bundle["coordinator"]["expectation"]
    progress.build_checkpoint_ingress_observation(
        {"root_task_id":expected["sources"]["owner"]["root_task_id"], "root_model":root["model"], "root_effort":root["effort"]},
        bundle["coordinator"], bundle["workers"])
    selection = bundle["workers"]["expectation"]
    if (selection["sources"]["owner"] != expected["sources"]["owner"]
            or any({key:selection["lanes"][lane][key] for key in ("model", "effort", "task_spec_sha256")}
                   != {key:expected["lanes"][lane][key] for key in ("model", "effort", "task_spec_sha256")} for lane in _LANES)):
        raise ValueError("different checkpoint membership")
    return bundle["workers"]["evidence"]["workers"]


def build_native_worker_finals_expectation(source_selection: Any, lanes: Any, checkpoint_sources: Any) -> dict:
    """Bind supplied controller selection to whole retained checkpoint transport."""
    bundle = host.decode_bounded_response(checkpoint_sources)
    expected = _expectation({"sources":source_selection, "lanes":lanes, "checkpoint_sources_sha256":_sha(bundle)})
    _sources(expected, bundle)
    return expected


def _check_worker(expected: dict, lane: str, row: Any, old: dict, inventory: dict) -> None:
    if type(row) is not dict or set(row) != {"result_report", "source", "native_source", "observed_checkpoint_sha256"}:
        raise ValueError("invalid final worker proof")
    source, before, result = row["source"], old["source"], row["result_report"]
    target = expected["lanes"][lane]
    root, worker = expected["sources"]["owner"]["root_task_id"], expected["sources"]["owner"]["worker_ids"][lane]
    binding = {"logical_worker_id":lane, "worker_id":worker, "observer_id":root, **{key:target[key] for key in ("model", "effort")}}
    if (results.validate_worker_result_report(result)["valid"] is not True or result["status"] != "OBSERVED"
            or result["binding"] != binding or not _same(result["task_spec"], old["progress_report"]["task_spec"])
            or type(source) is not dict or set(source) != set(before)
            or any(not _same(source[key], before[key]) for key in ("path", "task_id", "metadata_source_ref"))
            or type(source["prefix_bytes"]) is not int or not before["prefix_bytes"] < source["prefix_bytes"] <= native.owned.MAX_PRIVATE_ROLLOUT_BYTES
            or not native._digest(source["file_sha256"]) or row["observed_checkpoint_sha256"] != before["file_sha256"]
            or host.canonical_bytes(source["custody"]) != host.canonical_bytes({**before["custody"], "prefix_bytes":source["prefix_bytes"]})):
        raise ValueError("changed checkpoint custody or task")
    windows = source["windows"]
    if (type(windows) is not list or len(windows) != 3 or not _same(windows[:2], before["windows"])
            or host.validate_native_v1_runtime_window(row["native_source"])["valid"] is not True
            or not _same(row["native_source"]["native_window"], windows[-1])):
        raise ValueError("invalid final native window")
    last = windows[-1]
    selected = inventory["observation"]["sources"]
    if (source["path"] != selected[lane]["path"] or source["task_id"] != selected[lane]["task_id"]
            or selected[lane]["cwd"] != old["child_identity"]["cwd"]
            or [w["turn_id"] for w in windows] != [t["id"] for t in selected[lane]["turns"]]
            or last["turn_id"] != expected["sources"]["worker_turn_ids"][lane]
            or any(last[key] != target[key] for key in ("model", "effort", "root_turn_id"))
            or last["root_turn_id"] not in [t["id"] for t in selected["root"]["turns"]]
            or last["actions"]["count"] != 0 or last["start"]["line"] != windows[-2]["end"]["line"] + 1
            or native._clock(last["start"]["timestamp"]) < native._clock(windows[-2]["end"]["timestamp"])):
        raise ValueError("different final continuation")
    telemetry, runtime = source["usage"], result["runtime_observation"]
    refs = [ref for window in windows for ref in window["source_refs"]]
    if (usage.validate_usage_observation(telemetry)["valid"] is not True or telemetry["status"] != "OBSERVED"
            or telemetry["thread_id"] != worker or telemetry["session_id"] != root
            or telemetry["turn_ids"] != [w["turn_id"] for w in windows]
            or [turn["root_turn_id"] for turn in telemetry["per_turn"]] != [w["root_turn_id"] for w in windows]
            or not _same(telemetry["per_turn"][:2], before["usage"]["per_turn"])
            or any({key:ref[key] for key in ("line", "sha256")} not in refs for ref in telemetry["source_refs"])
            or runtime["source_sha256"] != source["file_sha256"]
            or runtime["terminal_record"] != row["native_source"]["canonical_source_refs"][-1]
            or runtime["usage_record"] not in row["native_source"]["canonical_source_refs"][1:-1]
            or runtime["usage"]["tool_calls"] != 0
            or any(telemetry["totals"]["reasoning_output_tokens" if key == "reasoning_tokens" else key] != runtime["usage"][key]
                   for key in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "total_tokens"))):
        raise ValueError("final result or usage not bound")


def _worker_proof(expected: dict, lane: str, old: dict, inventory: dict,
                  private: Path) -> dict:
    selected = inventory["observation"]["sources"][lane]
    scan = native._scan(selected, private, retain_runtime=True)
    child = host.native_v1_child_identity(scan["metadata"]["record"])
    if child != old["child_identity"] or child["cwd"] != selected["cwd"]:
        raise ValueError("different native child identity")
    target, last = expected["lanes"][lane], scan["turns"][-1]
    root = expected["sources"]["owner"]["root_task_id"]
    worker = expected["sources"]["owner"]["worker_ids"][lane]
    runtime = routing.build_session_runtime_observation(
        scan["raw"], session_id=worker, observer_id=root)
    binding = {
        "logical_worker_id": lane, "worker_id": worker,
        "observer_id": root,
        **{key: target[key] for key in ("model", "effort")},
    }
    result = results.build_worker_result_report(
        old["progress_report"]["task_spec"], binding, runtime,
        host.decode_response(last["terminal_text"]),
    )
    return {
        "result_report": result,
        "source": native._role(
            scan, scan["turns"], task_id=worker, root_id=root,
            route=target,
        ),
        "native_source": last["runtime_window"],
        "observed_checkpoint_sha256": hashlib.sha256(
            scan["raw"][:old["source"]["prefix_bytes"]]).hexdigest(),
    }


def _check(expected: dict, evidence: Any, bundle: Any) -> None:
    old = _sources(expected, bundle)
    if type(evidence) is not dict or set(evidence) != {"owner_before", "owner_after", "workers"}:
        raise ValueError("invalid final evidence")
    inventory = evidence["owner_before"]
    if (owner.validate_worker_final_sources(inventory)["valid"] is not True or inventory["status"] != "OBSERVED"
            or inventory["expectation"] != expected["sources"] or not _same(inventory, evidence["owner_after"])
            or type(evidence["workers"]) is not dict or set(evidence["workers"]) != set(_LANES)):
        raise ValueError("invalid final owner")
    for lane in _LANES:_check_worker(expected, lane, evidence["workers"][lane], old[lane], inventory)


def _check_arrival(expected: dict, evidence: Any, bundle: Any) -> None:
    old = _sources(expected, bundle)
    if (type(evidence) is not dict
            or set(evidence) != {"owner_before", "owner_after", "workers"}):
        raise ValueError("invalid final arrival evidence")
    inventory = evidence["owner_before"]
    if (owner.validate_worker_final_arrival_sources(inventory)["valid"]
            is not True
            or inventory["status"] != "OBSERVED"
            or inventory["expectation"] != expected["sources"]
            or not _same(inventory, evidence["owner_after"])):
        raise ValueError("invalid final arrival owner")
    completed = inventory["observation"]["completed_lane_ids"]
    pending = inventory["observation"]["pending_lane_ids"]
    if (type(completed) is not list or len(completed) != 1
            or type(pending) is not list or len(pending) != 1
            or completed + pending not in (
                ["spec", "standards"], ["standards", "spec"])
            or type(evidence["workers"]) is not dict
            or set(evidence["workers"]) != set(completed)):
        raise ValueError("invalid final arrival frontier")
    for lane in completed:
        _check_worker(
            expected, lane, evidence["workers"][lane], old[lane], inventory)


def observe_native_worker_finals(expectation: Any, checkpoint_sources: Any, *, env: Mapping[str, str] | None = None) -> dict:
    """Read a stable final frontier, preserving the complete v1 transport."""
    expected = _expectation(expectation)
    environment = os.environ if env is None else env
    evidence = None
    report_schema = SCHEMA
    try:
        bundle = host.decode_bounded_response(checkpoint_sources)
        old = _sources(expected, bundle)
        private = environment.get("CODEX_HOME")
        if not private and type(environment.get("HOME")) is str:private = str(Path(environment["HOME"]) / ".codex")
        if type(private) is not str or not private.startswith("/"):raise ValueError("private source unavailable")
        before = owner.observe_worker_final_sources(expected["sources"], env=environment)
        if owner.validate_worker_final_sources(before)["valid"] is not True or before["expectation"] != expected["sources"]:
            raise ValueError("invalid owner transport")
        if before["status"] == "OBSERVED":
            workers = {}
            for lane in _LANES:
                workers[lane] = _worker_proof(
                    expected, lane, old[lane], before, Path(private))
            after = owner.observe_worker_final_sources(expected["sources"], env=environment)
            if not _same(after, before):raise ValueError("worker_finals:owner_changed")
            evidence = {"owner_before":before, "owner_after":after, "workers":workers}
            _check(expected, evidence, bundle)
            status, issues = "OBSERVED", []
        elif before["status"] == "PENDING":
            frontier = owner.observe_worker_final_arrival_sources(
                expected["sources"], env=environment)
            if (owner.validate_worker_final_arrival_sources(frontier)["valid"]
                    is not True
                    or frontier["expectation"] != expected["sources"]):
                raise ValueError("invalid owner transport")
            if frontier["status"] != "OBSERVED":
                # The established complete-reader contract reports an absent
                # third-turn set as pending. A refused owner read remains a
                # refusal rather than being converted into retryable absence.
                status = ("PENDING" if frontier["status"] == "PENDING"
                          else "REFUSED")
                issues = ["worker_finals:sources_unavailable"]
            else:
                completed = frontier["observation"]["completed_lane_ids"]
                workers = {
                    lane: _worker_proof(
                        expected, lane, old[lane], frontier, Path(private))
                    for lane in completed
                }
                after = owner.observe_worker_final_arrival_sources(
                    expected["sources"], env=environment)
                if not _same(after, frontier):
                    raise ValueError("worker_finals:owner_changed")
                evidence = {
                    "owner_before": frontier, "owner_after": after,
                    "workers": workers,
                }
                _check_arrival(expected, evidence, bundle)
                report_schema = ARRIVAL_SCHEMA
                status, issues = "OBSERVED", []
        else:
            status, issues = before["status"], [
                "worker_finals:sources_unavailable"]
    except _INVALID as error:
        evidence = None
        # Partial evidence is publishable only after the complete arrival
        # proof validates. Earlier failures retain the established complete
        # transport's canonical negative shape.
        report_schema = SCHEMA
        status, issues = "REFUSED", [str(error) if str(error) in _ISSUES else "worker_finals:sources_unavailable"]
    if report_schema == ARRIVAL_SCHEMA:
        completed = (evidence["owner_before"]["observation"][
            "completed_lane_ids"] if evidence is not None else [])
        pending = (evidence["owner_before"]["observation"][
            "pending_lane_ids"] if evidence is not None else list(_LANES))
        core = {
            "schema": ARRIVAL_SCHEMA, "status": status, "issues": issues,
            "expectation": expected, "evidence": evidence,
            "completed_lane_ids": completed, "pending_lane_ids": pending,
            "scope": "owned_worker_final_frontier",
            "raw_final_custody_observed": status == "OBSERVED",
            **{field: False for field in _ARRIVAL_FALSE_FIELDS},
            "provider_free": True, "native_calls": 0, "model_calls": 0,
            "cost_usd": None,
        }
    else:
        core = {"schema":SCHEMA, "status":status, "issues":issues, "expectation":expected, "evidence":evidence,
                "scope":"owned_worker_final_transport", "continuation_permitted":False, "terminal_claim_permitted":False,
                "provider_free":True, "native_calls":0, "model_calls":0, "cost_usd":None}
    try:_bytes({**core, "report_sha256":"0" * 64})
    except ValueError:
        core.update(
            status="REFUSED",
            issues=["worker_finals:report_bounds"],
            evidence=None,
        )
        if report_schema == ARRIVAL_SCHEMA:
            core.update(
                completed_lane_ids=[],
                pending_lane_ids=list(_LANES),
                raw_final_custody_observed=False,
            )
    return {**core, "report_sha256":_sha(core)}


def validate_native_worker_final_arrivals(report: Any,
                                          checkpoint_sources: Any) -> dict:
    """Validate one exact owner-bound partial final frontier."""
    try:
        value = json.loads(_bytes(report))
        fields = {
            "schema", "status", "issues", "expectation", "evidence",
            "completed_lane_ids", "pending_lane_ids", "scope",
            "raw_final_custody_observed", *_ARRIVAL_FALSE_FIELDS,
            "provider_free", "native_calls", "model_calls", "cost_usd",
            "report_sha256",
        }
        if (set(value) != fields or value["schema"] != ARRIVAL_SCHEMA
                or value["scope"] != "owned_worker_final_frontier"
                or any(value[field] is not False
                       for field in _ARRIVAL_FALSE_FIELDS)
                or value["provider_free"] is not True
                or value["cost_usd"] is not None
                or any(type(value[key]) is not int or value[key] != 0
                       for key in ("native_calls", "model_calls"))
                or value["report_sha256"] != _sha({
                    key: child for key, child in value.items()
                    if key != "report_sha256"})):
            raise ValueError("invalid final arrival report")
        expected = _expectation(value["expectation"])
        bundle = host.decode_bounded_response(checkpoint_sources)
        _sources(expected, bundle)
        if value["status"] == "OBSERVED":
            if (value["issues"] != []
                    or value["raw_final_custody_observed"] is not True):
                raise ValueError("invalid affirmative arrival")
            _check_arrival(expected, value["evidence"], bundle)
            inventory = value["evidence"]["owner_before"]["observation"]
            if (value["completed_lane_ids"]
                    != inventory["completed_lane_ids"]
                    or value["pending_lane_ids"]
                    != inventory["pending_lane_ids"]):
                raise ValueError("invalid arrival sets")
        elif value["status"] == "REFUSED":
            if (value["issues"] != ["worker_finals:report_bounds"]
                    or value["evidence"] is not None
                    or value["completed_lane_ids"] != []
                    or value["pending_lane_ids"] != list(_LANES)
                    or value["raw_final_custody_observed"] is not False):
                raise ValueError("invalid negative arrival")
        else:
            raise ValueError("invalid arrival status")
    except _INVALID:
        return {"valid":False, "issues":["worker_finals:report_invalid"],
                "scope":"canonical_transport"}
    return {"valid":True, "issues":[], "scope":"canonical_transport"}


def validate_native_worker_finals(report: Any, checkpoint_sources: Any) -> dict:
    """Validate complete or partial canonical transport for the live reader."""
    try:
        value = json.loads(_bytes(report))
        if type(value) is not dict:
            raise ValueError("invalid final report")
        if value.get("schema") == ARRIVAL_SCHEMA:
            return validate_native_worker_final_arrivals(
                value, checkpoint_sources)
        if (set(value) != {"schema", "status", "issues", "expectation", "evidence", "scope", "continuation_permitted",
                          "terminal_claim_permitted", "provider_free", "native_calls", "model_calls", "cost_usd", "report_sha256"}
                or value["schema"] != SCHEMA or value["scope"] != "owned_worker_final_transport"
                or value["continuation_permitted"] is not False or value["terminal_claim_permitted"] is not False
                or value["provider_free"] is not True or value["cost_usd"] is not None
                or any(type(value[key]) is not int or value[key] != 0 for key in ("native_calls", "model_calls"))
                or value["report_sha256"] != _sha({key:child for key,child in value.items() if key != "report_sha256"})):
            raise ValueError("invalid final report")
        expected = _expectation(value["expectation"])
        bundle = host.decode_bounded_response(checkpoint_sources)
        _sources(expected, bundle)
        if value["status"] == "OBSERVED":
            if value["issues"] != []:raise ValueError("invalid affirmative report")
            _check(expected, value["evidence"], bundle)
        elif value["status"] in ("PENDING", "REFUSED"):
            if (value["evidence"] is not None or type(value["issues"]) is not list or len(value["issues"]) != 1
                    or type(value["issues"][0]) is not str or value["issues"][0] not in _ISSUES
                    or value["status"] == "PENDING" and value["issues"] != ["worker_finals:sources_unavailable"]):
                raise ValueError("invalid negative report")
        else:raise ValueError("invalid final status")
    except _INVALID:
        return {"valid":False, "issues":["worker_finals:report_invalid"], "scope":"canonical_transport"}
    return {"valid":True, "issues":[], "scope":"canonical_transport"}


def validate_complete_native_worker_finals(report: Any,
                                           checkpoint_sources: Any) -> dict:
    """Validate only the legacy two-lane complete-final transport."""
    result = validate_native_worker_finals(report, checkpoint_sources)
    try:
        value = json.loads(_bytes(report))
        if result["valid"] is not True or type(value) is not dict \
                or value.get("schema") != SCHEMA:
            raise ValueError("not a complete final report")
    except _INVALID:
        return {"valid":False, "issues":["worker_finals:report_invalid"],
                "scope":"canonical_transport"}
    return result


__all__ = [
    "SCHEMA", "ARRIVAL_SCHEMA", "build_native_worker_finals_expectation",
    "observe_native_worker_finals", "validate_native_worker_finals",
    "validate_native_worker_final_arrivals",
    "validate_complete_native_worker_finals",
]
