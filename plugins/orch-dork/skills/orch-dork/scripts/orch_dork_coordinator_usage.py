"""Observe coordinator usage through its actual unfinished admission call.

Worker checkpoint collection and this reader select the same pinned owner
inventory. Neither source constructor grants continuation or invents a final
turn. The admission producer must join their whole reports to its frozen plan.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Mapping

from lifecycle_conformance import host_adapter as host
import orch_dork_codex_usage as usage
import orch_dork_local_task_runtime as owner
import orch_dork_native_attempt_observer as native
import orch_dork_owned_file as owned

SCHEMA = "orch-dork/native-coordinator-usage/v1"
_ISSUES = {"coordinator_usage:" + name for name in (
    "owner_sources_unavailable", "owner_changed", "source_unavailable", "source_invalid", "report_bounds")}


def _sha(value: Any) -> str:
    return hashlib.sha256(host.canonical_bytes(value)).hexdigest()


def _expectation(value: Any) -> dict:
    value = host.decode_bounded_response(value)
    if (set(value) != {"sources", "model", "effort", "pending_call"}
            or any(type(value[k]) is not str or not 0 < len(value[k]) <= 128 for k in ("model", "effort"))):
        raise ValueError("coordinator_usage:expectation_invalid")
    owner._checkpoint_source_expectation(value["sources"])
    call = value["pending_call"]
    if (type(call) is not dict or set(call) != {"call_id", "name", "namespace"}
            or any(type(call[k]) is not str or not 0 < len(call[k]) <= 128 for k in ("call_id", "name"))
            or call["namespace"] is not None and (type(call["namespace"]) is not str or not 0 < len(call["namespace"]) <= 128)):
        raise ValueError("coordinator_usage:expectation_invalid")
    return value


def _check(expected: dict, evidence: Any) -> None:
    if (type(evidence) is not dict or set(evidence) != {"source_inventory", "source_inventory_after_sha256", "source", "identity", "windows", "active_prefix", "usage", "tool_calls"}
            or owner.validate_worker_checkpoint_sources(evidence["source_inventory"])["valid"] is not True):
        raise ValueError("coordinator_usage:source_invalid")
    inventory = evidence["source_inventory"]
    if (inventory["status"] != "OBSERVED" or inventory["expectation"] != expected["sources"]
            or evidence["source_inventory_after_sha256"] != inventory["report_sha256"]):
        raise ValueError("coordinator_usage:source_invalid")
    discovered = inventory["observation"]["sources"]["root"]
    source, identity = evidence["source"], evidence["identity"]
    if (type(source) is not dict or set(source) != {"path", "file_sha256", "prefix_bytes", "custody", "metadata_source_ref"}
            or source["path"] != discovered["path"] or not native._digest(source["file_sha256"])
            or type(source["prefix_bytes"]) is not int or not 0 < source["prefix_bytes"] <= owned.MAX_PRIVATE_ROLLOUT_BYTES
            or type(identity) is not dict or set(identity) != {"task_id", "session_id", "cwd", "canonical_record_sha256"}
            or identity["task_id"] != discovered["task_id"] or identity["session_id"] != discovered["task_id"]
            or identity["cwd"] != discovered["cwd"] or not native._digest(identity["canonical_record_sha256"])):
        raise ValueError("coordinator_usage:source_invalid")
    custody, ref = source["custody"], source["metadata_source_ref"]
    if (type(custody) is not dict or set(custody) != {"status", "scope", "owner_uid", "private_root_mode", "file_mode", "device", "inode", "links", "read_passes", "prefix_bytes", "link_identity_checked"}
            or custody["status"] != "observed" or custody["scope"] != "owned_prefix_snapshot" or custody["link_identity_checked"] is not True
            or any(type(custody[k]) is not int or custody[k] < 0 for k in ("owner_uid", "private_root_mode", "file_mode", "device", "inode", "links", "read_passes", "prefix_bytes"))
            or custody["private_root_mode"] > 0o7777 or custody["private_root_mode"] & 0o077
            or custody["file_mode"] > 0o7777 or custody["file_mode"] & 0o002
            or custody["links"] != 1 or custody["read_passes"] != 2 or custody["prefix_bytes"] != source["prefix_bytes"]
            or type(ref) is not dict or set(ref) != {"line", "sha256"} or type(ref["line"]) is not int or ref["line"] != 1
            or not native._digest(ref["sha256"])):
        raise ValueError("coordinator_usage:source_invalid")
    windows, active, telemetry = evidence["windows"], evidence["active_prefix"], evidence["usage"]
    if (type(windows) is not list or any(host.validate_native_v1_turn_window(w)["valid"] is not True for w in windows)
            or host.validate_native_v1_active_turn_prefix(active)["valid"] is not True
            or {k:active["pending_call"][k] for k in expected["pending_call"]} != expected["pending_call"]
            or active["turn_id"] != expected["sources"]["root_turn_id"]):
        raise ValueError("coordinator_usage:source_invalid")
    all_windows = [*windows, active]
    ids = [w["turn_id"] for w in all_windows]
    if (ids != [t["id"] for t in discovered["turns"]] or all_windows[0]["start"]["line"] != 2
            or any(w["root_turn_id"] != w["turn_id"] or w["model"] != expected["model"] or w["effort"] != expected["effort"] for w in all_windows)
            or any(b["start"]["line"] != a["end"]["line"] + 1
                   or native._clock(b["start"]["timestamp"]) < native._clock(a["end"]["timestamp"]) for a,b in zip(windows,all_windows[1:]))
            or usage.validate_usage_observation(telemetry)["valid"] is not True or telemetry["status"] != "OBSERVED"
            or telemetry["thread_id"] != discovered["task_id"] or telemetry["session_id"] != discovered["task_id"]
            or telemetry["turn_ids"] != ids or [t["root_turn_id"] for t in telemetry["per_turn"]] != ids
            or not any(ref["kind"] == "token_usage_record" and ref["line"] > active["pending_call"]["source_ref"]["line"]
                       for ref in telemetry["source_refs"])
            or any({"line":ref["line"],"sha256":ref["sha256"]} not in [r for w in all_windows for r in w["source_refs"]] for ref in telemetry["source_refs"])
            or type(evidence["tool_calls"]) is not int or evidence["tool_calls"] != sum(w["actions"]["count"] for w in all_windows)):
        raise ValueError("coordinator_usage:source_invalid")


def observe_coordinator_usage(expectation: Any, *, env: Mapping[str, str] | None = None) -> dict:
    """Read an owned active root prefix, with exact current-call and owner joins."""
    expected = _expectation(expectation)
    environment = os.environ if env is None else env
    evidence = None
    try:
        private = environment.get("CODEX_HOME")
        if not private and type(environment.get("HOME")) is str:private = str(Path(environment["HOME"]) / ".codex")
        if type(private) is not str or not private.startswith("/"):raise ValueError("coordinator_usage:source_unavailable")
        before = owner.observe_worker_checkpoint_sources(expected["sources"], env=environment)
        if owner.validate_worker_checkpoint_sources(before)["valid"] is not True or before["expectation"] != expected["sources"]:
            raise ValueError("coordinator_usage:owner_sources_unavailable")
        if before["status"] != "OBSERVED":
            status, issues = before["status"], ["coordinator_usage:owner_sources_unavailable"]
        else:
            scan = native._scan(before["observation"]["sources"]["root"], Path(private), pending_call_id=expected["pending_call"]["call_id"])
            active = scan["active"]; windows = [turn["window"] for turn in scan["turns"]]
            telemetry = usage.build_usage_observation([row for turn in scan["turns"] for row in turn["telemetry"]] + active["telemetry"],
                thread_id=expected["sources"]["owner"]["root_task_id"], turn_ids=[w["turn_id"] for w in windows] + [active["prefix"]["turn_id"]])
            after = owner.observe_worker_checkpoint_sources(expected["sources"], env=environment)
            if host.canonical_bytes(after) != host.canonical_bytes(before):raise ValueError("coordinator_usage:owner_changed")
            evidence = {"source_inventory":before, "source_inventory_after_sha256":after["report_sha256"],
                "source":{**{k:scan[k] for k in ("path", "file_sha256", "prefix_bytes", "custody")},
                          "metadata_source_ref":{k:scan["metadata"][k] for k in ("line", "sha256")}},
                "identity":host.native_v1_root_identity(scan["metadata"]["record"]), "windows":windows,
                "active_prefix":active["prefix"], "usage":telemetry,
                "tool_calls":sum(w["actions"]["count"] for w in [*windows,active["prefix"]])}
            _check(expected,evidence)
            status, issues = "OBSERVED", []
    except (KeyError, TypeError, ValueError, OSError, RecursionError, OverflowError) as error:
        evidence = None
        status, issues = "REFUSED", [str(error) if str(error) in _ISSUES else "coordinator_usage:source_unavailable"]
    core = {"schema":SCHEMA,"status":status,"issues":issues,"expectation":expected,"evidence":evidence,
            "scope":"owned_active_native_usage","continuation_permitted":False,"terminal_claim_permitted":False,
            "provider_free":True,"native_calls":0,"model_calls":0,"cost_usd":None}
    try:host.decode_bounded_response({**core,"report_sha256":"0"*64})
    except ValueError:core.update(status="REFUSED",issues=["coordinator_usage:report_bounds"],evidence=None)
    return {**core,"report_sha256":_sha(core)}


def validate_coordinator_usage(report: Any) -> dict:
    """Validate retained transport; the live controller invokes the reader itself."""
    try:
        value = host.decode_bounded_response(report)
        if (set(value) != {"schema","status","issues","expectation","evidence","scope","continuation_permitted","terminal_claim_permitted",
                          "provider_free","native_calls","model_calls","cost_usd","report_sha256"}
                or value["schema"] != SCHEMA or value["scope"] != "owned_active_native_usage"
                or value["continuation_permitted"] is not False or value["terminal_claim_permitted"] is not False
                or value["provider_free"] is not True or value["cost_usd"] is not None
                or any(type(value[k]) is not int or value[k] != 0 for k in ("native_calls","model_calls"))
                or value["report_sha256"] != _sha({k:v for k,v in value.items() if k != "report_sha256"})):
            raise ValueError("invalid report")
        expected = _expectation(value["expectation"])
        if value["status"] == "OBSERVED":
            if value["issues"] != []:raise ValueError("invalid observed report")
            _check(expected,value["evidence"])
        elif value["status"] in {"PENDING","REFUSED"}:
            if (value["evidence"] is not None or type(value["issues"]) is not list or len(value["issues"]) != 1
                    or type(value["issues"][0]) is not str or value["issues"][0] not in _ISSUES
                    or value["status"] == "PENDING" and value["issues"] != ["coordinator_usage:owner_sources_unavailable"]):
                raise ValueError("invalid negative report")
        else:raise ValueError("invalid status")
    except (KeyError, TypeError, ValueError, OSError, RecursionError, OverflowError):
        return {"valid":False,"issues":["coordinator_usage:report_invalid"],"scope":"canonical_transport"}
    return {"valid":True,"issues":[],"scope":"canonical_transport"}


__all__ = ["SCHEMA","observe_coordinator_usage","validate_coordinator_usage"]
