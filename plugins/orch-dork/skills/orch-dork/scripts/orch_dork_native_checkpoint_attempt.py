"""Observe the complete native lifecycle without replacing accepted checkpoints.

The owning controller supplies its retained checkpoint bundle and selection.
This reader authenticates current source custody and unchanged prefix bytes;
it does not establish quality, shared-capacity release, or qualification.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from lifecycle_conformance import host_adapter as host
import orch_dork_local_task_runtime as owner
import orch_dork_native_attempt_observer as native
import orch_dork_qualification_progress as progress

SCHEMA = "orch-dork/native-checkpoint-attempt-observation/v1"
_BASE_EVIDENCE = {"owner_before", "owner_after", "roles", "worker_events", "root_identity", "root_turn_ids", "root_extent"}
_ISSUES = {"checkpoint_attempt:" + reason for reason in (
    "owner_sources_unavailable", "owner_changed", "source_unavailable", "prefix_changed", "report_bounds")}
_INVALID = (KeyError, TypeError, ValueError, OSError, RecursionError, OverflowError)


def _sha(value: Any) -> str:
    return hashlib.sha256(host.canonical_bytes(value)).hexdigest()


def _report_bytes(value: Any) -> bytes:
    # A composed qualification artifact uses the existing qualification JSON
    # profile (4096 value nodes, 256 KiB). Raw native records still pass the
    # separate host graph profile, which also counts mapping keys. Requiring
    # the retained checkpoint bundle separately avoids copying that whole
    # already-bounded proof into another report.
    from orch_dork_qualification_verification import _bounded_bytes
    encoded = _bounded_bytes(value)
    host.canonical_bytes(value)
    return encoded


def _expectation(value: Any) -> dict:
    value = host.decode_bounded_response(value)
    if (set(value) != {"attempt", "checkpoint_sources_sha256"}
            or not native._digest(value["checkpoint_sources_sha256"])):
        raise ValueError("checkpoint_attempt:expectation_invalid")
    native._expectation(value["attempt"])
    return value


def _sources(expected: dict, sources: Any) -> dict:
    if type(sources) is not dict or set(sources) != {"coordinator", "workers"}:
        raise ValueError("checkpoint_attempt:prefix_changed")
    target = expected["attempt"]
    progress.build_checkpoint_ingress_observation(
        {"root_task_id":target["owner"]["root_task_id"], "root_model":target["root"]["model"],
         "root_effort":target["root"]["effort"]}, sources["coordinator"], sources["workers"])
    selection = sources["workers"]["expectation"]
    if (expected["checkpoint_sources_sha256"] != _sha(sources)
            or selection["sources"]["owner"] != target["owner"]
            or any({key:selection["lanes"][lane][key] for key in ("model", "effort")} != target["lanes"][lane]
                   for lane in ("spec", "standards"))):
        raise ValueError("checkpoint_attempt:prefix_changed")
    return {"root":sources["coordinator"]["evidence"]["source"],
            **{lane:row["source"] for lane,row in sources["workers"]["evidence"]["workers"].items()}}


def build_native_checkpoint_attempt_expectation(attempt_selection: Any, checkpoint_sources: Any) -> dict:
    """Bind a supplied selection to whole source transport, without authority."""
    sources = host.decode_bounded_response(checkpoint_sources)
    expected = _expectation({"attempt":attempt_selection, "checkpoint_sources_sha256":_sha(sources)})
    _sources(expected, sources)
    return expected


def _check(expected: dict, evidence: Any, checkpoint_sources: Any) -> None:
    if type(evidence) is not dict or set(evidence) != _BASE_EVIDENCE | {"checkpoint_prefixes"}:
        raise ValueError("checkpoint_attempt:prefix_changed")
    old_sources = _sources(expected, checkpoint_sources)
    native._check_evidence(expected["attempt"], {key:evidence[key] for key in _BASE_EVIDENCE}, continuation_count=2)
    links = evidence["checkpoint_prefixes"]
    if type(links) is not dict or set(links) != {"root", "spec", "standards"}:
        raise ValueError("checkpoint_attempt:prefix_changed")
    for role, before in old_sources.items():
        after, link = evidence["roles"][role], links[role]
        if (type(link) is not dict or set(link) != {"prefix_bytes", "accepted_sha256", "observed_sha256"}
                or type(link["prefix_bytes"]) is not int or link["prefix_bytes"] != before["prefix_bytes"]
                or not 0 < link["prefix_bytes"] < after["prefix_bytes"]
                or link["accepted_sha256"] != before["file_sha256"] or link["observed_sha256"] != before["file_sha256"]
                or before["path"] != after["path"] or before["metadata_source_ref"] != after["metadata_source_ref"]
                or any(before["custody"][key] != after["custody"][key] for key in ("owner_uid", "device", "inode"))):
            raise ValueError("checkpoint_attempt:prefix_changed")
        if role != "root":
            if (before["windows"] != after["windows"][:2]
                    or before["usage"]["per_turn"] != after["usage"]["per_turn"][:2]):
                raise ValueError("checkpoint_attempt:prefix_changed")
    root = checkpoint_sources["coordinator"]["evidence"]
    active = root["active_prefix"]
    window = next((row for row in evidence["roles"]["root"]["windows"] if row["turn_id"] == active["turn_id"]), None)
    old_ids = [row["id"] for row in root["source_inventory"]["observation"]["sources"]["root"]["turns"]]
    current_ids = [row["id"] for row in evidence["owner_before"]["observation"]["sources"]["root"]["turns"]]
    if (window is None or old_ids != current_ids[:len(old_ids)]
            or active["source_refs"] != window["source_refs"][:len(active["source_refs"])]
            or active["actions"]["items"] != window["actions"]["items"][:active["actions"]["count"]]):
        raise ValueError("checkpoint_attempt:prefix_changed")
    for lane in ("spec", "standards"):
        events = evidence["worker_events"][lane]
        if (not events[1]["source_refs"]["result"]["line"] < active["through"]["line"] < events[2]["source_refs"]["call"]["line"]
                or native._clock(old_sources[lane]["windows"][-1]["end"]["timestamp"]) > native._clock(active["through"]["timestamp"])):
            raise ValueError("checkpoint_attempt:prefix_changed")


def observe_native_checkpoint_attempt(expectation: Any, checkpoint_sources: Any, *, env: Mapping[str, str] | None = None) -> dict:
    """Read ACK/checkpoint/final turns and two distinct native continuations."""
    expected = _expectation(expectation)
    environment = os.environ if env is None else env
    evidence = None
    try:
        checkpoint_sources = host.decode_bounded_response(checkpoint_sources)
        old_sources = _sources(expected, checkpoint_sources)
        private = environment.get("CODEX_HOME")
        if not private and type(environment.get("HOME")) is str:private = str(Path(environment["HOME"]) / ".codex")
        if type(private) is not str or not private.startswith("/"):raise ValueError("checkpoint_attempt:source_unavailable")
        before = owner.observe_completed_attempt_sources(expected["attempt"]["owner"], env=environment)
        if (owner.validate_completed_attempt_sources(before)["valid"] is not True
                or before["expectation"] != expected["attempt"]["owner"]):
            raise ValueError("checkpoint_attempt:owner_sources_unavailable")
        if before["status"] != "OBSERVED":
            status, issues = before["status"], ["checkpoint_attempt:owner_sources_unavailable"]
        else:
            scans = {role:native._scan(source, Path(private), retain_raw=True)
                     for role,source in before["observation"]["sources"].items()}
            joined = native._join(expected["attempt"], before, scans, continuation_count=2)
            prefixes = {role:{"prefix_bytes":source["prefix_bytes"], "accepted_sha256":source["file_sha256"],
                             "observed_sha256":hashlib.sha256(scans[role]["raw"][:source["prefix_bytes"]]).hexdigest()}
                        for role,source in old_sources.items()}
            after = owner.observe_completed_attempt_sources(expected["attempt"]["owner"], env=environment)
            if after != before:raise ValueError("checkpoint_attempt:owner_changed")
            evidence = {"owner_before":before, "owner_after":after, **joined,
                        "checkpoint_prefixes":prefixes}
            _check(expected, evidence, checkpoint_sources)
            status, issues = "OBSERVED", []
    except _INVALID as error:
        evidence = None
        status, issues = "REFUSED", [str(error) if str(error) in _ISSUES else "checkpoint_attempt:source_unavailable"]
    core = {"schema":SCHEMA, "status":status, "issues":issues, "expectation":expected, "evidence":evidence,
            "scope":"owned_native_transport", "qualification_permitted":False, "resource_release_proven":False,
            "provider_free":True, "native_calls":0, "model_calls":0, "cost_usd":None}
    try:_report_bytes({**core, "report_sha256":"0" * 64})
    except ValueError:core.update(status="REFUSED", issues=["checkpoint_attempt:report_bounds"], evidence=None)
    return {**core, "report_sha256":_sha(core)}


def validate_native_checkpoint_attempt_observation(report: Any, checkpoint_sources: Any) -> dict:
    """Require the retained bundle bound by this report, without granting custody."""
    try:
        value = json.loads(_report_bytes(report))
        if (set(value) != {"schema", "status", "issues", "expectation", "evidence", "scope", "qualification_permitted",
                          "resource_release_proven", "provider_free", "native_calls", "model_calls", "cost_usd", "report_sha256"}
                or value["schema"] != SCHEMA or value["scope"] != "owned_native_transport" or value["provider_free"] is not True
                or value["qualification_permitted"] is not False or value["resource_release_proven"] is not False or value["cost_usd"] is not None
                or any(type(value[key]) is not int or value[key] != 0 for key in ("native_calls", "model_calls"))
                or value["report_sha256"] != _sha({key:child for key,child in value.items() if key != "report_sha256"})):
            raise ValueError("invalid transport")
        expected = _expectation(value["expectation"])
        checkpoint_sources = host.decode_bounded_response(checkpoint_sources)
        _sources(expected, checkpoint_sources)
        if value["status"] == "OBSERVED":
            if value["issues"] != []:raise ValueError("invalid observed transport")
            _check(expected, value["evidence"], checkpoint_sources)
        elif value["status"] in {"PENDING", "REFUSED"}:
            if (value["evidence"] is not None or type(value["issues"]) is not list or len(value["issues"]) != 1
                    or type(value["issues"][0]) is not str or value["issues"][0] not in _ISSUES
                    or value["status"] == "PENDING" and value["issues"] != ["checkpoint_attempt:owner_sources_unavailable"]):
                raise ValueError("invalid negative transport")
        else:raise ValueError("invalid status")
    except _INVALID:
        return {"valid":False, "issues":["checkpoint_attempt:report_invalid"], "scope":"canonical_transport"}
    return {"valid":True, "issues":[], "scope":"canonical_transport"}


__all__ = ["SCHEMA", "build_native_checkpoint_attempt_expectation", "observe_native_checkpoint_attempt",
           "validate_native_checkpoint_attempt_observation"]
