"""Verify review evidence and bind final observations without terminal authority.

The artifact covers the two complete worker handoffs and their observed semantic
review. It neither acquires owner evidence nor performs comprehensive final
qualification, physical settlement, or controller admission. A verified rejected
review is a known failure, not a successful qualification.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any

import orch_dork_adaptive_contracts as contracts
import orch_dork_governed_attempt as attempt
import orch_dork_hostile_input as hostile_input
import orch_dork_native_attempt_observer as native_observer
import orch_dork_native_checkpoint_attempt as checkpoint_observer
import orch_dork_qualification_results as results
import orch_dork_qualification_review as review

VERIFICATION_SCHEMA = "orch-dork/qualification-terminal-verification/v1"
_LANES = ("spec", "standards")
_COUNTERS = ("model_calls", "hosted_calls", "credential_reads", "network_calls", "task_creations", "native_calls")
_FIELDS = {"schema", "status", "outcome", "source_report", "lane_checks", "terminal_claim_permitted",
           "provider_free", "verification_sha256", *_COUNTERS}
_INVALID = (KeyError, TypeError, ValueError, OverflowError, RecursionError)


def _bounded_bytes(value: Any) -> bytes:
    """Bound exact JSON objects before encoding, then use the public profile."""
    profile = hostile_input.PROFILE
    stack = [(value, 0)]
    nodes = 0
    while stack:
        child, depth = stack.pop()
        nodes += 1
        if depth > profile.max_depth or nodes > profile.max_nodes:
            raise ValueError("terminal_verification:json_bounds")
        if type(child) is dict:
            if len(child) > profile.max_object_keys:
                raise ValueError("terminal_verification:json_bounds")
            for key, item in child.items():
                if type(key) is not str or len(key) > profile.max_key_bytes:
                    raise ValueError("terminal_verification:json_key")
                stack.append((item, depth + 1))
        elif type(child) is list:
            if len(child) > profile.max_array_items:
                raise ValueError("terminal_verification:json_bounds")
            stack.extend((item, depth + 1) for item in child)
        elif type(child) is str:
            if len(child) > profile.max_string_bytes:
                raise ValueError("terminal_verification:json_bounds")
        elif type(child) not in (int, float, bool, type(None)):
            raise ValueError("terminal_verification:json_type")
    encoded = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    for part in encoder.iterencode(value):
        chunk = part.encode("utf-8")
        if len(encoded) + len(chunk) > profile.canonical_json_bytes:
            raise ValueError("terminal_verification:json_bounds")
        encoded.extend(chunk)
    return hostile_input.canonicalize_bounded_json(encoded, profile=profile)


def _sha(value: Any) -> str:
    return hashlib.sha256(_bounded_bytes(value)).hexdigest()


def _core(source: Any) -> dict:
    _bounded_bytes(source)
    if (type(source) is not dict or source.get("operation") not in ("semantic_review", "capacity_settlement")
            or attempt.validate_post_batch_report(source).get("valid") is not True):
        raise ValueError("terminal_verification:source_invalid")
    receipt, root = source["receipt"], source["root_task_id"]
    bindings = receipt["bindings"]
    if (bindings.get("quality_phase") != "semantic_review"
            or bindings.get("review_outcome") not in ("accepted", "rejected")
            or attempt.post_batch_next_action(root, receipt) != "verify"):
        raise ValueError("terminal_verification:review_unresolved")
    workers = bindings["worker_results"]
    if results.join_decision(workers, bindings=bindings, root_task_id=root) != "AWAITING_RESULT_AGGREGATION":
        raise ValueError("terminal_verification:worker_join_invalid")
    packet, submission, context = (bindings[key] for key in ("review_packet", "review_submission", "review_context"))
    decision = review.review_observation_decision(packet, submission, context, bindings["review_observation"])
    if (decision not in ("accepted", "rejected") or decision != bindings["review_outcome"]
            or _bounded_bytes(bindings["review_acknowledgement"]) != _bounded_bytes(
                review.build_review_acknowledgement(packet, submission, context))):
        raise ValueError("terminal_verification:review_lineage_invalid")
    checks = []
    for lane, worker, row in zip(_LANES, workers, submission["verifications"]):
        task, handoff, raw = worker["task_spec"], worker["handoff_receipt"], row["verification_receipt"]
        task_check = contracts.validate_task_spec(task)
        handoff_check = contracts.validate_handoff_receipt(handoff, task_spec=task)
        verification_check = contracts.validate_verification_receipt(raw, task_spec=task, handoff_receipt=handoff)
        if (any(check.get("valid") is not True for check in (task_check, handoff_check, verification_check))
                or worker["binding"]["logical_worker_id"] != lane or row["logical_worker_id"] != lane
                or raw["verifier"]["identity"] != root or raw["verifier"]["clean_context"] is not True
                or raw["implementer_identity"] != worker["binding"]["worker_id"] or type(raw["pass"]) is not bool):
            raise ValueError("terminal_verification:lane_invalid")
        checks.append({"logical_worker_id": lane, "task_spec_sha256": task_check["digest"],
                       "handoff_receipt_sha256": _sha(handoff), "verification_receipt_sha256": _sha(raw),
                       "passed": raw["pass"]})
    if len(checks) != 2 or (decision == "accepted") != all(row["passed"] for row in checks):
        raise ValueError("terminal_verification:verdict_mismatch")
    return {"schema": VERIFICATION_SCHEMA, "status": "PASS", "outcome": "success" if decision == "accepted" else "failure",
            "source_report": deepcopy(source), "lane_checks": checks, "terminal_claim_permitted": False,
            "provider_free": True, **{key: 0 for key in _COUNTERS}}


def build_terminal_verification(predecessor_report: Any) -> dict:
    """Seal whole available evidence; acquire no authority and perform no effects.

    TaskSpec digests use the owning contract identity. The two receipt hashes
    cover the whole raw retained objects, including any optional receipt seal.
    """
    try:
        core = _core(predecessor_report)
        report = {**core, "verification_sha256": _sha(core)}
        _bounded_bytes(report)
        return report
    except _INVALID as error:
        raise ValueError("terminal_verification:source_invalid") from error


def validate_terminal_verification(report: Any) -> dict:
    """Check exact canonical transport; confer no admission or terminal authority."""
    try:
        encoded = _bounded_bytes(report)
        if type(report) is not dict or set(report) != _FIELDS:
            raise ValueError("terminal_verification:report_invalid")
        expected = build_terminal_verification(report["source_report"])
        if encoded != _bounded_bytes(expected):
            raise ValueError("terminal_verification:report_invalid")
    except _INVALID:
        return {"valid": False, "issues": ["terminal_verification:report_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def _native_attempt_expectation(predecessor_report: Any, *, source_capture: bool) -> dict:
    """Derive the same source identity at two distinct, verified boundaries."""
    try:
        _bounded_bytes(predecessor_report)
        if attempt.validate_post_batch_report(predecessor_report).get("valid") is not True:
            raise ValueError("invalid predecessor")
        root = predecessor_report["root_task_id"]
        receipt = predecessor_report["receipt"]
        bindings = receipt["bindings"]
        action = attempt.post_batch_next_action(root, receipt)
        ready = (receipt["stage"] == "cleanup" and action == "stop"
                 if source_capture else action == "final_qualification")
        if bindings.get("quality_phase") != "terminal_verification" or not ready:
            raise ValueError("verified source boundary not ready")
        joined = results.join_bindings(bindings, root)
        context = bindings["review_context"]
        if review.validate_review_context(bindings["review_packet"], context).get("valid") is not True:
            raise ValueError("invalid review context")
        call, inventory = context["native_call"], context["owner_hook_inventory_report"]
        expected = {
            "owner": {
                "root_task_id": root,
                "worker_ids": {row["binding"]["logical_worker_id"]: row["binding"]["worker_id"] for row in joined},
                "owner_identity_sha256": inventory["owner_identity_sha256"],
                "app_server_argv_sha256": inventory["app_server_argv_sha256"],
                "hook_inventory_report_sha256": inventory["report_sha256"],
            },
            "root": {"model": call["model"], "effort": call["effort"], "review_turn_id": call["turn_id"]},
            "lanes": {row["binding"]["logical_worker_id"]: {key: row["binding"][key] for key in ("model", "effort")}
                      for row in joined},
        }
        selected_text = [root, *expected["owner"]["worker_ids"].values(), *expected["root"].values(),
                         *(value for route in expected["lanes"].values() for value in route.values())]
        if any(type(value) is not str or not 0 < len(value) <= 128 for value in selected_text):
            raise ValueError("unsupported native selection")
        return expected
    except _INVALID as error:
        raise ValueError("final_observation:predecessor_invalid") from error


def build_native_attempt_expectation(predecessor_report: Any) -> dict:
    """Derive the complete native selection after verified physical release.

    This remains the final-success observation boundary. It proves neither
    current controller custody nor final qualification by itself.
    """
    return _native_attempt_expectation(predecessor_report, source_capture=False)


def build_native_source_capture_expectation(predecessor_report: Any) -> dict:
    """Select verified source bytes while the retained owner can still be read.

    A cleanup authorization permits observation, not a cleanup or release
    claim. The native reader independently requires an idle root and the whole
    completed action trace, including both closes. Failure verification may be
    captured as evidence but cannot pass the final-success boundary.
    """
    return _native_attempt_expectation(predecessor_report, source_capture=True)


def _native_selection(predecessor_report: Any, checkpoint_sources: Any, *, source_capture: bool = False) -> dict:
    expected = (build_native_source_capture_expectation(predecessor_report) if source_capture
                else build_native_attempt_expectation(predecessor_report))
    bindings = predecessor_report["receipt"]["bindings"]
    if "worker_checkpoint_profile" not in bindings:
        if checkpoint_sources is not None or "checkpoint_sources_sha256" in bindings:
            raise ValueError("final_observation:checkpoint_profile_invalid")
        return expected
    if (bindings["worker_checkpoint_profile"] != attempt.WORKER_CHECKPOINT_PROFILE
            or type(checkpoint_sources) is not dict):
        raise ValueError("final_observation:checkpoint_profile_invalid")
    selected = checkpoint_observer.build_native_checkpoint_attempt_expectation(expected, checkpoint_sources)
    if selected["checkpoint_sources_sha256"] != bindings.get("checkpoint_sources_sha256"):
        raise ValueError("final_observation:checkpoint_sources_changed")
    events = []
    for index, target in enumerate(results.join_bindings(bindings, predecessor_report["root_task_id"])):
        binding = target["binding"]
        report = checkpoint_sources["workers"]["evidence"]["workers"][binding["logical_worker_id"]]["progress_report"]
        if ({key:report["binding"][key] for key in binding} != binding
                or report["task_spec"]["task_spec_sha256"] != target["task_spec_sha256"]):
            raise ValueError("final_observation:checkpoint_membership_changed")
        packet = report["progress_packet"]
        events.append({"seq":index + 1, "type":"packet.observed", "logical_worker_id":binding["logical_worker_id"],
                       "worker_id":binding["worker_id"], "packet":packet, "evidence_pointer":packet["source_pointer"]})
    prefix = {"1":{"progress_id":"checkpoint:" + predecessor_report["receipt"]["attempt_id"] + ":1", "events":events}}
    if (type(bindings["capacity_wave_index"]) is not int or bindings["capacity_wave_index"] != 1
            or _bounded_bytes(bindings["progress_prefixes"]) != _bounded_bytes(prefix)):
        raise ValueError("final_observation:checkpoint_prefix_changed")
    return selected


def _check_native_observation(predecessor_report: dict, observation: Any, expected: dict, checkpoint_sources: Any) -> None:
    if checkpoint_sources is None:
        checked = native_observer.validate_native_two_lane_attempt_observation(observation)
    else:
        checked = checkpoint_observer.validate_native_checkpoint_attempt_observation(observation, checkpoint_sources)
    if checked.get("valid") is not True or observation["expectation"] != expected:
        raise ValueError("final_observation:reader_invalid")
    if checkpoint_sources is not None and observation["status"] == "OBSERVED":
        # A complete native trace must contain the exact final source bytes
        # whose typed handoffs were reviewed, not merely the same worker IDs.
        for result in predecessor_report["receipt"]["bindings"]["worker_results"]:
            lane = result["binding"]["logical_worker_id"]
            source = observation["evidence"]["roles"][lane]
            runtime = result["runtime_observation"]
            if (source["file_sha256"] != runtime["source_sha256"]
                    or source["windows"][-1]["end"]["line"] != runtime["terminal_record"]["line"]
                    or runtime["usage"]["tool_calls"] != 0
                    or any(source["usage"]["totals"]["reasoning_output_tokens" if key == "reasoning_tokens" else key] != runtime["usage"][key]
                           for key in ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "total_tokens"))):
                raise ValueError("final_observation:verified_result_changed")


def observe_verified_native_attempt(predecessor_report: Any, *, checkpoint_sources=None, env=None) -> dict:
    """Read only the verified predecessor's native attempt; perform no admission."""
    expected = _native_selection(predecessor_report, checkpoint_sources)
    observation = (native_observer.observe_native_two_lane_attempt(expected, env=env) if checkpoint_sources is None
                   else checkpoint_observer.observe_native_checkpoint_attempt(expected, checkpoint_sources, env=env))
    _check_native_observation(predecessor_report, observation, expected, checkpoint_sources)
    return observation


def validate_verified_native_attempt(predecessor_report: Any, observation: Any, *, checkpoint_sources=None) -> dict:
    """Join whole canonical proofs; neither authenticate custody nor qualify.

    A valid PENDING/REFUSED observation remains unobserved. A final gate must
    require OBSERVED and independently satisfy every other terminal condition.
    """
    try:
        expected = _native_selection(predecessor_report, checkpoint_sources)
        _check_native_observation(predecessor_report, observation, expected, checkpoint_sources)
    except _INVALID:
        return {"valid": False, "issues": ["final_observation:binding_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def observe_verified_native_source_capture(predecessor_report: Any, *, checkpoint_sources=None, env=None) -> dict:
    """Capture complete source evidence before owner process cleanup or release.

    No controller/grant/capacity state changes. PENDING and REFUSED remain
    unobserved. A later terminal gate must rejoin the observation to the released
    predecessor and independently verify all remaining closure obligations.
    """
    expected = _native_selection(predecessor_report, checkpoint_sources, source_capture=True)
    observation = (native_observer.observe_native_two_lane_attempt(expected, env=env) if checkpoint_sources is None
                   else checkpoint_observer.observe_native_checkpoint_attempt(expected, checkpoint_sources, env=env))
    _check_native_observation(predecessor_report, observation, expected, checkpoint_sources)
    return observation


def validate_verified_native_source_capture(predecessor_report: Any, observation: Any, *, checkpoint_sources=None) -> dict:
    """Validate source-capture transport without claiming current owner custody."""
    try:
        expected = _native_selection(predecessor_report, checkpoint_sources, source_capture=True)
        _check_native_observation(predecessor_report, observation, expected, checkpoint_sources)
    except _INVALID:
        return {"valid": False, "issues": ["source_capture:binding_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


NATIVE_DAG_CUSTODY_SCHEMA = "orch-dork/native-dependency-ordered-custody/v1"


def build_native_dependency_ordered_custody(logical_plan: Any, predecessor_report: Any, observation: Any,
                                             *, checkpoint_sources=None) -> dict:
    """Project known zero-tool lane custody from whole verified native sources.

    This bounded native profile has no worker resource accesses or ownership
    transfers. Nonzero or unknown actions require an access collector, never an
    invented empty list. The final host gate must authenticate these sources and
    the original plan, and still check root verification and every other gate.
    """
    import orch_dork_custody as custody
    try:
        _bounded_bytes(logical_plan)
        receipt = predecessor_report["receipt"]
        plan = attempt.efficiency_governor.validate_logical_plan(logical_plan)
        if (plan["status"] != "PASS" or plan["plan_sha256"] != receipt["plan_sha256"]
                or logical_plan["execution"]["profile"] != "finite_dag/v1"
                or logical_plan["integration"]["strategy"] != "dependency_ordered"
                or logical_plan["integration"]["release_required"] is not False
                or validate_verified_native_attempt(predecessor_report, observation,
                    checkpoint_sources=checkpoint_sources)["valid"] is not True
                or observation["status"] != "OBSERVED"):
            raise ValueError("unverified finite source")
        targets = results.join_bindings(receipt["bindings"], predecessor_report["root_task_id"])
        events, counts, sources = [], {}, {}
        for index, target in enumerate(targets, 1):
            lane, worker = target["binding"]["logical_worker_id"], target["binding"]["worker_id"]
            source = observation["evidence"]["roles"][lane]
            windows = source["windows"]
            if (not windows or source["task_id"] != worker
                    or any(type(window["actions"]["count"]) is not int or window["actions"]["count"] != 0
                           or window["actions"]["items"] != [] for window in windows)):
                raise ValueError("native access collector required")
            counts[lane] = 0
            events.append({"seq":index, "type":"lane.completed", "lane_id":lane, "worker_id":worker})
            sources[lane] = {"worker_id":worker, "source_sha256":source["file_sha256"],
                "completed_turn":deepcopy(windows[-1]["end"])}
        bundle = {"schema":custody.DEPENDENCY_ORDERED_EVENT_SCHEMA, "events":events, "access_counts":counts}
        checked = attempt.efficiency_governor._wave_custody(logical_plan, logical_plan_sha256=receipt["plan_sha256"],
            selected=list(counts), members=[{"logical_worker_id":row["lane_id"],"worker_id":row["worker_id"]} for row in events],
            event_bundle=bundle, typed_version=3)
        if checked["status"] != "PASS":raise ValueError("invalid native custody projection")
        core = {"schema":NATIVE_DAG_CUSTODY_SCHEMA, "status":"PASS", "scope":"canonical_native_custody_projection",
            "plan_sha256":receipt["plan_sha256"], "predecessor_receipt_sha256":receipt["receipt_sha256"],
            "native_observation_sha256":observation["report_sha256"],
            "checkpoint_sources_sha256":receipt["bindings"].get("checkpoint_sources_sha256"),
            "bundle":bundle, "lane_sources":sources, "custody_report":checked,
            "root_verification_required":True, "terminal_claim_permitted":False, "resource_release_proven":False,
            "provider_free":True, "model_calls":0, "native_calls":0}
        return deepcopy({**core,"report_sha256":attempt._sha(core)})
    except _INVALID as error:
        raise ValueError("native_custody:source_invalid") from error


def validate_native_dependency_ordered_custody(report: Any, logical_plan: Any, predecessor_report: Any,
                                               observation: Any, *, checkpoint_sources=None) -> bool:
    """Reconstruct the complete projection, without authenticating host custody."""
    try:
        return _bounded_bytes(report) == _bounded_bytes(build_native_dependency_ordered_custody(logical_plan,
            predecessor_report, observation, checkpoint_sources=checkpoint_sources))
    except _INVALID:
        return False


__all__ = ["VERIFICATION_SCHEMA", "build_terminal_verification", "validate_terminal_verification",
           "build_native_attempt_expectation", "observe_verified_native_attempt", "validate_verified_native_attempt",
           "build_native_source_capture_expectation", "observe_verified_native_source_capture", "validate_verified_native_source_capture",
           "build_native_dependency_ordered_custody", "validate_native_dependency_ordered_custody"]
