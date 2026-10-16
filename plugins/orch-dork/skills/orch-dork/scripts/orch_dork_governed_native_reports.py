"""Read-only transport validation for reports produced by the native controller.

The controller still owns action construction and all admission/authority
checks. This module reuses its constructors to check complete report bytes; it
does not turn a self-sealed report into evidence of execution or a current grant.
Embedded stage evidence remains the responsibility of its producer and the
controller's existing evaluation path.
"""
from __future__ import annotations

import math
import re
from copy import deepcopy

import orch_dork_governed_native_controller as native

COMPLETION_SOURCE_SCHEMA = "orch-dork/verified-native-completion-source-capture/v1"

_FIELDS = frozenset({
    "schema", "policy_version", "status", "decision", "controller_id", "issues", "cursor",
    "stage_report", "next_stage_action", "action", "controller_state", "hook_state_sha256",
    "provider_free", "hosted_calls", "model_calls", "native_calls", "task_creations",
    "worker_creations", "credential_reads", "authority_grants_minted", "native_action_authorizations",
    "report_sha256",
})
_STATE_FIELDS = frozenset({"terminal", "pending_intent", "action_outcome", "action_authorized",
                           "grant_state", "cleanup_required"})
_PASS = frozenset({"ACTIVATED_READ_ONLY", "ACTIVATION_RECOVERED_READ_ONLY", "STAGE_ADVANCED",
                   "ACTION_AUTHORIZED", "ACTION_PENDING", "ACTION_RESULT_READY", "ACTION_OBSERVED",
                   "WAITING_FOR_STAGE", "TERMINAL", "PRE_NATIVE_FAILURE_TERMINALIZED",
                   "REVIEW_OBSERVATION_PENDING", "CHECKPOINT_OBSERVATION_PENDING",
                   "PARTIAL_NATIVE_FAILURE_TERMINALIZED", "POST_SPAWN_FAILURE_TERMINALIZED",
                   "ACTIVATION_ONLY_FAILURE_TERMINALIZED",
                   "POST_ACK_BRIDGE_FAILURE_TERMINALIZED", "OBSERVED_SPAWN_STALL_TERMINALIZED"})
_BLOCKED = frozenset({"PROGRAM_REFUSED", "ACTIVATION_REFUSED", "CONTROLLER_NOT_ACTIVE",
                      "CONTROLLER_REFUSED", "INSPECTION_REFUSED", "STAGE_REFUSED", "STAGE_BLOCKED",
                      "OBSERVATION_REFUSED", "ACTION_EVIDENCE_CONTRADICTORY", "ACTION_TERMINAL_FAILURE",
                      "OUTCOME_UNKNOWN", "CLEANUP_REQUIRED"})
_GRANTS = frozenset({"PROVISIONAL", "AUTHORIZED", "DISPATCHED", "POST_OBSERVED", "OUTCOME_UNKNOWN",
                     "TERMINAL_OUTCOME_UNKNOWN", "TERMINAL_PRETOOL_DENIED", "TERMINAL_NOT_DISPATCHED",
                     "STALE", "MISSING"})
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("native_report:transport_invalid")


def _json(value, depth=0):
    _require(depth <= 128)
    if type(value) is dict:
        for key, child in value.items():
            _require(type(key) is str)
            _json(child, depth + 1)
    elif type(value) is list:
        for child in value:
            _json(child, depth + 1)
    elif type(value) is float:
        _require(math.isfinite(value))
    else:
        _require(type(value) in (str, int, bool, type(None)))


def _identifier(value):
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _digest(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _action(action, controller_id):
    _require(type(action) is dict and action.get("controller_id") == controller_id)
    for name in ("controller_id", "actor_thread_id", "action_id", "batch_id"):
        _require(_identifier(action.get(name)))
    for name in ("action_sha256", "tool_input_sha256", "batch_requests_sha256", "adapter_sha256"):
        _require(_digest(action.get(name)))
    _require(action.get("adapter_sha256") == native.CLOSED_NATIVE_ACTION_ADAPTER_SHA256)
    _require(action.get("predecessor_receipt_sha256") is None or _digest(action["predecessor_receipt_sha256"]))
    _require(type(action.get("batch_index")) is int and type(action.get("batch_size")) is int)
    _require(type(action.get("batch_lane_ids")) is list and all(_identifier(x) for x in action["batch_lane_ids"]))
    _require(type(action.get("batch_requests")) is list)
    # The existing owner constructor enforces the complete closed batch and
    # exact selected tool/input/action identity; the validator invents no fields.
    rebuilt = native._direct_batch_action(
        controller_id=action["controller_id"], batch_id=action["batch_id"], batch_kind=action["batch_kind"],
        batch_lane_ids=action["batch_lane_ids"], requests=action["batch_requests"], index=action["batch_index"],
        phase=action["batch_phase"], actor_thread_id=action["actor_thread_id"],
        adapter_sha256=action["adapter_sha256"], predecessor_receipt_sha256=action["predecessor_receipt_sha256"],
        failure_outcome=action["batch_failure_outcome"])
    _require(native._canonical(rebuilt) == native._canonical(action))


def validate_controller_report(report) -> dict:
    """Check complete transport bytes; this result conveys no dispatch authority."""
    try:
        _require(type(report) is dict)
        review_wait = report.get("schema") == native.REVIEW_WAIT_REPORT_SCHEMA
        _require(set(report) == (_FIELDS | {"review_observation"} if review_wait else _FIELDS))
        _json(report)
        raw = native._canonical(report)
        _require(len(raw) <= 4 * native.MAX_EVENT_BYTES)
        _require(report["schema"] in {native.REPORT_SCHEMA, native.REVIEW_WAIT_REPORT_SCHEMA}
                 and report["policy_version"] == native.CONTROLLER_POLICY_VERSION)
        status, decision = report["status"], report["decision"]
        _require(type(status) is str and type(decision) is str)
        _require((status == "PASS" and decision in _PASS) or (status == "BLOCKED" and decision in _BLOCKED))
        _require(review_wait == (decision == "REVIEW_OBSERVATION_PENDING"))
        _require(type(report["issues"]) is list and all(type(x) is str and x for x in report["issues"]))
        _require(report["issues"] == sorted(set(report["issues"])))
        _require((not report["issues"]) == (status == "PASS"))
        _require(status != "PASS" or _identifier(report["controller_id"]))
        state = report["controller_state"]
        _require(type(state) is dict and set(state) == _STATE_FIELDS)
        for name in ("terminal", "pending_intent", "action_authorized", "cleanup_required"):
            _require(type(state[name]) is bool)
        _require(state["action_outcome"] is None or state["action_outcome"] in native.ACTION_OUTCOMES)
        _require(state["grant_state"] is None or state["grant_state"] in _GRANTS)
        cursor = report["cursor"]
        _require(status != "PASS" or type(cursor) is dict)
        if cursor is not None:
            _require(type(cursor) is dict and set(cursor) == {"run_id", "seq", "event_hash"})
            _require(_identifier(cursor["run_id"]) and _digest(cursor["event_hash"]))
            _require(type(cursor["seq"]) is int and cursor["seq"] >= 1)
        _require(report["hook_state_sha256"] is None or _digest(report["hook_state_sha256"]))
        _require(report["stage_report"] is None or type(report["stage_report"]) is dict)
        action = report["action"]
        if action is not None:
            _action(action, report["controller_id"])
            _require(state["grant_state"] == "AUTHORIZED")
        _require(state["action_authorized"] is (action is not None))
        # Repeating the identical activation reports the current state read-only,
        # including an existing action or unresolved intent. It does not assert
        # operational readiness and does not authorize another dispatch.
        if status == "PASS" and decision != "ACTIVATION_RECOVERED_READ_ONLY":
            _require(not state["pending_intent"])
            _require((action is not None) == (decision in {"ACTION_AUTHORIZED", "ACTION_PENDING"}))
            _require(not (decision == "TERMINAL" or decision.endswith("_TERMINALIZED")) or state["terminal"])
            _require(decision != "ACTION_RESULT_READY" or state["grant_state"] == "POST_OBSERVED")
        for name in ("hosted_calls", "model_calls", "native_calls", "task_creations", "worker_creations",
                     "credential_reads", "authority_grants_minted", "native_action_authorizations"):
            _require(type(report[name]) is int)
        stage = report["stage_report"]
        receipt = stage.get("receipt") if type(stage) is dict else None
        bindings = receipt.get("bindings") if type(receipt) is dict else None
        if type(bindings) is dict and bindings.get("quality_phase") in {"review_submission", "semantic_review", "terminal_verification"}:
            _require(native.governed_attempt.validate_post_batch_report(stage).get("valid") is True)
            _require(bindings["review_context"]["controller_id"] == report["controller_id"])
            # Tentative evaluator receipts never become a native durable tip,
            # including on later inspect/cached-report paths.
            _require(bindings.get("review_outcome") != "pending")
            if bindings["quality_phase"] == "terminal_verification":
                # A fully validated owner-preparation stage seals dispatch
                # quiescence. Its retained owner and terminal claim are still
                # pending; ordinary verification/final stages stay live.
                _require(state["terminal"] is (receipt.get("stage") == "owner_disposition"))
        if decision == "CHECKPOINT_OBSERVATION_PENDING":
            _require(state == {"terminal":False, "pending_intent":False, "action_outcome":"completed",
                               "action_authorized":False, "grant_state":None, "cleanup_required":False})
            _require(type(stage) is dict and stage.get("schema") == native.governed_attempt.REPORT_SCHEMA
                     and stage.get("status") == "PASS" and stage.get("operation") == "worker_start"
                     and stage.get("next_action") == "continue")
            _require(type(receipt) is dict and receipt.get("stage") == "worker_start"
                     and receipt.get("status") == "AUTHORIZED" and receipt.get("next_action") == "continue")
            _require(type(bindings) is dict and bindings.get("worker_checkpoint_profile")
                     == native.governed_attempt.WORKER_CHECKPOINT_PROFILE)
        if review_wait:
            import orch_dork_qualification_review as review

            _require(status == "PASS" and state == {
                "terminal": False, "pending_intent": False, "action_outcome": None,
                "action_authorized": False, "grant_state": None, "cleanup_required": False})
            stage = report["stage_report"]
            _require(native.governed_attempt.validate_post_batch_report(stage).get("valid") is True)
            _require(stage["next_action"] == "observe_sol_review")
            bindings = stage["receipt"]["bindings"]
            _require(bindings["review_context"]["controller_id"] == report["controller_id"])
            _require(type(report["review_observation"]) is dict)
            _require(report["review_observation"].get("status") == "PENDING")
            _require(review.review_observation_decision(
                bindings["review_packet"], bindings["review_submission"], bindings["review_context"],
                report["review_observation"]) == "pending")
        rebuilt = native.GovernedNativeController._base_report(
            controller_id=report["controller_id"], status=status, decision=decision, issues=report["issues"],
            cursor=cursor, state={**state, "action": action, "stage_report": report["stage_report"]},
            hook_state_sha256=report["hook_state_sha256"],
            review_observation=report.get("review_observation") if review_wait else None)
        _require(native._canonical(rebuilt) == raw)
        return {"valid": True, "issues": [], "report_sha256": report["report_sha256"],
                "scope": "canonical_transport", "dispatch_authorized": False}
    except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
        return {"valid": False, "issues": ["native_report:transport_invalid"],
                "scope": "canonical_transport", "dispatch_authorized": False}


def completion_waiting_authority(authority):
    """Check the real compact canonical-owner projection, without I/O."""
    fields = {"status", "owner", "identity", "tip", "lifecycle", "policy", "hook_projection",
              "ground_state_sha256", "store_identity_sha256"}
    _require(type(authority) is dict)
    if "source_roots" in authority:
        fields.add("source_roots")
        native.owned_file.sealed_source_root_paths(authority["source_roots"])
    _require(set(authority) == fields)
    _require(authority["status"] == "VERIFIED")
    owner, identity, tip = authority["owner"], authority["identity"], authority["tip"]
    _require(type(owner) is dict and set(owner) == {
        "schema", "controller_id", "controller_run_id", "activation_sha256", "store_identity_sha256"})
    _require(owner["schema"] == native.native_grant_store.OWNER_SCHEMA)
    _require(type(identity) is dict and set(identity) == {
        "controller_id", "controller_run_id", "root_thread_id", "root_session_id", "root_model",
        "hook_definition_sha256", "hook_registration_sha256", "activation_sha256"})
    _require(type(tip) is dict and set(tip) == {"run_id", "seq", "event_hash"})
    _require(type(tip["seq"]) is int and tip["seq"] >= 1 and _digest(tip["event_hash"]))
    _require(tip["run_id"] == owner["controller_run_id"] == identity["controller_run_id"])
    _require(owner["controller_id"] == identity["controller_id"])
    _require(owner["activation_sha256"] == identity["activation_sha256"])
    _require(owner["store_identity_sha256"] == authority["store_identity_sha256"])
    for key in ("controller_id", "controller_run_id", "root_thread_id", "root_session_id", "root_model"):
        _require(_identifier(identity[key]))
    _require(identity["root_thread_id"] == identity["root_session_id"])
    for value in (identity["activation_sha256"], identity["hook_definition_sha256"],
                  identity["hook_registration_sha256"], authority["ground_state_sha256"], authority["store_identity_sha256"]):
        _require(_digest(value))
    _require(native._canonical(authority["lifecycle"]) == native._canonical({
        "terminal": False, "terminal_qualified": False, "terminal_evidence_sha256": None,
        "pending_intent": False, "cleanup_required": False, "action_sha256": None,
        "grant_state": None, "tool_use_id": None, "expected_binding_status": "WAITING"}))
    _require(type(authority["policy"]) is dict and set(authority["policy"]) == {"read_only_tools"})
    _require(type(authority["policy"]["read_only_tools"]) is list
             and all(type(item) is str for item in authority["policy"]["read_only_tools"]))
    _require(type(authority["hook_projection"]) is dict)


def completion_closed_batch(controller, authority, evidence, batch):
    """Reconstruct both exact receipt-derived closes and their aggregate."""
    completion_waiting_authority(authority)
    _require(validate_controller_report(controller)["valid"] is True)
    _require(controller["status"] == "PASS" and controller["decision"] == "WAITING_FOR_STAGE")
    _require(controller["controller_id"] == authority["owner"]["controller_id"])
    _require(native._canonical(controller["cursor"]) == native._canonical(authority["tip"]))
    _require(native._canonical(controller["controller_state"]) == native._canonical({
        "terminal": False, "pending_intent": False, "action_outcome": "completed",
        "action_authorized": False, "grant_state": None, "cleanup_required": False}))
    stage = controller["stage_report"]
    _require(native.governed_attempt.validate_verified_cleanup_report(stage)["valid"] is True)
    _require(stage["root_task_id"] == authority["identity"]["root_thread_id"])
    _require(stage["receipt"]["bindings"]["review_context"]["native_call"]["model"] == authority["identity"]["root_model"])
    _require(type(evidence) is list and len(evidence) == 2)
    for row in evidence:
        _require(type(row) is dict and set(row) == {"action", "pretool_report_sha256", "pretool_durable_record_sha256",
            "posttool_report_sha256", "posttool_durable_record_sha256", "result_binding"})
        for name in ("pretool_report_sha256", "pretool_durable_record_sha256", "posttool_report_sha256", "posttool_durable_record_sha256"):
            _require(_digest(row[name]))
        _action(row["action"], controller["controller_id"])
    first = evidence[0]["action"]
    proposal = {"schema": native.ACTION_PROPOSAL_SCHEMA, "action_id": first["batch_id"], "kind": "stop",
        "actor_thread_id": stage["root_task_id"], "adapter_sha256": native.CLOSED_NATIVE_ACTION_ADAPTER_SHA256}
    rebuilt, issues = native.ClosedNativeActionAdapter.authorize(proposal, next_action="stop", receipt=stage["receipt"],
        activation={"identity": {"root_thread_id": stage["root_task_id"],
            "native_adapter_sha256": native.CLOSED_NATIVE_ACTION_ADAPTER_SHA256}},
        controller_id=controller["controller_id"], seen_action_ids=[])
    _require(not issues and native._canonical(rebuilt) == native._canonical(first))
    second = native._direct_batch_action(controller_id=first["controller_id"], batch_id=first["batch_id"],
        batch_kind="stop", batch_lane_ids=first["batch_lane_ids"], requests=first["batch_requests"], index=1,
        phase="primary", actor_thread_id=first["actor_thread_id"], adapter_sha256=first["adapter_sha256"],
        predecessor_receipt_sha256=first["predecessor_receipt_sha256"])
    _require(native._canonical(second) == native._canonical(evidence[1]["action"]))
    rebuilt_batch = native.GovernedNativeController._aggregate_batch_result(evidence, first)
    _require(rebuilt_batch is not None and native._canonical(rebuilt_batch) == native._canonical(batch))


def completion_source_report(before, after, controller, evidence, batch, checkpoint, observation, closes):
    report = deepcopy({"schema": COMPLETION_SOURCE_SCHEMA, "status": observation["status"],
        "authority_before": before, "authority_after": after, "controller_report": controller,
        "action_evidence": evidence, "batch_result": batch, "checkpoint_sources": checkpoint,
        "source_observation": observation, "closes": closes, "scope": "owned_native_transport",
        "resource_release_proven": False, "terminal_claim_permitted": False,
        "provider_free": True, "native_calls": 0, "model_calls": 0, "cost_usd": None})
    return {**report, "report_sha256": native._sha(report)}


def validate_completion_source_capture(report) -> dict:
    """Check whole joins; self-sealing does not authenticate host custody.

    Hook result_sha256 covers the hook transport wrapper, whereas raw output
    covers the native return. Their exact normalized result bindings must agree;
    the two transport hashes must not be mistaken for the same bytes.
    """
    try:
        from lifecycle_conformance import host_adapter as host
        import orch_dork_qualification_verification as verification

        _require(type(report) is dict)
        _json(report)
        _require(len(native._canonical(report)) <= 4 * native.MAX_EVENT_BYTES)
        _require(report["schema"] == COMPLETION_SOURCE_SCHEMA)
        before, after, controller = report["authority_before"], report["authority_after"], report["controller_report"]
        _require(native._canonical(before) == native._canonical(after))
        rows = report["action_evidence"]
        completion_closed_batch(controller, before, rows, report["batch_result"])
        observation = report["source_observation"]
        _require(verification.validate_verified_native_source_capture(controller["stage_report"], observation,
            checkpoint_sources=report["checkpoint_sources"])["valid"] is True)
        _require(report["status"] == observation["status"])
        closes = report["closes"]
        _require(type(closes) is list)
        if observation["status"] != "OBSERVED":
            _require(closes == [])
        else:
            _require(len(closes) == 2)
            for index, lane in enumerate(("spec", "standards")):
                item, row = closes[index], rows[index]
                _require(type(item) is dict and set(item) == {"lane_id", "posttool", "source_pair"})
                _require(item["lane_id"] == lane)
                post, pair = item["posttool"], item["source_pair"]
                _require(type(post) is dict and set(post) == native.DURABLE_HOOK_EVENT_FIELDS)
                _require(post["schema"] == native.DURABLE_HOOK_EVENT_SCHEMA and post["hook_event_name"] == "PostToolUse")
                _require(post["status"] == "PASS" and post["decision"] == "OBSERVED")
                _require(post["report_sha256"] == row["posttool_report_sha256"])
                _require(post["durable_record_sha256"] == row["posttool_durable_record_sha256"]
                    == native._sha({k: v for k, v in post.items() if k != "durable_record_sha256"}))
                _require(post["tool_input_sha256"] == row["action"]["tool_input_sha256"])
                _require(type(post["identity"]) is dict and set(post["identity"]) == native.DURABLE_HOOK_IDENTITY_FIELDS)
                hook = post["native_controller"]
                _require(type(hook) is dict and set(hook) == native.DURABLE_POSTTOOL_NATIVE_FIELDS)
                _require(hook["present"] is True and hook["matched"] is True and hook["status"] == "ACTIVE")
                _require(hook["controller_id"] == controller["controller_id"] and hook["action_id"] == row["action"]["action_id"])
                _require(type(hook["controller_seq"]) is int and 0 < hook["controller_seq"] <= controller["cursor"]["seq"])
                _require(hook["grant_state"] == "POST_OBSERVED" and hook["outcome"] == "completed" and _digest(hook["result_sha256"]))
                _require(hook["pretool_report_sha256"] == row["pretool_report_sha256"])
                _require(type(pair) is dict and set(pair) == {"call", "result"})
                event = observation["evidence"]["worker_events"][lane][-1]
                for name in ("call", "result"):
                    source = pair[name]
                    _require(type(source) is dict and set(source) == {"line", "sha256", "record"})
                    _require(type(source["line"]) is int and source["line"] > 0 and _digest(source["sha256"]))
                    _require(native._canonical({k: source[k] for k in ("line", "sha256")}) == native._canonical(event["source_refs"][name]))
                    _require(source["record"]["ordinal"] == source["line"] - 1)
                call, result = pair["call"]["record"], pair["result"]["record"]
                fact = host.native_v1_worker_action_pair(call, result)
                rebuilt_event = {**fact, "turn_id": event["turn_id"], "call_timestamp": call["timestamp"],
                    "result_timestamp": result["timestamp"],
                    "source_refs": {key: {k: pair[key][k] for k in ("line", "sha256")} for key in ("call", "result")}}
                _require(native._canonical(rebuilt_event) == native._canonical(event))
                _require(fact["kind"] == "close" and fact["call_id"] == hook["tool_use_id"])
                _require(fact["worker_id"] == row["action"]["tool_input"]["target"])
                _require(post["identity"]["session_id"] == before["identity"]["root_session_id"]
                         and post["identity"]["turn_id"] == event["turn_id"])
                normalized = native.native_result.normalize_native_result(host.decode_response(result["payload"]["output"]),
                    action_kind="stop", expected_lane_ids=[lane], outcome="completed")
                _require(normalized is not None and native._canonical(normalized) == native._canonical(hook["result_binding"])
                         == native._canonical(row["result_binding"]))
        rebuilt = completion_source_report(before, after, controller, rows, report["batch_result"],
            report["checkpoint_sources"], observation, closes)
        _require(native._canonical(rebuilt) == native._canonical(report))
        return {"valid": True, "issues": [], "scope": "canonical_transport"}
    except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
        return {"valid": False, "issues": ["completion_sources:transport_invalid"], "scope": "canonical_transport"}
