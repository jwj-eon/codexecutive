"""Pure Sol-shaped review submissions, without model or controller authority.

These helpers validate submitted content and host-generated transport seals.
They establish neither actual model/root provenance nor controller acceptance,
qualification, or physical authority. Verification receipts remain whole raw
objects; the submission seal does not turn them into observed Sol output.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import PurePosixPath
from typing import Any

import orch_dork_adaptive_contracts as contracts
import orch_dork_governed_attempt as attempt
import orch_dork_hostile_input as hostile_input
import orch_dork_local_task_runtime as local_runtime
import orch_dork_model_profile_registry as model_profiles

PACKET_SCHEMA = "orch-dork/qualification-review-packet/v1"
SUBMISSION_SCHEMA = "orch-dork/qualification-review-submission/v1"
CONTEXT_SCHEMA = "orch-dork/qualification-review-context/v1"
BOOTSTRAP_CONTEXT_SCHEMA = "orch-dork/qualification-bootstrap-review-context/v1"
ACKNOWLEDGEMENT_SCHEMA = "orch-dork/qualification-review-acknowledgement/v1"
NATIVE_CALL_SCHEMA = "orch-dork/host-mcp-call-context/v1"
_PACKET_FIELDS = {"schema", "source_report", "subject_sha256", "packet_sha256"}
_SUBMISSION_FIELDS = {"schema", "subject_sha256", "verifications", "submission_sha256"}
_ROW_FIELDS = {"logical_worker_id", "verification_receipt"}
_CONTEXT_FIELDS = {"schema", "controller_id", "pre_turn_report_path", "pre_turn_report_sha256",
                   "native_call", "owner_hook_inventory_report"}
_BOOTSTRAP_CONTEXT_FIELDS = {"schema", "controller_id", "bootstrap_artifact_path",
                             "bootstrap_report_sha256", "native_call", "owner_hook_inventory_report"}
_NATIVE_CALL_FIELDS = {"schema", "task_id", "session_id", "turn_id", "tool_call_id", "model", "effort",
                      "turn_started_at_unix_ms", "source_meta_sha256"}
_INVALID_INPUT = (KeyError, TypeError, ValueError, OverflowError, RecursionError)


def _json_value(value: Any, depth: int = 0, nodes: list[int] | None = None) -> None:
    """Reject Python-only containers and scalars before sealing raw JSON values."""
    if depth > hostile_input.PROFILE.max_depth:
        raise ValueError("review:json_depth_exceeded")
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > hostile_input.PROFILE.max_nodes:
        raise ValueError("review:json_nodes_exceeded")
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str or len(key) > hostile_input.PROFILE.max_key_bytes:
                raise ValueError("review:json_key_invalid")
            _json_value(child, depth + 1, nodes)
    elif type(value) is list:
        for child in value:
            _json_value(child, depth + 1, nodes)
    elif type(value) is str and len(value) > hostile_input.PROFILE.max_string_bytes:
        raise ValueError("review:json_string_exceeded")
    elif type(value) not in (str, int, float, bool, type(None)):
        raise ValueError("review:json_value_invalid")


def _bounded_bytes(value: Any) -> bytes:
    _json_value(value)
    encoded = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    for part in encoder.iterencode(value):
        chunk = part.encode("utf-8")
        if len(encoded) + len(chunk) > hostile_input.PROFILE.canonical_json_bytes:
            raise ValueError("review:json_size_exceeded")
        encoded.extend(chunk)
    return hostile_input.canonicalize_bounded_json(encoded, profile=hostile_input.PROFILE)


def _sha(value: Any) -> str:
    return hashlib.sha256(_bounded_bytes(value)).hexdigest()


def _source_report(source: Any) -> dict:
    _bounded_bytes(source)
    if (type(source) is not dict or attempt.validate_post_batch_report(source).get("valid") is not True
            or attempt.post_batch_next_action(source["root_task_id"], source["receipt"]) != "sol_review"):
        raise ValueError("review_packet:source_invalid")
    return source


def _subject_sha256(source: dict) -> str:
    """Bind immutable review inputs, independently of physical cleanup state."""
    receipt = source["receipt"]
    subject = {key: receipt[key] for key in (
        "identity_sha256", "run_id", "attempt_id", "root_task_id", "plan_id", "plan_revision", "plan_sha256",
    )}
    subject.update(
        root_model=source["routing"]["root"]["model"], root_effort=source["routing"]["root"]["effort"],
        installed_version=source["tool"]["version"], worker_results=receipt["bindings"]["worker_results"],
    )
    return _sha(subject)


def build_review_packet(source_report: Any) -> dict:
    """Detach the whole canonical report awaiting review; perform no effects."""
    try:
        source = _source_report(source_report)
        core = {"schema": PACKET_SCHEMA, "source_report": source, "subject_sha256": _subject_sha256(source)}
        return {**deepcopy(core), "packet_sha256": _sha(core)}
    except _INVALID_INPUT as error:
        raise ValueError("review_packet:invalid") from error


def _packet_source(packet: Any) -> dict:
    if (type(packet) is not dict or set(packet) != _PACKET_FIELDS or packet["schema"] != PACKET_SCHEMA
            or type(packet["packet_sha256"]) is not str or type(packet["subject_sha256"]) is not str
            or packet["packet_sha256"] != _sha({key: child for key, child in packet.items() if key != "packet_sha256"})):
        raise ValueError("review_packet:invalid")
    source = _source_report(packet["source_report"])
    if packet["subject_sha256"] != _subject_sha256(source):
        raise ValueError("review_packet:subject_mismatch")
    return source


def validate_review_packet(packet: Any) -> dict:
    """Check canonical transport only, without authenticating model provenance."""
    try:
        _packet_source(packet)
    except _INVALID_INPUT:
        return {"valid": False, "issues": ["review_packet:invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def verification_receipt_templates(packet: Any) -> list[dict]:
    """Build the two verification rows the reviewer fills, one per lane.

    Every value the reviewer cannot judge is prefilled from the packet: the
    TaskSpec and handoff digests, the handoff's artifact references and check
    results, the acceptance criteria, the worker as implementer and the root
    task as clean-context verifier.  The verdict defaults to inconclusive, so
    nothing is accepted unless the reviewer decides it.  Rehearsal run 15's
    root, told only to derive complete receipts, invented a field set.
    """
    try:
        source = _packet_source(packet)
        rows = []
        for lane, result in zip(("spec", "standards"), source["receipt"]["bindings"]["worker_results"]):
            task, handoff = result["task_spec"], result["handoff_receipt"]
            rows.append({
                "logical_worker_id": lane,
                "verification_receipt": {
                    "schema": contracts.VERIFICATION_RECEIPT_SCHEMA,
                    "task_spec_sha256": contracts.validate_task_spec(task)["digest"],
                    "subject_handoff_sha256": contracts.validate_handoff_receipt(
                        handoff, task_spec=task)["digest"],
                    "artifact_refs": deepcopy(handoff["artifact_refs"]),
                    "diff_refs": [],
                    "acceptance_criteria": deepcopy(task["acceptance_checks"]),
                    "check_results": deepcopy(handoff["checks"]),
                    "implementer_identity": result["binding"]["worker_id"],
                    "verifier": {"identity": source["root_task_id"], "clean_context": True},
                    "disposition": "inconclusive",
                    "pass": False,
                    "findings": [],
                },
            })
        _verification_decision(source, rows)
        return rows
    except _INVALID_INPUT as error:
        raise ValueError("review_templates:invalid") from error


REVIEW_TEMPLATE_INSTRUCTION = (
    "Pass verifications exactly as the verification_templates array below, in "
    "the same order, changing only three fields of each verification_receipt "
    "after reviewing that lane's handoff in the review packet: set disposition "
    "to exactly one of fail, inconclusive, pass; set pass to true only when "
    "disposition is pass; and optionally add findings, each "
    '{"id","severity","statement","evidence_refs"} with a unique id, severity '
    "exactly one of error, info, warning, a one-sentence statement, and exactly "
    "one evidence_refs entry that is a complete object copied from that "
    "receipt's artifact_refs (never a URI string). Copy every other field "
    "unchanged and add no fields. Use severity error only for a statement the "
    "sealed review corpus or review packet contradicts or a disposition or check status the evidence "
    "does not support; set disposition fail only when at least one finding has "
    "severity error; record an unsupported or over-broad remark that does not "
    "change the lane's result as a warning finding and keep disposition pass; "
    "use inconclusive only when you cannot check the handoff against the packet."
)


def _verification_decision(source: dict, verifications: Any) -> str:
    _bounded_bytes(verifications)
    if type(verifications) is not list or len(verifications) != 2:
        raise ValueError("review_submission:verifications_invalid")
    results = source["receipt"]["bindings"]["worker_results"]
    for lane, result, row in zip(("spec", "standards"), results, verifications):
        if type(row) is not dict or set(row) != _ROW_FIELDS or row["logical_worker_id"] != lane:
            raise ValueError("review_submission:lane_invalid")
        raw = row["verification_receipt"]
        if type(raw) is not dict:
            raise ValueError("review_submission:verification_invalid:" + lane + ":not_object")
        report = contracts.validate_verification_receipt(
            raw, task_spec=result["task_spec"], handoff_receipt=result["handoff_receipt"])
        # Name the lane and the first contract issues so a refusal is
        # diagnosable from its own output (rehearsal run 15 reported only
        # "submission_refused").
        problems = list(report.get("issues") or [])[:3] if report.get("valid") is not True else []
        if not problems:
            if raw["verifier"]["identity"] != source["root_task_id"]:
                problems.append("verifier_identity_mismatch")
            if raw["verifier"]["clean_context"] is not True:
                problems.append("verifier_clean_context_required")
            if raw["implementer_identity"] != result["binding"]["worker_id"]:
                problems.append("implementer_identity_mismatch")
        if problems:
            raise ValueError("review_submission:verification_invalid:" + lane + ":" + ",".join(problems))
    return "accepted" if all(row["verification_receipt"]["pass"] is True for row in verifications) else "rejected"


def build_review_submission(packet: Any, verifications: Any) -> dict:
    """Seal raw submitted verifications, including valid failed or abstaining verdicts."""
    try:
        source = _packet_source(packet)
        _verification_decision(source, verifications)
        core = {"schema": SUBMISSION_SCHEMA, "subject_sha256": packet["subject_sha256"],
                "verifications": verifications}
        return {**deepcopy(core), "submission_sha256": _sha(core)}
    except _INVALID_INPUT as error:
        raise ValueError("review_submission:invalid") from error


def review_submission_decision(packet: Any, submission: Any) -> str:
    """Return accepted/rejected for valid content; raise for invalid transport.

    An accepted submission is a content verdict, not authenticated root output
    or controller acceptance.
    """
    try:
        source = _packet_source(packet)
        if (type(submission) is not dict or set(submission) != _SUBMISSION_FIELDS
                or submission["schema"] != SUBMISSION_SCHEMA
                or type(submission["submission_sha256"]) is not str or type(submission["subject_sha256"]) is not str
                or submission["subject_sha256"] != packet["subject_sha256"]
                or submission["submission_sha256"] != _sha({key: child for key, child in submission.items()
                                                            if key != "submission_sha256"})):
            raise ValueError("review_submission:invalid")
        return _verification_decision(source, submission["verifications"])
    except _INVALID_INPUT as error:
        raise ValueError("review_submission:invalid") from error


def validate_review_submission(packet: Any, submission: Any) -> dict:
    """Validate submitted content only; establish no provenance or authority."""
    try:
        decision = review_submission_decision(packet, submission)
    except ValueError:
        return {"valid": False, "issues": ["review_submission:invalid"], "scope": "submitted_only", "decision": None}
    return {"valid": True, "issues": [], "scope": "submitted_only", "decision": decision}


def _digest(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and not set(value) - set("0123456789abcdef")


def _context(packet: Any, context: Any) -> dict:
    source = _packet_source(packet)
    _bounded_bytes(context)
    successor = type(context) is dict and context.get("schema") == CONTEXT_SCHEMA
    bootstrap = type(context) is dict and context.get("schema") == BOOTSTRAP_CONTEXT_SCHEMA
    fields = _CONTEXT_FIELDS if successor else _BOOTSTRAP_CONTEXT_FIELDS
    path_key = "pre_turn_report_path" if successor else "bootstrap_artifact_path"
    digest_key = "pre_turn_report_sha256" if successor else "bootstrap_report_sha256"
    if (type(context) is not dict or not (successor or bootstrap) or set(context) != fields
            or any(type(context[key]) is not str or not context[key].strip() for key in ("controller_id", path_key))
            or not PurePosixPath(context[path_key]).is_absolute()
            or ".." in PurePosixPath(context[path_key]).parts or "\x00" in context[path_key]
            or not _digest(context[digest_key])):
        raise ValueError("review_context:invalid")
    call = context["native_call"]
    if (type(call) is not dict or set(call) != _NATIVE_CALL_FIELDS or call["schema"] != NATIVE_CALL_SCHEMA
            or any(type(call[key]) is not str or not call[key].strip()
                   for key in ("task_id", "session_id", "turn_id", "tool_call_id", "model", "effort"))
            or call["task_id"] != source["root_task_id"] or call["session_id"] != source["root_task_id"]
            # The review call runs on the plan's root, which must be
            # admitted: a registered orchestrator or an onboarded model (ADR
            # 0004's frontier proxy is the root-labor reviewer executing on
            # that root; Issue 185, ADR 0012).
            or call["model"] != source["routing"]["root"]["model"]
            or not model_profiles.root_admitted(call["model"])
            or call["effort"] != source["routing"]["root"]["effort"]
            or type(call["turn_started_at_unix_ms"]) is not int or call["turn_started_at_unix_ms"] < 0
            or not _digest(call["source_meta_sha256"])):
        raise ValueError("review_context:native_call_invalid")
    inventory = local_runtime.OwnerHookInventoryArtifact.from_report(context["owner_hook_inventory_report"])
    # The existing inventory constructor also checks the required plugin hook path.
    # Exact scalar checks prevent bool/int substitutions in its zero counters.
    if (any(type(inventory.report[key]) is not int or inventory.report[key] != 0
            for key in ("model_calls", "hosted_calls", "credential_reads", "network_calls", "task_creations", "native_calls"))
            or any(not _digest(inventory.report[key])
                   for key in ("report_sha256", "owner_identity_sha256", "app_server_argv_sha256"))):
        raise ValueError("review_context:inventory_invalid")
    return context


def validate_review_context(packet: Any, context: Any) -> dict:
    """Validate recorded context transport, without authenticating its custody."""
    try:
        _context(packet, context)
    except _INVALID_INPUT:
        return {"valid": False, "issues": ["review_context:invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def build_review_acknowledgement(packet: Any, submission: Any, context: Any) -> dict:
    """Acknowledge submitted content without claiming semantic acceptance."""
    try:
        review_submission_decision(packet, submission)
        value = _context(packet, context)
        core = {"schema": ACKNOWLEDGEMENT_SCHEMA, "status": "PASS", "decision": "REVIEW_SUBMITTED",
                "controller_id": value["controller_id"], "subject_sha256": packet["subject_sha256"],
                "submission_sha256": submission["submission_sha256"], "native_call": value["native_call"]}
        return {**deepcopy(core), "acknowledgement_sha256": _sha(core)}
    except _INVALID_INPUT as error:
        raise ValueError("review_acknowledgement:invalid") from error


def review_call_arguments(packet: Any, submission: Any, context: Any) -> dict:
    """Return exact submission-call arguments, preserving raw verifications."""
    try:
        review_submission_decision(packet, submission)
        value = _context(packet, context)
        origin = ({"pre_turn_report_path": value["pre_turn_report_path"],
                   "pre_turn_report_sha256": value["pre_turn_report_sha256"]} if value["schema"] == CONTEXT_SCHEMA else
                  {"bootstrap_artifact_path": value["bootstrap_artifact_path"],
                   "bootstrap_report_sha256": value["bootstrap_report_sha256"]})
        return {**origin, "subject_sha256": packet["subject_sha256"], "verifications": deepcopy(submission["verifications"])}
    except _INVALID_INPUT as error:
        raise ValueError("review_call_arguments:invalid") from error


def review_observation_expectation(packet: Any, submission: Any, context: Any) -> dict:
    """Bind the exact owner, historical turn, native call, raw arguments and ACK."""
    acknowledgement = build_review_acknowledgement(packet, submission, context)
    arguments = review_call_arguments(packet, submission, context)
    call, inventory = context["native_call"], context["owner_hook_inventory_report"]
    return {
        "task_id": call["task_id"], "turn_id": call["turn_id"], "tool_call_id": call["tool_call_id"],
        "owner_identity_sha256": inventory["owner_identity_sha256"],
        "app_server_argv_sha256": inventory["app_server_argv_sha256"],
        "hook_inventory_report_sha256": inventory["report_sha256"],
        "server": "orch-dork", "tool": ("submit_issue94_semantic_review" if context["schema"] == CONTEXT_SCHEMA else "submit_issue94_bootstrapped_semantic_review"),
        "arguments": arguments, "structured_result": acknowledgement,
    }


def review_observation_decision(packet: Any, submission: Any, context: Any, observation: Any) -> str:
    """Resolve submitted content only after the exact canonical owner observation.

    PENDING may be polled from the unchanged durable receipt and cursor; a
    tentative evaluator receipt is not committed. REFUSED requires external
    evidence and must not be polled again. Current thread settings cannot attest
    the route of the historical native call retained in the ACK.
    """
    try:
        expected = review_observation_expectation(packet, submission, context)
        _bounded_bytes(observation)
        if (local_runtime.validate_current_local_task_mcp_observation(observation).get("valid") is not True
                or _bounded_bytes(observation["expectation"]) != _bounded_bytes(expected)):
            raise ValueError("review_observation:invalid")
        if observation["status"] == "OBSERVED":
            return review_submission_decision(packet, submission)
        if observation["status"] == "PENDING":
            return "pending"
        if observation["status"] == "REFUSED":
            return "evidence_required"
        raise ValueError("review_observation:status_invalid")
    except _INVALID_INPUT as error:
        raise ValueError("review_observation:invalid") from error


__all__ = [
    "PACKET_SCHEMA", "SUBMISSION_SCHEMA", "build_review_packet", "validate_review_packet",
    "build_review_submission", "review_submission_decision", "validate_review_submission",
    "CONTEXT_SCHEMA", "NATIVE_CALL_SCHEMA", "ACKNOWLEDGEMENT_SCHEMA", "validate_review_context",
    "build_review_acknowledgement", "review_call_arguments",
    "review_observation_expectation", "review_observation_decision",
]
