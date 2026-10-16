"""Verified failure closure for rejected review or known completion exhaustion.

Canonical report validation is transport-only. The native controller injects
the current-state signature observer before recording an intent. A caller's
JSON cannot supply that observer or discharge owner disposition.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

import orch_dork_completion_settlement as settlement
import orch_dork_governed_attempt as attempt
import orch_dork_observer_receipt as observer_receipt
from orch_dork_governed_native_reports import _json

SCHEMA = "orch-dork/verified-failure-closure/v1"
LIFECYCLE_SCHEMA = "orch-dork/lifecycle-failure-closure/v1"
CLEANUP_BINDING_SCHEMA = "orch-dork/lifecycle-failure-cleanup-binding/v1"
CHECKS = ("verified_failure", "grant_settlement", "lane_cleanup", "process_group", "capacity_settlement", "owner_identity")
_INVALID = (KeyError, IndexError, TypeError, ValueError, OverflowError, RecursionError)


def _require(condition: bool, issue: str = "binding_invalid") -> None:
    if not condition:
        raise ValueError("failure_closure:" + issue)


def _same(left: Any, right: Any) -> bool:
    return attempt._canonical(left) == attempt._canonical(right)


def _source(identity: Any, source: Any) -> dict:
    try:
        _json(source)
        _require(len(attempt._canonical(source)) <= settlement.native.MAX_PROGRAM_BYTES)
        _require(settlement.validate_completed_capacity_settlement(source)["valid"])
        issues = []
        bound = attempt._validate_identity(identity, issues)
        stage = source["native_result"]["stage_report"]
        receipt = attempt._post_batch_predecessor_report(bound, stage, issues)
        _require(not issues, "identity_invalid")
        _require(receipt["stage"] == "capacity_settlement" and receipt["next_action"] == "failure_closure")
        _require(receipt["bindings"]["terminal_verification"]["outcome"] == "failure"
            and receipt["bindings"]["review_outcome"] == "rejected", "verified_failure_required")
        return receipt
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as error:
        raise ValueError("failure_closure:source_invalid") from error


def _current_observation(source: dict, observed: Any) -> None:
    """Check the whole host-observer transport, without authenticating JSON."""
    _json(observed)
    signatures = observed["signature_reports"]
    _require(type(signatures) is list and len(signatures) == 2)
    for release, verified in zip(source["release_receipts"], signatures):
        envelope = release["cleanup_observer_receipt"]
        _require(observer_receipt._text(envelope["host_id"], limit=256)
            and observer_receipt._text(envelope["key_id"], limit=256))
        generation = verified["trust_generation"]
        _require(observer_receipt._text(generation, limit=256))
        core = {"schema": observer_receipt.REPORT_SCHEMA, "status": "PASS", "reason": "verified", "verified": True,
            "receipt_kind": "lane-cleanup-observation", "host_id": envelope["host_id"], "key_id": envelope["key_id"],
            "trust_generation": generation, "payload_sha256": envelope["payload_sha256"],
            "signed_receipt_sha256": release["cleanup_evidence_sha256"], "payload": envelope["payload"],
            "provider_free": True, "network_attempts": 0, "model_calls": 0, "hosted_calls": 0}
        _require(_same(verified, {**core, "report_sha256": attempt._sha(core)}))
    _require(len({row["trust_generation"] for row in signatures}) == 1)
    _require(len({row["host_id"] for row in signatures}) == 1)
    core = {"schema": "orch-dork/current-completion-settlement-observation/v1", "status": "OBSERVED", "issues": [],
        "settlement_report_sha256": source["report_sha256"], "authority_before": source["authority_after"],
        "authority_after": source["authority_after"], "capacity_before": source["capacity_after"],
        "capacity_after": source["capacity_after"], "signature_reports": signatures,
        "scope": "current_owned_completion_settlement", "resource_release_proven": True,
        "terminal_claim_permitted": False, "model_calls": 0, "native_calls": 0, "signing_key_reads": 0}
    _require(_same(observed, {**core, "report_sha256": attempt._sha(core)}), "observation_unverified")


def build_failure_closure_program(identity: Any, settlement_report: Any, *, pre_spawn_program: Any = None) -> dict:
    """Build the closed input; it contains no caller-supplied verification result."""
    if pre_spawn_program is not None:
        from orch_dork_qualification_budget_failure import build_budget_failure_program
        return build_budget_failure_program(identity, settlement_report, pre_spawn_program)
    if isinstance(settlement_report, dict) and settlement_report.get("schema") == settlement.CLEANUP_SETTLEMENT_SCHEMA:
        prior, binding = _cleanup_binding(identity, settlement_report)
        return deepcopy({"schema": attempt.PROGRAM_SCHEMA, "operation": "failure_closure", "identity": identity,
            "predecessor_receipt": prior, "payload": {"cleanup_binding": binding}})
    receipt = _source(identity, settlement_report)
    return deepcopy({"schema": attempt.PROGRAM_SCHEMA, "operation": "failure_closure", "identity": identity,
        "predecessor_receipt": receipt, "payload": {"settlement_report": settlement_report}})


def _verified_failure_receipt(receipt: dict) -> None:
    _require(receipt["stage"] == "capacity_settlement" and receipt["next_action"] == "failure_closure"
        and receipt["bindings"]["capacity_authority_lane_ids"] == []
        and receipt["bindings"]["terminal_verification"]["outcome"] == "failure"
        and receipt["bindings"]["review_outcome"] == "rejected", "verified_failure_required")


def _cleanup_source(identity: Any, source: Any) -> dict:
    """The owner's cleanup-observed settlement of a rejected review.

    Rehearsals 21 and 22: the Sol review rejected a lane, the owner settled
    capacity from host cleanup, and nothing could close the attempt from that
    settlement, so the controller stayed non-terminal.  Final qualification
    already closes a successful attempt from the same settlement.
    """
    try:
        _json(identity)
        _json(source)
        _require(len(attempt._canonical(source)) <= 4 * settlement.native.MAX_PROGRAM_BYTES)
        issues: list = []
        bound = attempt._validate_identity(identity, issues)
        _require(not issues and settlement.validate_cleanup_capacity_settlement(source)["valid"])
        receipt = attempt._post_batch_predecessor_report(bound, source["native_result"]["stage_report"], issues)
        _require(not issues and source["capacity_after"]["state"]["active_lane_ids"] == [])
        _verified_failure_receipt(receipt)
        return receipt
    except _INVALID as error:
        raise ValueError("failure_closure:cleanup_source_invalid") from error


def _cleanup_binding(identity: Any, source: dict) -> tuple[dict, dict]:
    prior = _cleanup_source(identity, source)
    core = {
        "schema": CLEANUP_BINDING_SCHEMA,
        "identity": deepcopy(identity),
        "settlement_report_sha256": source["report_sha256"],
        "host_cleanup_sha256": source["host_cleanup"]["report_sha256"],
        "capacity_store_id": source["capacity_after"]["store_id"],
        "capacity_state_sha256": source["capacity_after"]["state_sha256"],
        "authority_after": deepcopy(source["authority_after"]),
    }
    return prior, {**core, "binding_sha256": attempt._sha(core)}


def _validated_cleanup_binding(identity: Any, predecessor: Any, binding: Any) -> tuple[dict, dict]:
    try:
        for value in (identity, predecessor, binding):
            _json(value)
            _require(len(attempt._canonical(value)) <= settlement.native.MAX_PROGRAM_BYTES)
        issues: list = []
        bound = attempt._validate_identity(identity, issues)
        prior = attempt._validate_receipt(predecessor, bound, issues,
            allowed_stages={"capacity_settlement"}, allowed_actions={"failure_closure"})
        core = {key: child for key, child in binding.items() if key != "binding_sha256"}
        _require(not issues and prior["status"] == "SETTLED"
            and binding.get("schema") == CLEANUP_BINDING_SCHEMA
            and _same(binding.get("identity"), bound)
            and binding.get("binding_sha256") == attempt._sha(core)
            and settlement.capacity._digest(binding.get("settlement_report_sha256"))
            and settlement.capacity._digest(binding.get("host_cleanup_sha256"))
            and isinstance(binding.get("capacity_store_id"), str) and bool(binding["capacity_store_id"])
            and settlement.capacity._digest(binding.get("capacity_state_sha256")))
        _verified_failure_receipt(prior)
        settlement.completion_waiting_authority(binding["authority_after"])
        return deepcopy(dict(prior)), deepcopy(dict(binding))
    except _INVALID as error:
        raise ValueError("failure_closure:cleanup_binding_invalid") from error


def _lifecycle_closed_report(identity: Any, predecessor: Any, binding: Any) -> dict:
    prior, checked = _validated_cleanup_binding(identity, predecessor, binding)
    proof = {"schema": LIFECYCLE_SCHEMA, "outcome": "failure", "predecessor_receipt": deepcopy(prior),
        "cleanup_binding": checked, "owner_disposition": "pending"}
    receipt = attempt._receipt(stage="failure_closure", status="VERIFIED_FAILURE", identity=identity,
        plan={"plan_id": prior["plan_id"], "revision": prior["plan_revision"]}, plan_sha256=prior["plan_sha256"],
        predecessor=prior, next_action="owner_disposition",
        bindings={**deepcopy(prior["bindings"]), "lifecycle_failure_closure": proof})
    return deepcopy(attempt._report(operation="failure_closure", identity=identity, status="PASS",
        disposition="VERIFIED_FAILURE_CLOSED", issues=[], stages=[attempt._stage("clean_lifecycle", "PASS", proof, [])],
        receipt=receipt))


def _checks(identity: dict, source: dict, observed: dict) -> list:
    """Project six closure bodies from evidence already checked by its profile."""
    prior = source['native_result']['stage_report']['receipt']
    capture = source["completion_capture"]
    reports = [
        {"identity": identity, "settlement_report": source, "current_observation": observed,
         "terminal_verification_sha256": attempt._sha(prior["bindings"]["terminal_verification"])},
        {"authority_sha256": attempt._sha(observed["authority_after"]),
         "completed_action_evidence_sha256": attempt._sha(capture["action_evidence"]), "outstanding_grant": False},
        {"closed_lane_ids": ["spec", "standards"], "close_evidence_sha256": attempt._sha(capture["closes"])},
        {"observation_sha256": source["process_observation"]["report_sha256"], "owned_descendants": 0},
        {"authority_sha256": attempt._sha(source["capacity_after"]),
         "released_lane_ids": capture["controller_report"]["stage_report"]["receipt"]["bindings"]["capacity_authority_lane_ids"]},
        {"owner": observed["authority_after"]["owner"], "owner_disposition": "pending"},
    ]
    return reports


def _closed_report(identity: dict, source: dict, observed: dict) -> dict:
    prior = _source(identity, source)
    _current_observation(source, observed)
    reports = _checks(identity, source, observed)
    stages = [attempt._stage(name, "PASS", value, []) for name, value in zip(CHECKS, reports)]
    proof = {"schema": SCHEMA, "outcome": "failure", "settlement_report_sha256": source["report_sha256"],
        "current_observation_sha256": observed["report_sha256"], "checks_sha256": attempt._sha(stages),
        "checks": reports, "owner_disposition": "pending"}
    receipt = attempt._receipt(stage="failure_closure", status="VERIFIED_FAILURE", identity=identity,
        plan={"plan_id": prior["plan_id"], "revision": prior["plan_revision"]}, plan_sha256=prior["plan_sha256"],
        predecessor=prior, next_action="owner_disposition", bindings={**deepcopy(prior["bindings"]), "failure_closure": proof})
    return deepcopy(attempt._report(operation="failure_closure", identity=identity, status="PASS", disposition="VERIFIED_FAILURE_CLOSED",
        issues=[], stages=stages, receipt=receipt))


def evaluate_failure_closure(identity: Any, predecessor: Any, payload: Any, *, observer=None) -> dict:
    """Only a host-injected observer can establish current signature authority."""
    try:
        if type(payload) is dict and payload.get('failure_profile') == 'completion_budget_exhausted':
            from orch_dork_qualification_budget_failure import evaluate_budget_failure
            return evaluate_budget_failure(identity, predecessor, payload, observer=observer)
        if type(payload) is dict and set(payload) == {"cleanup_binding"}:
            return _lifecycle_closed_report(identity, predecessor, payload["cleanup_binding"])
        _require(type(payload) is dict and set(payload) == {"settlement_report"}, "payload_invalid")
        source = payload["settlement_report"]
        prior = _source(identity, source)
        _require(_same(prior, predecessor), "predecessor_invalid")
        _require(callable(observer), "observer_required")
        observed = observer(deepcopy(source))
        return _closed_report(identity, source, observed)
    except Exception as error:
        issue = str(error) if type(error) is ValueError and str(error).startswith("failure_closure:") else "failure_closure:" + type(error).__name__
        return attempt._report(operation="failure_closure", identity=identity, status="BLOCKED", disposition="FAILURE_CLOSURE_REFUSED",
            issues=[issue], stages=[])


def validate_failure_closure_report(report: Any) -> dict:
    """Validate the complete retained proof transport; confer no owner authority."""
    try:
        _json(report)
        _require(len(attempt._canonical(report)) <= 4 * settlement.native.MAX_EVENT_BYTES)
        expected = _reconstruct(report["receipt"]["bindings"])
        _require(_same(report, expected))
    except (KeyError, IndexError, TypeError, ValueError, OverflowError, RecursionError):
        return {"valid": False, "issues": ["failure_closure:report_invalid"], "scope": "canonical_transport"}
    return {"valid": True, "issues": [], "scope": "canonical_transport"}


def failure_closure_next_action(root_task_id: str, receipt: Any) -> str:
    """Keep the ordinary quality-frontier API consistent with a closed failure."""
    try:
        expected = _reconstruct(receipt["bindings"])
        _require(expected["root_task_id"] == root_task_id and _same(receipt, expected["receipt"]))
        return "owner_disposition"
    except (KeyError, IndexError, TypeError, ValueError, OverflowError, RecursionError) as error:
        raise ValueError("failure_closure:receipt_invalid") from error


def _reconstruct(bindings: dict) -> dict:
    lifecycle = bindings.get('lifecycle_failure_closure')
    if isinstance(lifecycle, dict):
        return _lifecycle_closed_report(lifecycle['cleanup_binding']['identity'],
            lifecycle['predecessor_receipt'], lifecycle['cleanup_binding'])
    proof = bindings['failure_closure']
    first = proof['checks'][0]
    if proof['schema'] == 'orch-dork/completion-budget-failure-closure/v1':
        from orch_dork_qualification_budget_failure import _closed_report as budget_report
        return budget_report(first['identity'], first['settlement_report'], proof['pre_spawn_program'], proof['metadata'])
    return _closed_report(first['identity'], first['settlement_report'], first['current_observation'])


def _commit_time(controller, validated_report: dict, *, not_before):
    """Recheck closure authority after validation without demanding budget PASS.

    Closing known failed work may follow budget exhaustion. This grants no
    worker work or success claim; current signatures, state and clock still
    must be valid immediately before the native intent.
    """
    lifecycle = validated_report['receipt']['bindings'].get('lifecycle_failure_closure')
    if isinstance(lifecycle, dict):
        binding = lifecycle['cleanup_binding']
        _require(validate_failure_closure_report(validated_report)['valid'], 'cleanup_report_invalid')
        _require(_same(controller.grants.canonical_authority(), binding['authority_after']), 'cleanup_owner_changed')
        current_capacity = settlement._read_capacity(controller)
        _require(current_capacity['store_id'] == binding['capacity_store_id']
            and current_capacity['state_sha256'] == binding['capacity_state_sha256']
            and current_capacity['state']['active_lane_ids'] == [], 'cleanup_capacity_changed')
        now = controller._evaluation_time()
        _require(now >= not_before, 'commit_clock_regressed')
        return now
    proof = validated_report['receipt']['bindings']['failure_closure']
    source = proof['checks'][0]['settlement_report']
    observed = settlement.observe_current_completion_settlement(controller, source)
    _current_observation(source, observed)
    now = controller._evaluation_time()
    _require(now >= not_before, 'commit_clock_regressed')
    if 'metadata' in proof:
        _require(now >= observer_receipt.evidence.instant(proof['metadata']['observed_at']), 'commit_clock_regressed')
    for release in source['release_receipts']:
        signed = release['cleanup_observer_receipt']
        _require(observer_receipt.evidence.instant(signed['issued_at']) <= now
            <= observer_receipt.evidence.instant(signed['valid_until']), 'commit_signature_expired')
    return now


__all__ = ["build_failure_closure_program", "evaluate_failure_closure", "validate_failure_closure_report",
           "failure_closure_next_action", "CHECKS"]
