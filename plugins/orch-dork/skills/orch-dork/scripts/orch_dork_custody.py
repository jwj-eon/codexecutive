#!/usr/bin/env python3
"""Attempt membership and staged resource-custody validation."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import json
from typing import Any, Mapping


def _load_sibling(name: str):
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name + " unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    import orch_dork_evidence_core as evidence_core
    import orch_dork_observer_receipt as observer_receipts
except ModuleNotFoundError:  # standalone spec loading in focused tests
    evidence_core = _load_sibling("orch_dork_evidence_core")
    observer_receipts = _load_sibling("orch_dork_observer_receipt")


SCHEMA = "orch-dork/custody/v1"
EVENT_SCHEMA = "orch-dork/custody-events/v1"
OBSERVER_RECEIPT_SCHEMA = "orch-dork/custody-observer-receipt/v1"
OBSERVER_RECEIPT_FIELDS = {
    "schema",
    "status",
    "evidence_tier",
    "observer_id",
    "independent",
    "attempt_id",
    "session_id",
    "event_count",
    "access_count",
    "events_sha256",
    "coverage",
    "observed_at",
    "source_pointer",
    "source_sha256",
    "receipt_sha256",
}
_SHA256 = evidence_core.SHA256_PATTERN
ALLOWED_EVENT_FIELDS = {
    "lane.completed": {"seq", "type", "lane_id", "worker_id"},
    "integrator.started": {"seq", "type", "worker_id"},
    "lane.released": {
        "seq",
        "type",
        "lane_id",
        "owner_worker_id",
        "integrator_worker_id",
    },
    "resource.access": {
        "seq",
        "type",
        "worker_id",
        "lane_id",
        "resource",
        "operation",
        "phase",
        "source_pointer",
    },
    "integrator.completed": {"seq", "type", "worker_id"},
}


def _load_ownership():
    path = Path(__file__).resolve().with_name("orch_dork_ownership.py")
    spec = importlib.util.spec_from_file_location("orch_dork_ownership", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("ownership analyzer unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ownership = _load_ownership()
_plan_closure_spec = importlib.util.spec_from_file_location(
    "orch_dork_plan_closure",
    Path(__file__).resolve().with_name("orch_dork_plan_closure.py"),
)
if _plan_closure_spec is None or _plan_closure_spec.loader is None:
    plan_closure = None
else:
    plan_closure = importlib.util.module_from_spec(_plan_closure_spec)
    _plan_closure_spec.loader.exec_module(plan_closure)


def _declared_integrator_lane(
    plan: Mapping[str, Any],
) -> str | None:
    """Resolve the integration owner the frozen plan declares.

    Returns the lane id when the plan's frozen acceptance closure names a
    lane as its integration owner, else None (root owner, missing closure,
    or a plan that cannot be analyzed). Both validators must resolve the
    same lane for the same attempt: orch_dork_policy._qualify_orchestrated
    (issue 87) reads the identical ``integration_owner`` from its own
    ``validate_plan`` closure report, and this helper reads it from
    ``validate_acceptance_resource_closure``, the same function that
    ``validate_plan`` calls -- one authority, no fork. It is mirrored here
    rather than imported because policy already imports this module (a
    reverse import is not a cycle at import time, but it would force the
    standalone custody CLI to pull the policy module, which it does not
    otherwise need).
    """
    if plan_closure is None:
        return None
    try:
        report = plan_closure.validate_acceptance_resource_closure(plan)
    except Exception:
        return None
    if not isinstance(report, dict):
        return None
    owner = report.get("integration_owner", {})
    if not isinstance(owner, dict) or owner.get("kind") != "lane":
        return None
    lane_id = owner.get("id")
    if not isinstance(lane_id, str) or not lane_id:
        return None
    return lane_id


_sha = evidence_core.digest


_issue = evidence_core.add_issue


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _timestamp(value: Any) -> bool:
    return evidence_core.instant(value) is not None


def _observer_receipt_issues(
    receipt: Mapping[str, Any],
    bundle: Mapping[str, Any],
    *,
    expected_attempt_id: str,
    expected_session_id: str,
) -> list[str]:
    """Validate one closed receipt emitted by an independent observer seam."""

    issues: list[str] = []
    _exact_keys(receipt, OBSERVER_RECEIPT_FIELDS, "observer_receipt", issues)
    events = bundle.get("events", [])
    if not isinstance(events, list):
        events = []
    if receipt.get("schema") != OBSERVER_RECEIPT_SCHEMA:
        _issue(issues, "custody:observer_receipt_schema_invalid")
    if receipt.get("status") != "observed":
        _issue(issues, "custody:observer_receipt_status_invalid")
    if receipt.get("evidence_tier") != "runtime-observed":
        _issue(issues, "custody:observer_receipt_tier_invalid")
    if not _text(receipt.get("observer_id")):
        _issue(issues, "custody:observer_receipt_observer_invalid")
    if receipt.get("independent") is not True:
        _issue(issues, "custody:observer_receipt_not_independent")
    if not _text(receipt.get("attempt_id")):
        _issue(issues, "custody:observer_receipt_attempt_invalid")
    elif receipt.get("attempt_id") != expected_attempt_id:
        _issue(issues, "custody:observer_receipt_attempt_mismatch")
    if not _text(receipt.get("session_id")):
        _issue(issues, "custody:observer_receipt_session_invalid")
    elif receipt.get("session_id") != expected_session_id:
        _issue(issues, "custody:observer_receipt_session_mismatch")
    if receipt.get("event_count") != len(events):
        _issue(issues, "custody:observer_receipt_event_count_mismatch")
    access_count = sum(
        isinstance(item, Mapping) and item.get("type") == "resource.access"
        for item in events
    )
    if receipt.get("access_count") != access_count or access_count < 1:
        _issue(issues, "custody:observer_receipt_access_count_mismatch")
    if receipt.get("events_sha256") != _sha(bundle):
        _issue(issues, "custody:observer_receipt_hash_mismatch")
    if receipt.get("coverage") != "complete":
        _issue(issues, "custody:observer_receipt_coverage_incomplete")
    if not _timestamp(receipt.get("observed_at")):
        _issue(issues, "custody:observer_receipt_observed_at_invalid")
    if not _text(receipt.get("source_pointer")):
        _issue(issues, "custody:observer_receipt_source_invalid")
    if not isinstance(receipt.get("source_sha256"), str) or _SHA256.fullmatch(
        receipt.get("source_sha256", "")
    ) is None:
        _issue(issues, "custody:observer_receipt_source_hash_invalid")
    if not evidence_core.check_seal(receipt, "receipt_sha256"):
        _issue(issues, "custody:observer_receipt_seal_mismatch")
    return sorted(set(issues))


def _exact_keys(
    value: Any, required: set[str], label: str, issues: list[str]
) -> bool:
    return evidence_core.closed(value, required, label, issues) is not None


def _plan_sha256(plan: Mapping[str, Any]) -> str:
    return _sha(plan)


def _lane_scopes(
    plan: Mapping[str, Any], issues: list[str]
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    lanes: dict[str, list[dict[str, Any]]] = {}
    for index, lane in enumerate(plan.get("lanes", [])):
        if not isinstance(lane, Mapping):
            _issue(issues, f"plan:lane_not_object:{index}")
            continue
        lane_id = lane.get("id")
        if not isinstance(lane_id, str) or not lane_id:
            _issue(issues, f"plan:lane_id_invalid:{index}")
            continue
        scopes = []
        for raw in lane.get("owned_resources", []):
            try:
                scopes.append(ownership.normalize_resource(raw))
            except Exception:
                _issue(issues, f"plan:resource_invalid:{lane_id}")
        lanes[lane_id] = scopes
    protected = []
    for raw in plan.get("protected_resources", []):
        try:
            protected.append(ownership.normalize_resource(raw))
        except Exception:
            _issue(issues, "plan:protected_resource_invalid")
    return lanes, protected


def _matches(scopes: list[Mapping[str, Any]], resource: Mapping[str, Any]) -> bool:
    return any(ownership.resource_contains(scope, resource) for scope in scopes)


def _evaluate_custody(
    plan: Mapping[str, Any],
    spawn_wave: Mapping[str, Any],
    event_bundle: Mapping[str, Any] | list[Mapping[str, Any]],
    *, worker_integration: bool,
) -> dict[str, Any]:
    """Shared membership and access checks with an explicit integration policy."""

    issues: list[str] = []
    plan_value = plan if isinstance(plan, Mapping) else {}
    plan_hash = _plan_sha256(plan_value)
    wave = spawn_wave if isinstance(spawn_wave, Mapping) else {}
    if (
        wave.get("schema") != "orch-dork/spawn-wave/v1"
        or wave.get("status") != "PASS"
        or wave.get("complete") is not True
        or wave.get("plan_sha256") != plan_hash
        or wave.get("replacement_permitted") is not False
        or wave.get("reuse_permitted") is not False
    ):
        _issue(issues, "custody:spawn_wave_invalid")
    members_value = wave.get("members", [])
    members: dict[str, str] = {}
    workers: dict[str, str] = {}
    if not isinstance(members_value, list):
        _issue(issues, "custody:members_not_array")
        members_value = []
    for index, member in enumerate(members_value):
        if not isinstance(member, Mapping):
            _issue(issues, f"custody:member_not_object:{index}")
            continue
        lane_id, worker_id = member.get("lane_id"), member.get("worker_id")
        if (
            not isinstance(lane_id, str)
            or not lane_id
            or not isinstance(worker_id, str)
            or not worker_id
            or lane_id in members
            or worker_id in workers
        ):
            _issue(issues, f"custody:member_identity_invalid:{index}")
            continue
        members[lane_id] = worker_id
        workers[worker_id] = lane_id

    lanes, protected = _lane_scopes(plan_value, issues)
    if set(members) != set(lanes):
        _issue(issues, "custody:membership_lane_mismatch")

    if isinstance(event_bundle, list):
        events = event_bundle
        bundle_value: Mapping[str, Any] = {
            "schema": EVENT_SCHEMA,
            "events": event_bundle,
        }
    elif isinstance(event_bundle, Mapping):
        bundle_value = event_bundle
        if bundle_value.get("schema") != EVENT_SCHEMA:
            _issue(issues, "custody:event_schema_invalid")
        events = bundle_value.get("events", [])
    else:
        bundle_value = {}
        events = []
        _issue(issues, "custody:event_bundle_invalid")
    if not isinstance(events, list):
        events = []
        _issue(issues, "custody:events_not_array")

    previous_seq = 0
    completions: dict[str, list[Mapping[str, Any]]] = {}
    releases: dict[str, list[Mapping[str, Any]]] = {}
    integrator_starts: list[Mapping[str, Any]] = []
    integrator_completions: list[Mapping[str, Any]] = []
    accesses: list[Mapping[str, Any]] = []
    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            _issue(issues, f"custody:event_not_object:{index}")
            continue
        event_type = event.get("type")
        required = ALLOWED_EVENT_FIELDS.get(event_type)
        if required is None:
            _issue(issues, f"custody:event_type_invalid:{index}")
            continue
        _exact_keys(event, required, f"events[{index}]", issues)
        seq = event.get("seq")
        if type(seq) is not int or seq <= previous_seq:
            _issue(issues, f"custody:sequence_invalid:{index}")
        else:
            previous_seq = seq
        if event_type == "lane.completed":
            completions.setdefault(str(event.get("lane_id")), []).append(event)
        elif event_type == "integrator.started":
            integrator_starts.append(event)
        elif event_type == "lane.released":
            releases.setdefault(str(event.get("lane_id")), []).append(event)
        elif event_type == "resource.access":
            accesses.append(event)
        elif event_type == "integrator.completed":
            integrator_completions.append(event)

    if not worker_integration:
        integrator_id = None
        integrator_start_seq = None
        if integrator_starts or integrator_completions or releases:
            _issue(issues, "custody:unplanned_worker_integration_or_release")
    elif len(integrator_starts) != 1:
        _issue(issues, f"custody:integrator_start_count:{len(integrator_starts)}")
        integrator_id = None
        integrator_start_seq = None
    else:
        integrator_id = integrator_starts[0].get("worker_id")
        integrator_start_seq = integrator_starts[0].get("seq")
        if integrator_id not in workers:
            _issue(issues, "custody:nonmember_integrator")
    integrator_lane = workers.get(str(integrator_id)) if integrator_id else None

    completion_seq: dict[str, int] = {}
    for lane_id in sorted(lanes):
        lane_events = completions.get(lane_id, [])
        if len(lane_events) != 1:
            _issue(
                issues,
                f"custody:completion_count:{lane_id}:{len(lane_events)}",
            )
            continue
        event = lane_events[0]
        if event.get("worker_id") != members.get(lane_id):
            _issue(issues, f"custody:completion_member_mismatch:{lane_id}")
        if type(event.get("seq")) is int:
            completion_seq[lane_id] = event["seq"]

    # Resolve the integrator the same way the trace qualifier does
    # (orch_dork_policy._qualify_orchestrated, issue 87). When the frozen
    # plan declares a lane integration owner that completed exactly once and
    # is not the first completer, that lane is the authority: it integrates
    # and its completion anchors the checklist below. Every other shape --
    # no owner, a root owner, an owner that never completed, an owner equal
    # to the first completer, or no completed lanes at all -- keeps the
    # historical runtime first-completed-worker rule byte-for-byte, exactly
    # as the qualifier does.
    first_lane = None
    designated_lane = None
    if worker_integration and completion_seq:
        first_lane = min(
            completion_seq,
            key=lambda lane_id: (completion_seq[lane_id], members.get(lane_id, "")),
        )
        if integrator_lane is not None:
            declared = _declared_integrator_lane(plan_value)
            if (
                declared is not None
                and completion_seq.get(declared) is not None
                and declared != first_lane
            ):
                designated_lane = declared
        if designated_lane is None:
            anchor_lane = first_lane
            if integrator_lane is not None and integrator_lane != first_lane:
                _issue(issues, "custody:integrator_not_first_completed")
        else:
            # The declared owner is the authority for identity: it integrates.
            anchor_lane = designated_lane
            if integrator_lane != anchor_lane:
                _issue(issues, "custody:declared_integrator_not_designated")
                # The failed run misidentifies the integrator the same way a
                # pre-declaration run would have, so the historical diagnostic
                # is emitted alongside when the attempted integrator also is
                # not the first completer (same co-emit as the qualifier).
                if integrator_lane != first_lane:
                    _issue(issues, "custody:integrator_not_first_completed")
        if (
            integrator_start_seq is not None
            and integrator_start_seq <= completion_seq[anchor_lane]
        ):
            _issue(issues, "custody:integrator_started_too_early")

    released_at: dict[str, int] = {}
    for lane_id in sorted(lanes):
        lane_releases = releases.get(lane_id, [])
        if not worker_integration:
            continue
        if lane_id == integrator_lane:
            if lane_releases:
                _issue(issues, "custody:integrator_lane_released")
            continue
        if len(lane_releases) != 1:
            _issue(
                issues,
                f"custody:release_count:{lane_id}:{len(lane_releases)}",
            )
            continue
        event = lane_releases[0]
        if event.get("owner_worker_id") != members.get(lane_id):
            _issue(issues, f"custody:release_owner_mismatch:{lane_id}")
        if event.get("integrator_worker_id") != integrator_id:
            _issue(issues, f"custody:release_target_mismatch:{lane_id}")
        seq = event.get("seq")
        if type(seq) is int:
            released_at[lane_id] = seq
            if lane_id in completion_seq and seq <= completion_seq[lane_id]:
                _issue(issues, f"custody:release_before_completion:{lane_id}")
            if integrator_start_seq is not None and seq <= integrator_start_seq:
                _issue(issues, f"custody:release_before_integrator:{lane_id}")
    for unknown_lane in sorted(set(releases) - set(lanes)):
        _issue(issues, f"custody:release_unknown_lane:{unknown_lane}")

    if not accesses and worker_integration:
        _issue(issues, "custody:access_evidence_missing")
    access_rows = []
    for index, event in enumerate(accesses):
        worker_id = event.get("worker_id")
        lane_id = event.get("lane_id")
        operation = event.get("operation")
        phase = event.get("phase")
        source_pointer = event.get("source_pointer")
        if worker_id not in workers:
            _issue(issues, f"custody:nonmember_access:{index}")
            continue
        member_lane = workers[worker_id]
        if lane_id != member_lane:
            _issue(issues, f"custody:access_lane_identity_mismatch:{index}")
        if operation not in {"read", "write"}:
            _issue(issues, f"custody:operation_invalid:{index}")
            continue
        if phase not in ({"initial", "integration"} if worker_integration else {"initial"}):
            _issue(issues, f"custody:phase_invalid:{index}")
            continue
        if not isinstance(source_pointer, str) or not source_pointer:
            _issue(issues, f"custody:source_pointer_missing:{index}")
        try:
            resource = ownership.normalize_resource(
                f"{operation}:" + str(event.get("resource"))
            )
        except Exception:
            _issue(issues, f"custody:resource_invalid:{index}")
            continue
        if operation == "write" and _matches(protected, resource):
            _issue(issues, f"custody:protected_resource_access:{index}")

        allowed_lanes = []
        for owner_lane, scopes in lanes.items():
            if _matches(scopes, resource):
                allowed_lanes.append(owner_lane)
        if not allowed_lanes:
            _issue(issues, f"custody:access_outside_scope:{index}")
        if phase == "initial":
            if (not worker_integration and type(event.get("seq")) is int
                    and event["seq"] >= completion_seq.get(member_lane, 0)):
                _issue(issues, f"custody:access_after_or_without_completion:{index}")
            own_allowed = _matches(lanes.get(member_lane, []), resource)
            shared_read = operation == "read" and all(
                scope["mode"] == "read"
                for owner_lane in allowed_lanes
                for scope in lanes.get(owner_lane, [])
                if ownership.resource_contains(scope, resource)
            )
            if not own_allowed and not shared_read:
                _issue(issues, f"custody:cross_lane_access_before_release:{index}")
        else:
            if worker_id != integrator_id:
                _issue(issues, f"custody:nonintegrator_integration_access:{index}")
            for owner_lane in allowed_lanes:
                if owner_lane == integrator_lane:
                    continue
                if event.get("seq", 0) <= released_at.get(owner_lane, 10**18):
                    _issue(
                        issues,
                        f"custody:cross_lane_access_before_release:{index}",
                    )
        access_rows.append(
            {
                "seq": event.get("seq"),
                "worker_id": worker_id,
                "lane_id": lane_id,
                "resource": resource.get("normalized"),
                "operation": operation,
                "phase": phase,
                "source_pointer": source_pointer,
            }
        )

    if worker_integration and len(integrator_completions) != 1:
        _issue(
            issues,
            f"custody:integrator_completion_count:{len(integrator_completions)}",
        )
    elif worker_integration and integrator_completions[0].get("worker_id") != integrator_id:
        _issue(issues, "custody:integrator_completion_member_mismatch")
    elif worker_integration and released_at and integrator_completions[0].get("seq", 0) <= max(
        released_at.values()
    ):
        _issue(issues, "custody:integrator_completed_before_release")

    issues = sorted(set(issues))
    return {
        "schema": SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        # This public seam receives caller-submitted facts.  Structural
        # conformance cannot prove that the caller omitted no accesses, so a
        # clean submitted bundle never establishes complete custody.
        "custody_preserved": None,
        "event_conformance": not issues,
        "issues": issues,
        "plan_sha256": plan_hash,
        "spawn_wave_sha256": _sha(wave),
        "events_sha256": _sha(bundle_value),
        "members": [
            {"lane_id": lane_id, "worker_id": members[lane_id]}
            for lane_id in sorted(members)
        ],
        "integrator_worker_id": integrator_id,
        "integrator_lane_id": integrator_lane,
        "released_lanes": sorted(released_at),
        "accesses": access_rows,
        "access_count": len(access_rows),
        "evidence_tier": "submitted",
        "coverage": "unknown",
        "claim_permitted": False,
        "observer_receipt_sha256": None,
        "command_bodies_collected": False,
        "message_bodies_collected": False,
    }


DEPENDENCY_ORDERED_EVENT_SCHEMA = "orch-dork/dependency-ordered-custody-events/v1"


def evaluate_custody(plan, spawn_wave, event_bundle) -> dict[str, Any]:
    """Historical worker-integrator custody, with unchanged events and reports."""
    return _evaluate_custody(plan, spawn_wave, event_bundle, worker_integration=True)


def evaluate_dependency_ordered_custody(plan, spawn_wave, event_bundle) -> dict[str, Any]:
    """Check finite-DAG lane work without granting transfer or root verification.

    Each lane works within its declared scope and completes once. No event may
    manufacture a worker integrator or release ownership. Whole source coverage
    and root final verification remain separate, mandatory qualification gates.
    Explicit per-lane counts distinguish declared zero access from unknown;
    the host must bind both counts and events to independent source coverage.
    This structural seam cannot authenticate caller-submitted events.
    """
    issues: list[str] = []
    valid = _exact_keys(event_bundle, {"schema", "events", "access_counts"}, "event_bundle", issues)
    if not valid or event_bundle.get("schema") != DEPENDENCY_ORDERED_EVENT_SCHEMA:
        _issue(issues, "custody:dependency_ordered_bundle_invalid")
    bundle = dict(event_bundle) if isinstance(event_bundle, Mapping) else {}
    # Reuse the same closed per-event and ownership checks; only the declared
    # integration policy differs. Do not add synthetic lifecycle events.
    bundle["schema"] = EVENT_SCHEMA
    counts = bundle.pop("access_counts", None)
    report = _evaluate_custody(plan, spawn_wave, bundle, worker_integration=False)
    members = {row["lane_id"] for row in report["members"]}
    valid_counts = (type(counts) is dict and set(counts) == members
        and all(type(value) is int and value >= 0 for value in counts.values()))
    if not valid_counts:
        _issue(issues, "custody:access_counts_unknown_or_invalid")
    elif any(counts[lane] != sum(row["lane_id"] == lane for row in report["accesses"]) for lane in members):
        _issue(issues, "custody:access_counts_mismatch")
    issues = sorted(set(issues + report["issues"]))
    return {**report, "status": "FAIL" if issues else "PASS", "issues": issues,
        "event_conformance": not issues, "events_sha256": _sha(event_bundle),
        "integration_profile": "dependency_ordered", "root_verification_required": True,
        "declared_access_counts": dict(counts) if valid_counts else None}


def evaluate_observed_custody(
    plan: Mapping[str, Any],
    spawn_wave: Mapping[str, Any],
    event_bundle: Mapping[str, Any] | list[Mapping[str, Any]],
    observer_receipt: Mapping[str, Any],
    *,
    expected_attempt_id: str,
    expected_session_id: str,
    evaluation_time: Any = None,
    trust_store: Any = None,
    replay_guard: Any = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Qualify custody only through one host-signed observer receipt.

    The public MCP validator intentionally does not expose this seam.  It is
    used only after the governed completion boundary has independently bound
    the observer receipt to the attempt observation.
    """

    report = evaluate_custody(plan, spawn_wave, event_bundle)
    issues = list(report["issues"])
    bundle_value: Mapping[str, Any]
    if isinstance(event_bundle, list):
        bundle_value = {"schema": EVENT_SCHEMA, "events": event_bundle}
    elif isinstance(event_bundle, Mapping):
        bundle_value = event_bundle
    else:
        bundle_value = {}
    events = bundle_value.get("events", [])
    submitted_receipt = (
        dict(observer_receipt) if isinstance(observer_receipt, Mapping) else {}
    )
    signed_report = observer_receipts.require_signed_payload(
        submitted_receipt,
        expected_kind="custody-observation",
        expected_payload={
            "attempt_id": expected_attempt_id,
            "session_id": expected_session_id,
            "event_count": len(events) if isinstance(events, list) else 0,
            "events_sha256": _sha(bundle_value),
        },
        evaluation_time=(
            evaluation_time
            if evaluation_time is not None
            # Custody receipts are durable historical evidence rather than a
            # live scheduling input. The host-signed issuance instant is the
            # replay verification instant; capacity and brief calibration use
            # a current host clock because their decisions expire.
            else submitted_receipt.get("issued_at")
        ),
        trust_store=trust_store,
        replay_guard=replay_guard,
        environ=environ,
    )
    receipt = (
        dict(signed_report["payload"])
        if isinstance(signed_report.get("payload"), Mapping)
        else {}
    )
    for signature_issue in observer_receipts.signature_issue_codes(
        signed_report,
        required_code="custody:observer_host_signature_required",
        status_prefix="custody:observer_signature_",
        reason_prefix="custody:observer_signature:",
    ):
        _issue(issues, signature_issue)
    provenance = observer_receipts.signing_provenance(signed_report)
    if not _text(expected_attempt_id):
        _issue(issues, "custody:expected_attempt_invalid")
    if not _text(expected_session_id):
        _issue(issues, "custody:expected_session_invalid")
    if not isinstance(observer_receipt, Mapping):
        _issue(issues, "custody:observer_receipt_not_object")
    else:
        for issue in _observer_receipt_issues(
            receipt,
            bundle_value,
            expected_attempt_id=expected_attempt_id,
            expected_session_id=expected_session_id,
        ):
            _issue(issues, issue)

    issues = sorted(set(issues))
    qualified = not issues
    report.update(
        {
            "status": "PASS" if qualified else "FAIL",
            "custody_preserved": True if qualified else None,
            "issues": issues,
            "evidence_tier": "runtime-observed" if qualified else "submitted",
            "coverage": "complete" if qualified else "unknown",
            "claim_permitted": qualified,
            "observer_receipt_sha256": (
                provenance.get("signed_receipt_sha256") if qualified else None
            ),
            "observer_payload_sha256": (
                receipt.get("receipt_sha256") if qualified else None
            ),
            "observer_signing_key_id": (
                provenance.get("signing_key_id") if qualified else None
            ),
            "observer_trust_generation": (
                provenance.get("trust_generation") if qualified else None
            ),
            "receipt_binding": "host-signed" if qualified else "invalid",
            "observed_attempt_id": expected_attempt_id if qualified else None,
            "observed_session_id": expected_session_id if qualified else None,
        }
    )
    return report


def _load(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan")
    parser.add_argument("spawn_wave")
    parser.add_argument("events")
    args = parser.parse_args(argv)
    report = evaluate_custody(
        _load(args.plan),
        _load(args.spawn_wave),
        _load(args.events),
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
