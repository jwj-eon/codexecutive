#!/usr/bin/env python3
"""Provider-free, ticket-bound classification admission.

This module is intentionally a small policy boundary.  It does not inspect a
prompt, contact a model, write a checkout, or launch a worker.  A caller gives
it a declarative ticket identity and concrete decomposition evidence and gets
one sealed decision which can be carried by the controller and project
adapter.  The older ``audit_orchestration_classification`` surface remains in
``orch_dork_policy``; this module is the fresh per-ticket gate.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Iterable


PROGRAM_SCHEMA = "orch-dork/ticket-admission-program/v2"
ADMISSION_SCHEMA = "orch-dork/ticket-admission/v2"
EVENT_SCHEMA = "orch-dork/ticket-admission-events/v2"
CLASSIFICATION_POLICY_VERSION = "classification-policy/v2"
POLICY_VERSION = CLASSIFICATION_POLICY_VERSION

ATOMIC_ADMITTED = "ATOMIC_ADMITTED"
ORCHESTRATION_PLAN_REQUIRED = "ORCHESTRATION_PLAN_REQUIRED"
REFUSED = "REFUSED"
RECLASSIFICATION_REQUIRED = "RECLASSIFICATION_REQUIRED"
DECISIONS = frozenset(
    {ATOMIC_ADMITTED, ORCHESTRATION_PLAN_REQUIRED, REFUSED, RECLASSIFICATION_REQUIRED}
)

RESOURCE_KINDS = frozenset(
    {"shared_mutable_core", "strict_serial_dependency", "integration_only", "read_only_contract"}
)
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")


def compact_json(value: Any) -> str:
    """Return the one canonical representation used by every seal."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def json_sha256(value: Any) -> str:
    return hashlib.sha256(compact_json(value).encode("utf-8")).hexdigest()


# Names used by sibling lanes and by older integrations.  Keeping these tiny
# aliases here lets a controller import this module without depending on a
# particular naming style.
sha256 = json_sha256
canonical_json = compact_json


class TicketAdmissionDecision(dict):
    """A sealed decision with normal mapping and attribute-style access.

    Existing Orch Dork evaluators return JSON-compatible dictionaries.  A
    dict subclass keeps that wire contract while giving callers a named
    ``TicketAdmissionDecision`` return type.
    """

    def __getattr__(self, name: str) -> Any:  # pragma: no cover - convenience
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    @property
    def decision(self) -> str:
        return str(self["decision"])

    @property
    def admitted(self) -> bool:
        return bool(self.get("admitted", False))

    @property
    def admission_hash(self) -> str:
        return str(self.get("admission_sha256", ""))

    def to_dict(self) -> dict[str, Any]:
        return deepcopy(dict(self))


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_id(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value.strip()) is not None


def _first(value: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in value and value[name] is not None:
            return value[name]
    return None


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _digest(value: Any) -> str | None:
    if isinstance(value, str) and _SHA256.fullmatch(value):
        return value
    return None


def _bound_hash(value: Any, *explicit_names: str, source: Mapping[str, Any] | None = None) -> str:
    """Recompute identity from the value; an explicit digest is never trusted."""

    del explicit_names, source
    return json_sha256(value)


def _normalise_acceptance(program: Mapping[str, Any]) -> Any:
    value = _first(program, "acceptance_criteria", "acceptance", "criteria")
    if value is None:
        value = []
    return value


def _normalise_authority(program: Mapping[str, Any]) -> Any:
    value = _first(program, "authority_scope", "authority", "writable_scope")
    if value is None:
        value = {}
    return value


def _normalise_invocation(program: Mapping[str, Any]) -> Any:
    value = _first(program, "invocation_identity", "invocation", "invocation_id")
    if value is None:
        value = {}
    return value


def _normalise_spec(program: Mapping[str, Any]) -> Any:
    value = _first(program, "ticket_spec", "spec", "canonical_spec")
    if value is None:
        value = {}
    return value


def _normalise_lanes(program: Mapping[str, Any]) -> list[Any]:
    value = _first(program, "candidate_lanes", "lanes", "decomposition", "candidates")
    if isinstance(value, list):
        # Preserve malformed entries so they cannot disappear before hashing
        # and validation.
        return [dict(item) if isinstance(item, Mapping) else item for item in value]
    if isinstance(value, Mapping):
        return [dict(value)]
    return []


def _normalise_scope(program: Mapping[str, Any]) -> Any:
    # Writable scope is independently named because changing it must always
    # invalidate a previous admission, even when the broader authority scope
    # did not change.
    authority = _normalise_authority(program)
    writable = _first(program, "writable_scope", "owned_resources", "writable_resources")
    return {"authority": authority, "writable": [] if writable is None else writable}


def _resource_entry(value: Any) -> tuple[str | None, str | None]:
    if isinstance(value, Mapping):
        resource = _first(value, "resource", "path", "name", "id")
        kind = _first(value, "kind", "type", "sharing", "resource_type")
        return (str(resource) if resource is not None else None, str(kind) if kind is not None else None)
    return (str(value), None) if _is_text(value) else (None, None)


def _lane_analysis(lanes: list[Any], issues: list[str]) -> dict[str, Any]:
    """Validate and classify candidate lanes without relying on lane count alone."""

    seen_ids: set[str] = set()
    owners: dict[str, tuple[str, str | None]] = {}
    typed_shared: list[dict[str, str]] = []
    independent: list[str] = []
    coupled: list[str] = []
    lane_rows: list[dict[str, Any]] = []
    for index, raw_lane in enumerate(lanes):
        path = f"candidate_lanes[{index}]"
        if not isinstance(raw_lane, Mapping):
            issues.append(f"{path}:type_invalid")
            lane: Mapping[str, Any] = {}
        else:
            lane = raw_lane
        lane_id = _first(lane, "lane_id", "id", "name")
        if not _is_id(lane_id) or lane_id in seen_ids:
            issues.append(f"{path}:lane_id_invalid_or_duplicate")
            lane_id = f"<invalid-{index}>"
        else:
            seen_ids.add(str(lane_id))
        objective = _first(lane, "objective", "purpose", "goal")
        if not _is_text(objective):
            issues.append(f"{path}:objective_required")
        resources = _first(lane, "owned_resources", "resources", "resource_set")
        if not isinstance(resources, list):
            resources = [] if resources is None else [resources]
            if not resources:
                issues.append(f"{path}:owned_resources_required")
        normalized_resources: list[dict[str, Any]] = []
        has_coupling = False
        for resource in resources:
            resource_id, kind = _resource_entry(resource)
            if not _is_text(resource_id):
                issues.append(f"{path}:resource_invalid")
                continue
            if kind is not None and kind not in RESOURCE_KINDS:
                issues.append(f"{path}:resource_kind_invalid:{kind}")
            row = {"resource": str(resource_id), "kind": kind}
            normalized_resources.append(row)
            previous = owners.get(str(resource_id))
            if previous is not None and previous[0] != str(lane_id):
                previous_kind = previous[1]
                effective_kind = kind or previous_kind
                if effective_kind in {"shared_mutable_core", "strict_serial_dependency"}:
                    has_coupling = True
                    coupled.extend([previous[0], str(lane_id)])
                elif effective_kind in {"integration_only", "read_only_contract"}:
                    # Shared integration/read-only contracts are intentionally
                    # not production ownership.  They remain visible in the
                    # sealed resource inventory but do not collapse lanes.
                    pass
                else:
                    # Untyped overlap is unsafe and cannot be assumed to be
                    # an integration seam.
                    has_coupling = True
                    issues.append(f"{path}:resource_overlap:{resource_id}")
                typed_shared.append({"resource": str(resource_id), "kind": effective_kind or "untyped_shared"})
            else:
                owners[str(resource_id)] = (str(lane_id), kind)
            if kind in {"shared_mutable_core", "strict_serial_dependency"}:
                has_coupling = True
                typed_shared.append({"resource": str(resource_id), "kind": str(kind)})
        explicit_shared = _first(lane, "shared_resources", "shared_seams", "shared_mutation_seams")
        if isinstance(explicit_shared, list):
            for item in explicit_shared:
                resource_id, kind = _resource_entry(item)
                if kind not in RESOURCE_KINDS:
                    issues.append(f"{path}:shared_resource_kind_invalid")
                if kind in {"shared_mutable_core", "strict_serial_dependency"}:
                    has_coupling = True
                if resource_id is not None and kind is not None:
                    typed_shared.append({"resource": resource_id, "kind": kind})
        rejection = _first(lane, "rejection_reason", "not_independent_reason", "rejection")
        if has_coupling:
            coupled.append(str(lane_id))
            if not _is_text(rejection):
                # Coupled lanes need a concrete reason rather than a count.
                issues.append(f"{path}:rejection_reason_required_for_coupling")
        else:
            independent.append(str(lane_id))
            if rejection is not None and not _is_text(rejection):
                issues.append(f"{path}:rejection_reason_invalid")
        lane_rows.append(
            {
                "lane_id": str(lane_id),
                "objective": str(objective).strip() if _is_text(objective) else None,
                "owned_resources": normalized_resources,
                "rejection_reason": str(rejection).strip() if _is_text(rejection) else None,
                "independent": not has_coupling,
            }
        )
    # Explicitly typed shared integration/read-only resources do not merge
    # otherwise independent lanes.  This is a central Issue 33 regression.
    independent_count = len(independent)
    return {
        "lanes": lane_rows,
        "independent_lane_ids": sorted(set(independent)),
        "coupled_lane_ids": sorted(set(coupled)),
        "independent_lane_count": independent_count,
        "typed_shared_resources": sorted(
            {compact_json(item): item for item in typed_shared}.values(), key=lambda item: (item["resource"], item["kind"])
        ),
        "resource_owners": {key: value[0] for key, value in sorted(owners.items())},
    }


def admission_identity(program: Mapping[str, Any], *, classification: Mapping[str, Any] | None = None, lanes: list[Any] | None = None) -> dict[str, Any]:
    """Build the hash-bound identity subset for a ticket program."""

    value = _as_mapping(program)
    lane_value = _normalise_lanes(value) if lanes is None else lanes
    class_value = _first(value, "classification", "classification_evidence") if classification is None else classification
    ticket_id = _first(value, "ticket_id", "ticket_key", "id")
    root_task = _first(value, "root_task_id", "root_thread_id", "task_id", "root_id")
    spec = _normalise_spec(value)
    criteria = _normalise_acceptance(value)
    authority = _normalise_authority(value)
    invocation = _normalise_invocation(value)
    scope = _normalise_scope(value)
    return {
        "ticket_id": ticket_id,
        "ticket_spec_sha256": _bound_hash(spec, "ticket_spec_sha256", "spec_sha256", "ticket_spec_hash", source=value),
        "acceptance_criteria_sha256": _bound_hash(criteria, "acceptance_criteria_sha256", "acceptance_sha256", "criteria_sha256", source=value),
        "authority_scope_sha256": _bound_hash(authority, "authority_scope_sha256", "authority_sha256", source=value),
        "writable_scope_sha256": _bound_hash(scope, "writable_scope_sha256", "writable_sha256", source=value),
        "root_task_id": root_task,
        "invocation_identity_sha256": _bound_hash(invocation, "invocation_identity_sha256", "invocation_sha256", source=value),
        "classification_evidence_sha256": _bound_hash(class_value if class_value is not None else {}, "classification_evidence_sha256", "classification_sha256", source=value),
        "candidate_lanes_sha256": _bound_hash(lane_value, "candidate_lanes_sha256", "lanes_sha256", source=value),
        "policy_version": CLASSIFICATION_POLICY_VERSION,
    }


def build_ticket_admission_program(
    *,
    ticket_id: str,
    ticket_spec: Mapping[str, Any],
    acceptance_criteria: list[Any],
    authority_scope: Mapping[str, Any],
    writable_scope: list[Any],
    root_task_id: str,
    invocation_identity: Mapping[str, Any],
    classification: Mapping[str, Any],
    candidate_lanes: list[Any],
) -> dict[str, Any]:
    """Construct one canonical v2 program without caller schema literals."""

    return {
        "schema": PROGRAM_SCHEMA,
        "ticket_id": ticket_id,
        "ticket_spec": deepcopy(dict(ticket_spec)),
        "acceptance_criteria": deepcopy(list(acceptance_criteria)),
        "authority_scope": deepcopy(dict(authority_scope)),
        "writable_scope": deepcopy(list(writable_scope)),
        "root_task_id": root_task_id,
        "invocation_identity": deepcopy(dict(invocation_identity)),
        "classification": deepcopy(dict(classification)),
        "candidate_lanes": deepcopy(list(candidate_lanes)),
    }


def _input_issues(program: Mapping[str, Any], identity: Mapping[str, Any], analysis: Mapping[str, Any]) -> list[str]:
    issues: list[str] = []
    value = _as_mapping(program)
    if value.get("schema") not in {None, PROGRAM_SCHEMA, ADMISSION_SCHEMA}:
        issues.append("program:schema_invalid")
    if not _is_id(identity.get("ticket_id")):
        issues.append("ticket_id:required")
    if not _is_id(identity.get("root_task_id")):
        issues.append("root_task_id:required")
    if identity.get("ticket_spec_sha256") is None:
        issues.append("ticket_spec:missing")
    if identity.get("acceptance_criteria_sha256") is None:
        issues.append("acceptance_criteria:missing")
    if identity.get("authority_scope_sha256") is None:
        issues.append("authority_scope:missing")
    if identity.get("invocation_identity_sha256") is None:
        issues.append("invocation_identity:missing")
    digest_fields = (
        (_normalise_spec(value), ("ticket_spec_sha256", "spec_sha256", "ticket_spec_hash"), "ticket_spec"),
        (_normalise_acceptance(value), ("acceptance_criteria_sha256", "acceptance_sha256", "criteria_sha256"), "acceptance_criteria"),
        (_normalise_authority(value), ("authority_scope_sha256", "authority_sha256"), "authority_scope"),
        (_normalise_scope(value), ("writable_scope_sha256", "writable_sha256"), "writable_scope"),
        (_normalise_invocation(value), ("invocation_identity_sha256", "invocation_sha256"), "invocation_identity"),
        (_first(value, "classification", "classification_evidence") or {}, ("classification_evidence_sha256", "classification_sha256"), "classification_evidence"),
        (_normalise_lanes(value), ("candidate_lanes_sha256", "lanes_sha256"), "candidate_lanes"),
    )
    for material, aliases, label in digest_fields:
        expected = json_sha256(material)
        for alias in aliases:
            if alias not in value:
                continue
            supplied = value.get(alias)
            if not _digest(supplied):
                issues.append(f"{label}:digest_invalid")
            elif supplied != expected:
                issues.append(f"{label}:digest_mismatch")
    classification = _as_mapping(_first(value, "classification", "classification_evidence"))
    mode = _first(classification, "mode", "classification", "decision")
    if mode not in {"atomic", "orchestrated", "refused"}:
        issues.append("classification:mode_invalid")
    evidence = _first(classification, "evidence", "decomposition_evidence", "decomposition")
    if not isinstance(evidence, Mapping):
        evidence = classification
    authority_available = _first(
        evidence,
        "authority_available",
        "required_authority_available",
        "safe_authority_available",
    )
    ownership_available = _first(
        evidence,
        "ownership_available",
        "safe_resource_ownership_available",
        "safe_ownership_available",
    )
    if authority_available is False:
        issues.append("authority:unavailable")
    if ownership_available is False:
        issues.append("safe_resource_ownership:unavailable")
    if mode == "atomic":
        attempted = _first(evidence, "attempted_decomposition", "decomposition_attempt", "decomposition_basis")
        proof = _first(evidence, "single_coherent_operation_proof", "coherent_operation_proof", "coherence_proof")
        if not _is_text(attempted) and not _is_text(proof):
            issues.append("classification:atomic_decomposition_evidence_required")
    if mode == "orchestrated" and analysis.get("independent_lane_count", 0) < 2:
        issues.append("classification:orchestrated_requires_two_independent_lanes")
    # A missing lane list is fine for a truly single atomic operation only if
    # its evidence says it is one coherent operation.
    if not analysis.get("lanes") and mode != "atomic":
        issues.append("candidate_lanes:required")
    return sorted(set(issues))


def _prior_mismatch(previous: Mapping[str, Any], identity: Mapping[str, Any]) -> list[str]:
    if not isinstance(previous, Mapping):
        return []
    validation = validate_decision(previous)
    if not validation.get("valid"):
        return ["previous_admission_invalid"]
    old_identity = previous.get("identity")
    if not isinstance(old_identity, Mapping):
        return ["previous_admission_identity_missing"]
    reasons: list[str] = []
    labels = {
        "ticket_id": "ticket_id_changed",
        "ticket_spec_sha256": "ticket_spec_changed",
        "acceptance_criteria_sha256": "acceptance_criteria_changed",
        "authority_scope_sha256": "authority_scope_changed",
        "writable_scope_sha256": "writable_scope_changed",
        "root_task_id": "root_task_changed",
        "invocation_identity_sha256": "invocation_identity_changed",
        "classification_evidence_sha256": "classification_evidence_changed",
        "candidate_lanes_sha256": "candidate_lanes_changed",
    }
    for field, reason in labels.items():
        if field not in old_identity:
            reasons.append("previous_admission_identity_incomplete")
        elif old_identity.get(field) != identity.get(field):
            reasons.append(reason)
    return reasons


def _decision_payload(identity: Mapping[str, Any], decision: str, analysis: Mapping[str, Any], issues: Iterable[str], invalidation: Iterable[str]) -> dict[str, Any]:
    return {
        "schema": ADMISSION_SCHEMA,
        "policy_version": CLASSIFICATION_POLICY_VERSION,
        "decision": decision,
        "admitted": decision == ATOMIC_ADMITTED,
        "identity": dict(identity),
        "ticket_id": identity.get("ticket_id"),
        "root_task_id": identity.get("root_task_id"),
        "root_thread_id": identity.get("root_task_id"),
        "independent_lane_count": int(analysis.get("independent_lane_count", 0)),
        "candidate_lanes": deepcopy(analysis.get("lanes", [])),
        "typed_shared_resources": deepcopy(analysis.get("typed_shared_resources", [])),
        "classification_evidence": {
            "independent_lane_ids": list(analysis.get("independent_lane_ids", [])),
            "coupled_lane_ids": list(analysis.get("coupled_lane_ids", [])),
            "typed_shared_resources": deepcopy(analysis.get("typed_shared_resources", [])),
        },
        "issues": sorted(set(str(item) for item in issues)),
        "invalidation_reasons": sorted(set(str(item) for item in invalidation)),
        "evidence_tier": "provider-free-submitted",
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "hard_admission": False,
        "mutation_permitted": False,
        "requires_admission_kernel": True,
    }


def seal_admission(decision: Mapping[str, Any]) -> TicketAdmissionDecision:
    """Seal an already assembled report, excluding mutable seal aliases."""

    core = deepcopy(dict(decision))
    core.pop("admission_sha256", None)
    core.pop("admission_hash", None)
    # Lifecycle events carry the resulting seal.  Excluding the event list
    # from the identity material avoids a circular hash (the seal is itself
    # present in each event) while retaining the complete event list in the
    # serialized decision.
    events = core.pop("events", None)
    # Keep identity and resulting decision in the sealed material.  This is
    # what prevents a same-ticket decision from being swapped after compaction.
    seal_material = {"identity": core.get("identity", {}), "decision": core.get("decision"), "report": core}
    digest = json_sha256(seal_material)
    core["admission_sha256"] = digest
    core["admission_hash"] = digest
    if events is not None:
        core["events"] = events
    return TicketAdmissionDecision(core)


def evaluate_ticket_admission(program: Any) -> TicketAdmissionDecision:
    """Evaluate one fresh ticket classification and return a sealed decision."""

    value = _as_mapping(program)
    lanes = _normalise_lanes(value)
    analysis_issues: list[str] = []
    analysis = _lane_analysis(lanes, analysis_issues)
    classification = _first(value, "classification", "classification_evidence")
    identity = admission_identity(value, classification=classification, lanes=lanes)
    issues = analysis_issues + _input_issues(value, identity, analysis)

    classification_value = _as_mapping(classification)
    mode = _first(classification_value, "mode", "classification", "decision")
    if mode == "refused":
        decision = REFUSED
    elif any(item.startswith("authority_scope:") for item in issues) or any(
        item in {"authority:unavailable", "safe_resource_ownership:unavailable", "authority_unavailable", "ownership_unavailable"}
        for item in issues
    ):
        decision = REFUSED
    elif issues:
        # Malformed or absent identity/evidence cannot be safely admitted.
        decision = REFUSED
    elif mode == "orchestrated":
        decision = ORCHESTRATION_PLAN_REQUIRED
    elif analysis["independent_lane_count"] >= 2:
        decision = ORCHESTRATION_PLAN_REQUIRED
    else:
        decision = ATOMIC_ADMITTED

    previous = _first(value, "previous_admission", "prior_admission", "admission")
    invalidation = _prior_mismatch(previous, identity) if isinstance(previous, Mapping) else []
    # A previous decision only invalidates when its identity changed.  A
    # matching prior admission is explicitly reusable across compaction.
    if invalidation:
        decision = RECLASSIFICATION_REQUIRED
        issues.extend("invalidation:" + reason for reason in invalidation)

    report = _decision_payload(identity, decision, analysis, issues, invalidation)
    report["fresh"] = not bool(previous)
    report["compaction_preserved"] = bool(previous) and not bool(invalidation)
    report["root_owned"] = decision == ATOMIC_ADMITTED
    report["plan_required"] = decision == ORCHESTRATION_PLAN_REQUIRED
    report["workers_permitted"] = False if decision == ATOMIC_ADMITTED else decision == ORCHESTRATION_PLAN_REQUIRED
    # Seal first, then bind every durable event to that final hash.  Events
    # are intentionally excluded from the hash material by ``seal_admission``
    # to keep this two-step construction deterministic.
    sealed = seal_admission(report)
    sealed["events"] = durable_admission_events(value, sealed, include_unobserved=True)
    return sealed


def compare_admission_identity(previous: Mapping[str, Any], program: Mapping[str, Any]) -> dict[str, Any]:
    identity = admission_identity(_as_mapping(program))
    reasons = _prior_mismatch(_as_mapping(previous), identity)
    return {
        "valid": not reasons and bool(previous),
        "decision": ATOMIC_ADMITTED if not reasons else RECLASSIFICATION_REQUIRED,
        "invalidation_reasons": reasons,
        "identity": identity,
        "admission_sha256": _as_mapping(previous).get("admission_sha256"),
    }


def validate_admission_binding(program: Mapping[str, Any], admission: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Check that an event/controller has the exact current ticket seal."""

    supplied = admission if isinstance(admission, Mapping) else _first(_as_mapping(program), "ticket_admission", "admission")
    if not isinstance(supplied, Mapping):
        return {"valid": False, "decision": RECLASSIFICATION_REQUIRED, "issues": ["admission:missing"], "invalidation_reasons": ["admission_missing"]}
    expected_program = dict(_as_mapping(program))
    expected_program.pop("previous_admission", None)
    expected_program.pop("prior_admission", None)
    expected = evaluate_ticket_admission(expected_program)
    reasons = _prior_mismatch(supplied, expected.get("identity", {}))
    issues: list[str] = []
    supplied_hash = _first(supplied, "admission_sha256", "admission_hash")
    if supplied_hash != expected.get("admission_sha256"):
        # A supplied admission can be the expected decision even when the
        # evaluator would choose a different terminal outcome for a changed
        # program; hash comparison remains the final authority.
        issues.append("admission:hash_mismatch")
    if supplied.get("policy_version") != CLASSIFICATION_POLICY_VERSION:
        issues.append("admission:policy_version_mismatch")
    if reasons:
        issues.extend("invalidation:" + reason for reason in reasons)
    return {
        "valid": not issues,
        "decision": expected.get("decision") if not issues else RECLASSIFICATION_REQUIRED,
        "issues": sorted(set(issues)),
        "invalidation_reasons": sorted(set(reasons)),
        "expected_admission_sha256": expected.get("admission_sha256"),
        "admission_sha256": supplied_hash,
        "identity": expected.get("identity"),
    }


def admission_is_valid(program: Mapping[str, Any], admission: Mapping[str, Any] | None = None) -> bool:
    return bool(validate_admission_binding(program, admission).get("valid"))


def invalidate_admission(previous: Mapping[str, Any], program: Mapping[str, Any]) -> dict[str, Any]:
    """Return durable invalidation evidence without mutating the prior seal."""

    comparison = compare_admission_identity(previous, program)
    return {
        "schema": EVENT_SCHEMA,
        "type": "admission.invalidated",
        "ticket_id": comparison["identity"].get("ticket_id"),
        "admission_sha256": _as_mapping(previous).get("admission_sha256"),
        "decision": RECLASSIFICATION_REQUIRED if comparison["invalidation_reasons"] else ATOMIC_ADMITTED,
        "reason": comparison["invalidation_reasons"] or ["unchanged_admission"],
        "source_pointer": "ticket-admission#invalidation",
    }


def compact_admission(admission: Mapping[str, Any]) -> TicketAdmissionDecision:
    """Preserve an unchanged admission across compaction, without re-sealing it."""

    value = deepcopy(dict(admission))
    digest = _first(value, "admission_sha256", "admission_hash")
    if _digest(digest):
        value["admission_sha256"] = digest
        value["admission_hash"] = digest
    value["compaction_preserved"] = True
    return TicketAdmissionDecision(value)


preserve_compacted_admission = compact_admission


def durable_admission_events(program: Mapping[str, Any], decision: Mapping[str, Any], *, include_unobserved: bool = False) -> list[dict[str, Any]]:
    """Create sanitized append-only lifecycle facts bound to one admission."""

    value = _as_mapping(program)
    report = _as_mapping(decision)
    ticket_id = _first(report, "ticket_id") or _first(value, "ticket_id", "ticket_key", "id")
    root_task_id = _first(report, "root_task_id", "root_thread_id") or _first(value, "root_task_id", "root_thread_id", "task_id")
    admission_hash = _first(report, "admission_sha256", "admission_hash")
    events: list[dict[str, Any]] = [
        {
            "schema": EVENT_SCHEMA,
            "seq": 1,
            "type": "ticket.claimed",
            "ticket_id": ticket_id,
            "root_task_id": root_task_id,
            "admission_sha256": admission_hash,
            "source_pointer": "ticket-admission#claim",
        },
        {
            "schema": EVENT_SCHEMA,
            "seq": 2,
            "type": "admission.issued",
            "ticket_id": ticket_id,
            "root_task_id": root_task_id,
            "admission_sha256": admission_hash,
            "decision": report.get("decision"),
            "source_pointer": "ticket-admission#decision",
        },
    ]
    invalidation = report.get("invalidation_reasons") or []
    if invalidation:
        events.append(
            {
                "schema": EVENT_SCHEMA,
                "seq": len(events) + 1,
                "type": "admission.invalidated",
                "ticket_id": ticket_id,
                "root_task_id": root_task_id,
                "admission_sha256": admission_hash,
                "reason": list(invalidation),
                "source_pointer": "ticket-admission#invalidation",
            }
        )
    observed = _first(value, "observed_events", "lifecycle_events", "events")
    if isinstance(observed, list):
        for item in observed:
            if not isinstance(item, Mapping):
                continue
            event_type = _first(item, "type", "event")
            if event_type not in {"implementation.started", "ticket.completed", "completion.bound"}:
                continue
            event = {
                "schema": EVENT_SCHEMA,
                "seq": len(events) + 1,
                "type": event_type,
                "ticket_id": ticket_id,
                "root_task_id": root_task_id,
                "admission_sha256": _first(item, "admission_sha256", "admission_hash") or admission_hash,
                "source_pointer": _first(item, "source_pointer") or "ticket-admission#observed",
            }
            if event_type == "implementation.started":
                event["first_mutation"] = bool(_first(item, "first_mutation", "first_write", "write_mode"))
            if event_type in {"ticket.completed", "completion.bound"}:
                event["completion_binding"] = _first(item, "completion_binding", "binding") or admission_hash
            events.append(event)
    if include_unobserved:
        existing = {event["type"] for event in events}
        for event_type in ("implementation.started", "ticket.completed"):
            if event_type in existing:
                continue
            event = {
                "schema": EVENT_SCHEMA,
                "seq": len(events) + 1,
                "type": event_type,
                "ticket_id": ticket_id,
                "root_task_id": root_task_id,
                "admission_sha256": admission_hash,
                "observed": False,
                "source_pointer": "ticket-admission#pending",
            }
            if event_type == "implementation.started":
                event["first_mutation"] = False
            else:
                event["completion_binding"] = admission_hash
            events.append(event)
    return events


build_admission_events = durable_admission_events
admission_events = durable_admission_events


def append_admission_event(events: Iterable[Mapping[str, Any]], event: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return a new append-only event list after basic seal binding checks."""

    result = [dict(item) for item in events if isinstance(item, Mapping)]
    item = dict(event) if isinstance(event, Mapping) else {}
    if not _is_text(item.get("type")):
        raise ValueError("event type is required")
    if result:
        previous = result[-1]
        if item.get("admission_sha256") != previous.get("admission_sha256"):
            raise ValueError("event admission hash mismatch")
        item["seq"] = len(result) + 1
    else:
        item.setdefault("seq", 1)
    item.setdefault("schema", EVENT_SCHEMA)
    result.append(item)
    return result


def historical_fixture(ticket_id: str) -> dict[str, Any]:
    """Build deterministic Issue 23--30 regression inputs."""

    try:
        number = int(str(ticket_id).lower().replace("issue-", "").replace("issue", ""))
    except ValueError:
        number = 23
    if number in {23, 24, 25, 26}:
        lane_count = 0
        mode = "atomic"
        evidence = {"single_coherent_operation_proof": f"Issue {number} is one coherent root operation"}
    elif number == 27:
        lane_count = 2
        mode = "orchestrated"
        evidence = {"attempted_decomposition": "Evaluator and registry projection have disjoint ownership"}
    elif number == 30:
        lane_count = 3
        mode = "orchestrated"
        evidence = {"attempted_decomposition": "Transport, workspace, and adapter evidence are disjoint"}
    else:
        lane_count = 1
        mode = "atomic"
        evidence = {"single_coherent_operation_proof": "One coherent operation"}
    lanes = [
        {
            "lane_id": f"issue-{number}-lane-{index}",
            "objective": f"Issue {number} production lane {index}",
            "owned_resources": [f"issue-{number}/lane-{index}.py"],
        }
        for index in range(1, lane_count + 1)
    ]
    if number == 27:
        lanes[0]["owned_resources"].append({"resource": "issue-27/integration", "kind": "integration_only"})
        lanes[1]["owned_resources"].append({"resource": "issue-27/integration", "kind": "integration_only"})
    return {
        "schema": PROGRAM_SCHEMA,
        "ticket_id": f"issue-{number}",
        "ticket_spec": {"historical_issue": number, "source": f"issues/{number}.md"},
        "acceptance_criteria": [f"Issue {number} provider-free regression"],
        "authority_scope": {"provider_free": True, "writable": [f"issue-{number}"], "hosted_calls": 0},
        "writable_scope": [f"issue-{number}"],
        "root_task_id": f"root-issue-{number}",
        "invocation_identity": {"surface": "orch-dork", "policy": CLASSIFICATION_POLICY_VERSION},
        "classification": {"mode": mode, "evidence": evidence},
        "candidate_lanes": lanes,
    }


def regression_fixtures() -> dict[str, dict[str, Any]]:
    return {f"issue-{number}": historical_fixture(f"issue-{number}") for number in (23, 24, 25, 26, 27, 30)}


def evaluate_historical_fixture(ticket_id: str) -> TicketAdmissionDecision:
    return evaluate_ticket_admission(historical_fixture(ticket_id))


def validate_decision(value: Any) -> dict[str, Any]:
    """Validate a serialized decision without recomputing caller program data."""

    issues: list[str] = []
    report = _as_mapping(value)
    if report.get("schema") != ADMISSION_SCHEMA:
        issues.append("schema_invalid")
    if report.get("policy_version") != CLASSIFICATION_POLICY_VERSION:
        issues.append("policy_version_invalid")
    if report.get("decision") not in DECISIONS:
        issues.append("decision_invalid")
    required = {
        "schema", "policy_version", "decision", "admitted", "identity",
        "ticket_id", "root_task_id", "root_thread_id", "independent_lane_count",
        "candidate_lanes", "typed_shared_resources", "classification_evidence",
        "issues", "invalidation_reasons", "evidence_tier", "provider_free",
        "model_calls", "hosted_calls", "fresh", "compaction_preserved",
        "root_owned", "plan_required", "workers_permitted", "admission_sha256",
        "admission_hash", "events", "hard_admission", "mutation_permitted",
        "requires_admission_kernel",
    }
    if not required.issubset(report):
        issues.append("report_shape_incomplete")
    identity = report.get("identity")
    identity_fields = {
        "ticket_id", "ticket_spec_sha256", "acceptance_criteria_sha256",
        "authority_scope_sha256", "writable_scope_sha256", "root_task_id",
        "invocation_identity_sha256", "classification_evidence_sha256",
        "candidate_lanes_sha256", "policy_version",
    }
    if not isinstance(identity, Mapping) or set(identity) != identity_fields:
        issues.append("identity_shape_invalid")
    admitted_expected = report.get("decision") == ATOMIC_ADMITTED
    if report.get("admitted") is not admitted_expected:
        issues.append("admitted_decision_mismatch")
    digest = _first(report, "admission_sha256", "admission_hash")
    material = {key: item for key, item in report.items() if key not in {"admission_sha256", "admission_hash", "compaction_preserved"}}
    # Compaction preservation is a transport annotation and is not permitted
    # to alter the original decision seal.
    if "compaction_preserved" in report:
        material["compaction_preserved"] = False
    expected = seal_admission(material).get("admission_sha256")
    if digest != expected:
        issues.append("admission_hash_invalid")
    return {"valid": not issues, "issues": sorted(set(issues)), "admission_sha256": digest}


__all__ = [
    "PROGRAM_SCHEMA", "ADMISSION_SCHEMA", "EVENT_SCHEMA", "CLASSIFICATION_POLICY_VERSION", "POLICY_VERSION",
    "ATOMIC_ADMITTED", "ORCHESTRATION_PLAN_REQUIRED", "REFUSED", "RECLASSIFICATION_REQUIRED", "DECISIONS",
    "RESOURCE_KINDS", "TicketAdmissionDecision", "compact_json", "json_sha256", "sha256", "canonical_json",
    "admission_identity", "build_ticket_admission_program", "evaluate_ticket_admission", "seal_admission", "validate_decision", "validate_admission_binding",
    "admission_is_valid", "compare_admission_identity", "invalidate_admission", "compact_admission", "preserve_compacted_admission",
    "durable_admission_events", "build_admission_events", "admission_events", "append_admission_event",
    "historical_fixture", "regression_fixtures", "evaluate_historical_fixture",
]
