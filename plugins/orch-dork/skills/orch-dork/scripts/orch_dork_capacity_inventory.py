#!/usr/bin/env python3
"""Normalize collaboration capacity as a reusable concurrent lane pool.

Only dispatch-reserved/executing records occupy capacity; native
``pending_init``/``running`` statuses are their compatibility representation.
Terminal records release only when an exact lane/run/native-route cleanup
record with no owned descendants is covered by the short-lived host-signed
observation. Otherwise they remain visible, nonreusable, and occupying.
"""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
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
    import orch_dork_observer_receipt as observer_receipt
    import orch_dork_shared_capacity as shared_capacity
except ModuleNotFoundError:  # standalone spec loading in focused tests
    evidence_core = _load_sibling("orch_dork_evidence_core")
    observer_receipt = _load_sibling("orch_dork_observer_receipt")
    shared_capacity = _load_sibling("orch_dork_shared_capacity")


INVENTORY_SCHEMA_V1 = "orch-dork/collaboration-inventory/v1"
INVENTORY_SCHEMA_V2 = "orch-dork/collaboration-inventory/v2"
SLOT_ACCOUNTING_SCHEMA = "orch-dork/slot-accounting-capability/v1"
NATIVE_OBSERVATION_SCHEMA = "orch-dork/native-capacity-observation/v1"
NATIVE_ADAPTER_REPORT_SCHEMA = "orch-dork/native-capacity-adapter-report/v1"
RELEASE_EVIDENCE_SCHEMA = shared_capacity.RELEASE_SCHEMA
NATIVE_RELEASE_ROUTE = "native_luna"
ACTIVE_ONLY = "active_only"
RETAINED_UNTIL_SHUTDOWN = "retained_until_shutdown"
ACTIVE_STATUSES = frozenset({"running", "pending_init"})
TERMINAL_STATUSES = frozenset(
    {"completed", "failed", "cancelled", "errored", "interrupted"}
)
VISIBLE_STATUSES = ACTIVE_STATUSES | TERMINAL_STATUSES | {"shutdown", "not_found"}
RETAINED_OCCUPIED_STATUSES = ACTIVE_STATUSES | TERMINAL_STATUSES
MAX_CAPABILITY_VALIDITY_SECONDS = 300
MAX_CONCURRENT_LANES = shared_capacity.MAX_CONCURRENT_LANES

_SHA256 = evidence_core.SHA256_PATTERN
capacity_authority_projection = evidence_core.capacity_authority_projection
_V1_KEYS = {"schema", "root_thread_id", "capacity", "retirement_supported", "workers"}
_V2_KEYS = _V1_KEYS | {"slot_accounting"}
_SLOT_KEYS = {
    "schema", "mode", "capacity_kind", "surface_id", "root_thread_id",
    "occupied_statuses", "terminal_records_consume_slots", "evidence_tier",
    "observed_at", "evaluated_at", "valid_until", "source_pointer",
    "source_sha256",
}
_NATIVE_KEYS = {
    "schema", "status", "observer_id", "independent", "root_thread_id",
    "capacity", "retirement_supported", "workers", "slot_accounting_mode",
    "surface_id", "observed_at", "evaluated_at", "valid_until",
    "source_pointer", "source_sha256", "observation_sha256",
}
_WORKER_KEYS = {"worker_id", "status", "attempt_id"}
_RELEASE_EVIDENCE_KEYS = {
    "schema", "status", "released", "lane_id", "run_id", "route",
    "terminal_state",
    "owned_descendants", "cleanup_status", "terminal_evidence_sha256",
    "cleanup_evidence_sha256", "identity_retained_not_reusable",
    "cleanup_observer_receipt", "reason_codes", "receipt_sha256",
}


_sha = evidence_core.digest


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


_timestamp = evidence_core.instant


_issue = evidence_core.add_issue


def _exact(value: Any, keys: set[str], label: str, issues: list[str]) -> bool:
    return evidence_core.closed(value, keys, label, issues) is not None


def _release_evidence(
    value: Any,
    *,
    worker_id: Any,
    attempt_id: Any,
    terminal_status: Any,
    signed_observation: bool,
    observer_trust_store: Any,
    observer_replay_guard: Any,
    observer_evaluation_time: Any,
    observer_environ: Mapping[str, str] | None,
    label: str,
    issues: list[str],
) -> bool:
    proof_issues: list[str] = []
    _exact(value, _RELEASE_EVIDENCE_KEYS, label, proof_issues)
    item = dict(value) if isinstance(value, Mapping) else {}
    if item.get("schema") != RELEASE_EVIDENCE_SCHEMA:
        _issue(proof_issues, label + ":schema_invalid")
    if item.get("status") != "RELEASED" or item.get("released") is not True:
        _issue(proof_issues, label + ":release_not_confirmed")
    if item.get("lane_id") != worker_id:
        _issue(proof_issues, label + ":lane_identity_mismatch")
    if item.get("run_id") != attempt_id:
        _issue(proof_issues, label + ":run_identity_mismatch")
    if item.get("route") != NATIVE_RELEASE_ROUTE:
        _issue(proof_issues, label + ":route_identity_mismatch")
    canonical_terminal = shared_capacity.canonical_terminal_state(
        terminal_status
    )
    if (
        terminal_status not in TERMINAL_STATUSES
        or canonical_terminal is None
        or item.get("terminal_state") != canonical_terminal
    ):
        _issue(proof_issues, label + ":terminal_state_mismatch")
    if type(item.get("owned_descendants")) is not int:
        _issue(proof_issues, label + ":owned_descendants_invalid")
    elif item.get("owned_descendants") != 0:
        _issue(proof_issues, label + ":owned_descendants_present")
    if item.get("cleanup_status") not in {"complete", "not_required"}:
        _issue(proof_issues, label + ":cleanup_status_unknown")
    for field in ("terminal_evidence_sha256", "cleanup_evidence_sha256"):
        if not isinstance(item.get(field), str) or _SHA256.fullmatch(
            item.get(field, "")
        ) is None:
            _issue(proof_issues, label + ":" + field + "_invalid")
    if item.get("identity_retained_not_reusable") is not True:
        _issue(proof_issues, label + ":identity_retention_invalid")
    if item.get("reason_codes") != []:
        _issue(proof_issues, label + ":reason_codes_not_empty")
    if not shared_capacity.validate_release_receipt(
        item,
        lane_id=str(worker_id),
        run_id=str(attempt_id),
        route=NATIVE_RELEASE_ROUTE,
        terminal_state=str(terminal_status),
    ):
        _issue(proof_issues, label + ":receipt_seal_invalid")
    if not shared_capacity.validate_release_receipt_authority(
        item,
        lane_id=str(worker_id),
        run_id=str(attempt_id),
        route=NATIVE_RELEASE_ROUTE,
        terminal_state=str(terminal_status),
        observer_trust_store=observer_trust_store,
        observer_replay_guard=observer_replay_guard,
        observer_evaluation_time=observer_evaluation_time,
        observer_environ=observer_environ,
    ):
        _issue(proof_issues, label + ":cleanup_observer_authority_invalid")
    if not signed_observation:
        _issue(proof_issues, label + ":host_signature_required")
    for proof_issue in proof_issues:
        _issue(issues, proof_issue)
    return not proof_issues


def _slot_accounting(
    value: Any,
    *,
    root_thread_id: Any,
    label: str,
    issues: list[str],
) -> dict[str, Any]:
    slot_label = label + ".slot_accounting"
    _exact(value, _SLOT_KEYS, slot_label, issues)
    item = dict(value) if isinstance(value, Mapping) else {}
    if item.get("schema") != SLOT_ACCOUNTING_SCHEMA:
        _issue(issues, slot_label + ":schema_invalid")
    mode = item.get("mode")
    if mode == RETAINED_UNTIL_SHUTDOWN:
        _issue(issues, slot_label + ":retained_terminal_mode_removed")
        mode = ACTIVE_ONLY
    elif mode != ACTIVE_ONLY:
        _issue(issues, slot_label + ":mode_invalid")
        mode = ACTIVE_ONLY
    if item.get("capacity_kind") != "active_agents_excluding_root":
        _issue(issues, slot_label + ":capacity_kind_invalid")
    if not _text(item.get("surface_id")):
        _issue(issues, slot_label + ":surface_id_invalid")
    if item.get("root_thread_id") != root_thread_id:
        _issue(issues, slot_label + ":root_identity_mismatch")
    if item.get("evidence_tier") != "runtime_observed":
        _issue(issues, slot_label + ":not_runtime_observed")
    if not _text(item.get("source_pointer")):
        _issue(issues, slot_label + ":source_pointer_invalid")
    if not isinstance(item.get("source_sha256"), str) or _SHA256.fullmatch(
        item.get("source_sha256", "")
    ) is None:
        _issue(issues, slot_label + ":source_sha256_invalid")

    observed = _timestamp(item.get("observed_at"))
    evaluated = _timestamp(item.get("evaluated_at"))
    valid_until = _timestamp(item.get("valid_until"))
    if observed is None:
        _issue(issues, slot_label + ":observed_at_invalid")
    if evaluated is None:
        _issue(issues, slot_label + ":evaluated_at_invalid")
    if valid_until is None:
        _issue(issues, slot_label + ":valid_until_invalid")
    if observed is not None and evaluated is not None and valid_until is not None:
        freshness = evidence_core.freshness_issues(
            observed,
            evaluated,
            valid_until,
            now=evaluated,
            max_seconds=MAX_CAPABILITY_VALIDITY_SECONDS,
        )
        if "freshness:interval_invalid" in freshness:
            _issue(issues, slot_label + ":validity_interval_invalid")
        if "freshness:interval_too_long" in freshness:
            _issue(issues, slot_label + ":validity_interval_too_long")

    expected_statuses = sorted(ACTIVE_STATUSES)
    if item.get("occupied_statuses") != expected_statuses:
        _issue(issues, slot_label + ":occupied_statuses_noncanonical")
    if item.get("terminal_records_consume_slots") is not False:
        _issue(issues, slot_label + ":terminal_accounting_contradiction")
    return {
        **item,
        "mode": mode,
        "occupied_statuses": expected_statuses,
        "terminal_records_consume_slots": False,
    }


def _evaluate_inventory(
    value: Any,
    *,
    root_thread_id: str | None = None,
    label: str = "inventory",
    authority_source: str = "submitted",
    capacity_adapter_sha256: str | None = None,
    capacity_observation_sha256: str | None = None,
    capacity_provenance: Mapping[str, Any] | None = None,
    release_trust_store: Any = None,
    release_replay_guard: Any = None,
    release_evaluation_time: Any = None,
    release_environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return one normalized report with module-owned authority provenance."""

    issues: list[str] = []
    item = dict(value) if isinstance(value, Mapping) else {}
    schema = item.get("schema")
    if schema == INVENTORY_SCHEMA_V2:
        _exact(value, _V2_KEYS, label, issues)
    else:
        _exact(value, _V1_KEYS, label, issues)
        if schema != INVENTORY_SCHEMA_V1:
            _issue(issues, label + ":schema_invalid")

    observed_root = item.get("root_thread_id")
    if not _text(observed_root):
        _issue(issues, label + ":root_identity_invalid")
    if root_thread_id is not None and observed_root != root_thread_id:
        _issue(issues, label + ":root_identity_mismatch")
    capacity = item.get("capacity")
    if type(capacity) is not int or capacity < 0:
        _issue(issues, label + ":capacity_invalid")
        capacity = 0
    elif capacity > MAX_CONCURRENT_LANES:
        _issue(issues, label + ":capacity_exceeds_max_concurrent_lanes")
        capacity = 0
    retirement_supported = item.get("retirement_supported")
    if not isinstance(retirement_supported, bool):
        _issue(issues, label + ":retirement_capability_invalid")
        retirement_supported = False
    workers = item.get("workers")
    if not isinstance(workers, list):
        _issue(issues, label + ":workers_not_array")
        workers = []
    normalized: list[dict[str, Any]] = []
    released_terminal_ids: set[str] = set()
    signed_release_evidence = bool(
        authority_source == "host-signed-observer"
        and isinstance(capacity_provenance, Mapping)
        and isinstance(capacity_provenance.get("signed_receipt_sha256"), str)
        and _SHA256.fullmatch(
            capacity_provenance.get("signed_receipt_sha256", "")
        )
    )
    seen: set[str] = set()
    for index, worker in enumerate(workers):
        worker_label = f"{label}.workers[{index}]"
        worker_keys = _WORKER_KEYS
        if (
            schema == INVENTORY_SCHEMA_V2
            and isinstance(worker, Mapping)
            and "release_evidence" in worker
        ):
            worker_keys = _WORKER_KEYS | {"release_evidence"}
        _exact(worker, worker_keys, worker_label, issues)
        row = dict(worker) if isinstance(worker, Mapping) else {}
        worker_id = row.get("worker_id")
        if not _text(worker_id) or worker_id in seen:
            _issue(issues, worker_label + ":worker_identity_invalid")
            continue
        seen.add(str(worker_id))
        if row.get("status") not in VISIBLE_STATUSES:
            _issue(issues, worker_label + ":status_invalid")
            continue
        if not _text(row.get("attempt_id")):
            _issue(issues, worker_label + ":attempt_id_invalid")
            continue
        if schema == INVENTORY_SCHEMA_V2 and "release_evidence" in row:
            if _release_evidence(
                row.get("release_evidence"),
                worker_id=worker_id,
                attempt_id=row.get("attempt_id"),
                terminal_status=row.get("status"),
                signed_observation=signed_release_evidence,
                observer_trust_store=release_trust_store,
                observer_replay_guard=release_replay_guard,
                observer_evaluation_time=release_evaluation_time,
                observer_environ=release_environ,
                label=worker_label + ".release_evidence",
                issues=issues,
            ):
                released_terminal_ids.add(str(worker_id))
        normalized.append(row)

    slot = None
    if schema == INVENTORY_SCHEMA_V2:
        slot = _slot_accounting(
            item.get("slot_accounting"), root_thread_id=observed_root,
            label=label, issues=issues,
        )
        mode = slot["mode"]
        occupied_statuses = set(slot["occupied_statuses"])
        evidence_tier = slot.get("evidence_tier")
        terminal_records_consume_slots = slot["terminal_records_consume_slots"]
    else:
        mode = RETAINED_UNTIL_SHUTDOWN
        occupied_statuses = set(RETAINED_OCCUPIED_STATUSES)
        evidence_tier = "legacy-submitted"
        terminal_records_consume_slots = True

    occupied = sorted(
        row["worker_id"]
        for row in normalized
        if row["status"] in occupied_statuses
        or (
            schema == INVENTORY_SCHEMA_V2
            and row["status"] in TERMINAL_STATUSES
            and row["worker_id"] not in released_terminal_ids
        )
    )
    if len(occupied) > capacity:
        _issue(issues, label + ":occupied_exceeds_capacity")
    terminal_records = sorted(
        row["worker_id"] for row in normalized if row["status"] in TERMINAL_STATUSES
    )
    released_terminals = sorted(released_terminal_ids)
    unreleased_terminals = sorted(set(terminal_records) - released_terminal_ids)
    if schema == INVENTORY_SCHEMA_V2:
        terminal_records_consume_slots = bool(unreleased_terminals)
    capacity_authoritative = (
        schema == INVENTORY_SCHEMA_V2
        and not issues
        and evidence_tier == "runtime_observed"
        and authority_source == "host-signed-observer"
    )
    provenance = (
        dict(capacity_provenance)
        if capacity_authoritative and isinstance(capacity_provenance, Mapping)
        else {}
    )
    core = {
        "schema": "orch-dork/normalized-collaboration-inventory/v1",
        "status": "PASS" if not issues else "FAIL",
        "input_schema": schema,
        "root_thread_id": observed_root,
        "capacity": capacity,
        "max_concurrent_lanes": MAX_CONCURRENT_LANES,
        "capacity_basis": "instantaneous_occupancy",
        "cumulative_lane_limit": None,
        "root_counts_toward_lane_capacity": False,
        "retirement_supported": retirement_supported,
        "workers": normalized,
        "slot_accounting_mode": mode,
        "slot_accounting_evidence_tier": evidence_tier,
        "terminal_records_consume_slots": terminal_records_consume_slots,
        "terminal_record_worker_ids": terminal_records,
        "released_terminal_worker_ids": released_terminals,
        "unreleased_terminal_worker_ids": unreleased_terminals,
        "occupied_worker_ids": occupied,
        "occupied_slots": len(occupied),
        "free_slots": max(0, capacity - len(occupied)),
        "worker_reuse_permitted": False,
        "capacity_authoritative": capacity_authoritative,
        "capacity_claim_permitted": capacity_authoritative,
        "capacity_scope": (
            "authoritative" if capacity_authoritative else "advisory"
        ),
        "capacity_evidence_tier": (
            "runtime-observed" if capacity_authoritative else "submitted"
        ),
        "capacity_authority_source": (
            "host-signed-observer" if capacity_authoritative else "submitted"
        ),
        "capacity_adapter_sha256": (
            capacity_adapter_sha256 if capacity_authoritative else None
        ),
        "capacity_observation_sha256": (
            capacity_observation_sha256 if capacity_authoritative else None
        ),
        "capacity_signed_receipt_sha256": (
            provenance.get("signed_receipt_sha256")
        ),
        "capacity_signing_key_id": (
            provenance.get("signing_key_id")
        ),
        "capacity_trust_generation": (
            provenance.get("trust_generation")
        ),
        "issues": sorted(issues),
        "inventory_sha256": _sha(item),
        "slot_accounting_sha256": None if slot is None else _sha(slot),
    }
    return {**core, "report_sha256": _sha(core), "raw": item}


def evaluate_inventory(
    value: Any,
    *,
    root_thread_id: str | None = None,
    label: str = "inventory",
) -> dict[str, Any]:
    """Normalize submitted v1 or v2 capacity without promoting its tier."""

    return _evaluate_inventory(
        value,
        root_thread_id=root_thread_id,
        label=label,
        authority_source="submitted",
    )


def adapt_native_capacity_observation(
    value: Any,
    *,
    expected_root_thread_id: str | None = None,
    evaluation_time: datetime | str | None = None,
    trust_store: Any = None,
    replay_guard: Any = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Normalize one host-signed observation into authoritative v2 inventory.

    This is an adapter, not an observer. It never invents capacity and returns
    no authoritative inventory for a caller-produced SHA-256 self-seal.  The
    Ed25519 trust root and replay state come only from host-owned adapters.
    """

    issues: list[str] = []
    if evaluation_time is None:
        evaluated_now = datetime.now(timezone.utc)
    elif isinstance(evaluation_time, datetime):
        evaluated_now = (
            evaluation_time.astimezone(timezone.utc)
            if evaluation_time.tzinfo is not None
            else None
        )
    else:
        evaluated_now = _timestamp(evaluation_time)
    if evaluated_now is None:
        _issue(issues, "adapter:evaluation_time_invalid")

    submitted = dict(value) if isinstance(value, Mapping) else {}
    signed_report = observer_receipt.require_signed_payload(
        submitted,
        expected_kind="capacity-observation",
        expected_payload=(
            {"root_thread_id": expected_root_thread_id}
            if expected_root_thread_id is not None
            else {}
        ),
        evaluation_time=evaluated_now,
        trust_store=trust_store,
        replay_guard=replay_guard,
        environ=environ,
    )
    item = (
        dict(signed_report["payload"])
        if isinstance(signed_report.get("payload"), Mapping)
        else {}
    )
    for signature_issue in observer_receipt.signature_issue_codes(
        signed_report,
        required_code="observation:host_signature_required",
        status_prefix="observation:host_signature_",
        reason_prefix="observation:signature:",
    ):
        _issue(issues, signature_issue)
    provenance = observer_receipt.signing_provenance(signed_report)

    _exact(item, _NATIVE_KEYS, "observation", issues)
    if item.get("schema") != NATIVE_OBSERVATION_SCHEMA:
        _issue(issues, "observation:schema_invalid")
    if item.get("status") != "observed":
        _issue(issues, "observation:status_invalid")
    if not _text(item.get("observer_id")):
        _issue(issues, "observation:observer_id_invalid")
    if item.get("independent") is not True:
        _issue(issues, "observation:observer_not_independent")
    root_thread_id = item.get("root_thread_id")
    if not _text(root_thread_id):
        _issue(issues, "observation:root_identity_invalid")
    if (
        expected_root_thread_id is not None
        and root_thread_id != expected_root_thread_id
    ):
        _issue(issues, "observation:root_identity_mismatch")
    if item.get("observer_id") == root_thread_id:
        _issue(issues, "observation:observer_not_independent")
    capacity = item.get("capacity")
    if type(capacity) is not int or capacity < 0:
        _issue(issues, "observation:capacity_invalid")
    elif capacity > MAX_CONCURRENT_LANES:
        _issue(issues, "observation:capacity_exceeds_max_concurrent_lanes")
    if not isinstance(item.get("retirement_supported"), bool):
        _issue(issues, "observation:retirement_capability_invalid")
    if not isinstance(item.get("workers"), list):
        _issue(issues, "observation:workers_not_array")
    mode = item.get("slot_accounting_mode")
    if mode == RETAINED_UNTIL_SHUTDOWN:
        _issue(issues, "observation:retained_terminal_mode_removed")
        mode = ACTIVE_ONLY
    elif mode != ACTIVE_ONLY:
        _issue(issues, "observation:slot_accounting_mode_invalid")
        mode = ACTIVE_ONLY
    for field in ("surface_id", "source_pointer"):
        if not _text(item.get(field)):
            _issue(issues, f"observation:{field}_invalid")
    if not isinstance(item.get("source_sha256"), str) or _SHA256.fullmatch(
        item.get("source_sha256", "")
    ) is None:
        _issue(issues, "observation:source_sha256_invalid")
    receipt_evaluated = _timestamp(item.get("evaluated_at"))
    valid_until = _timestamp(item.get("valid_until"))
    if (
        evaluated_now is not None
        and receipt_evaluated is not None
        and receipt_evaluated > evaluated_now
    ):
        _issue(issues, "observation:evaluation_precedes_receipt")
    if (
        evaluated_now is not None
        and valid_until is not None
        and evaluated_now > valid_until
    ):
        _issue(issues, "observation:stale")
    supplied = item.get("observation_sha256")
    unsigned = dict(item)
    unsigned.pop("observation_sha256", None)
    if not isinstance(supplied, str) or _SHA256.fullmatch(supplied) is None:
        _issue(issues, "observation:observation_sha256_invalid")
    elif supplied != _sha(unsigned):
        _issue(issues, "observation:observation_sha256_mismatch")

    inventory = {
        "schema": INVENTORY_SCHEMA_V2,
        "root_thread_id": root_thread_id,
        "capacity": capacity,
        "retirement_supported": item.get("retirement_supported"),
        "workers": item.get("workers") if isinstance(item.get("workers"), list) else [],
        "slot_accounting": {
            "schema": SLOT_ACCOUNTING_SCHEMA,
            "mode": mode,
            "capacity_kind": "active_agents_excluding_root",
            "surface_id": item.get("surface_id"),
            "root_thread_id": root_thread_id,
            "occupied_statuses": sorted(ACTIVE_STATUSES),
            "terminal_records_consume_slots": False,
            "evidence_tier": "runtime_observed",
            "observed_at": item.get("observed_at"),
            "evaluated_at": item.get("evaluated_at"),
            "valid_until": item.get("valid_until"),
            "source_pointer": item.get("source_pointer"),
            "source_sha256": item.get("source_sha256"),
        },
    }
    normalized = _evaluate_inventory(
        inventory,
        root_thread_id=expected_root_thread_id,
        label="native_inventory",
        authority_source="host-signed-observer",
        capacity_observation_sha256=supplied,
        capacity_provenance=provenance,
        release_trust_store=trust_store,
        release_replay_guard=replay_guard,
        release_evaluation_time=evaluated_now,
        release_environ=environ,
    )
    issues.extend(normalized.get("issues", []))
    issues = sorted(set(issues))
    authoritative = not issues and normalized.get("capacity_authoritative") is True
    core = {
        "schema": NATIVE_ADAPTER_REPORT_SCHEMA,
        "status": "PASS" if authoritative else "FAIL",
        "issues": issues,
        "capacity_authoritative": authoritative,
        "capacity_claim_permitted": authoritative,
        "evidence_tier": (
            "runtime-observed" if authoritative else "submitted"
        ),
        "adapter_evaluated_at": (
            evaluated_now.isoformat().replace("+00:00", "Z")
            if evaluated_now is not None
            else None
        ),
        "observation_sha256": supplied if not issues else None,
        "signed_receipt_sha256": (
            provenance.get("signed_receipt_sha256") if authoritative else None
        ),
        "signing_key_id": (
            provenance.get("signing_key_id") if authoritative else None
        ),
        "trust_generation": (
            provenance.get("trust_generation") if authoritative else None
        ),
        "inventory": inventory if authoritative else None,
        "inventory_sha256": (
            normalized.get("inventory_sha256") if authoritative else None
        ),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "report_sha256": _sha(core)}


def _reseal_inventory_report(
    report: Mapping[str, Any], *, raw: Mapping[str, Any]
) -> dict[str, Any]:
    core = {
        key: value
        for key, value in report.items()
        if key not in {"raw", "report_sha256"}
    }
    return {**core, "report_sha256": _sha(core), "raw": dict(raw)}


def evaluate_capacity_evidence(
    value: Any,
    *,
    root_thread_id: str | None = None,
    label: str = "inventory",
    evaluation_time: datetime | str | None = None,
    trust_store: Any = None,
    replay_guard: Any = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Normalize submitted inventory or adapt one native observer receipt.

    Raw v1/v2 inventories always remain advisory. Only this seam can attach
    adapter and observation bindings to an authoritative normalized report.
    """

    item = dict(value) if isinstance(value, Mapping) else {}
    if item.get("schema") not in {
        NATIVE_OBSERVATION_SCHEMA,
        observer_receipt.ENVELOPE_SCHEMA,
    }:
        return evaluate_inventory(
            value, root_thread_id=root_thread_id, label=label
        )

    adapted = adapt_native_capacity_observation(
        item,
        expected_root_thread_id=root_thread_id,
        evaluation_time=evaluation_time,
        trust_store=trust_store,
        replay_guard=replay_guard,
        environ=environ,
    )
    if adapted.get("status") == "PASS" and isinstance(
        adapted.get("inventory"), Mapping
    ):
        report = _evaluate_inventory(
            adapted["inventory"],
            root_thread_id=root_thread_id,
            label=label,
            authority_source="host-signed-observer",
            capacity_adapter_sha256=adapted.get("report_sha256"),
            capacity_observation_sha256=adapted.get("observation_sha256"),
            capacity_provenance={
                "signed_receipt_sha256": adapted.get(
                    "signed_receipt_sha256"
                ),
                "signing_key_id": adapted.get("signing_key_id"),
                "trust_generation": adapted.get("trust_generation"),
            },
            release_trust_store=trust_store,
            release_replay_guard=replay_guard,
            release_evaluation_time=adapted.get("adapter_evaluated_at"),
            release_environ=environ,
        )
        return _reseal_inventory_report(report, raw=item)

    signed_envelope = item.get("schema") == observer_receipt.ENVELOPE_SCHEMA
    payload = {} if signed_envelope else item
    fallback = {
        "schema": INVENTORY_SCHEMA_V1,
        "root_thread_id": payload.get("root_thread_id"),
        "capacity": payload.get("capacity"),
        "retirement_supported": payload.get("retirement_supported"),
        "workers": payload.get("workers"),
    }
    report = evaluate_inventory(
        fallback, root_thread_id=root_thread_id, label=label
    )
    report.update(
        {
            "status": "FAIL",
            "issues": sorted(
                set(report.get("issues", [])) | set(adapted.get("issues", []))
            ),
            "input_schema": item.get("schema"),
            "capacity_authoritative": False,
            "capacity_claim_permitted": False,
            "capacity_scope": "advisory",
            "capacity_evidence_tier": "submitted",
            "capacity_authority_source": "invalid-native-observation",
            "capacity_adapter_sha256": adapted.get("report_sha256"),
            "capacity_observation_sha256": None,
            "capacity_signed_receipt_sha256": None,
            "capacity_signing_key_id": None,
            "capacity_trust_generation": None,
        }
    )
    raw = (
        {
            "schema": observer_receipt.ENVELOPE_SCHEMA,
            "signed_receipt_sha256": adapted.get("signed_receipt_sha256"),
        }
        if signed_envelope
        else item
    )
    return _reseal_inventory_report(report, raw=raw)


__all__ = [
    "ACTIVE_ONLY", "ACTIVE_STATUSES", "INVENTORY_SCHEMA_V1",
    "INVENTORY_SCHEMA_V2", "RETAINED_UNTIL_SHUTDOWN",
    "MAX_CONCURRENT_LANES",
    "NATIVE_ADAPTER_REPORT_SCHEMA", "NATIVE_OBSERVATION_SCHEMA",
    "RELEASE_EVIDENCE_SCHEMA", "SLOT_ACCOUNTING_SCHEMA", "TERMINAL_STATUSES",
    "adapt_native_capacity_observation", "evaluate_capacity_evidence",
    "evaluate_inventory", "capacity_authority_projection",
]
