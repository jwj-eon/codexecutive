#!/usr/bin/env python3
"""Provider-free worker retirement and one-wave root policy.

This evaluator consumes runtime observations but never retires a worker,
creates a task, transfers a lease, launches a worker, or calls a model.
Authoritative active-only inventory releases completed, failed, or cancelled
workers only when the host-signed observation also carries exact lane/run/route
cleanup evidence with no owned descendants; identities stay nonreusable. A
caller-submitted terminal status is not proof of release and remains occupied.
Unknown cleanup remains fail-closed.
"""

from __future__ import annotations

from datetime import datetime
import importlib.util
from pathlib import Path
from typing import Any, Mapping


PROGRAM_SCHEMA = "orch-dork/worker-lifecycle-program/v1"
REPORT_SCHEMA = "orch-dork/worker-lifecycle-report/v1"
CAPABILITY_SCHEMA = "orch-dork/worker-retirement-capability/v1"
OBSERVATION_SCHEMA = "orch-dork/capacity-observation/v1"
RETIREMENT_SCHEMA = "orch-dork/worker-retirement/v1"
ONE_WAVE_SCHEMA = "orch-dork/one-wave-root/v1"
INVENTORY_SCHEMA = "orch-dork/collaboration-inventory/v1"
INVENTORY_SCHEMA_V2 = "orch-dork/collaboration-inventory/v2"
SLOT_ACCOUNTING_SCHEMA = "orch-dork/slot-accounting-capability/v1"

_TERMINAL = frozenset(
    {"completed", "failed", "cancelled", "errored", "interrupted"}
)
_OCCUPIED = frozenset(
    {"running", "completed", "failed", "cancelled", "errored", "interrupted", "pending_init"}
)
_WORKER_STATUSES = _OCCUPIED | {"shutdown", "not_found"}


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ImportError:  # pragma: no cover - unusual import loaders.
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


task_creation = _load_sibling("orch_dork_task_creation")
efficiency_governor = _load_sibling("orch_dork_efficiency_governor")
capacity_inventory = _load_sibling("orch_dork_capacity_inventory")
evidence_core = _load_sibling("orch_dork_evidence_core")
_SHA256 = evidence_core.SHA256_PATTERN


_sha = evidence_core.digest


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


_timestamp = evidence_core.instant


_issue = evidence_core.add_issue


def _exact(value: Any, keys: set[str], label: str, issues: list[str]) -> bool:
    return evidence_core.closed(value, keys, label, issues) is not None


def _capability(value: Any, issues: list[str]) -> dict[str, Any]:
    _exact(
        value,
        {
            "schema",
            "status",
            "operation",
            "evidence_tier",
            "observed_at",
            "source_pointer",
        },
        "capability",
        issues,
    )
    result = dict(value) if isinstance(value, Mapping) else {}
    if result.get("schema") != CAPABILITY_SCHEMA:
        _issue(issues, "capability:schema_invalid")
    if result.get("status") not in {"supported", "unsupported", "unknown"}:
        _issue(issues, "capability:status_invalid")
    if result.get("operation") != "retire_worker":
        _issue(issues, "capability:operation_invalid")
    if result.get("evidence_tier") != "runtime_observed":
        _issue(issues, "capability:not_runtime_observed")
    if _timestamp(result.get("observed_at")) is None:
        _issue(issues, "capability:observed_at_invalid")
    if not _text(result.get("source_pointer")):
        _issue(issues, "capability:source_pointer_invalid")
    return result


def _inventory(
    value: Any,
    root_task_id: str,
    label: str,
    issues: list[str],
    *,
    evaluation_time: datetime | None = None,
) -> dict[str, Any]:
    if capacity_inventory is None:
        _issue(issues, label + ":capacity_inventory_unavailable")
        return {
            "raw": {},
            "capacity": 0,
            "workers": [],
            "occupied_worker_ids": [],
            "occupied_slots": 0,
            "free_slots": 0,
            "inventory_sha256": _sha({}),
            **evidence_core.capacity_authority_projection(None),
            "worker_reuse_permitted": False,
        }
    report = capacity_inventory.evaluate_capacity_evidence(
        value,
        root_thread_id=root_task_id,
        label=label + ".inventory",
        evaluation_time=evaluation_time,
    )
    for issue in report.get("issues", []):
        _issue(issues, issue)
    return report


def _observation(
    value: Any, root_task_id: str, label: str, issues: list[str]
) -> dict[str, Any]:
    _exact(
        value,
        {
            "schema",
            "status",
            "observation_id",
            "observed_at",
            "source_pointer",
            "inventory",
        },
        label,
        issues,
    )
    item = dict(value) if isinstance(value, Mapping) else {}
    if item.get("schema") != OBSERVATION_SCHEMA:
        _issue(issues, label + ":schema_invalid")
    if item.get("status") not in {"observed", "partial", "ambiguous"}:
        _issue(issues, label + ":status_invalid")
    if not _text(item.get("observation_id")):
        _issue(issues, label + ":observation_id_invalid")
    observed_at = _timestamp(item.get("observed_at"))
    if observed_at is None:
        _issue(issues, label + ":observed_at_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, label + ":source_pointer_invalid")
    inventory = _inventory(
        item.get("inventory"),
        root_task_id,
        label,
        issues,
        evaluation_time=observed_at,
    )
    # Preserve the observation lifecycle state; the nested normalized
    # inventory has its own validation status and must not overwrite it.
    return {**inventory, **item, "parsed_at": observed_at}


def _retirement(value: Any, root_task_id: str, issues: list[str]) -> dict[str, Any]:
    _exact(
        value,
        {
            "schema",
            "worker",
            "request",
            "receipt",
            "inventory_before_release",
            "inventory_after_release",
        },
        "retirement",
        issues,
    )
    item = dict(value) if isinstance(value, Mapping) else {}
    if item.get("schema") != RETIREMENT_SCHEMA:
        _issue(issues, "retirement:schema_invalid")
    worker = item.get("worker")
    _exact(
        worker,
        {
            "worker_id",
            "terminal_status",
            "owned_live_processes",
            "pending_deliveries",
            "source_pointer",
        },
        "retirement.worker",
        issues,
    )
    worker_value = dict(worker) if isinstance(worker, Mapping) else {}
    if not _text(worker_value.get("worker_id")):
        _issue(issues, "retirement.worker:identity_invalid")
    if worker_value.get("terminal_status") not in _TERMINAL:
        _issue(issues, "retirement.worker:not_terminal")
    for field in ("owned_live_processes", "pending_deliveries"):
        if type(worker_value.get(field)) is not int or worker_value[field] < 0:
            _issue(issues, "retirement.worker:" + field + "_invalid")
    if not _text(worker_value.get("source_pointer")):
        _issue(issues, "retirement.worker:source_pointer_invalid")

    request = item.get("request")
    _exact(
        request,
        {
            "status",
            "request_id",
            "worker_id",
            "operation",
            "requested_at",
            "source_pointer",
        },
        "retirement.request",
        issues,
    )
    request_value = dict(request) if isinstance(request, Mapping) else {}
    if request_value.get("status") not in {"not_requested", "issued"}:
        _issue(issues, "retirement.request:status_invalid")
    if request_value.get("status") == "issued":
        if not _text(request_value.get("request_id")):
            _issue(issues, "retirement.request:id_invalid")
        if request_value.get("worker_id") != worker_value.get("worker_id"):
            _issue(issues, "retirement.request:worker_identity_mismatch")
        if request_value.get("operation") != "retire_worker":
            _issue(issues, "retirement.request:operation_invalid")
        if _timestamp(request_value.get("requested_at")) is None:
            _issue(issues, "retirement.request:requested_at_invalid")
        if not _text(request_value.get("source_pointer")):
            _issue(issues, "retirement.request:source_pointer_invalid")
    elif any(
        request_value.get(field) is not None
        for field in set(request_value) - {"status"}
    ):
        _issue(issues, "retirement.request:not_requested_has_values")

    receipt = item.get("receipt")
    _exact(
        receipt,
        {"status", "request_id", "worker_id", "observed_at", "source_pointer"},
        "retirement.receipt",
        issues,
    )
    receipt_value = dict(receipt) if isinstance(receipt, Mapping) else {}
    if receipt_value.get("status") not in {
        "not_observed",
        "succeeded",
        "failed",
        "ambiguous",
    }:
        _issue(issues, "retirement.receipt:status_invalid")
    if receipt_value.get("status") != "not_observed":
        if receipt_value.get("request_id") != request_value.get("request_id"):
            _issue(issues, "retirement.receipt:request_identity_mismatch")
        if receipt_value.get("worker_id") != worker_value.get("worker_id"):
            _issue(issues, "retirement.receipt:worker_identity_mismatch")
        if _timestamp(receipt_value.get("observed_at")) is None:
            _issue(issues, "retirement.receipt:observed_at_invalid")
        if not _text(receipt_value.get("source_pointer")):
            _issue(issues, "retirement.receipt:source_pointer_invalid")
    elif any(
        receipt_value.get(field) is not None
        for field in set(receipt_value) - {"status"}
    ):
        _issue(issues, "retirement.receipt:not_observed_has_values")

    before = _observation(
        item.get("inventory_before_release"),
        root_task_id,
        "retirement.inventory_before_release",
        issues,
    )
    after = _observation(
        item.get("inventory_after_release"),
        root_task_id,
        "retirement.inventory_after_release",
        issues,
    )
    return {
        "worker": worker_value,
        "request": request_value,
        "receipt": receipt_value,
        "before": before,
        "after": after,
    }


def _one_wave(value: Any, root_task_id: str, issues: list[str]) -> dict[str, Any]:
    _exact(
        value,
        {
            "schema",
            "root_task_id",
            "one_wave_only",
            "declared_before_freeze",
            "planned_worker_ids",
            "later_wave_required",
            "rollover_scheduled",
            "rollover_checkpoint_sha256",
            "source_pointer",
        },
        "one_wave_plan",
        issues,
    )
    item = dict(value) if isinstance(value, Mapping) else {}
    if item.get("schema") != ONE_WAVE_SCHEMA:
        _issue(issues, "one_wave_plan:schema_invalid")
    if item.get("root_task_id") != root_task_id:
        _issue(issues, "one_wave_plan:root_identity_mismatch")
    if (
        item.get("one_wave_only") is not True
        or item.get("declared_before_freeze") is not True
    ):
        _issue(issues, "one_wave_plan:not_declared_before_freeze")
    planned = item.get("planned_worker_ids")
    if not isinstance(planned, list) or any(
        not _text(worker_id) for worker_id in planned
    ):
        _issue(issues, "one_wave_plan:planned_worker_ids_invalid")
        planned = []
    if len(planned) != len(set(planned)):
        _issue(issues, "one_wave_plan:planned_worker_ids_duplicate")
    if not isinstance(item.get("later_wave_required"), bool):
        _issue(issues, "one_wave_plan:later_wave_required_invalid")
    if not isinstance(item.get("rollover_scheduled"), bool):
        _issue(issues, "one_wave_plan:rollover_scheduled_invalid")
    checkpoint_sha = item.get("rollover_checkpoint_sha256")
    if item.get("later_wave_required") is True:
        if item.get("rollover_scheduled") is not True:
            _issue(issues, "one_wave_plan:rollover_not_scheduled")
        if (
            not isinstance(checkpoint_sha, str)
            or _SHA256.fullmatch(checkpoint_sha) is None
        ):
            _issue(issues, "one_wave_plan:checkpoint_sha256_invalid")
    elif item.get("rollover_scheduled") is not False or checkpoint_sha is not None:
        _issue(issues, "one_wave_plan:unexpected_rollover")
    if not _text(item.get("source_pointer")):
        _issue(issues, "one_wave_plan:source_pointer_invalid")
    return {**item, "planned_worker_ids": planned}


def _same_inventory(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    return first.get("inventory_sha256") == second.get("inventory_sha256")


def _fresh(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    first_time = first.get("parsed_at")
    second_time = second.get("parsed_at")
    return bool(
        first.get("status") == "observed"
        and second.get("status") == "observed"
        and first.get("observation_id") != second.get("observation_id")
        and first.get("source_pointer") != second.get("source_pointer")
        and isinstance(first_time, datetime)
        and isinstance(second_time, datetime)
        and first_time < second_time
    )


def _retirement_proven(retirement: Mapping[str, Any]) -> bool:
    worker = retirement["worker"]
    worker_id = worker.get("worker_id")
    before = retirement["before"]
    after = retirement["after"]
    before_rows = {row["worker_id"]: row for row in before.get("workers", [])}
    after_rows = {row["worker_id"]: row for row in after.get("workers", [])}
    before_worker = before_rows.get(worker_id)
    after_worker = after_rows.get(worker_id)
    other_before = {
        key: value for key, value in before_rows.items() if key != worker_id
    }
    other_after = {
        key: value for key, value in after_rows.items() if key != worker_id
    }
    return bool(
        before.get("status") == "observed"
        and after.get("status") == "observed"
        and before_worker
        and before_worker.get("status") == worker.get("terminal_status")
        and (
            after_worker is None
            or after_worker.get("status") in {"shutdown", "not_found"}
        )
        and other_before == other_after
        and before.get("capacity") == after.get("capacity")
        and after.get("free_slots") == before.get("free_slots", 0) + 1
        and _fresh(before, after)
    )


def evaluate_worker_lifecycle(program: Any) -> dict[str, Any]:
    """Evaluate one worker-capacity transition without performing it."""

    issues: list[str] = []
    value = dict(program) if isinstance(program, Mapping) else {}
    _exact(
        value,
        {
            "schema",
            "lifecycle_id",
            "root_task_id",
            "required_slots",
            "capability",
            "capacity_before_freeze",
            "capacity_before_spawn",
            "retirement",
            "one_wave_plan",
            "task_creation_program",
            "rollover_program",
        },
        "program",
        issues,
    )
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    if not _text(value.get("lifecycle_id")):
        _issue(issues, "program:lifecycle_id_invalid")
    root_task_id = value.get("root_task_id")
    if not _text(root_task_id):
        _issue(issues, "program:root_task_id_invalid")
        root_task_id = "invalid-root"
    required_slots = value.get("required_slots")
    if type(required_slots) is not int or required_slots < 1:
        _issue(issues, "program:required_slots_invalid")
        required_slots = 1

    capability = _capability(value.get("capability"), issues)
    before_freeze = _observation(
        value.get("capacity_before_freeze"),
        root_task_id,
        "capacity_before_freeze",
        issues,
    )
    before_spawn = _observation(
        value.get("capacity_before_spawn"),
        root_task_id,
        "capacity_before_spawn",
        issues,
    )
    expected_supported = capability.get("status") == "supported"
    for label, observation in (
        ("capacity_before_freeze", before_freeze),
        ("capacity_before_spawn", before_spawn),
    ):
        if (
            observation.get("retirement_supported") is not expected_supported
        ):
            _issue(issues, label + ":capability_mismatch")

    retirement = None
    if value.get("retirement") is not None:
        retirement = _retirement(value.get("retirement"), root_task_id, issues)
        for label, observation in (
            ("inventory_before_release", retirement["before"]),
            ("inventory_after_release", retirement["after"]),
        ):
            if (
                observation.get("retirement_supported")
                is not expected_supported
            ):
                _issue(issues, "retirement." + label + ":capability_mismatch")

    one_wave = None
    if value.get("one_wave_plan") is not None:
        one_wave = _one_wave(value.get("one_wave_plan"), root_task_id, issues)

    observations_complete = (
        before_freeze.get("status") == "observed"
        and before_spawn.get("status") == "observed"
    )
    inventories_same = _same_inventory(before_freeze, before_spawn)
    observations_fresh = _fresh(before_freeze, before_spawn)
    effective_free_slots = before_spawn.get("free_slots", 0)
    outcome = "CAPACITY_READY"
    retired_worker_id = None
    task_report = None
    rollover_report = None

    if issues:
        outcome = "REFUSED"
    elif not observations_complete:
        outcome = "INVENTORY_UNCERTAIN_STOP_UNFROZEN"
    elif not inventories_same:
        outcome = "INVENTORY_CHANGED_STOP_UNFROZEN"
    elif not observations_fresh:
        outcome = "STALE_INVENTORY_STOP_UNFROZEN"
    elif before_spawn.get("slot_accounting_mode") == "active_only":
        if effective_free_slots < required_slots:
            outcome = "CAPACITY_UNAVAILABLE"
        else:
            outcome = "ACTIVE_ONLY_CAPACITY_READY"
    elif capability.get("status") == "supported":
        if retirement is None:
            terminal_occupants = [
                row
                for row in before_freeze.get("workers", [])
                if row.get("status") in _TERMINAL
            ]
            if effective_free_slots < required_slots and terminal_occupants:
                outcome = "RETIREMENT_REQUIRED"
            elif effective_free_slots < required_slots:
                outcome = "CAPACITY_UNAVAILABLE"
        elif (
            retirement["worker"].get("owned_live_processes") != 0
            or retirement["worker"].get("pending_deliveries") != 0
        ):
            outcome = "RETIREMENT_NOT_SAFE"
        elif retirement["request"].get("status") != "issued":
            outcome = "RETIREMENT_REQUEST_REQUIRED"
        elif retirement["receipt"].get("status") == "not_observed":
            outcome = "RETIREMENT_RECEIPT_PENDING"
        elif retirement["receipt"].get("status") in {"failed", "ambiguous"}:
            outcome = "RETIREMENT_FAILED_STOP"
        elif not _retirement_proven(retirement):
            outcome = "RETIREMENT_NOT_PROVEN"
        elif not _same_inventory(retirement["after"], before_freeze) or not _fresh(
            retirement["after"], before_freeze
        ):
            outcome = "POST_RETIREMENT_INVENTORY_STALE"
        elif effective_free_slots < required_slots:
            outcome = "CAPACITY_UNAVAILABLE"
        else:
            outcome = "SLOT_RETIRED"
            retired_worker_id = retirement["worker"].get("worker_id")
    else:
        if retirement is not None:
            _issue(issues, "retirement:capability_not_supported")
            outcome = "REFUSED"
        elif one_wave is None:
            outcome = "ONE_WAVE_DECLARATION_REQUIRED"
        elif len(one_wave["planned_worker_ids"]) > effective_free_slots:
            outcome = "ONE_WAVE_EXCEEDS_CAPACITY_STOP_UNFROZEN"
        elif one_wave.get("later_wave_required") is not (
            required_slots > len(one_wave["planned_worker_ids"])
        ):
            _issue(issues, "one_wave_plan:later_wave_requirement_mismatch")
            outcome = "REFUSED"
        elif not one_wave.get("later_wave_required"):
            if len(one_wave["planned_worker_ids"]) != required_slots:
                _issue(issues, "one_wave_plan:planned_count_mismatch")
                outcome = "REFUSED"
            else:
                outcome = "ONE_WAVE_READY"
        elif (
            value.get("task_creation_program") is None
            or value.get("rollover_program") is None
        ):
            outcome = "ROLLOVER_PREPARATION_REQUIRED"
        elif task_creation is None or efficiency_governor is None:
            _issue(issues, "rollover:evaluator_unavailable")
            outcome = "REFUSED"
        else:
            task_report = task_creation.evaluate_task_creation(
                value["task_creation_program"]
            )
            rollover_report = efficiency_governor.evaluate_root_rollover(
                value["rollover_program"]
            )
            if task_report.get("status") != "PASS":
                _issue(issues, "rollover:task_creation_intent_invalid")
                outcome = "REFUSED"
            elif task_report.get("outcome") == "DUPLICATE_QUARANTINE_REQUIRED":
                outcome = "DUPLICATE_SUCCESSOR_QUARANTINE_REQUIRED"
            else:
                intent = value["task_creation_program"].get("intent", {})
                checkpoint = value["rollover_program"].get("checkpoint", {})
                binding_ok = all(
                    (
                        intent.get("parent_task_id") == root_task_id,
                        intent.get("task_role") == "read-only-successor",
                        intent.get("prompt_marker") == checkpoint.get("marker"),
                        intent.get("project_id")
                        == checkpoint.get("routing", {}).get("project_id"),
                        intent.get("initial_cwd")
                        == checkpoint.get("routing", {}).get("cwd"),
                        intent.get("host")
                        == checkpoint.get("routing", {}).get("host"),
                        one_wave.get("rollover_checkpoint_sha256")
                        == rollover_report.get("checkpoint_sha256"),
                    )
                )
                if not binding_ok:
                    _issue(issues, "rollover:identity_binding_mismatch")
                    outcome = "REFUSED"
                elif (
                    task_report.get("outcome") == "READY_FOR_SINGLE_CALL"
                    and rollover_report.get("status") == "READY_TO_CREATE"
                ):
                    outcome = "ROLLOVER_CREATION_READY"
                elif task_report.get("outcome") != "READ_ONLY_CANDIDATE":
                    outcome = "ROLLOVER_CREATION_PENDING"
                elif (
                    task_report.get("candidate_task_id")
                    != rollover_report.get("successor_thread_id")
                ):
                    _issue(issues, "rollover:successor_identity_mismatch")
                    outcome = "REFUSED"
                elif (
                    rollover_report.get("status") == "ROLLOVER_COMPLETE"
                    and rollover_report.get("successor_verified") is True
                    and rollover_report.get("predecessor_terminal") is True
                ):
                    outcome = "ROLLOVER_COMPLETE"
                else:
                    outcome = "ROLLOVER_PENDING"

    issues = sorted(set(issues))
    if issues:
        outcome = "REFUSED"
    capacity_ready = outcome in {
        "CAPACITY_READY",
        "ACTIVE_ONLY_CAPACITY_READY",
        "SLOT_RETIRED",
        "ONE_WAVE_READY",
    }
    capacity_projection = evidence_core.capacity_authority_projection(
        before_spawn
    )
    core = {
        "schema": REPORT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "outcome": outcome,
        "lifecycle_id": value.get("lifecycle_id"),
        "root_task_id": root_task_id,
        "retirement_capability": capability.get("status"),
        **capacity_projection,
        "terminal_record_worker_ids": before_spawn.get(
            "terminal_record_worker_ids", []
        ),
        "unknown_capability_uses_unsupported_branch": (
            capability.get("status") == "unknown"
        ),
        "required_slots": required_slots,
        "free_slots": effective_free_slots,
        "capacity_before_freeze_sha256": before_freeze.get("inventory_sha256"),
        "capacity_before_spawn_sha256": before_spawn.get("inventory_sha256"),
        "fresh_capacity_pair": (
            observations_complete and inventories_same and observations_fresh
        ),
        "retired_worker_id": retired_worker_id,
        "one_wave_only": bool(one_wave and one_wave.get("one_wave_only")),
        "planned_worker_ids": (
            [] if one_wave is None else one_wave["planned_worker_ids"]
        ),
        "freeze_permitted": capacity_ready,
        "spawn_permitted": capacity_ready,
        "plan_must_remain_unfrozen": not capacity_ready,
        "later_wave_blocked_until_rollover": bool(
            one_wave
            and one_wave.get("later_wave_required")
            and outcome != "ROLLOVER_COMPLETE"
        ),
        "task_creation_outcome": (
            None if task_report is None else task_report.get("outcome")
        ),
        "rollover_status": (
            None if rollover_report is None else rollover_report.get("status")
        ),
        "replacement_permitted": False,
        "worker_reuse_permitted": False,
        "plan_shrink_permitted": False,
        "root_implementation_fallback_permitted": False,
        "second_creation_call_permitted": False,
        "live_worker_retirements": 0,
        "live_task_operations": 0,
        "workers_launched": 0,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "issues": issues,
    }
    return {**core, "report_sha256": _sha(core)}


def issue33_capacity_fixture() -> dict[str, Any]:
    """Immutable `0 < 3` regression: completed still occupies capacity."""

    return {
        "fixture": "issue-33-capacity-0-lt-3",
        "available_slots": 0,
        "required_slots": 3,
        "completed_workers_are_retired": False,
        "expected_next_state": "RETIREMENT_OR_ONE_WAVE_ROLLOVER_REQUIRED",
        "source_pointer": "historical:issue33-capacity-admission",
    }


def issue17_stale_worker_fixture() -> dict[str, Any]:
    """Immutable regression: a completed stale worker is never reusable."""

    return {
        "fixture": "issue-17-stale-worker-reuse",
        "worker_status": "completed",
        "release_receipt": "not_observed",
        "fresh_inventory": False,
        "qualified": False,
        "worker_reuse_permitted": False,
        "source_pointer": "historical:issue17-terminal-failure",
    }


__all__ = [
    "CAPABILITY_SCHEMA",
    "INVENTORY_SCHEMA",
    "INVENTORY_SCHEMA_V2",
    "SLOT_ACCOUNTING_SCHEMA",
    "OBSERVATION_SCHEMA",
    "ONE_WAVE_SCHEMA",
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "RETIREMENT_SCHEMA",
    "evaluate_worker_lifecycle",
    "issue17_stale_worker_fixture",
    "issue33_capacity_fixture",
]
