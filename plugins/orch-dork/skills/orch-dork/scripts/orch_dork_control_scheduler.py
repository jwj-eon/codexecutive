#!/usr/bin/env python3
"""Provider-free multidimensional scheduler arithmetic for Control Tower."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Any, Mapping

import orch_dork_shared_capacity as shared_capacity


CAPACITY_SCHEMA = "orch-dork/control-scheduler-capacity/v1"
RESOURCE_SCHEMA = "orch-dork/control-scheduler-resources/v1"
RESERVATION_SCHEMA = "orch-dork/control-scheduler-reservation/v1"
MAX_CONCURRENT_LANES = shared_capacity.MAX_CONCURRENT_LANES

RESOURCE_FIELDS = (
    "logical_runs",
    "live_sessions",
    "gpu_memory_mib",
    "process_slots",
    "integration_slots",
    "tokens",
    "context_tokens",
    "hosted_calls",
    "wall_time_ms",
)
_CAPACITY_FIELDS = frozenset({"schema", *RESOURCE_FIELDS})
_RESOURCE_FIELDS = frozenset({"schema", *RESOURCE_FIELDS})
_RESERVATION_FIELDS = frozenset(
    {
        "schema",
        "reservation_id",
        "run_id",
        "resources",
        "intent_sha256",
        "issued_at_ms",
        "expires_at_ms",
        "capacity_sha256",
        "reservation_sha256",
    }
)
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,127}\Z")


class SchedulerContractError(ValueError):
    """The scheduler input cannot be interpreted without widening it."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _vector(value: Any, *, schema: str, fields: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SchedulerContractError("scheduler_vector_contract_invalid")
    if value.get("schema") != schema:
        raise SchedulerContractError("scheduler_vector_schema_invalid")
    result = {"schema": schema}
    for field in RESOURCE_FIELDS:
        item = value.get(field)
        if type(item) is not int or item < 0:
            raise SchedulerContractError("scheduler_vector_value_invalid:" + field)
        result[field] = item
    return result


def validate_capacity(value: Any) -> dict[str, Any]:
    """Return one canonical closed capacity vector or fail closed."""

    canonical = _vector(value, schema=CAPACITY_SCHEMA, fields=_CAPACITY_FIELDS)
    if canonical["logical_runs"] < 1:
        raise SchedulerContractError("scheduler_capacity_logical_runs_empty")
    if canonical["live_sessions"] > MAX_CONCURRENT_LANES:
        raise SchedulerContractError(
            "scheduler_capacity_live_sessions_exceeds_max_concurrent_lanes"
        )
    if canonical["hosted_calls"] != 0:
        raise SchedulerContractError("scheduler_capacity_hosted_calls_forbidden")
    core = {**canonical, "provider_free": True, "hosted_model_calls": 0}
    return {**core, "capacity_sha256": sha256(core)}


def capacity_vector(value: Mapping[str, Any]) -> dict[str, Any]:
    """Project a validated capacity report back to its closed input vector."""

    raw = {"schema": value.get("schema")}
    raw.update({field: value.get(field) for field in RESOURCE_FIELDS})
    return _vector(raw, schema=CAPACITY_SCHEMA, fields=_CAPACITY_FIELDS)


def validate_resources(value: Any) -> dict[str, Any]:
    return _vector(value, schema=RESOURCE_SCHEMA, fields=_RESOURCE_FIELDS)


def validate_reservation(value: Any) -> dict[str, Any]:
    """Return one exact sealed reservation or fail closed."""

    if not isinstance(value, Mapping) or set(value) != _RESERVATION_FIELDS:
        raise SchedulerContractError("scheduler_reservation_contract_invalid")
    if value.get("schema") != RESERVATION_SCHEMA:
        raise SchedulerContractError("scheduler_reservation_schema_invalid")
    run_id = value.get("run_id")
    if not isinstance(run_id, str) or _IDENTIFIER.fullmatch(run_id) is None:
        raise SchedulerContractError("scheduler_reservation_run_id_invalid")
    for field in (
        "reservation_id",
        "intent_sha256",
        "capacity_sha256",
        "reservation_sha256",
    ):
        if not isinstance(value.get(field), str) or _SHA256.fullmatch(
            value[field]
        ) is None:
            raise SchedulerContractError(
                "scheduler_reservation_digest_invalid:" + field
            )
    issued = value.get("issued_at_ms")
    expires = value.get("expires_at_ms")
    if (
        type(issued) is not int
        or type(expires) is not int
        or issued < 0
        or expires < issued
    ):
        raise SchedulerContractError("scheduler_reservation_time_invalid")
    core = {
        "schema": RESERVATION_SCHEMA,
        "reservation_id": value["reservation_id"],
        "run_id": run_id,
        "resources": validate_resources(value.get("resources")),
        "intent_sha256": value["intent_sha256"],
        "issued_at_ms": issued,
        "expires_at_ms": expires,
        "capacity_sha256": value["capacity_sha256"],
    }
    if value["reservation_sha256"] != sha256(core):
        raise SchedulerContractError("scheduler_reservation_seal_invalid")
    return {**core, "reservation_sha256": value["reservation_sha256"]}


def zero_resources() -> dict[str, Any]:
    return {"schema": RESOURCE_SCHEMA, **{field: 0 for field in RESOURCE_FIELDS}}


def add_resources(left: Mapping[str, Any], right: Mapping[str, Any]) -> dict[str, Any]:
    first = validate_resources(left)
    second = validate_resources(right)
    return {
        "schema": RESOURCE_SCHEMA,
        **{field: first[field] + second[field] for field in RESOURCE_FIELDS},
    }


def fits(resources: Mapping[str, Any], capacity: Mapping[str, Any]) -> bool:
    requested = validate_resources(resources)
    available = capacity_vector(capacity)
    return all(requested[field] <= available[field] for field in RESOURCE_FIELDS)


def reservation_resources(
    task_brief: Mapping[str, Any],
    capability: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive the exact direct-node reservation from bound preparation data."""

    budgets = task_brief.get("budgets")
    resources = capability.get("resources")
    if not isinstance(budgets, Mapping) or not isinstance(resources, Mapping):
        raise SchedulerContractError("scheduler_reservation_basis_invalid")
    values = {
        "schema": RESOURCE_SCHEMA,
        "logical_runs": 1,
        "live_sessions": 1,
        "gpu_memory_mib": resources.get("gpu_memory_mib"),
        "process_slots": resources.get("process_slots"),
        "integration_slots": resources.get("integration_slots"),
        "tokens": (
            budgets.get("context_tokens", 0)
            + budgets.get("output_tokens", 0)
            + budgets.get("handoff_tokens", 0)
        ),
        "context_tokens": budgets.get("context_tokens"),
        "hosted_calls": 0,
        "wall_time_ms": budgets.get("wall_time_ms"),
    }
    return validate_resources(values)


def choose(
    *,
    capacity: Mapping[str, Any],
    active: list[Mapping[str, Any]],
    candidates: list[Mapping[str, Any]],
    max_dispatches: int,
) -> dict[str, Any]:
    """Select a deterministic fair feasible prefix without mutating state."""

    available = capacity_vector(capacity)
    if (
        type(max_dispatches) is not int
        or not 1 <= max_dispatches <= MAX_CONCURRENT_LANES
    ):
        raise SchedulerContractError("scheduler_max_dispatches_invalid")
    usage = zero_resources()
    for record in active:
        usage = add_resources(usage, record.get("resources"))
    if not fits(usage, available):
        raise SchedulerContractError("scheduler_active_overcommit")

    normalized = []
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            raise SchedulerContractError("scheduler_candidate_invalid")
        run_id = candidate.get("run_id")
        dispatch_count = candidate.get("dispatch_count")
        if not isinstance(run_id, str) or not run_id:
            raise SchedulerContractError("scheduler_candidate_run_id_invalid")
        if type(dispatch_count) is not int or dispatch_count < 0:
            raise SchedulerContractError("scheduler_candidate_count_invalid")
        normalized.append(
            {
                "run_id": run_id,
                "dispatch_count": dispatch_count,
                "resources": validate_resources(candidate.get("resources")),
                "intent": deepcopy(candidate.get("intent")),
            }
        )
    normalized.sort(key=lambda item: (item["dispatch_count"], item["run_id"]))

    selected = []
    waiting = []
    oversized = []
    for candidate in normalized:
        if not fits(candidate["resources"], available):
            oversized.append(candidate["run_id"])
            continue
        projected = add_resources(usage, candidate["resources"])
        if len(selected) < max_dispatches and fits(projected, available):
            selected.append(candidate)
            usage = projected
        else:
            waiting.append(candidate["run_id"])
    return {
        "selected": selected,
        "waiting_run_ids": waiting,
        "oversized_run_ids": oversized,
        "resource_usage": usage,
    }


__all__ = [
    "CAPACITY_SCHEMA",
    "RESOURCE_SCHEMA",
    "RESERVATION_SCHEMA",
    "MAX_CONCURRENT_LANES",
    "RESOURCE_FIELDS",
    "SchedulerContractError",
    "validate_capacity",
    "capacity_vector",
    "validate_resources",
    "validate_reservation",
    "zero_resources",
    "add_resources",
    "fits",
    "reservation_resources",
    "choose",
    "sha256",
]
