#!/usr/bin/env python3
"""Bounded provider-free routing and causal-comparability contracts."""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any


PROGRAM_SCHEMA = "orch-dork/route-policy-program/v1"
REPORT_SCHEMA = "orch-dork/route-policy-report/v1"
INDEPENDENCE_QUORUM_SCHEMA = "orch-dork/independence-quorum/v1"
SERVING_EPOCH_SCHEMA = "orch-dork/serving-epoch-comparison/v1"
TASK_SPEC_DELIVERY_SCHEMA = "orch-dork/task-spec-delivery-program/v1"
TASK_SPEC_ACK_SCHEMA = "orch-dork/task-spec-delivery-ack/v1"
TASK_SPEC_PRE_WORK_RECEIPT_SCHEMA = (
    "orch-dork/native-task-pre-work-receipt/v1"
)

ROUTE_POLICY_OPERATIONS = (
    "independence_quorum",
    "serving_epoch",
    "task_spec_delivery",
)
MAX_ITEMS = 64
MAX_CANONICAL_BYTES = 262_144
MAX_DEPTH = 32
MAX_NODES = 4_096
MAX_OBJECT_KEYS = 256
MAX_ARRAY_ITEMS = 256
MAX_STRING_BYTES = 65_536
_IDENTIFIER = re.compile(r"^[A-Za-z0-9/][A-Za-z0-9._:/-]{0,159}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_bytes(value: Any) -> bytes:
    _validate_json(value, depth=0, nodes=[0])
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > MAX_CANONICAL_BYTES:
        raise ValueError("canonical_json:too_large")
    return raw


def _validate_json(value: Any, *, depth: int, nodes: list[int]) -> None:
    nodes[0] += 1
    if nodes[0] > MAX_NODES or depth > MAX_DEPTH:
        raise ValueError("canonical_json:structure_bound")
    if value is None or type(value) in (bool, int, float):
        return
    if type(value) is str:
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise ValueError("canonical_json:string_bound")
        return
    if type(value) is list:
        if len(value) > MAX_ARRAY_ITEMS:
            raise ValueError("canonical_json:array_bound")
        for child in value:
            _validate_json(child, depth=depth + 1, nodes=nodes)
        return
    if type(value) is dict:
        if len(value) > MAX_OBJECT_KEYS or any(type(key) is not str for key in value):
            raise ValueError("canonical_json:object_bound")
        for key, child in value.items():
            _validate_json(key, depth=depth + 1, nodes=nodes)
            _validate_json(child, depth=depth + 1, nodes=nodes)
        return
    raise ValueError("canonical_json:type_invalid")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def task_spec_pre_work_receipt(
    *, logical_lane_id: str, task_spec_sha256: str
) -> dict[str, Any]:
    """Build the identity-free receipt a fresh worker can emit before work."""

    issues: list[str] = []
    lane_id = _identifier(
        logical_lane_id, "pre_work_receipt.logical_lane_id", issues
    )
    task_digest = _sha(
        task_spec_sha256,
        "pre_work_receipt.task_spec_sha256",
        issues,
    )
    if issues:
        raise ValueError(";".join(sorted(issues)))
    return {
        "schema": TASK_SPEC_PRE_WORK_RECEIPT_SCHEMA,
        "logical_lane_id": lane_id,
        "task_spec_sha256": task_digest,
        "substantive_work_started": False,
    }


def independence_group_digest(group_id: str, members: list[dict[str, str]]) -> str:
    """Return the stable digest for one opaque group and exact route members."""

    normalized = sorted(
        (
            {
                "worker_id": item["worker_id"],
                "session_id": item["session_id"],
                "route_id": item["route_id"],
            }
            for item in members
        ),
        key=lambda item: (item["worker_id"], item["session_id"], item["route_id"]),
    )
    return canonical_sha256({"independence_group_id": group_id, "members": normalized})


def _closed(value: Any, path: str, required: frozenset[str], issues: list[str]) -> dict[str, Any] | None:
    if type(value) is not dict:
        issues.append(f"{path}:not_object")
        return None
    for key in sorted(set(value) - required):
        issues.append(f"{path}:unknown_field:{key}")
    for key in sorted(required - set(value)):
        issues.append(f"{path}:missing:{key}")
    return value


def _identifier(value: Any, path: str, issues: list[str]) -> str | None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        issues.append(f"{path}:invalid")
        return None
    return value


def _sha(value: Any, path: str, issues: list[str]) -> str | None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        issues.append(f"{path}:invalid_sha256")
        return None
    return value


def _integer(value: Any, path: str, issues: list[str], minimum: int = 0) -> int | None:
    if type(value) is not int or value < minimum:
        issues.append(f"{path}:invalid_integer")
        return None
    return value


def _id_list(value: Any, path: str, issues: list[str]) -> list[str]:
    if type(value) is not list:
        issues.append(f"{path}:not_array")
        return []
    if len(value) > MAX_ITEMS:
        issues.append(f"{path}:too_many_items")
    result: list[str] = []
    for index, child in enumerate(value[:MAX_ITEMS]):
        parsed = _identifier(child, f"{path}[{index}]", issues)
        if parsed is not None:
            result.append(parsed)
    if len(result) != len(set(result)):
        issues.append(f"{path}:duplicate")
    return result


def _report(
    operation: str | None,
    issues: list[str],
    result: dict[str, Any] | None,
    *,
    pass_decision: str = "ACCEPTED",
    fail_decision: str = "REJECTED",
) -> dict[str, Any]:
    unique = sorted(set(issues))
    return {
        "schema": REPORT_SCHEMA,
        "status": "FAIL" if unique else "PASS",
        "decision": fail_decision if unique else pass_decision,
        "operation": operation,
        "issues": unique,
        "result": result,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _independence_quorum(payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    item = _closed(
        payload,
        "quorum",
        frozenset({"schema", "quorum_id", "required_groups", "declared_group_count", "members"}),
        issues,
    )
    result = None
    if item is not None:
        if item.get("schema") != INDEPENDENCE_QUORUM_SCHEMA:
            issues.append("quorum:schema_invalid")
        quorum_id = _identifier(item.get("quorum_id"), "quorum.quorum_id", issues)
        required_groups = _integer(item.get("required_groups"), "quorum.required_groups", issues, 1)
        declared_groups = _integer(item.get("declared_group_count"), "quorum.declared_group_count", issues)
        raw_members = item.get("members")
        if type(raw_members) is not list or not raw_members or len(raw_members) > MAX_ITEMS:
            issues.append("quorum.members:invalid_array")
            raw_members = []
        members: list[dict[str, str]] = []
        identities: set[tuple[str, str, str]] = set()
        worker_ids: set[str] = set()
        session_ids: set[str] = set()
        groups: dict[str, list[dict[str, str]]] = {}
        bindings: dict[str, set[str]] = {}
        member_required = frozenset(
            {"worker_id", "session_id", "route_id", "independence_group_id", "group_binding_sha256"}
        )
        for index, raw in enumerate(raw_members):
            member = _closed(raw, f"quorum.members[{index}]", member_required, issues)
            if member is None:
                continue
            worker = _identifier(member.get("worker_id"), f"quorum.members[{index}].worker_id", issues)
            session = _identifier(member.get("session_id"), f"quorum.members[{index}].session_id", issues)
            route = _identifier(member.get("route_id"), f"quorum.members[{index}].route_id", issues)
            group = _identifier(
                member.get("independence_group_id"),
                f"quorum.members[{index}].independence_group_id",
                issues,
            )
            binding = _sha(
                member.get("group_binding_sha256"),
                f"quorum.members[{index}].group_binding_sha256",
                issues,
            )
            if None in (worker, session, route, group, binding):
                continue
            identity = (worker, session, route)
            if identity in identities:
                issues.append("quorum:duplicate_route_identity")
            identities.add(identity)
            if worker in worker_ids:
                issues.append("quorum:duplicate_worker_id")
            worker_ids.add(worker)
            if session in session_ids:
                issues.append("quorum:duplicate_session_id")
            session_ids.add(session)
            normalized = {"worker_id": worker, "session_id": session, "route_id": route}
            members.append({**normalized, "independence_group_id": group, "group_binding_sha256": binding})
            groups.setdefault(group, []).append(normalized)
            bindings.setdefault(group, set()).add(binding)
        for group, group_members in sorted(groups.items()):
            expected = independence_group_digest(group, group_members)
            if bindings.get(group) != {expected}:
                issues.append("quorum:group_binding_mismatch")
        stable_group_count = len(groups)
        if declared_groups is not None and declared_groups != stable_group_count:
            issues.append("quorum:declared_group_count_mismatch")
        if required_groups is not None and stable_group_count < required_groups:
            issues.append("quorum:insufficient_independence_groups")
        result = {
            "quorum_id": quorum_id,
            "member_count": len(members),
            "stable_group_count": stable_group_count,
            "stable_group_ids": sorted(groups),
            "quorum_basis": "stable_independence_groups",
            "quorum_met": not issues,
        }
    return _report("independence_quorum", issues, result)


def _serving_epoch(payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    item = _closed(
        payload,
        "epoch",
        frozenset({"schema", "comparison_id", "requested_attribution", "observations"}),
        issues,
    )
    result = None
    fail_decision = "REJECTED"
    if item is not None:
        if item.get("schema") != SERVING_EPOCH_SCHEMA:
            issues.append("epoch:schema_invalid")
        comparison_id = _identifier(item.get("comparison_id"), "epoch.comparison_id", issues)
        requested = item.get("requested_attribution")
        if requested not in {"descriptive", "causal"}:
            issues.append("epoch.requested_attribution:invalid")
        raw_observations = item.get("observations")
        if type(raw_observations) is not list or not raw_observations or len(raw_observations) > MAX_ITEMS:
            issues.append("epoch.observations:invalid_array")
            raw_observations = []
        observation_required = frozenset(
            {"observation_id", "serving_epoch_id", "arm_id", "metric_name", "metric_value"}
        )
        ids: set[str] = set()
        epochs: set[str] = set()
        arms: set[str] = set()
        metrics: set[str] = set()
        count = 0
        for index, raw in enumerate(raw_observations):
            observation = _closed(raw, f"epoch.observations[{index}]", observation_required, issues)
            if observation is None:
                continue
            observation_id = _identifier(
                observation.get("observation_id"),
                f"epoch.observations[{index}].observation_id",
                issues,
            )
            epoch_id = _identifier(
                observation.get("serving_epoch_id"),
                f"epoch.observations[{index}].serving_epoch_id",
                issues,
            )
            arm = _identifier(observation.get("arm_id"), f"epoch.observations[{index}].arm_id", issues)
            metric = _identifier(
                observation.get("metric_name"),
                f"epoch.observations[{index}].metric_name",
                issues,
            )
            value = observation.get("metric_value")
            if type(value) not in (int, float) or not math.isfinite(value):
                issues.append(f"epoch.observations[{index}].metric_value:invalid")
            if observation_id is not None:
                if observation_id in ids:
                    issues.append("epoch:duplicate_observation_id")
                ids.add(observation_id)
            if epoch_id is not None:
                epochs.add(epoch_id)
            if arm is not None:
                arms.add(arm)
            if metric is not None:
                metrics.add(metric)
            count += 1
        if len(metrics) > 1:
            issues.append("epoch:metric_mismatch")
        cross_epoch = len(epochs) > 1
        if requested == "causal" and cross_epoch:
            issues.append("epoch:cross_epoch_causal_attribution_refused")
            fail_decision = "CAUSAL_ATTRIBUTION_REFUSED"
        scope = "descriptive_only" if cross_epoch or requested == "descriptive" else "epoch_compatible"
        result = {
            "comparison_id": comparison_id,
            "observation_count": count,
            "serving_epoch_ids": sorted(epochs),
            "arm_ids": sorted(arms),
            "comparison_scope": scope,
            "causal_attribution_permitted": requested == "causal" and not cross_epoch and not issues,
        }
    return _report(
        "serving_epoch",
        issues,
        result,
        pass_decision="DESCRIPTIVE" if result and result["comparison_scope"] == "descriptive_only" else "ACCEPTED",
        fail_decision=fail_decision,
    )


def _task_spec_delivery(payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    item = _closed(
        payload,
        "delivery",
        frozenset(
            {
                "schema",
                "expected_task_spec_sha256",
                "expected_lane_id",
                "expected_native_worker_id",
                "expected_session_id",
                "prior_ack_ids",
                "acknowledgement",
            }
        ),
        issues,
    )
    result = None
    if item is not None:
        if item.get("schema") != TASK_SPEC_DELIVERY_SCHEMA:
            issues.append("delivery:schema_invalid")
        expected_task = _sha(item.get("expected_task_spec_sha256"), "delivery.expected_task_spec_sha256", issues)
        expected_lane = _identifier(item.get("expected_lane_id"), "delivery.expected_lane_id", issues)
        expected_worker = _identifier(
            item.get("expected_native_worker_id"), "delivery.expected_native_worker_id", issues
        )
        expected_session = _identifier(item.get("expected_session_id"), "delivery.expected_session_id", issues)
        prior_ack_ids = _id_list(item.get("prior_ack_ids"), "delivery.prior_ack_ids", issues)
        ack = _closed(
            item.get("acknowledgement"),
            "ack",
            frozenset(
                {
                    "schema",
                    "ack_id",
                    "task_spec_sha256",
                    "logical_lane_id",
                    "native_worker_id",
                    "session_id",
                    "acknowledged_seq",
                    "first_substantial_work_seq",
                }
            ),
            issues,
        )
        ack_id = None
        ack_digest = None
        acknowledged_seq = None
        first_work_seq = None
        if ack is not None:
            if ack.get("schema") != TASK_SPEC_ACK_SCHEMA:
                issues.append("ack:schema_invalid")
            ack_id = _identifier(ack.get("ack_id"), "ack.ack_id", issues)
            task = _sha(ack.get("task_spec_sha256"), "ack.task_spec_sha256", issues)
            lane = _identifier(ack.get("logical_lane_id"), "ack.logical_lane_id", issues)
            worker = _identifier(ack.get("native_worker_id"), "ack.native_worker_id", issues)
            session = _identifier(ack.get("session_id"), "ack.session_id", issues)
            acknowledged_seq = _integer(ack.get("acknowledged_seq"), "ack.acknowledged_seq", issues, 1)
            first_work_seq = _integer(
                ack.get("first_substantial_work_seq"),
                "ack.first_substantial_work_seq",
                issues,
                1,
            )
            if task != expected_task:
                issues.append("ack:task_spec_mismatch")
            if lane != expected_lane:
                issues.append("ack:logical_lane_mismatch")
            if worker != expected_worker:
                issues.append("ack:native_worker_mismatch")
            if session != expected_session:
                issues.append("ack:session_mismatch")
            if ack_id in prior_ack_ids:
                issues.append("ack:replayed")
            if acknowledged_seq is not None and first_work_seq is not None and acknowledged_seq >= first_work_seq:
                issues.append("ack:late")
            try:
                ack_digest = canonical_sha256(ack)
            except (TypeError, ValueError):
                issues.append("ack:canonicalization_failed")
        result = {
            "ack_id": ack_id,
            "ack_sha256": ack_digest,
            "acknowledged_before_work": (
                acknowledged_seq is not None
                and first_work_seq is not None
                and acknowledged_seq < first_work_seq
                and not issues
            ),
        }
    return _report("task_spec_delivery", issues, result)


def evaluate_route_policy(program: Any) -> dict[str, Any]:
    """Evaluate one closed routing policy operation without side effects."""

    try:
        canonical_bytes(program)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return _report(None, ["program:invalid_or_unbounded_json"], None)
    issues: list[str] = []
    item = _closed(program, "program", frozenset({"schema", "operation", "payload"}), issues)
    if item is None:
        return _report(None, issues, None)
    if item.get("schema") != PROGRAM_SCHEMA:
        issues.append("program:schema_invalid")
    operation = item.get("operation")
    if operation not in ROUTE_POLICY_OPERATIONS:
        issues.append("program:operation_invalid")
    if type(item.get("payload")) is not dict:
        issues.append("program.payload:not_object")
    if issues:
        return _report(operation if operation in ROUTE_POLICY_OPERATIONS else None, issues, None)
    evaluators = {
        "independence_quorum": _independence_quorum,
        "serving_epoch": _serving_epoch,
        "task_spec_delivery": _task_spec_delivery,
    }
    try:
        return evaluators[operation](item["payload"])
    except (TypeError, ValueError, OverflowError):
        return _report(operation, [f"{operation}:evaluation_failed"], None)


__all__ = [
    "INDEPENDENCE_QUORUM_SCHEMA",
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "ROUTE_POLICY_OPERATIONS",
    "SERVING_EPOCH_SCHEMA",
    "TASK_SPEC_ACK_SCHEMA",
    "TASK_SPEC_DELIVERY_SCHEMA",
    "TASK_SPEC_PRE_WORK_RECEIPT_SCHEMA",
    "canonical_bytes",
    "canonical_sha256",
    "evaluate_route_policy",
    "independence_group_digest",
    "task_spec_pre_work_receipt",
]
