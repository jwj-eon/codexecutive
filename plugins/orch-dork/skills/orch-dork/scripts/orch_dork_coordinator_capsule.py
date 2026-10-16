#!/usr/bin/env python3
"""Provider-free durable coordinator capsule and efficiency budget.

The evaluator is deliberately pure.  A controller supplies one closed program
and receives either a sealed capsule/update or a read-only resume, wait,
handoff, or historical-replay decision.  It never reads conversation history,
creates a task, sends a worker message, polls a runtime, transfers a lease,
reserves authority, or contacts a model.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Any, Mapping


PROGRAM_SCHEMA = "orch-dork/coordinator-capsule-program/v1"
CAPSULE_SCHEMA = "orch-dork/coordinator-capsule/v1"
REPORT_SCHEMA = "orch-dork/coordinator-capsule-report/v1"
EVENT_SCHEMA = "orch-dork/coordinator-capsule-event/v1"
LEASE_SCHEMA = "orch-dork/execution-lease/v1"

OPERATIONS = frozenset({"initialize", "update", "resume", "wait", "handoff", "replay"})
TELEMETRY_CATEGORIES = (
    "setup",
    "core_work",
    "waiting",
    "integration",
    "validation",
    "cleanup",
    "rollover",
)
NEXT_ACTION_KINDS = frozenset(
    {
        "continue_local",
        "wait_for_event",
        "record_transition",
        "checkpoint_rollover",
        "verify_successor",
        "stop_for_authority",
        "stop_unknown",
        "complete_ticket",
    }
)
EVENT_TYPES = frozenset(
    {
        "progress.changed",
        "cursor.advanced",
        "checkpoint.sealed",
        "unknown.resolved",
        "validation.completed",
    }
)
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _nonnegative(value: Any) -> bool:
    return type(value) is int and value >= 0


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, keys: set[str], label: str, issues: list[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return {}
    item = dict(value)
    for key in sorted(keys - set(item)):
        _issue(issues, label + ":missing:" + key)
    for key in sorted(set(item) - keys):
        _issue(issues, label + ":unknown:" + str(key))
    return item


def _lease(value: Any, label: str, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "schema",
            "version",
            "status",
            "owner_thread_id",
            "checkpoint_sha256",
            "source_pointer",
        },
        label,
        issues,
    )
    if item.get("schema") != LEASE_SCHEMA:
        _issue(issues, label + ":schema_invalid")
    if not _nonnegative(item.get("version")) or item.get("version") == 0:
        _issue(issues, label + ":version_invalid")
    if item.get("status") not in {"active_successor", "active", "transferred", "terminal"}:
        _issue(issues, label + ":status_invalid")
    if not _identifier(item.get("owner_thread_id")):
        _issue(issues, label + ":owner_invalid")
    if not _digest(item.get("checkpoint_sha256")):
        _issue(issues, label + ":checkpoint_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, label + ":source_pointer_invalid")
    return item


def _authority(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {"status", "authority_id", "grant_state", "grant_reusable", "source_pointer"},
        "identity.authority",
        issues,
    )
    if item.get("status") not in {
        "not_required",
        "available",
        "reserved",
        "consumed",
        "failed",
        "unknown",
    }:
        _issue(issues, "identity.authority:status_invalid")
    if item.get("authority_id") is not None and not _identifier(item.get("authority_id")):
        _issue(issues, "identity.authority:id_invalid")
    if item.get("grant_state") not in {
        "none",
        "available",
        "reserved",
        "consumed",
        "failed",
        "unknown",
    }:
        _issue(issues, "identity.authority:grant_state_invalid")
    if not isinstance(item.get("grant_reusable"), bool):
        _issue(issues, "identity.authority:grant_reusable_invalid")
    if item.get("grant_state") in {"consumed", "failed"} and item.get("grant_reusable") is not False:
        _issue(issues, "identity.authority:spent_grant_reusable")
    if not _text(item.get("source_pointer")):
        _issue(issues, "identity.authority:source_pointer_invalid")
    return item


def _identity(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "ticket_id",
            "acceptance_sha256",
            "admission_sha256",
            "plan_sha256",
            "execution_lease",
            "authority",
            "source_version",
            "installed_version",
        },
        "identity",
        issues,
    )
    if not _identifier(item.get("ticket_id")):
        _issue(issues, "identity:ticket_id_invalid")
    for field in ("acceptance_sha256", "admission_sha256", "plan_sha256"):
        if not _digest(item.get(field)):
            _issue(issues, "identity:" + field + "_invalid")
    item["execution_lease"] = _lease(
        item.get("execution_lease"), "identity.execution_lease", issues
    )
    item["authority"] = _authority(item.get("authority"), issues)
    for field in ("source_version", "installed_version"):
        if not _text(item.get(field)):
            _issue(issues, "identity:" + field + "_invalid")
    return item


def _cursor(value: Any, label: str, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {"stream_id", "seq", "prefix_sha256", "source_pointer"},
        label,
        issues,
    )
    if not _identifier(item.get("stream_id")):
        _issue(issues, label + ":stream_id_invalid")
    if not _nonnegative(item.get("seq")):
        _issue(issues, label + ":seq_invalid")
    if not _digest(item.get("prefix_sha256")):
        _issue(issues, label + ":prefix_sha256_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, label + ":source_pointer_invalid")
    return item


def _next_action(value: Any, label: str, issues: list[str]) -> dict[str, Any]:
    item = _exact(value, {"kind", "reason", "source_pointer"}, label, issues)
    if item.get("kind") not in NEXT_ACTION_KINDS:
        _issue(issues, label + ":kind_invalid")
    if not _text(item.get("reason")) or not _text(item.get("source_pointer")):
        _issue(issues, label + ":evidence_invalid")
    return item


def _state(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "workers",
            "integration",
            "event_cursor",
            "invariant_sha256",
            "artifact_hashes",
            "unresolved_unknowns",
            "completion_reserve",
            "no_change_count",
            "next_action",
        },
        "state",
        issues,
    )
    workers = item.get("workers")
    if not isinstance(workers, list):
        _issue(issues, "state.workers:not_array")
        workers = []
    normalized_workers: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(workers):
        label = f"state.workers[{index}]"
        row = _exact(
            raw,
            {"worker_id", "status", "last_event_seq", "source_pointer"},
            label,
            issues,
        )
        worker_id = row.get("worker_id")
        if not _identifier(worker_id) or worker_id in seen:
            _issue(issues, label + ":worker_id_invalid_or_duplicate")
        else:
            seen.add(str(worker_id))
        if row.get("status") not in {
            "planned",
            "active",
            "waiting",
            "completed",
            "failed",
            "cancelled",
            "shutdown",
        }:
            _issue(issues, label + ":status_invalid")
        if not _nonnegative(row.get("last_event_seq")) or not _text(row.get("source_pointer")):
            _issue(issues, label + ":evidence_invalid")
        normalized_workers.append(row)
    item["workers"] = normalized_workers

    integration = _exact(
        item.get("integration"),
        {"status", "owner_id", "release_count", "source_pointer"},
        "state.integration",
        issues,
    )
    if integration.get("status") not in {
        "not_started",
        "waiting",
        "active",
        "validating",
        "completed",
        "failed",
    }:
        _issue(issues, "state.integration:status_invalid")
    if integration.get("owner_id") is not None and not _identifier(integration.get("owner_id")):
        _issue(issues, "state.integration:owner_invalid")
    if not _nonnegative(integration.get("release_count")) or not _text(
        integration.get("source_pointer")
    ):
        _issue(issues, "state.integration:evidence_invalid")
    item["integration"] = integration
    item["event_cursor"] = _cursor(item.get("event_cursor"), "state.event_cursor", issues)
    if not _digest(item.get("invariant_sha256")):
        _issue(issues, "state:invariant_sha256_invalid")

    artifacts = item.get("artifact_hashes")
    if not isinstance(artifacts, Mapping) or not artifacts:
        _issue(issues, "state.artifact_hashes:invalid")
        artifacts = {}
    normalized_artifacts: dict[str, str] = {}
    for key, digest in sorted(dict(artifacts).items()):
        if not _identifier(key) or not _digest(digest):
            _issue(issues, "state.artifact_hashes:entry_invalid")
        else:
            normalized_artifacts[str(key)] = str(digest)
    item["artifact_hashes"] = normalized_artifacts
    unknowns = item.get("unresolved_unknowns")
    if not isinstance(unknowns, list) or any(not _identifier(value) for value in unknowns):
        _issue(issues, "state.unresolved_unknowns:invalid")
        unknowns = []
    item["unresolved_unknowns"] = sorted(set(str(value) for value in unknowns))

    reserve = _exact(
        item.get("completion_reserve"),
        {"status", "remaining", "unit", "source_pointer"},
        "state.completion_reserve",
        issues,
    )
    if reserve.get("status") not in {"available", "protected", "exhausted", "unknown"}:
        _issue(issues, "state.completion_reserve:status_invalid")
    remaining = reserve.get("remaining")
    if reserve.get("status") == "unknown":
        if remaining is not None:
            _issue(issues, "state.completion_reserve:unknown_is_not_null")
    elif not _nonnegative(remaining):
        _issue(issues, "state.completion_reserve:remaining_invalid")
    if not _text(reserve.get("unit")) or not _text(reserve.get("source_pointer")):
        _issue(issues, "state.completion_reserve:evidence_invalid")
    item["completion_reserve"] = reserve
    if not _nonnegative(item.get("no_change_count")):
        _issue(issues, "state:no_change_count_invalid")
    item["next_action"] = _next_action(item.get("next_action"), "state.next_action", issues)
    return item


def _telemetry(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(value, set(TELEMETRY_CATEGORIES), "telemetry", issues)
    result: dict[str, Any] = {}
    for category in TELEMETRY_CATEGORIES:
        label = "telemetry." + category
        row = _exact(
            item.get(category),
            {"known", "value", "unit", "source_pointer"},
            label,
            issues,
        )
        known = row.get("known")
        if not isinstance(known, bool):
            _issue(issues, label + ":known_invalid")
        if known is True and not _nonnegative(row.get("value")):
            _issue(issues, label + ":value_invalid")
        if known is False and row.get("value") is not None:
            _issue(issues, label + ":unknown_must_be_null")
        if not _text(row.get("unit")) or not _text(row.get("source_pointer")):
            _issue(issues, label + ":evidence_invalid")
        result[category] = row
    return result


def _policy(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "no_change_budget",
            "context_checkpoint_bps",
            "context_critical_bps",
            "completion_reserve_min",
            "max_capsule_bytes",
            "source_pointer",
        },
        "policy",
        issues,
    )
    if not _nonnegative(item.get("no_change_budget")) or item.get("no_change_budget") == 0:
        _issue(issues, "policy:no_change_budget_invalid")
    checkpoint = item.get("context_checkpoint_bps")
    critical = item.get("context_critical_bps")
    if (
        type(checkpoint) is not int
        or type(critical) is not int
        or not 1 <= checkpoint < critical <= 10_000
    ):
        _issue(issues, "policy:context_thresholds_invalid")
    if not _nonnegative(item.get("completion_reserve_min")):
        _issue(issues, "policy:completion_reserve_min_invalid")
    if type(item.get("max_capsule_bytes")) is not int or not 1024 <= item.get(
        "max_capsule_bytes", 0
    ) <= 1_000_000:
        _issue(issues, "policy:max_capsule_bytes_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, "policy:source_pointer_invalid")
    return item


def _observation(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "ticket_id",
            "acceptance_sha256",
            "admission_sha256",
            "plan_sha256",
            "lease",
            "source_version",
            "installed_version",
            "artifact_hashes",
            "event_cursor",
            "invariant_sha256",
            "context_used",
            "context_limit",
            "completion_reserve_remaining",
            "successor_lease",
            "successor_capsule_version",
            "successor_capsule_sha256",
            "evidence_complete",
            "source_pointer",
        },
        "observation",
        issues,
    )
    if not _identifier(item.get("ticket_id")):
        _issue(issues, "observation:ticket_id_invalid")
    for field in ("acceptance_sha256", "admission_sha256", "plan_sha256", "invariant_sha256"):
        if not _digest(item.get(field)):
            _issue(issues, "observation:" + field + "_invalid")
    item["lease"] = _lease(item.get("lease"), "observation.lease", issues)
    for field in ("source_version", "installed_version"):
        if not _text(item.get(field)):
            _issue(issues, "observation:" + field + "_invalid")
    artifacts = item.get("artifact_hashes")
    if not isinstance(artifacts, Mapping) or any(
        not _identifier(key) or not _digest(digest)
        for key, digest in dict(artifacts or {}).items()
    ):
        _issue(issues, "observation:artifact_hashes_invalid")
        artifacts = {}
    item["artifact_hashes"] = dict(artifacts)
    item["event_cursor"] = _cursor(item.get("event_cursor"), "observation.event_cursor", issues)
    for field in ("context_used", "context_limit", "completion_reserve_remaining"):
        if item.get(field) is not None and not _nonnegative(item.get(field)):
            _issue(issues, "observation:" + field + "_invalid")
    if item.get("context_limit") == 0:
        _issue(issues, "observation:context_limit_zero")
    if item.get("successor_lease") is not None:
        item["successor_lease"] = _lease(
            item.get("successor_lease"), "observation.successor_lease", issues
        )
    if item.get("successor_capsule_version") is not None and not _nonnegative(
        item.get("successor_capsule_version")
    ):
        _issue(issues, "observation:successor_capsule_version_invalid")
    if item.get("successor_capsule_sha256") is not None and not _digest(
        item.get("successor_capsule_sha256")
    ):
        _issue(issues, "observation:successor_capsule_sha256_invalid")
    if not isinstance(item.get("evidence_complete"), bool):
        _issue(issues, "observation:evidence_complete_invalid")
    if not _text(item.get("source_pointer")):
        _issue(issues, "observation:source_pointer_invalid")
    return item


def _event(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "event_id",
            "type",
            "previous_capsule_sha256",
            "expected_version",
            "observed_invariant_sha256",
            "source_pointer",
        },
        "event",
        issues,
    )
    if not _identifier(item.get("event_id")) or item.get("type") not in EVENT_TYPES:
        _issue(issues, "event:identity_invalid")
    if not _digest(item.get("previous_capsule_sha256")) or not _digest(
        item.get("observed_invariant_sha256")
    ):
        _issue(issues, "event:hash_invalid")
    if not _nonnegative(item.get("expected_version")) or not _text(item.get("source_pointer")):
        _issue(issues, "event:evidence_invalid")
    return item


def _historical(value: Any, issues: list[str]) -> dict[str, Any]:
    if not isinstance(value, list):
        _issue(issues, "historical_replays:not_array")
        return {"coordinators": 0, "compactions": 0, "bounded_wakeups": False}
    total_compactions = 0
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        label = f"historical_replays[{index}]"
        row = _exact(
            raw,
            {
                "coordinator_id",
                "compaction_count",
                "wakeups",
                "duplicate_routing_updates",
                "failed_run_facts_preserved",
                "next_actions",
                "source_pointer",
            },
            label,
            issues,
        )
        coordinator_id = row.get("coordinator_id")
        if not _identifier(coordinator_id) or coordinator_id in seen:
            _issue(issues, label + ":coordinator_invalid_or_duplicate")
        else:
            seen.add(str(coordinator_id))
        count = row.get("compaction_count")
        wakeups = row.get("wakeups")
        if not _nonnegative(count) or count == 0:
            _issue(issues, label + ":compaction_count_invalid")
            count = 0
        if not _nonnegative(wakeups) or wakeups > count + 1:
            _issue(issues, label + ":wakeups_unbounded")
        if row.get("duplicate_routing_updates") != 0:
            _issue(issues, label + ":duplicate_routing_updates")
        if row.get("failed_run_facts_preserved") is not True:
            _issue(issues, label + ":failed_run_facts_not_preserved")
        actions = row.get("next_actions")
        deterministic = (
            isinstance(actions, list)
            and bool(actions)
            and all(isinstance(action, str) and action in NEXT_ACTION_KINDS for action in actions)
            and len(set(actions)) == 1
        )
        if not deterministic:
            _issue(issues, label + ":next_action_nondeterministic")
        if not _text(row.get("source_pointer")):
            _issue(issues, label + ":source_pointer_invalid")
        total_compactions += count
        rows.append(row)
    if len(rows) != 3:
        _issue(issues, "historical_replays:coordinator_count_not_three")
    if total_compactions != 18:
        _issue(issues, "historical_replays:compaction_total_not_eighteen")
    return {
        "coordinators": len(rows),
        "compactions": total_compactions,
        "bounded_wakeups": not any("wakeups_unbounded" in issue for issue in issues),
        "duplicate_routing_updates": sum(
            row.get("duplicate_routing_updates", 0)
            for row in rows
            if _nonnegative(row.get("duplicate_routing_updates"))
        ),
        "failed_run_facts_preserved": all(
            row.get("failed_run_facts_preserved") is True for row in rows
        ),
        "deterministic_next_actions": all(
            isinstance(row.get("next_actions"), list)
            and bool(row.get("next_actions"))
            and all(
                isinstance(action, str) and action in NEXT_ACTION_KINDS
                for action in row.get("next_actions", [])
            )
            and len(set(row.get("next_actions", []))) == 1
            for row in rows
        ),
    }


def _capsule_core(capsule: Mapping[str, Any]) -> dict[str, Any]:
    value = deepcopy(dict(capsule))
    value.pop("capsule_sha256", None)
    return value


def _seal_capsule(capsule: Mapping[str, Any]) -> dict[str, Any]:
    core = _capsule_core(capsule)
    return {**core, "capsule_sha256": _sha(core)}


def _validate_capsule(value: Any, issues: list[str]) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "schema",
            "capsule_id",
            "version",
            "identity",
            "state",
            "telemetry",
            "policy",
            "event_log",
            "capsule_sha256",
        },
        "current_capsule",
        issues,
    )
    if item.get("schema") != CAPSULE_SCHEMA:
        _issue(issues, "current_capsule:schema_invalid")
    if not _identifier(item.get("capsule_id")) or not _nonnegative(item.get("version")) or item.get("version") == 0:
        _issue(issues, "current_capsule:identity_invalid")
    item["identity"] = _identity(item.get("identity"), issues)
    item["state"] = _state(item.get("state"), issues)
    item["telemetry"] = _telemetry(item.get("telemetry"), issues)
    item["policy"] = _policy(item.get("policy"), issues)
    events = item.get("event_log")
    if not isinstance(events, list) or len(events) != item.get("version"):
        _issue(issues, "current_capsule:event_log_version_mismatch")
        events = []
    for index, event in enumerate(events, 1):
        if not isinstance(event, Mapping) or event.get("schema") != EVENT_SCHEMA or event.get("seq") != index:
            _issue(issues, f"current_capsule:event_log_invalid:{index}")
    item["event_log"] = deepcopy(events)
    if not _digest(item.get("capsule_sha256")) or item.get("capsule_sha256") != _sha(
        _capsule_core(item)
    ):
        _issue(issues, "current_capsule:seal_mismatch")
    return item


def _matching_observation(
    identity: Mapping[str, Any], state: Mapping[str, Any], observation: Mapping[str, Any], issues: list[str]
) -> None:
    pairs = {
        "ticket_id": "ticket_id",
        "acceptance_sha256": "acceptance_sha256",
        "admission_sha256": "admission_sha256",
        "plan_sha256": "plan_sha256",
        "source_version": "source_version",
        "installed_version": "installed_version",
    }
    for identity_field, observation_field in pairs.items():
        if identity.get(identity_field) != observation.get(observation_field):
            _issue(issues, "observation:" + observation_field + "_mismatch")
    if identity.get("execution_lease") != observation.get("lease"):
        _issue(issues, "observation:lease_contradiction")
    if state.get("artifact_hashes") != observation.get("artifact_hashes"):
        _issue(issues, "observation:artifact_hashes_mismatch")
    if observation.get("evidence_complete") is not True:
        _issue(issues, "observation:evidence_incomplete")


def _pressure(policy: Mapping[str, Any], observation: Mapping[str, Any]) -> tuple[str, int | None]:
    used = observation.get("context_used")
    limit = observation.get("context_limit")
    remaining = observation.get("completion_reserve_remaining")
    checkpoint = policy.get("context_checkpoint_bps")
    critical = policy.get("context_critical_bps")
    reserve_min = policy.get("completion_reserve_min")
    if (
        not _nonnegative(used)
        or not _nonnegative(limit)
        or limit == 0
        or not _nonnegative(remaining)
        or type(checkpoint) is not int
        or type(critical) is not int
        or not _nonnegative(reserve_min)
    ):
        return "unknown", None
    context_bps = used * 10_000 // limit
    if context_bps >= critical:
        return "critical", context_bps
    if context_bps >= checkpoint or remaining < reserve_min:
        return "checkpoint", context_bps
    return "normal", context_bps


def _action(kind: str, reason: str, pointer: str = "coordinator-capsule#decision") -> dict[str, Any]:
    return {"kind": kind, "reason": reason, "source_pointer": pointer}


def build_initialization_program(
    *,
    capsule_id: str,
    ticket_id: str,
    acceptance_sha256: str,
    admission_sha256: str,
    plan_sha256: str,
    root_task_id: str,
    source_version: str,
    installed_version: str,
    worker_ids: list[str],
) -> dict[str, Any]:
    """Construct one provider-free initial capsule program."""

    lease = {
        "schema": LEASE_SCHEMA,
        "version": 1,
        "status": "active_successor",
        "owner_thread_id": root_task_id,
        "checkpoint_sha256": _sha(
            {"root_task_id": root_task_id, "plan_sha256": plan_sha256}
        ),
        "source_pointer": "qualification-pre-spawn#lease",
    }
    identity = {
        "ticket_id": ticket_id,
        "acceptance_sha256": acceptance_sha256,
        "admission_sha256": admission_sha256,
        "plan_sha256": plan_sha256,
        "execution_lease": lease,
        "authority": {
            "status": "not_required",
            "authority_id": None,
            "grant_state": "none",
            "grant_reusable": False,
            "source_pointer": "qualification-pre-spawn#authority",
        },
        "source_version": source_version,
        "installed_version": installed_version,
    }
    state = {
        "workers": [
            {
                "worker_id": worker_id,
                "status": "planned",
                "last_event_seq": 0,
                "source_pointer": (
                    "qualification-pre-spawn#worker-" + worker_id
                ),
            }
            for worker_id in worker_ids
        ],
        "integration": {
            "status": "not_started",
            "owner_id": root_task_id,
            "release_count": 0,
            "source_pointer": "qualification-pre-spawn#integration",
        },
        "event_cursor": {
            "stream_id": "governed-attempt",
            "seq": 0,
            "prefix_sha256": _sha([]),
            "source_pointer": "qualification-pre-spawn#cursor",
        },
        "invariant_sha256": _sha(
            {
                "ticket_id": ticket_id,
                "admission_sha256": admission_sha256,
                "plan_sha256": plan_sha256,
            }
        ),
        "artifact_hashes": {
            "plan": plan_sha256,
            "ticket_admission": admission_sha256,
        },
        "unresolved_unknowns": [],
        "completion_reserve": {
            "status": "protected",
            "remaining": 100,
            "unit": "work_units",
            "source_pointer": "qualification-pre-spawn#completion-reserve",
        },
        "no_change_count": 0,
        "next_action": {
            "kind": "continue_local",
            "reason": "complete shared capacity admission",
            "source_pointer": "qualification-pre-spawn#next-action",
        },
    }
    telemetry = {
        category: {
            "known": True,
            "value": 0,
            "unit": "milliseconds",
            "source_pointer": "qualification-pre-spawn#" + category,
        }
        for category in TELEMETRY_CATEGORIES
    }
    observation = {
        "ticket_id": ticket_id,
        "acceptance_sha256": acceptance_sha256,
        "admission_sha256": admission_sha256,
        "plan_sha256": plan_sha256,
        "lease": deepcopy(lease),
        "source_version": source_version,
        "installed_version": installed_version,
        "artifact_hashes": deepcopy(state["artifact_hashes"]),
        "event_cursor": deepcopy(state["event_cursor"]),
        "invariant_sha256": state["invariant_sha256"],
        "context_used": 0,
        "context_limit": 1000,
        "completion_reserve_remaining": 100,
        "successor_lease": None,
        "successor_capsule_version": None,
        "successor_capsule_sha256": None,
        "evidence_complete": True,
        "source_pointer": "qualification-pre-spawn#observation",
    }
    return {
        "schema": PROGRAM_SCHEMA,
        "operation": "initialize",
        "capsule_id": capsule_id,
        "expected_version": 0,
        "current_capsule": None,
        "identity": identity,
        "state": state,
        "telemetry": telemetry,
        "policy": {
            "no_change_budget": 2,
            "context_checkpoint_bps": 7000,
            "context_critical_bps": 9000,
            "completion_reserve_min": 20,
            "max_capsule_bytes": 24000,
            "source_pointer": "qualification-pre-spawn#policy",
        },
        "observation": observation,
        "event": None,
        "historical_replays": None,
    }


def evaluate_coordinator_capsule(program: Any) -> dict[str, Any]:
    """Evaluate one CAS mutation or read-only coordinator decision."""

    issues: list[str] = []
    value = _exact(
        program,
        {
            "schema",
            "operation",
            "capsule_id",
            "expected_version",
            "current_capsule",
            "identity",
            "state",
            "telemetry",
            "policy",
            "observation",
            "event",
            "historical_replays",
        },
        "program",
        issues,
    )
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    operation = value.get("operation")
    if operation not in OPERATIONS:
        _issue(issues, "program:operation_invalid")
    if not _identifier(value.get("capsule_id")):
        _issue(issues, "program:capsule_id_invalid")
    if not _nonnegative(value.get("expected_version")):
        _issue(issues, "program:expected_version_invalid")

    identity = _identity(value.get("identity"), issues)
    state = _state(value.get("state"), issues)
    telemetry = _telemetry(value.get("telemetry"), issues)
    policy = _policy(value.get("policy"), issues)
    observation = _observation(value.get("observation"), issues)
    _matching_observation(identity, state, observation, issues)
    pressure, context_bps = _pressure(policy, observation)
    historical = _historical(value.get("historical_replays"), issues) if operation == "replay" else None
    if operation != "replay" and value.get("historical_replays") not in (None, []):
        _issue(issues, "historical_replays:unexpected_for_operation")

    current: dict[str, Any] = {}
    if operation == "initialize":
        if value.get("current_capsule") is not None or value.get("expected_version") != 0:
            _issue(issues, "initialize:current_or_version_invalid")
        if value.get("event") is not None:
            _issue(issues, "initialize:event_must_be_null")
    else:
        current = _validate_capsule(value.get("current_capsule"), issues)
        if current.get("capsule_id") != value.get("capsule_id"):
            _issue(issues, "current_capsule:capsule_id_mismatch")
        if current.get("version") != value.get("expected_version"):
            _issue(issues, "cas:stale_writer")
        if any(
            current.get(field) != proposed
            for field, proposed in (
                ("identity", identity),
                ("state", state),
                ("telemetry", telemetry),
                ("policy", policy),
            )
            if operation not in {"update"}
        ):
            _issue(issues, "program:current_capsule_projection_mismatch")
        if operation == "update" and current.get("identity") != identity:
            _issue(issues, "update:identity_changed")

    capsule: dict[str, Any] | None = None
    decision = "STOPPED"
    next_action = _action("stop_unknown", "invalid coordinator capsule program")
    user_update_required = False
    worker_message_required = False
    polling_required = False
    invariant_changed = False
    handoff_complete = False
    resume_reads = 0
    discovery_required = False
    completed_checks_repeated = False

    if operation == "initialize":
        event_log = [
            {
                "schema": EVENT_SCHEMA,
                "seq": 1,
                "event_id": "capsule-initialized",
                "type": "capsule.initialized",
                "previous_capsule_sha256": None,
                "observed_invariant_sha256": observation.get("invariant_sha256"),
                "source_pointer": "coordinator-capsule#initialize",
            }
        ]
        capsule = _seal_capsule(
            {
                "schema": CAPSULE_SCHEMA,
                "capsule_id": value.get("capsule_id"),
                "version": 1,
                "identity": identity,
                "state": state,
                "telemetry": telemetry,
                "policy": policy,
                "event_log": event_log,
            }
        )
        decision = "CAPSULE_CREATED"
        next_action = deepcopy(state.get("next_action"))
    elif operation == "update":
        event = _event(value.get("event"), issues)
        if event.get("previous_capsule_sha256") != current.get("capsule_sha256"):
            _issue(issues, "event:previous_capsule_mismatch")
        if event.get("expected_version") != current.get("version"):
            _issue(issues, "event:expected_version_mismatch")
        if event.get("observed_invariant_sha256") != observation.get("invariant_sha256"):
            _issue(issues, "event:invariant_mismatch")
        if state.get("event_cursor", {}).get("seq", 0) < current.get("state", {}).get(
            "event_cursor", {}
        ).get("seq", 0):
            _issue(issues, "update:event_cursor_regressed")
        current_version = current.get("version") if _nonnegative(current.get("version")) else 0
        event_row = {
            "schema": EVENT_SCHEMA,
            "seq": current_version + 1,
            "event_id": event.get("event_id"),
            "type": event.get("type"),
            "previous_capsule_sha256": event.get("previous_capsule_sha256"),
            "observed_invariant_sha256": event.get("observed_invariant_sha256"),
            "source_pointer": event.get("source_pointer"),
        }
        capsule = _seal_capsule(
            {
                "schema": CAPSULE_SCHEMA,
                "capsule_id": value.get("capsule_id"),
                "version": current_version + 1,
                "identity": identity,
                "state": state,
                "telemetry": telemetry,
                "policy": policy,
                "event_log": list(current.get("event_log", [])) + [event_row],
            }
        )
        decision = "CAPSULE_UPDATED"
        next_action = deepcopy(state.get("next_action"))
    elif operation == "resume":
        resume_reads = 1
        if pressure == "unknown":
            decision = "STOP_UNKNOWN"
            next_action = _action("stop_unknown", "context or completion reserve is unknown")
        elif pressure in {"checkpoint", "critical"}:
            decision = "CHECKPOINT_REQUIRED" if pressure == "checkpoint" else "STOP_CONTEXT_CRITICAL"
            next_action = _action("checkpoint_rollover", "context or completion reserve requires rollover")
        elif identity.get("authority", {}).get("status") in {"failed", "unknown"}:
            decision = "STOP_FOR_AUTHORITY"
            next_action = _action("stop_for_authority", "authority state is failed or unknown")
        else:
            decision = "RESUME_LOCAL"
            next_action = deepcopy(state.get("next_action"))
    elif operation == "wait":
        cursor = state.get("event_cursor", {})
        observed_cursor = observation.get("event_cursor", {})
        invariant_changed = (
            state.get("invariant_sha256") != observation.get("invariant_sha256")
            or cursor.get("seq") != observed_cursor.get("seq")
            or cursor.get("prefix_sha256") != observed_cursor.get("prefix_sha256")
        )
        if invariant_changed:
            decision = "STATE_CHANGED"
            next_action = _action("record_transition", "cursor or invariant hash changed")
            user_update_required = True
        elif state.get("no_change_count", 0) >= policy.get("no_change_budget", 0):
            decision = "CHECKPOINT_REQUIRED"
            next_action = _action("checkpoint_rollover", "bounded no-change budget exhausted")
        else:
            decision = "WAIT_NO_CHANGE"
            next_action = _action("wait_for_event", "no cursor or invariant change")
    elif operation == "handoff":
        successor = observation.get("successor_lease")
        current_lease_version = current.get("identity", {}).get(
            "execution_lease", {}
        ).get("version")
        if not _nonnegative(current_lease_version):
            current_lease_version = 0
        exact_capsule = (
            observation.get("successor_capsule_version") == current.get("version")
            and observation.get("successor_capsule_sha256") == current.get("capsule_sha256")
        )
        exact_lease = (
            isinstance(successor, Mapping)
            and _nonnegative(successor.get("version"))
            and successor.get("version", 0) > current_lease_version
            and successor.get("owner_thread_id")
            != current.get("identity", {}).get("execution_lease", {}).get("owner_thread_id")
            and successor.get("status") == "active_successor"
            and successor.get("checkpoint_sha256")
            == current.get("identity", {}).get("execution_lease", {}).get("checkpoint_sha256")
        )
        if exact_capsule and exact_lease:
            decision = "HANDOFF_COMPLETE"
            next_action = _action("complete_ticket", "successor lease and exact capsule re-read")
            handoff_complete = True
        else:
            decision = "HANDOFF_PENDING"
            next_action = _action("verify_successor", "successor lease or capsule re-read incomplete")
    elif operation == "replay":
        decision = "REPLAY_PASS"
        next_action = deepcopy(state.get("next_action"))

    if capsule is not None:
        capsule_bytes = len(_canonical(capsule))
        max_capsule_bytes = policy.get("max_capsule_bytes")
        if type(max_capsule_bytes) is not int or capsule_bytes > max_capsule_bytes:
            _issue(issues, "capsule:size_limit_exceeded")
    else:
        capsule_bytes = len(_canonical(current)) if current else 0
        capsule = deepcopy(current) if current else None

    if issues:
        decision = "STOPPED"
        next_action = _action("stop_unknown", sorted(set(issues))[0])
        capsule = None if operation in {"initialize", "update"} else capsule

    no_change_budget = policy.get("no_change_budget")
    no_change_count = state.get("no_change_count")
    if not _nonnegative(no_change_budget):
        no_change_budget = 0
    if not _nonnegative(no_change_count):
        no_change_count = 0
    core = {
        "schema": REPORT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "decision": decision,
        "operation": operation,
        "capsule": capsule,
        "capsule_sha256": capsule.get("capsule_sha256") if isinstance(capsule, Mapping) else None,
        "capsule_version": capsule.get("version") if isinstance(capsule, Mapping) else None,
        "capsule_bytes": capsule_bytes,
        "event_cursor": deepcopy(state.get("event_cursor")),
        "next_action": next_action,
        "invariant_changed": invariant_changed,
        "user_update_required": user_update_required,
        "worker_message_required": worker_message_required,
        "polling_required": polling_required,
        "resume_reads": resume_reads,
        "broad_discovery_required": discovery_required,
        "completed_checks_repeated": completed_checks_repeated,
        "no_change_budget_remaining": max(0, no_change_budget - no_change_count),
        "context_pressure_bps": context_bps,
        "rollover_required": decision in {
            "CHECKPOINT_REQUIRED",
            "STOP_CONTEXT_CRITICAL",
        },
        "handoff_complete": handoff_complete,
        "historical_replay": historical,
        "telemetry": deepcopy(telemetry),
        "issues": sorted(set(issues)),
        "provider_free": True,
        "private_chain_of_thought_stored": False,
        "conversation_history_stored": False,
        "credential_reads": 0,
        "grant_reservations": 0,
        "hosted_calls": 0,
        "model_calls": 0,
        "task_creations": 0,
        "worker_messages": 0,
        "workers": 0,
        "retries": 0,
        "fallbacks": 0,
        "replacements": 0,
        "resampling": 0,
    }
    return {**core, "report_sha256": _sha(core)}


__all__ = [
    "CAPSULE_SCHEMA",
    "EVENT_SCHEMA",
    "LEASE_SCHEMA",
    "NEXT_ACTION_KINDS",
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "TELEMETRY_CATEGORIES",
    "build_initialization_program",
    "evaluate_coordinator_capsule",
]
