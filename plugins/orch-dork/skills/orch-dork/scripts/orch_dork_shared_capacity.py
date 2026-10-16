#!/usr/bin/env python3
"""Issue 159: one reusable concurrent lane-capacity pool across routes.

At most 32 dispatch-reserved or executing lanes occupy the pool at one instant.
The root is control plane, not a lane, and proven terminal lanes release their
slots without erasing or reusing their identities. Cumulative run history is
never a fixed capacity limit, but the root's append-only identity ledger keeps
it available for explicit per-run task-budget enforcement. Route-specific
resource budgets (including Qwen's serving sequence limit) narrow their
adapters and are never added to the shared pool.

Provider-free. Adapters are caller-supplied seams; this module performs no
discovery, no transport, and no model call.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Callable, Mapping

import orch_dork_observer_receipt as observer_receipt

CAPACITY_SCHEMA = "orch-dork/shared-lane-capacity/v2"
DECISION_SCHEMA = "orch-dork/capacity-admission-decision/v2"
RELEASE_SCHEMA = "orch-dork/lane-capacity-release/v1"
IDENTITY_LEDGER_SCHEMA = "orch-dork/lane-identity-ledger/v1"
AUTHORITY_STATE_SCHEMA = "orch-dork/shared-lane-authority-state/v1"
AUTHORITY_READ_SCHEMA = "orch-dork/shared-lane-authority-read/v1"
AUTHORITY_DELTA_SCHEMA = "orch-dork/shared-lane-authority-delta/v1"
CONTROL_RESERVATION_SCHEMA = "orch-dork/shared-lane-reservation/v1"
CONTROL_DELTA_SCHEMA = "orch-dork/shared-lane-delta/v1"
ROUTE_AUTHORITY_PAYLOAD_SCHEMA = "orch-dork/route-inventory-authority/v1"
LANE_CLEANUP_PAYLOAD_SCHEMA = "orch-dork/lane-cleanup-observer-payload/v1"

MAX_CONCURRENT_LANES = 32
CONCURRENT_CAP_STAGES = (4, 8, 16, 32)
MAX_AUTHORITY_DELTA_FACTS = MAX_CONCURRENT_LANES
MAX_AUTHORITY_DELTA_BYTES = 128 * 1024
# Compatibility export for callers that enumerate the closed configured stages.
RAMP_STAGES = CONCURRENT_CAP_STAGES
CLEAN_WINDOW_SECONDS = 15 * 60

ROUTES = ("native_luna", "portable_qwen")
CONTROL_TOWER_ROUTE = "control_tower"
LEDGER_ROUTES = ROUTES + (CONTROL_TOWER_ROUTE,)
# Qwen admission stays here until its 4/8/12/16 benchmark has a sealed result.
QWEN_DEFAULT_ADMISSION = 8
QWEN_HARD_ADMISSION = 16
QWEN_BENCHMARK_POINTS = (4, 8, 12, 16)
# Conservative native forward limit; not a second agent pool.
NATIVE_FORWARD_LIMIT_PER_AGENT = 1

CANONICAL_OCCUPYING_STATES = frozenset({"dispatch_reserved", "executing"})
LEGACY_OCCUPYING_STATES = frozenset(
    {"pending-init", "pending_init", "running", "spawning", "active", "in_flight"}
)
OCCUPYING_STATES = CANONICAL_OCCUPYING_STATES | LEGACY_OCCUPYING_STATES
CANONICAL_TERMINAL_STATES = frozenset({"completed", "failed", "cancelled"})
LEGACY_TERMINAL_STATE_ALIASES = {
    "errored": "failed",
    "interrupted": "cancelled",
}
TERMINAL_STATES = frozenset(
    {*CANONICAL_TERMINAL_STATES, *LEGACY_TERMINAL_STATE_ALIASES, "released"}
)
EMPTY_IDENTITY_LEDGER_HEAD = "0" * 64
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


class CapacityError(Exception):
    """Caller misuse only. Unknown facts deny admission instead of raising."""


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= 512
        and "\x00" not in value
    )


def canonical_terminal_state(value: Any) -> str | None:
    """Return the canonical capacity-releasing outcome for one terminal fact."""
    if type(value) is not str:
        return None
    if value in CANONICAL_TERMINAL_STATES:
        return str(value)
    return LEGACY_TERMINAL_STATE_ALIASES.get(value)


def _sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def empty_identity_ledger() -> dict[str, Any]:
    """Return the first root-persisted append-only identity ledger value."""
    return {
        "schema": IDENTITY_LEDGER_SCHEMA,
        "entry_count": 0,
        "head_sha256": EMPTY_IDENTITY_LEDGER_HEAD,
        "entries": [],
    }


def validate_identity_ledger(value: Any) -> dict[str, Any]:
    """Validate the complete hash-chained identity history supplied by root."""
    result = {
        "status": "UNKNOWN",
        "entry_count": 0,
        "head_sha256": None,
        "bindings": {},
        "run_counts": {},
        "reason_codes": [],
    }
    fields = {"schema", "entry_count", "head_sha256", "entries"}
    if not isinstance(value, Mapping) or set(value) != fields:
        result["reason_codes"] = ["identity_ledger:shape_invalid"]
        return result
    if value.get("schema") != IDENTITY_LEDGER_SCHEMA:
        result["reason_codes"] = ["identity_ledger:schema_invalid"]
        return result
    entries = value.get("entries")
    entry_count = value.get("entry_count")
    if not isinstance(entries, list) or not _positive_int(entry_count):
        result["reason_codes"] = ["identity_ledger:entries_invalid"]
        return result
    if entry_count != len(entries):
        result["reason_codes"] = ["identity_ledger:entry_count_mismatch"]
        return result

    previous = EMPTY_IDENTITY_LEDGER_HEAD
    bindings: dict[str, dict[str, str]] = {}
    run_counts: dict[str, int] = {}
    entry_fields = {
        "ordinal",
        "lane_id",
        "run_id",
        "route",
        "previous_entry_sha256",
        "entry_sha256",
    }
    for index, raw in enumerate(entries):
        if not isinstance(raw, Mapping) or set(raw) != entry_fields:
            result["reason_codes"] = ["identity_ledger:entry_shape_invalid"]
            return result
        core = {name: raw[name] for name in sorted(entry_fields - {"entry_sha256"})}
        lane_id = raw.get("lane_id")
        run_id = raw.get("run_id")
        route = raw.get("route")
        if (
            raw.get("ordinal") != index + 1
            or not _text(lane_id)
            or not _text(run_id)
            or route not in LEDGER_ROUTES
            or raw.get("previous_entry_sha256") != previous
            or raw.get("entry_sha256") != _sha256(core)
        ):
            result["reason_codes"] = ["identity_ledger:entry_invalid"]
            return result
        if lane_id in bindings:
            result["reason_codes"] = ["identity_ledger:lane_identity_reused"]
            return result
        bindings[lane_id] = {"run_id": run_id, "route": route}
        run_counts[run_id] = run_counts.get(run_id, 0) + 1
        previous = str(raw["entry_sha256"])

    if value.get("head_sha256") != previous:
        result["reason_codes"] = ["identity_ledger:head_mismatch"]
        return result
    result.update(
        {
            "status": "RESOLVED",
            "entry_count": entry_count,
            "head_sha256": previous,
            "bindings": bindings,
            "run_counts": run_counts,
            "reason_codes": [],
        }
    )
    return result


def append_identity_ledger(
    ledger: Any,
    *,
    lane_id: str,
    run_id: str,
    route: str,
) -> dict[str, Any]:
    """Build the next immutable ledger value after one successful reservation."""
    validation = validate_identity_ledger(ledger)
    if validation["status"] != "RESOLVED":
        return {"status": "UNKNOWN", "reason_codes": validation["reason_codes"]}
    if not _text(lane_id) or not _text(run_id) or route not in LEDGER_ROUTES:
        return {"status": "UNKNOWN", "reason_codes": ["identity_ledger:append_invalid"]}
    if lane_id in validation["bindings"]:
        return {"status": "REFUSE", "reason_codes": ["identity_ledger:lane_identity_reused"]}
    ordinal = validation["entry_count"] + 1
    core = {
        "lane_id": lane_id,
        "ordinal": ordinal,
        "previous_entry_sha256": validation["head_sha256"],
        "route": route,
        "run_id": run_id,
    }
    entry = dict(core)
    entry["entry_sha256"] = _sha256(core)
    next_ledger = {
        "schema": IDENTITY_LEDGER_SCHEMA,
        "entry_count": ordinal,
        "head_sha256": entry["entry_sha256"],
        "entries": [dict(item) for item in ledger["entries"]] + [entry],
    }
    return {"status": "APPENDED", "ledger": next_ledger, "entry": entry, "reason_codes": []}


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _seal_authority_state(core: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(core)
    value["state_sha256"] = _sha256(value)
    return value


def empty_authority_state(generation: str = "root-authority/v1") -> dict[str, Any]:
    """Return the first sealed state owned by the root's durable adapter."""
    if not _text(generation):
        raise CapacityError("authority:generation_invalid")
    return _seal_authority_state(
        {
            "schema": AUTHORITY_STATE_SCHEMA,
            "generation": generation,
            "state_version": 0,
            "previous_state_sha256": None,
            "identity_ledger": empty_identity_ledger(),
            "runs": [],
            "active_lane_ids": [],
        }
    )


def validate_authority_state(value: Any) -> dict[str, Any]:
    """Validate one exact state read from the trusted root-owned adapter."""
    fields = {
        "schema",
        "generation",
        "state_version",
        "previous_state_sha256",
        "identity_ledger",
        "runs",
        "active_lane_ids",
        "state_sha256",
    }
    refused = {
        "status": "UNKNOWN",
        "reason_codes": ["authority:state_invalid"],
        "state": None,
        "runs": {},
        "active_lane_ids": set(),
        "ledger": None,
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        return refused
    core = {name: value[name] for name in sorted(fields - {"state_sha256"})}
    if (
        value.get("schema") != AUTHORITY_STATE_SCHEMA
        or not _text(value.get("generation"))
        or not _positive_int(value.get("state_version"))
        or (
            value.get("state_version") == 0
            and value.get("previous_state_sha256") is not None
        )
        or (
            value.get("state_version") > 0
            and not _digest(value.get("previous_state_sha256"))
        )
        or value.get("state_sha256") != _sha256(core)
    ):
        return refused
    ledger = validate_identity_ledger(value.get("identity_ledger"))
    if ledger["status"] != "RESOLVED":
        refused["reason_codes"] = ledger["reason_codes"]
        return refused

    raw_runs = value.get("runs")
    if not isinstance(raw_runs, list):
        return refused
    runs: dict[str, dict[str, Any]] = {}
    run_fields = {
        "run_id",
        "root_thread_id",
        "task_node_budget",
        "plan_revisions",
    }
    revision_fields = {"revision", "plan_sha256"}
    for raw in raw_runs:
        if not isinstance(raw, Mapping) or set(raw) != run_fields:
            return refused
        run_id = raw.get("run_id")
        if (
            not _text(run_id)
            or run_id in runs
            or not _text(raw.get("root_thread_id"))
            or not _positive_int(raw.get("task_node_budget"))
            or raw.get("task_node_budget") == 0
        ):
            return refused
        revisions = raw.get("plan_revisions")
        if not isinstance(revisions, list) or not revisions:
            return refused
        expected_revision = 1
        normalized_revisions: list[dict[str, Any]] = []
        for revision in revisions:
            if (
                not isinstance(revision, Mapping)
                or set(revision) != revision_fields
                or revision.get("revision") != expected_revision
                or not _digest(revision.get("plan_sha256"))
            ):
                return refused
            normalized_revisions.append(dict(revision))
            expected_revision += 1
        runs[run_id] = {
            **dict(raw),
            "plan_revisions": normalized_revisions,
        }
    if list(runs) != sorted(runs):
        return refused

    active = value.get("active_lane_ids")
    if (
        not isinstance(active, list)
        or active != sorted(active)
        or len(active) != len(set(active))
        or len(active) > MAX_CONCURRENT_LANES
        or any(lane_id not in ledger["bindings"] for lane_id in active)
    ):
        return refused
    for lane_id, binding in ledger["bindings"].items():
        if binding["run_id"] not in runs:
            return refused
    if any(
        ledger["run_counts"].get(run_id, 0) > run["task_node_budget"]
        for run_id, run in runs.items()
    ):
        refused["reason_codes"] = ["authority:task_node_budget_exceeded"]
        return refused
    return {
        "status": "RESOLVED",
        "reason_codes": [],
        "state": dict(value),
        "runs": runs,
        "active_lane_ids": set(active),
        "ledger": ledger,
    }


def validate_authority_transition(
    predecessor: Any,
    successor: Any,
    *,
    release_receipts: Any = (),
    observer_trust_store: Any = None,
    observer_replay_guard: Any = None,
    observer_evaluation_time: Any = None,
) -> dict[str, Any]:
    """Validate one legal append-only CAS transition between sealed states."""
    before = validate_authority_state(predecessor)
    after = validate_authority_state(successor)
    refused = {
        "status": "UNKNOWN",
        "reason_codes": ["authority:transition_invalid"],
        "new_identity_entries": [],
        "added_active_lane_ids": [],
        "removed_active_lane_ids": [],
    }
    if before["status"] != "RESOLVED" or after["status"] != "RESOLVED":
        return refused
    if (
        successor.get("generation") != predecessor.get("generation")
        or successor.get("state_version") != predecessor.get("state_version") + 1
        or successor.get("previous_state_sha256")
        != predecessor.get("state_sha256")
    ):
        refused["reason_codes"] = ["authority:transition_continuity_invalid"]
        return refused

    old_entries = predecessor["identity_ledger"]["entries"]
    new_entries = successor["identity_ledger"]["entries"]
    if len(new_entries) < len(old_entries) or new_entries[: len(old_entries)] != old_entries:
        refused["reason_codes"] = ["authority:identity_history_not_append_only"]
        return refused
    appended = [dict(item) for item in new_entries[len(old_entries) :]]

    old_runs = before["runs"]
    new_runs = after["runs"]
    if not set(old_runs) <= set(new_runs):
        refused["reason_codes"] = ["authority:run_history_truncated"]
        return refused
    for run_id, old_run in old_runs.items():
        new_run = new_runs[run_id]
        old_revisions = old_run["plan_revisions"]
        new_revisions = new_run["plan_revisions"]
        if (
            new_run["root_thread_id"] != old_run["root_thread_id"]
            or new_run["task_node_budget"] != old_run["task_node_budget"]
            or len(new_revisions) < len(old_revisions)
            or new_revisions[: len(old_revisions)] != old_revisions
        ):
            refused["reason_codes"] = ["authority:run_binding_mutated"]
            return refused

    old_active = before["active_lane_ids"]
    new_active = after["active_lane_ids"]
    added_active = new_active - old_active
    removed_active = old_active - new_active
    appended_ids = {str(entry["lane_id"]) for entry in appended}
    if not added_active <= appended_ids:
        refused["reason_codes"] = ["authority:inactive_identity_reactivated"]
        return refused

    if not isinstance(release_receipts, (list, tuple)):
        refused["reason_codes"] = ["authority:release_receipts_invalid"]
        return refused
    receipt_by_lane: dict[str, Mapping[str, Any]] = {}
    bindings = after["ledger"]["bindings"]
    for receipt in release_receipts:
        if not isinstance(receipt, Mapping):
            refused["reason_codes"] = ["authority:release_receipts_invalid"]
            return refused
        lane_id = receipt.get("lane_id")
        if not _text(lane_id):
            refused["reason_codes"] = ["authority:release_receipt_invalid"]
            return refused
        binding = bindings.get(lane_id)
        if (
            lane_id in receipt_by_lane
            or binding is None
            or not validate_release_receipt_authority(
                receipt,
                lane_id=str(lane_id),
                run_id=binding["run_id"],
                route=binding["route"],
                terminal_state=receipt.get("terminal_state"),
                observer_trust_store=observer_trust_store,
                observer_replay_guard=observer_replay_guard,
                observer_evaluation_time=(
                    observer_evaluation_time.get(str(lane_id))
                    if isinstance(observer_evaluation_time, Mapping)
                    else observer_evaluation_time
                ),
            )
        ):
            refused["reason_codes"] = ["authority:release_receipt_invalid"]
            return refused
        receipt_by_lane[str(lane_id)] = receipt

    if appended_ids - new_active:
        refused["reason_codes"] = [
            "authority:new_identity_must_enter_active_inventory"
        ]
        return refused
    released_ids = removed_active
    if set(receipt_by_lane) != released_ids:
        refused["reason_codes"] = ["authority:release_proof_mismatch"]
        return refused
    if not appended_ids <= new_active | set(receipt_by_lane):
        refused["reason_codes"] = ["authority:new_identity_state_invalid"]
        return refused
    return {
        "status": "RESOLVED",
        "reason_codes": [],
        "new_identity_entries": appended,
        "added_active_lane_ids": sorted(added_active),
        "removed_active_lane_ids": sorted(removed_active),
    }


_AUTHORITY_DELTA_FIELDS = {
    "schema",
    "generation",
    "predecessor_state_version",
    "predecessor_state_sha256",
    "successor_state_version",
    "successor_state_sha256",
    "new_runs",
    "revision_appends",
    "new_identity_entries",
    "added_active_lane_ids",
    "removed_active_lane_ids",
    "release_receipts",
    "release_evaluation_times",
    "delta_sha256",
}


def _authority_delta_refusal(reason: str) -> dict[str, Any]:
    return {
        "status": "UNKNOWN",
        "reason_codes": [reason],
        "delta": None,
        "state": None,
        "transition": None,
    }


def _evaluation_time_text(value: Any) -> str | None:
    if isinstance(value, str) and _text(value):
        return value
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return None


def _copy_authority_run(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "run_id": value["run_id"],
        "root_thread_id": value["root_thread_id"],
        "task_node_budget": value["task_node_budget"],
        "plan_revisions": [dict(row) for row in value["plan_revisions"]],
    }


def build_authority_delta(
    predecessor: Any,
    successor: Any,
    *,
    release_receipts: Any = (),
    observer_trust_store: Any = None,
    observer_replay_guard: Any = None,
    observer_evaluation_time: Any = None,
) -> dict[str, Any]:
    """Encode one authority CAS transition without repeating prior history."""
    transition = validate_authority_transition(
        predecessor,
        successor,
        release_receipts=release_receipts,
        observer_trust_store=observer_trust_store,
        observer_replay_guard=observer_replay_guard,
        observer_evaluation_time=observer_evaluation_time,
    )
    if transition["status"] != "RESOLVED":
        return _authority_delta_refusal(transition["reason_codes"][0])
    before = validate_authority_state(predecessor)
    after = validate_authority_state(successor)
    receipt_rows = list(release_receipts)
    evaluation_times = {
        str(receipt["lane_id"]): _evaluation_time_text(
            observer_evaluation_time.get(str(receipt["lane_id"]))
            if isinstance(observer_evaluation_time, Mapping)
            else observer_evaluation_time
        )
        for receipt in receipt_rows
    }
    if any(value is None for value in evaluation_times.values()):
        return _authority_delta_refusal("authority:release_evaluation_time_invalid")

    new_runs = [
        _copy_authority_run(after["runs"][run_id])
        for run_id in sorted(set(after["runs"]) - set(before["runs"]))
    ]
    revision_appends = []
    for run_id in sorted(before["runs"]):
        prior_count = len(before["runs"][run_id]["plan_revisions"])
        appended = after["runs"][run_id]["plan_revisions"][prior_count:]
        if appended:
            revision_appends.append(
                {
                    "run_id": run_id,
                    "plan_revisions": [dict(row) for row in appended],
                }
            )
    if (
        len(new_runs) > MAX_AUTHORITY_DELTA_FACTS
        or len(revision_appends) > MAX_AUTHORITY_DELTA_FACTS
        or sum(
            len(item["plan_revisions"])
            for item in [*new_runs, *revision_appends]
        )
        > MAX_AUTHORITY_DELTA_FACTS
        or len(transition["new_identity_entries"])
        > MAX_AUTHORITY_DELTA_FACTS
        or len(receipt_rows) > MAX_AUTHORITY_DELTA_FACTS
    ):
        return _authority_delta_refusal("authority:delta_bounds_exceeded")
    core = {
        "schema": AUTHORITY_DELTA_SCHEMA,
        "generation": successor["generation"],
        "predecessor_state_version": predecessor["state_version"],
        "predecessor_state_sha256": predecessor["state_sha256"],
        "successor_state_version": successor["state_version"],
        "successor_state_sha256": successor["state_sha256"],
        "new_runs": new_runs,
        "revision_appends": revision_appends,
        "new_identity_entries": deepcopy(transition["new_identity_entries"]),
        "added_active_lane_ids": list(transition["added_active_lane_ids"]),
        "removed_active_lane_ids": list(transition["removed_active_lane_ids"]),
        "release_receipts": deepcopy(receipt_rows),
        "release_evaluation_times": evaluation_times,
    }
    delta = {**core, "delta_sha256": _sha256(core)}
    if len(
        json.dumps(
            delta,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ) > MAX_AUTHORITY_DELTA_BYTES:
        return _authority_delta_refusal("authority:delta_bytes_exceeded")
    return {
        "status": "BUILT",
        "reason_codes": [],
        "delta": delta,
        "state": dict(successor),
        "transition": transition,
    }


def apply_authority_delta(
    predecessor: Any,
    delta: Any,
    *,
    observer_trust_store: Any = None,
    observer_replay_guard: Any = None,
) -> dict[str, Any]:
    """Reconstruct and verify one bounded persisted authority transition."""
    before = validate_authority_state(predecessor)
    if before["status"] != "RESOLVED":
        return _authority_delta_refusal("authority:delta_predecessor_invalid")
    if not isinstance(delta, Mapping) or set(delta) != _AUTHORITY_DELTA_FIELDS:
        return _authority_delta_refusal("authority:delta_shape_invalid")
    try:
        encoded_delta = json.dumps(
            delta,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        return _authority_delta_refusal("authority:delta_content_invalid")
    if len(encoded_delta) > MAX_AUTHORITY_DELTA_BYTES:
        return _authority_delta_refusal("authority:delta_bytes_exceeded")
    core = {
        field: deepcopy(delta[field])
        for field in sorted(_AUTHORITY_DELTA_FIELDS - {"delta_sha256"})
    }
    if (
        delta.get("schema") != AUTHORITY_DELTA_SCHEMA
        or delta.get("delta_sha256") != _sha256(core)
        or delta.get("generation") != predecessor.get("generation")
        or delta.get("predecessor_state_version")
        != predecessor.get("state_version")
        or delta.get("predecessor_state_sha256")
        != predecessor.get("state_sha256")
        or delta.get("successor_state_version")
        != predecessor.get("state_version") + 1
        or not _digest(delta.get("successor_state_sha256"))
    ):
        return _authority_delta_refusal("authority:delta_continuity_invalid")

    new_runs = delta.get("new_runs")
    revision_appends = delta.get("revision_appends")
    new_entries = delta.get("new_identity_entries")
    added = delta.get("added_active_lane_ids")
    removed = delta.get("removed_active_lane_ids")
    release_receipts = delta.get("release_receipts")
    evaluation_times = delta.get("release_evaluation_times")
    # Normalize the closed identity lists at the existing read
    # boundary before ordering/hashing so unhashable mappings or
    # mutually unorderable types surface as the existing typed
    # ``authority:delta_content_invalid`` refusal rather than escaping
    # as an untyped TypeError that loses the named reason in the
    # public retained-read path. ``isinstance(item, str)`` is the
    # minimum element-type guarantee: ``sorted`` and ``set`` over the
    # closed string lists always succeed, so no new refusal codes or
    # relaxed assertions are introduced and canonical string element
    # behavior is preserved exactly.
    if (
        not isinstance(new_runs, list)
        or not isinstance(revision_appends, list)
        or not isinstance(new_entries, list)
        or not isinstance(added, list)
        or any(not isinstance(item, str) for item in added)
        or added != sorted(added)
        or len(added) != len(set(added))
        or not isinstance(removed, list)
        or any(not isinstance(item, str) for item in removed)
        or removed != sorted(removed)
        or len(removed) != len(set(removed))
        or not isinstance(release_receipts, list)
        or not isinstance(evaluation_times, Mapping)
        or set(evaluation_times)
        != {
            str(receipt.get("lane_id"))
            for receipt in release_receipts
            if isinstance(receipt, Mapping)
        }
        or any(not _text(value) for value in evaluation_times.values())
        or len(new_runs) > MAX_AUTHORITY_DELTA_FACTS
        or len(revision_appends) > MAX_AUTHORITY_DELTA_FACTS
        # Validate revision containers and rows before bounds or reconstruction.
        or any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("plan_revisions"), list)
            or any(not isinstance(row, Mapping) for row in item["plan_revisions"])
            for item in [*new_runs, *revision_appends]
        )
        or sum(
            len(item["plan_revisions"])
            for item in [*new_runs, *revision_appends]
        )
        > MAX_AUTHORITY_DELTA_FACTS
        or len(new_entries) > MAX_AUTHORITY_DELTA_FACTS
        or len(release_receipts) > MAX_AUTHORITY_DELTA_FACTS
    ):
        return _authority_delta_refusal("authority:delta_content_invalid")

    try:
        runs = {
            run_id: _copy_authority_run(run)
            for run_id, run in before["runs"].items()
        }
        new_run_ids: set[str] = set()
        for raw_run in new_runs:
            if not isinstance(raw_run, Mapping):
                raise ValueError
            run_id = raw_run.get("run_id")
            if not _text(run_id) or run_id in runs or run_id in new_run_ids:
                raise ValueError
            copied = _copy_authority_run(raw_run)
            runs[str(run_id)] = copied
            new_run_ids.add(str(run_id))

        revised_run_ids: set[str] = set()
        for raw_append in revision_appends:
            if (
                not isinstance(raw_append, Mapping)
                or set(raw_append) != {"run_id", "plan_revisions"}
            ):
                raise ValueError
            run_id = raw_append.get("run_id")
            rows = raw_append.get("plan_revisions")
            if (
                not _text(run_id)
                or run_id not in before["runs"]
                or run_id in revised_run_ids
                or not isinstance(rows, list)
                or not rows
            ):
                raise ValueError
            for row in rows:
                if not isinstance(row, Mapping):
                    raise ValueError
                runs[str(run_id)]["plan_revisions"].append(dict(row))
            revised_run_ids.add(str(run_id))

        ledger_entries = [
            dict(entry) for entry in predecessor["identity_ledger"]["entries"]
        ]
        for entry in new_entries:
            if not isinstance(entry, Mapping):
                raise ValueError
            ledger_entries.append(dict(entry))
        ledger = {
            "schema": IDENTITY_LEDGER_SCHEMA,
            "entry_count": len(ledger_entries),
            "head_sha256": (
                ledger_entries[-1]["entry_sha256"]
                if ledger_entries
                else EMPTY_IDENTITY_LEDGER_HEAD
            ),
            "entries": ledger_entries,
        }
        prior_active = set(before["active_lane_ids"])
        if not set(removed) <= prior_active or prior_active & set(added):
            raise ValueError
        active = sorted((prior_active - set(removed)) | set(added))
        successor = _next_authority_state(
            predecessor,
            identity_ledger=ledger,
            runs=[runs[run_id] for run_id in sorted(runs)],
            active_lane_ids=active,
        )
    except (KeyError, TypeError, ValueError):
        return _authority_delta_refusal("authority:delta_content_invalid")

    if successor["state_sha256"] != delta["successor_state_sha256"]:
        return _authority_delta_refusal("authority:delta_successor_mismatch")
    transition = validate_authority_transition(
        predecessor,
        successor,
        release_receipts=release_receipts,
        observer_trust_store=observer_trust_store,
        observer_replay_guard=observer_replay_guard,
        observer_evaluation_time=evaluation_times,
    )
    if transition["status"] != "RESOLVED":
        return _authority_delta_refusal(transition["reason_codes"][0])
    if (
        transition["new_identity_entries"] != new_entries
        or transition["added_active_lane_ids"] != added
        or transition["removed_active_lane_ids"] != removed
    ):
        return _authority_delta_refusal("authority:delta_transition_mismatch")
    return {
        "status": "APPLIED",
        "reason_codes": [],
        "delta": dict(delta),
        "state": successor,
        "transition": transition,
        "release_receipts": deepcopy(release_receipts),
    }


def authority_read_report(state: Any, *, store_id: str) -> dict[str, Any]:
    """Seal one adapter-owned monotonic read for the admission boundary."""
    validation = validate_authority_state(state)
    if validation["status"] != "RESOLVED" or not _text(store_id):
        return {
            "schema": AUTHORITY_READ_SCHEMA,
            "status": "UNKNOWN",
            "store_id": store_id,
            "continuity_verified": False,
            "state": None,
            "state_sha256": None,
            "reason_codes": ["authority:read_invalid"],
        }
    return {
        "schema": AUTHORITY_READ_SCHEMA,
        "status": "VERIFIED",
        "store_id": store_id,
        "continuity_verified": True,
        "state": dict(state),
        "state_sha256": state["state_sha256"],
        "reason_codes": [],
    }


def _next_authority_state(
    state: Mapping[str, Any],
    *,
    identity_ledger: Mapping[str, Any] | None = None,
    runs: list[Mapping[str, Any]] | None = None,
    active_lane_ids: list[str] | None = None,
) -> dict[str, Any]:
    core = {
        "schema": AUTHORITY_STATE_SCHEMA,
        "generation": state["generation"],
        "state_version": state["state_version"] + 1,
        "previous_state_sha256": state["state_sha256"],
        "identity_ledger": dict(
            identity_ledger if identity_ledger is not None else state["identity_ledger"]
        ),
        "runs": [dict(item) for item in (runs if runs is not None else state["runs"])],
        "active_lane_ids": sorted(
            active_lane_ids if active_lane_ids is not None else state["active_lane_ids"]
        ),
    }
    return _seal_authority_state(core)


def collapse_authority_transition(
    base: Any,
    successor: Any,
    *,
    release_receipts: Any = (),
    observer_trust_store: Any = None,
    observer_replay_guard: Any = None,
    observer_evaluation_time: Any = None,
) -> dict[str, Any]:
    """Collapse a validated in-memory batch into one durable CAS successor."""
    base_report = validate_authority_state(base)
    successor_report = validate_authority_state(successor)
    if (
        base_report["status"] != "RESOLVED"
        or successor_report["status"] != "RESOLVED"
        or base.get("generation") != successor.get("generation")
    ):
        raise CapacityError("authority:batch_invalid")
    collapsed = _next_authority_state(
        base,
        identity_ledger=successor["identity_ledger"],
        runs=successor["runs"],
        active_lane_ids=successor["active_lane_ids"],
    )
    transition = validate_authority_transition(
        base,
        collapsed,
        release_receipts=release_receipts,
        observer_trust_store=observer_trust_store,
        observer_replay_guard=observer_replay_guard,
        observer_evaluation_time=observer_evaluation_time,
    )
    if transition["status"] != "RESOLVED":
        raise CapacityError(transition["reason_codes"][0])
    return collapsed


def register_run_authority(
    state: Any,
    *,
    run_id: str,
    root_thread_id: str,
    task_node_budget: int,
    plan_sha256: str,
) -> dict[str, Any]:
    validation = validate_authority_state(state)
    if validation["status"] != "RESOLVED":
        return {"status": "UNKNOWN", "reason_codes": validation["reason_codes"]}
    if (
        not _text(run_id)
        or not _text(root_thread_id)
        or not _positive_int(task_node_budget)
        or task_node_budget == 0
        or not _digest(plan_sha256)
    ):
        return {"status": "UNKNOWN", "reason_codes": ["authority:run_invalid"]}
    if run_id in validation["runs"]:
        return {"status": "REFUSE", "reason_codes": ["authority:run_already_registered"]}
    runs = [dict(item) for item in state["runs"]]
    runs.append(
        {
            "run_id": run_id,
            "root_thread_id": root_thread_id,
            "task_node_budget": task_node_budget,
            "plan_revisions": [{"revision": 1, "plan_sha256": plan_sha256}],
        }
    )
    runs.sort(key=lambda item: item["run_id"])
    return {
        "status": "REGISTERED",
        "state": _next_authority_state(state, runs=runs),
        "reason_codes": [],
    }


def revise_run_authority(
    state: Any,
    *,
    run_id: str,
    predecessor_plan_sha256: str,
    successor_plan_sha256: str,
) -> dict[str, Any]:
    validation = validate_authority_state(state)
    if validation["status"] != "RESOLVED":
        return {"status": "UNKNOWN", "reason_codes": validation["reason_codes"]}
    run = validation["runs"].get(run_id)
    if run is None:
        return {"status": "REFUSE", "reason_codes": ["authority:run_unknown"]}
    revisions = run["plan_revisions"]
    if (
        revisions[-1]["plan_sha256"] != predecessor_plan_sha256
        or not _digest(successor_plan_sha256)
    ):
        return {"status": "REFUSE", "reason_codes": ["authority:revision_predecessor_mismatch"]}
    runs = [dict(item) for item in state["runs"]]
    for item in runs:
        item["plan_revisions"] = [dict(row) for row in item["plan_revisions"]]
        if item["run_id"] == run_id:
            item["plan_revisions"].append(
                {
                    "revision": len(item["plan_revisions"]) + 1,
                    "plan_sha256": successor_plan_sha256,
                }
            )
    return {
        "status": "REVISED",
        "state": _next_authority_state(state, runs=runs),
        "reason_codes": [],
    }


def reserve_authority_lane(
    state: Any,
    *,
    lane_id: str,
    run_id: str,
    route: str,
    plan_revision: int,
    plan_sha256: str,
) -> dict[str, Any]:
    validation = validate_authority_state(state)
    if validation["status"] != "RESOLVED":
        return {"status": "UNKNOWN", "reason_codes": validation["reason_codes"]}
    run = validation["runs"].get(run_id)
    if run is None:
        return {"status": "REFUSE", "reason_codes": ["authority:run_unknown"]}
    current = run["plan_revisions"][-1]
    if current != {"revision": plan_revision, "plan_sha256": plan_sha256}:
        return {"status": "REFUSE", "reason_codes": ["authority:frozen_plan_mismatch"]}
    ledger = validation["ledger"]
    if lane_id in ledger["bindings"]:
        return {"status": "REFUSE", "reason_codes": ["capacity:lane_identity_reuse_forbidden"]}
    if ledger["run_counts"].get(run_id, 0) >= run["task_node_budget"]:
        return {"status": "REFUSE", "reason_codes": ["budget:task_node_limit_reached"]}
    if len(validation["active_lane_ids"]) >= MAX_CONCURRENT_LANES:
        return {"status": "QUEUED", "reason_codes": ["capacity:max_concurrent_lanes_reached"]}
    appended = append_identity_ledger(
        state["identity_ledger"], lane_id=lane_id, run_id=run_id, route=route
    )
    if appended["status"] != "APPENDED":
        return appended
    active = sorted(validation["active_lane_ids"] | {lane_id})
    return {
        "status": "RESERVED",
        "state": _next_authority_state(
            state,
            identity_ledger=appended["ledger"],
            active_lane_ids=active,
        ),
        "identity_entry": appended["entry"],
        "reason_codes": [],
    }


def release_authority_lane(
    state: Any,
    release_receipt: Any,
    *,
    observer_trust_store: Any = None,
    observer_replay_guard: Any = None,
    observer_evaluation_time: Any = None,
) -> dict[str, Any]:
    validation = validate_authority_state(state)
    if validation["status"] != "RESOLVED":
        return {"status": "UNKNOWN", "reason_codes": validation["reason_codes"]}
    if not isinstance(release_receipt, Mapping):
        return {"status": "UNKNOWN", "reason_codes": ["release:receipt_invalid"]}
    lane_id = release_receipt.get("lane_id")
    binding = validation["ledger"]["bindings"].get(lane_id)
    if (
        binding is None
        or not validate_release_receipt_authority(
            release_receipt,
            lane_id=lane_id,
            run_id=binding["run_id"],
            route=binding["route"],
            terminal_state=release_receipt.get("terminal_state"),
            observer_trust_store=observer_trust_store,
            observer_replay_guard=observer_replay_guard,
            observer_evaluation_time=(
                observer_evaluation_time.get(str(lane_id))
                if isinstance(observer_evaluation_time, Mapping)
                else observer_evaluation_time
            ),
        )
    ):
        return {"status": "REFUSE", "reason_codes": ["release:authority_binding_invalid"]}
    if lane_id not in validation["active_lane_ids"]:
        return {
            "status": "RELEASED",
            "state": dict(state),
            "idempotent_replay": True,
            "state_changed": False,
            "reason_codes": [],
        }
    active = sorted(validation["active_lane_ids"] - {lane_id})
    return {
        "status": "RELEASED",
        "state": _next_authority_state(state, active_lane_ids=active),
        "idempotent_replay": False,
        "state_changed": True,
        "reason_codes": [],
    }


_CONTROL_RESERVATION_FIELDS = {
    "schema",
    "run_id",
    "node_id",
    "intent_sha256",
    "reservation_sha256",
}
_CONTROL_DELTA_FIELDS = {
    "schema",
    "capacity",
    "released",
    "reserved",
    "delta_sha256",
}


def control_reservation(
    *, run_id: str, node_id: str, intent_sha256: str
) -> dict[str, Any]:
    """Build the canonical reservation used by every Control Tower path."""
    core = {
        "schema": CONTROL_RESERVATION_SCHEMA,
        "run_id": run_id,
        "node_id": node_id,
        "intent_sha256": intent_sha256,
    }
    return {**core, "reservation_sha256": _sha256(core)}


def validate_control_reservation(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == _CONTROL_RESERVATION_FIELDS
        and value.get("schema") == CONTROL_RESERVATION_SCHEMA
        and _text(value.get("run_id"))
        and _text(value.get("node_id"))
        and _digest(value.get("intent_sha256"))
        and value.get("reservation_sha256")
        == _sha256(
            {
                "schema": CONTROL_RESERVATION_SCHEMA,
                "run_id": value.get("run_id"),
                "node_id": value.get("node_id"),
                "intent_sha256": value.get("intent_sha256"),
            }
        )
    )


def control_delta(
    *, released: list[Mapping[str, Any]], reserved: list[Mapping[str, Any]]
) -> dict[str, Any]:
    """Build one sealed delta for the root-owned persisted lane ledger."""
    core = {
        "schema": CONTROL_DELTA_SCHEMA,
        "capacity": MAX_CONCURRENT_LANES,
        "released": [dict(item) for item in released],
        "reserved": [dict(item) for item in reserved],
    }
    return {**core, "delta_sha256": _sha256(core)}


def reduce_control_deltas(values: Any) -> dict[str, Any]:
    """Reduce Control Tower's durable stream under the shared public contract."""
    if not isinstance(values, list):
        return {"status": "UNKNOWN", "reason_codes": ["lane_ledger:deltas_invalid"]}
    active: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in values:
        if (
            not isinstance(raw, Mapping)
            or set(raw) != _CONTROL_DELTA_FIELDS
            or raw.get("schema") != CONTROL_DELTA_SCHEMA
            or raw.get("capacity") != MAX_CONCURRENT_LANES
        ):
            return {"status": "UNKNOWN", "reason_codes": ["lane_ledger:delta_invalid"]}
        core = {name: raw[name] for name in sorted(_CONTROL_DELTA_FIELDS - {"delta_sha256"})}
        if raw.get("delta_sha256") != _sha256(core):
            return {"status": "UNKNOWN", "reason_codes": ["lane_ledger:delta_seal_invalid"]}
        released = raw.get("released")
        reserved = raw.get("reserved")
        if not isinstance(released, list) or not isinstance(reserved, list):
            return {"status": "UNKNOWN", "reason_codes": ["lane_ledger:records_invalid"]}
        if not all(validate_control_reservation(item) for item in released + reserved):
            return {"status": "UNKNOWN", "reason_codes": ["lane_ledger:reservation_invalid"]}
        for record in released:
            key = (str(record["run_id"]), str(record["node_id"]))
            if active.get(key) != record:
                return {"status": "UNKNOWN", "reason_codes": ["lane_ledger:release_invalid"]}
            del active[key]
        for record in reserved:
            key = (str(record["run_id"]), str(record["node_id"]))
            if key in active:
                return {"status": "UNKNOWN", "reason_codes": ["lane_ledger:duplicate_active"]}
            active[key] = dict(record)
        if len(active) > MAX_CONCURRENT_LANES:
            return {"status": "REFUSE", "reason_codes": ["lane_ledger:capacity_exceeded"]}
    return {"status": "RESOLVED", "active": active, "reason_codes": []}


def _release_receipt_valid(
    value: Any,
    *,
    lane_id: str,
    run_id: str,
    route: str,
    state: str,
) -> bool:
    fields = {
        "schema",
        "status",
        "released",
        "lane_id",
        "run_id",
        "route",
        "terminal_state",
        "owned_descendants",
        "cleanup_status",
        "terminal_evidence_sha256",
        "cleanup_evidence_sha256",
        "cleanup_observer_receipt",
        "identity_retained_not_reusable",
        "reason_codes",
        "receipt_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        return False
    core = dict(value)
    receipt_sha256 = core.pop("receipt_sha256", None)
    return (
        value.get("schema") == RELEASE_SCHEMA
        and value.get("status") == "RELEASED"
        and value.get("released") is True
        and value.get("lane_id") == lane_id
        and value.get("run_id") == run_id
        and value.get("route") == route
        and state in CANONICAL_TERMINAL_STATES
        and value.get("terminal_state") == state
        and value.get("owned_descendants") == 0
        and value.get("cleanup_status") in {"complete", "not_required"}
        and _digest(value.get("terminal_evidence_sha256"))
        and _digest(value.get("cleanup_evidence_sha256"))
        and isinstance(value.get("cleanup_observer_receipt"), Mapping)
        and value.get("identity_retained_not_reusable") is True
        and value.get("reason_codes") == []
        and receipt_sha256 == _sha256(core)
    )


def validate_release_receipt(
    value: Any,
    *,
    lane_id: Any,
    run_id: Any,
    route: Any,
    terminal_state: Any,
) -> bool:
    """Public exact validator shared by route and Control Tower ledgers.

    Every caller receives safe typed validation: the closed string fields
    are normalized at this boundary, so an unhashable or non-string value
    returns False rather than raising TypeError from set/frozenset
    membership inside canonical_terminal_state or _release_receipt_valid.
    """
    if (
        not isinstance(lane_id, str)
        or not isinstance(run_id, str)
        or not isinstance(route, str)
        or not isinstance(terminal_state, str)
        or not isinstance(value, Mapping)
    ):
        return False
    inner_terminal_state = value.get("terminal_state")
    inner_cleanup_status = value.get("cleanup_status")
    if (
        not isinstance(inner_terminal_state, str)
        or not isinstance(inner_cleanup_status, str)
    ):
        return False
    expected_state = canonical_terminal_state(terminal_state)
    if terminal_state == "released":
        expected_state = canonical_terminal_state(inner_terminal_state)
    if expected_state is None:
        return False
    return _release_receipt_valid(
        value,
        lane_id=lane_id,
        run_id=run_id,
        route=route,
        state=expected_state,
    )


def cleanup_observer_payload(
    *,
    lane_id: str,
    run_id: str,
    route: str,
    terminal_state: str,
    cleanup_status: str,
    owned_descendants: int,
    terminal_evidence_sha256: str,
) -> dict[str, Any]:
    canonical_state = canonical_terminal_state(terminal_state)
    if (
        not _text(lane_id)
        or not _text(run_id)
        or route not in LEDGER_ROUTES
        or canonical_state is None
        or cleanup_status not in {"complete", "not_required", "unknown"}
        or not _positive_int(owned_descendants)
        or not _digest(terminal_evidence_sha256)
    ):
        raise CapacityError("release:cleanup_payload_invalid")
    return {
        "schema": LANE_CLEANUP_PAYLOAD_SCHEMA,
        "lane_id": lane_id,
        "run_id": run_id,
        "route": route,
        "terminal_state": canonical_state,
        "cleanup_status": cleanup_status,
        "owned_descendants": owned_descendants,
        "terminal_evidence_sha256": terminal_evidence_sha256,
    }


def validate_release_receipt_authority(
    value: Any,
    *,
    lane_id: str,
    run_id: str,
    route: str,
    terminal_state: str,
    observer_trust_store: Any,
    observer_replay_guard: Any,
    observer_evaluation_time: Any,
    observer_environ: Mapping[str, str] | None = None,
) -> bool:
    canonical_state = canonical_terminal_state(terminal_state)
    if canonical_state is None:
        return False
    if not validate_release_receipt(
        value,
        lane_id=lane_id,
        run_id=run_id,
        route=route,
        terminal_state=canonical_state,
    ) or observer_evaluation_time is None:
        return False
    expected_payload = cleanup_observer_payload(
        lane_id=lane_id,
        run_id=run_id,
        route=route,
        terminal_state=terminal_state,
        cleanup_status=value["cleanup_status"],
        owned_descendants=value["owned_descendants"],
        terminal_evidence_sha256=value["terminal_evidence_sha256"],
    )
    verification = observer_receipt.verify_signed_receipt(
        value["cleanup_observer_receipt"],
        expected_kind="lane-cleanup-observation",
        expected_payload=expected_payload,
        evaluation_time=observer_evaluation_time,
        trust_store=observer_trust_store,
        replay_guard=observer_replay_guard,
        environ=observer_environ,
    )
    return (
        verification.get("status") == "PASS"
        and verification.get("signed_receipt_sha256")
        == value.get("cleanup_evidence_sha256")
    )


def effective_cap(configured: Any, last_clean_stage: Any = None) -> dict[str, Any]:
    """Resolve a configured concurrent cap, never exceeding 32 lanes."""
    if not _positive_int(configured) or configured == 0:
        return {"status": "UNKNOWN", "effective_cap": 0, "reason_codes": ["cap:configured_invalid"]}
    if configured > MAX_CONCURRENT_LANES:
        return {
            "status": "REFUSE",
            "effective_cap": 0,
            "reason_codes": ["cap:exceeds_max_concurrent_lanes"],
        }
    if configured not in CONCURRENT_CAP_STAGES:
        return {"status": "REFUSE", "effective_cap": 0, "reason_codes": ["cap:not_a_ramp_stage"]}
    if last_clean_stage is not None:
        if not _positive_int(last_clean_stage) or last_clean_stage not in CONCURRENT_CAP_STAGES:
            return {"status": "UNKNOWN", "effective_cap": 0, "reason_codes": ["cap:clean_stage_invalid"]}
        if configured > last_clean_stage:
            return {
                "status": "REFUSE",
                "effective_cap": last_clean_stage,
                "reason_codes": ["cap:above_last_clean_stage"],
            }
    return {"status": "RESOLVED", "effective_cap": configured, "reason_codes": []}


def next_ramp_stage(current: Any) -> dict[str, Any]:
    """Return the single next permitted stage. No stage may be skipped."""
    if current is None:
        return {"status": "RESOLVED", "next_stage": CONCURRENT_CAP_STAGES[0]}
    if current not in CONCURRENT_CAP_STAGES:
        return {"status": "REFUSE", "next_stage": None, "reason_codes": ["ramp:not_a_stage"]}
    index = CONCURRENT_CAP_STAGES.index(current)
    if index + 1 >= len(CONCURRENT_CAP_STAGES):
        return {"status": "COMPLETE", "next_stage": None}
    return {"status": "RESOLVED", "next_stage": CONCURRENT_CAP_STAGES[index + 1]}


def evaluate_clean_window(observation: Any) -> dict[str, Any]:
    """A stage passes only on one complete, unextended, unrepeated window."""
    if not isinstance(observation, Mapping):
        return {"status": "UNKNOWN", "reason_codes": ["window:input_invalid"]}
    duration = observation.get("duration_seconds")
    if not _positive_int(duration):
        return {"status": "UNKNOWN", "reason_codes": ["window:duration_unknown"]}
    issues = []
    if duration < CLEAN_WINDOW_SECONDS:
        issues.append("window:incomplete")
    if observation.get("extended") is True:
        issues.append("window:extended")
    if observation.get("split") is True:
        issues.append("window:split")
    if observation.get("repeated_after_result") is True:
        issues.append("window:repeated_after_result")
    if observation.get("overlapped_another_stage") is True:
        issues.append("window:overlapped")
    if observation.get("workload_seed") is None:
        issues.append("window:seed_unknown")
    if issues:
        return {"status": "FAIL", "reason_codes": sorted(issues)}
    return {"status": "PASS", "reason_codes": []}


def route_inventory_authority_sha256(
    report: Any,
    *,
    authority_source: str,
    source_capacity_receipt_sha256: str | None = None,
) -> str:
    if not isinstance(report, Mapping):
        raise CapacityError("route:report_invalid")
    core = dict(report)
    for field in (
        "authority_sha256",
        "authority_source",
        "source_capacity_receipt_sha256",
        "source_receipt",
    ):
        core.pop(field, None)
    core["authority_source"] = authority_source
    core["source_capacity_receipt_sha256"] = (
        source_capacity_receipt_sha256
    )
    return _sha256(core)


def route_authority_payload(
    *,
    route: str,
    inventory_sha256: str,
    source_capacity_receipt_sha256: str,
) -> dict[str, Any]:
    if (
        route not in ROUTES
        or not _digest(inventory_sha256)
        or not _digest(source_capacity_receipt_sha256)
    ):
        raise CapacityError("route:authority_payload_invalid")
    return {
        "schema": ROUTE_AUTHORITY_PAYLOAD_SCHEMA,
        "route": route,
        "inventory_sha256": inventory_sha256,
        "source_capacity_receipt_sha256": source_capacity_receipt_sha256,
    }


def seal_route_inventory(
    report: Any,
    *,
    authority_source: str,
    source_capacity_receipt_sha256: str | None = None,
    source_receipt: Any = None,
) -> dict[str, Any]:
    """Bind a trusted adapter's authority claim to the exact route payload."""
    if not isinstance(report, Mapping) or authority_source not in {
        "host-signed-observer",
        "trusted-local-adapter",
    }:
        raise CapacityError("route:authority_evidence_invalid")
    if authority_source == "host-signed-observer":
        if (
            not _digest(source_capacity_receipt_sha256)
            or not isinstance(source_receipt, Mapping)
        ):
            raise CapacityError("route:source_receipt_invalid")
    elif (
        source_capacity_receipt_sha256 is not None
        or source_receipt is not None
    ):
        raise CapacityError("route:source_receipt_unexpected")
    core = dict(report)
    for field in (
        "authority_sha256",
        "authority_source",
        "source_capacity_receipt_sha256",
        "source_receipt",
    ):
        core.pop(field, None)
    core["authority_source"] = authority_source
    core["source_capacity_receipt_sha256"] = (
        source_capacity_receipt_sha256
    )
    return {
        **core,
        "source_receipt": (
            dict(source_receipt)
            if isinstance(source_receipt, Mapping)
            else None
        ),
        "authority_sha256": _sha256(core),
    }


def normalize_route_inventory(
    adapter_report: Any,
    route: str,
    *,
    observer_trust_store: Any = None,
    observer_replay_guard: Any = None,
    observer_evaluation_time: Any = None,
) -> dict[str, Any]:
    """Count authoritative current occupancy while retaining terminal history."""
    if route not in ROUTES:
        return {"status": "UNKNOWN", "active": 0, "reason_codes": ["route:unknown"]}
    if not isinstance(adapter_report, Mapping):
        return {"status": "UNKNOWN", "active": 0, "reason_codes": ["route:report_invalid"]}
    if adapter_report.get("route") != route:
        return {"status": "UNKNOWN", "active": 0, "reason_codes": ["route:identity_mismatch"]}
    if adapter_report.get("authoritative") is not True:
        return {"status": "UNKNOWN", "active": 0, "reason_codes": ["route:not_authoritative"]}
    authority_source = adapter_report.get("authority_source")
    source_capacity_receipt_sha256 = adapter_report.get(
        "source_capacity_receipt_sha256"
    )
    source_receipt = adapter_report.get("source_receipt")
    if authority_source not in {
        "host-signed-observer",
        "trusted-local-adapter",
    }:
        return {
            "status": "UNKNOWN",
            "active": 0,
            "reason_codes": ["route:authority_evidence_invalid"],
        }
    if (
        authority_source == "host-signed-observer"
        and (
            not _digest(source_capacity_receipt_sha256)
            or not isinstance(source_receipt, Mapping)
            or observer_evaluation_time is None
        )
    ) or (
        authority_source == "trusted-local-adapter"
        and (
            source_capacity_receipt_sha256 is not None
            or source_receipt is not None
        )
    ):
        return {
            "status": "UNKNOWN",
            "active": 0,
            "reason_codes": ["route:authority_evidence_invalid"],
        }
    authority_core = dict(adapter_report)
    supplied_authority_sha256 = authority_core.pop("authority_sha256", None)
    authority_core.pop("source_receipt", None)
    if supplied_authority_sha256 != _sha256(authority_core):
        return {
            "status": "UNKNOWN",
            "active": 0,
            "reason_codes": ["route:authority_payload_mismatch"],
        }
    if authority_source == "host-signed-observer":
        expected_payload = route_authority_payload(
            route=route,
            inventory_sha256=supplied_authority_sha256,
            source_capacity_receipt_sha256=source_capacity_receipt_sha256,
        )
        verification = observer_receipt.verify_signed_receipt(
            source_receipt,
            expected_kind="shared-route-inventory",
            expected_payload=expected_payload,
            evaluation_time=observer_evaluation_time,
            trust_store=observer_trust_store,
            replay_guard=observer_replay_guard,
        )
        if verification.get("status") != "PASS":
            return {
                "status": "UNKNOWN",
                "active": 0,
                "reason_codes": ["route:source_receipt_unverified"],
            }
    if adapter_report.get("stale") is True:
        return {"status": "UNKNOWN", "active": 0, "reason_codes": ["route:stale"]}

    agents = adapter_report.get("agents")
    if not isinstance(agents, list):
        return {"status": "UNKNOWN", "active": 0, "reason_codes": ["route:agents_invalid"]}

    occupying_ids: list[str] = []
    terminal_ids: list[str] = []
    released_terminal_ids: list[str] = []
    unreleased_terminal_ids: list[str] = []
    seen_ids: set[str] = set()
    lane_bindings: dict[str, dict[str, str]] = {}
    for row in agents:
        if not isinstance(row, Mapping):
            return {"status": "UNKNOWN", "active": 0, "reason_codes": ["route:agent_entry_invalid"]}
        lane_id = row.get("lane_id")
        run_id = row.get("run_id")
        if not _text(lane_id) or lane_id in seen_ids:
            return {
                "status": "UNKNOWN",
                "active": 0,
                "reason_codes": ["route:lane_identity_invalid"],
            }
        if not _text(run_id):
            return {
                "status": "UNKNOWN",
                "active": 0,
                "reason_codes": ["route:run_identity_invalid"],
            }
        seen_ids.add(lane_id)
        lane_bindings[lane_id] = {"run_id": run_id, "route": route}
        state = row.get("state")
        if state in OCCUPYING_STATES:
            occupying_ids.append(lane_id)
        elif state in TERMINAL_STATES:
            terminal_ids.append(lane_id)
            release_receipt = row.get("release_receipt")
            if release_receipt is None:
                occupying_ids.append(lane_id)
                unreleased_terminal_ids.append(lane_id)
            elif validate_release_receipt(
                release_receipt,
                lane_id=lane_id,
                run_id=run_id,
                route=route,
                terminal_state=state,
            ):
                released_terminal_ids.append(lane_id)
            else:
                return {
                    "status": "UNKNOWN",
                    "active": 0,
                    "reason_codes": ["route:release_receipt_invalid"],
                }
        else:
            return {"status": "UNKNOWN", "active": 0, "reason_codes": ["route:state_unknown"]}

    occupying = len(occupying_ids)

    result = {
        "status": "RESOLVED",
        "route": route,
        "occupying": occupying,
        # Compatibility alias for v1 callers; v2 admission uses ``occupying``.
        "active": occupying,
        "occupancy_basis": "dispatch_reserved_or_executing_or_unreleased_terminal",
        "occupying_lane_ids": sorted(occupying_ids),
        "terminal_lane_ids": sorted(terminal_ids),
        "released_terminal_lane_ids": sorted(released_terminal_ids),
        "unreleased_terminal_lane_ids": sorted(unreleased_terminal_ids),
        "retained_terminal": len(terminal_ids),
        "retained_counts_as_slot": bool(unreleased_terminal_ids),
        "released_terminal_counts_as_slot": False,
        "lane_bindings": dict(sorted(lane_bindings.items())),
        "reason_codes": [],
    }

    # Route budgets are reported, never summed into the shared pool.
    if route == "native_luna":
        limit = adapter_report.get("forward_limit_per_agent", NATIVE_FORWARD_LIMIT_PER_AGENT)
        in_flight = adapter_report.get("in_flight_forwards")
        result["route_budget"] = {
            "forward_limit_per_agent": limit,
            "in_flight_forwards": in_flight,
            "counts_toward_shared_cap": False,
        }
        if _positive_int(in_flight) and _positive_int(limit) and in_flight > occupying * limit:
            result["status"] = "REFUSE"
            result["reason_codes"] = ["native:forward_limit_exceeded"]
    else:
        seq = adapter_report.get("sequence_limit")
        forwards = adapter_report.get("forward_concurrency")
        if seq is None or forwards is None:
            return {"status": "UNKNOWN", "active": 0, "reason_codes": ["qwen:budget_unobservable"]}
        result["route_budget"] = {
            "sequence_limit": seq,
            "forward_concurrency": forwards,
            "counts_toward_shared_cap": False,
            "is_resource_bound_not_agent_pool": True,
        }
        result["repeated_sequential_calls_permitted"] = True
    return result


def admit(
    request: Any,
    configured_cap: Any,
    *,
    authority_state_reader: Callable[[], Any],
    inventory_reader: Callable[[], Any],
    benchmark_state: Any = None,
    last_clean_stage: Any = None,
    observer_trust_store: Any = None,
    observer_replay_guard: Any = None,
    observer_evaluation_time: Any = None,
) -> dict[str, Any]:
    """Reserve one slot from root-owned state read outside the request.

    Both readers are trusted adapter seams configured by the root/controller;
    neither the request nor route payload may choose its own history, budget,
    or active-reservation baseline.
    """
    decision: dict[str, Any] = {
        "schema": DECISION_SCHEMA,
        "capacity_schema": CAPACITY_SCHEMA,
        "admitted": False,
        "queued": False,
        "state": None,
        "route": None,
        "lane_id": None,
        "run_id": None,
        "plan_revision": None,
        "plan_sha256": None,
        "effective_cap": 0,
        "max_concurrent_lanes": MAX_CONCURRENT_LANES,
        "capacity_basis": "instantaneous_occupancy",
        "cumulative_lane_limit": None,
        "root_counts_toward_lane_capacity": False,
        "occupying_before": None,
        "active_before": None,
        "task_node_budget": None,
        "run_lane_count_before": None,
        "authority_state_sha256_before": None,
        "authority_state_version_before": None,
        "next_authority_state": None,
        "identity_ledger_append": None,
        # Retained for v1 readers; the v2 root/control plane consumes no lane.
        "coordinator_slots": 0,
        "reason_codes": [],
        "route_budgets": {},
        "model_calls": 0,
        "workers_created": 0,
        "retry_count": 0,
        "replacement_count": 0,
        "fallback_count": 0,
    }

    if not isinstance(request, Mapping):
        decision["state"] = "UNKNOWN"
        decision["reason_codes"] = ["admit:request_invalid"]
        return decision

    route = request.get("route")
    lane_id = request.get("lane_id")
    run_id = request.get("run_id")
    plan_revision = request.get("plan_revision")
    plan_sha256 = request.get("plan_sha256")
    decision["route"] = route
    decision["lane_id"] = lane_id
    decision["run_id"] = run_id
    decision["plan_revision"] = plan_revision
    decision["plan_sha256"] = plan_sha256
    if not _text(lane_id):
        decision["state"] = "REFUSE"
        decision["reason_codes"] = ["admit:lane_identity_invalid"]
        return decision
    if route not in ROUTES:
        decision["state"] = "REFUSE"
        decision["reason_codes"] = ["admit:route_unknown"]
        return decision
    if not _text(run_id):
        decision["state"] = "REFUSE"
        decision["reason_codes"] = ["admit:run_identity_invalid"]
        return decision
    if not _positive_int(plan_revision) or plan_revision == 0 or not _digest(plan_sha256):
        decision["state"] = "REFUSE"
        decision["reason_codes"] = ["admit:frozen_plan_identity_invalid"]
        return decision
    if not callable(authority_state_reader) or not callable(inventory_reader):
        decision["state"] = "UNKNOWN"
        decision["reason_codes"] = ["admit:trusted_reader_unavailable"]
        return decision

    cap = effective_cap(configured_cap, last_clean_stage)
    decision["effective_cap"] = cap["effective_cap"]
    if cap["status"] != "RESOLVED":
        decision["state"] = "REFUSE" if cap["status"] == "REFUSE" else "UNKNOWN"
        decision["reason_codes"] = cap["reason_codes"]
        return decision

    try:
        authority_read = authority_state_reader()
        inventory_reports = inventory_reader()
    except Exception:
        decision["state"] = "UNKNOWN"
        decision["reason_codes"] = ["admit:trusted_reader_failed"]
        return decision
    read_fields = {
        "schema",
        "status",
        "store_id",
        "continuity_verified",
        "state",
        "state_sha256",
        "reason_codes",
    }
    if (
        not isinstance(authority_read, Mapping)
        or set(authority_read) != read_fields
        or authority_read.get("schema") != AUTHORITY_READ_SCHEMA
        or authority_read.get("status") != "VERIFIED"
        or authority_read.get("continuity_verified") is not True
        or not _text(authority_read.get("store_id"))
        or not _digest(authority_read.get("state_sha256"))
        or authority_read.get("reason_codes") != []
        or not isinstance(authority_read.get("state"), Mapping)
        or authority_read["state"].get("state_sha256")
        != authority_read.get("state_sha256")
    ):
        decision["state"] = "UNKNOWN"
        decision["reason_codes"] = ["authority:read_unverified"]
        return decision
    authority_value = authority_read["state"]
    authority = validate_authority_state(authority_value)
    if authority["status"] != "RESOLVED":
        decision["state"] = "UNKNOWN"
        decision["reason_codes"] = authority["reason_codes"]
        return decision
    state = authority["state"]
    decision["authority_state_sha256_before"] = state["state_sha256"]
    decision["authority_state_version_before"] = state["state_version"]
    run = authority["runs"].get(run_id)
    if run is None:
        decision["state"] = "REFUSE"
        decision["reason_codes"] = ["authority:run_unknown"]
        return decision
    current_plan = run["plan_revisions"][-1]
    if current_plan != {"revision": plan_revision, "plan_sha256": plan_sha256}:
        decision["state"] = "REFUSE"
        decision["reason_codes"] = ["authority:frozen_plan_mismatch"]
        return decision
    decision["task_node_budget"] = run["task_node_budget"]
    ledger_report = authority["ledger"]
    decision["run_lane_count_before"] = ledger_report["run_counts"].get(run_id, 0)

    if not isinstance(inventory_reports, Mapping):
        decision["state"] = "UNKNOWN"
        decision["reason_codes"] = ["admit:inventory_invalid"]
        return decision

    normalized_routes: dict[str, dict[str, Any]] = {}
    occupying_lane_ids: set[str] = set()
    observed_lane_ids: set[str] = set()
    observed_bindings: dict[str, dict[str, str]] = {}
    for name in ROUTES:
        normalized = normalize_route_inventory(
            inventory_reports.get(name),
            name,
            observer_trust_store=observer_trust_store,
            observer_replay_guard=observer_replay_guard,
            observer_evaluation_time=observer_evaluation_time,
        )
        normalized_routes[name] = normalized
        decision["route_budgets"][name] = normalized.get("route_budget")
        if normalized["status"] == "UNKNOWN":
            decision["state"] = "UNKNOWN"
            decision["reason_codes"] = normalized["reason_codes"]
            return decision
        if normalized["status"] == "REFUSE":
            decision["state"] = "REFUSE"
            decision["reason_codes"] = normalized["reason_codes"]
            return decision
        route_occupying = set(normalized["occupying_lane_ids"])
        route_terminal = set(normalized["terminal_lane_ids"])
        route_lane_ids = route_occupying | route_terminal
        if observed_lane_ids & route_lane_ids:
            decision["state"] = "UNKNOWN"
            decision["reason_codes"] = ["capacity:cross_route_identity_conflict"]
            return decision
        observed_lane_ids.update(route_lane_ids)
        observed_bindings.update(normalized["lane_bindings"])
        occupying_lane_ids.update(route_occupying)

    ledger_bindings = ledger_report["bindings"]
    if any(
        lane_id not in ledger_bindings or ledger_bindings[lane_id] != binding
        for lane_id, binding in observed_bindings.items()
    ):
        decision["state"] = "UNKNOWN"
        decision["reason_codes"] = ["identity_ledger:inventory_binding_missing"]
        return decision

    active_lane_ids = authority["active_lane_ids"]
    if not occupying_lane_ids <= active_lane_ids:
        decision["state"] = "UNKNOWN"
        decision["reason_codes"] = ["authority:occupancy_not_reserved"]
        return decision
    for normalized in normalized_routes.values():
        if set(normalized["released_terminal_lane_ids"]) & active_lane_ids:
            decision["state"] = "UNKNOWN"
            decision["reason_codes"] = ["authority:released_lane_still_active"]
            return decision

    total_occupying = len(active_lane_ids)
    decision["occupying_before"] = total_occupying
    decision["active_before"] = total_occupying

    if lane_id in ledger_bindings:
        decision["state"] = "REFUSE"
        decision["reason_codes"] = ["capacity:lane_identity_reuse_forbidden"]
        return decision
    if decision["run_lane_count_before"] >= run["task_node_budget"]:
        decision["state"] = "REFUSE"
        decision["reason_codes"] = ["budget:task_node_limit_reached"]
        return decision

    # Qwen keeps default 8 / hard 16 until its benchmark is sealed at 4/8/12/16.
    if route == "portable_qwen":
        qwen_active = sum(
            1
            for active_id in active_lane_ids
            if ledger_bindings[active_id]["route"] == "portable_qwen"
        )
        bench = benchmark_state if isinstance(benchmark_state, Mapping) else {}
        sealed_points = bench.get("sealed_points")
        benchmark_complete = (
            isinstance(sealed_points, list)
            and sorted(p for p in sealed_points if _positive_int(p)) == list(QWEN_BENCHMARK_POINTS)
            and bench.get("status") == "PASS"
        )
        limit = QWEN_HARD_ADMISSION if benchmark_complete else QWEN_DEFAULT_ADMISSION
        decision["qwen_admission_limit"] = limit
        decision["qwen_benchmark_complete"] = benchmark_complete
        if qwen_active >= limit:
            decision["state"] = "QUEUED"
            decision["queued"] = True
            decision["reason_codes"] = ["qwen:admission_limit_reached"]
            return decision

    if total_occupying >= cap["effective_cap"]:
        decision["state"] = "QUEUED"
        decision["queued"] = True
        decision["reason_codes"] = ["capacity:max_concurrent_lanes_reached"]
        return decision

    reserved = reserve_authority_lane(
        state,
        lane_id=lane_id,
        run_id=run_id,
        route=route,
        plan_revision=plan_revision,
        plan_sha256=plan_sha256,
    )
    if reserved["status"] != "RESERVED":
        decision["state"] = reserved["status"]
        decision["queued"] = reserved["status"] == "QUEUED"
        decision["reason_codes"] = reserved["reason_codes"]
        return decision
    decision["admitted"] = True
    decision["state"] = "ADMITTED"
    decision["reason_codes"] = ["capacity:slot_available"]
    decision["next_authority_state"] = reserved["state"]
    decision["identity_ledger_append"] = reserved["identity_entry"]
    return decision


def release(terminal_receipt: Any, owned_descendants: Any) -> dict[str, Any]:
    """Release a slot only on a matching terminal receipt with no descendants."""
    if not isinstance(terminal_receipt, Mapping):
        return {"status": "UNKNOWN", "released": False, "reason_codes": ["release:receipt_invalid"]}
    lane_id = terminal_receipt.get("lane_id")
    run_id = terminal_receipt.get("run_id")
    route = terminal_receipt.get("route")
    state = terminal_receipt.get("state")
    canonical_state = canonical_terminal_state(state)
    cleanup_status = terminal_receipt.get("cleanup_status")
    terminal_evidence_sha256 = terminal_receipt.get(
        "terminal_evidence_sha256"
    )
    cleanup_evidence_sha256 = terminal_receipt.get(
        "cleanup_evidence_sha256"
    )
    cleanup_observer_receipt = terminal_receipt.get(
        "cleanup_observer_receipt"
    )
    if not _text(lane_id):
        return {"status": "UNKNOWN", "released": False, "reason_codes": ["release:lane_identity_invalid"]}
    if not _text(run_id):
        return {"status": "UNKNOWN", "released": False, "reason_codes": ["release:run_identity_invalid"]}
    if route not in LEDGER_ROUTES:
        return {"status": "UNKNOWN", "released": False, "reason_codes": ["release:route_invalid"]}
    if canonical_state is None:
        return {"status": "REFUSE", "released": False, "reason_codes": ["release:not_terminal"]}
    if cleanup_status not in {"complete", "not_required"}:
        return {"status": "UNKNOWN", "released": False, "reason_codes": ["release:cleanup_unknown"]}
    if not _digest(terminal_evidence_sha256):
        return {"status": "UNKNOWN", "released": False, "reason_codes": ["release:terminal_evidence_unknown"]}
    if not _digest(cleanup_evidence_sha256):
        return {"status": "UNKNOWN", "released": False, "reason_codes": ["release:cleanup_evidence_unknown"]}
    if not isinstance(cleanup_observer_receipt, Mapping):
        return {"status": "UNKNOWN", "released": False, "reason_codes": ["release:cleanup_observer_receipt_unknown"]}
    if not _positive_int(owned_descendants):
        return {"status": "UNKNOWN", "released": False, "reason_codes": ["release:descendants_unknown"]}
    if owned_descendants > 0:
        return {"status": "REFUSE", "released": False, "reason_codes": ["release:owns_descendants"]}
    core = {
        "schema": RELEASE_SCHEMA,
        "status": "RELEASED",
        "released": True,
        "lane_id": lane_id,
        "run_id": run_id,
        "route": route,
        "terminal_state": canonical_state,
        "owned_descendants": 0,
        "cleanup_status": cleanup_status,
        "terminal_evidence_sha256": terminal_evidence_sha256,
        "cleanup_evidence_sha256": cleanup_evidence_sha256,
        "cleanup_observer_receipt": dict(cleanup_observer_receipt),
        "identity_retained_not_reusable": True,
        "reason_codes": [],
    }
    return {**core, "receipt_sha256": _sha256(core)}


def reduce_cap_after_regression(current_stage: Any, last_clean_stage: Any) -> dict[str, Any]:
    """Reversibly reduce the cap to the last clean stage, preserving history."""
    if current_stage not in CONCURRENT_CAP_STAGES:
        return {"status": "UNKNOWN", "new_cap": None, "reason_codes": ["regression:stage_unknown"]}
    target = (
        last_clean_stage
        if last_clean_stage in CONCURRENT_CAP_STAGES
        else CONCURRENT_CAP_STAGES[0]
    )
    if target > current_stage:
        target = CONCURRENT_CAP_STAGES[0]
    return {
        "status": "REDUCED",
        "new_cap": target,
        "previous_stage": current_stage,
        "reversible": True,
        "failed_receipt_preserved": True,
        "destructive_rollback": False,
        "workers_deleted": 0,
        "restoration_requires_fresh_clean_window": True,
        "reason_codes": ["regression:reduced_to_last_clean_stage"],
    }
