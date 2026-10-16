#!/usr/bin/env python3
"""Pure normalization for closed native action results.

The lifecycle hook and governed controller share this module so the exact
spawn, continue, and stop receipt grammar has one runtime implementation.
It performs no I/O and grants no authority.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


NATIVE_SPAWN_RESULT_SCHEMA = "orch-dork/native-spawn-result/v1"
NATIVE_CONTINUE_RESULT_SCHEMA = "orch-dork/native-continue-result/v1"
NATIVE_STOP_RESULT_SCHEMA = "orch-dork/native-stop-result/v1"

_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SCALAR_STOP_STATUSES = frozenset(
    {"pending_init", "running", "interrupted", "shutdown", "not_found"}
)
DIRECT_RESULT_KEY_SETS = {
    "spawn": frozenset({"agent_id", "nickname"}),
    "continue": frozenset({"submission_id"}),
    "stop": frozenset({"previous_status"}),
}


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _expected_lanes(value: Any) -> list[str] | None:
    if (
        not isinstance(value, list)
        or any(not _identifier(item) for item in value)
        or len(value) != len(set(value))
    ):
        return None
    return sorted(value)


def spawn_result_binding(
    value: Any, expected_lane_ids: Any
) -> dict[str, Any] | None:
    expected = _expected_lanes(expected_lane_ids)
    if (
        expected is None
        or not isinstance(value, Mapping)
        or set(value) != {"schema", "lanes"}
        or value.get("schema") != NATIVE_SPAWN_RESULT_SCHEMA
        or not isinstance(value.get("lanes"), list)
    ):
        return None
    lanes: list[dict[str, str]] = []
    for row in value["lanes"]:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"lane_id", "agent_id"}
            or not _identifier(row.get("lane_id"))
            or not _identifier(row.get("agent_id"))
        ):
            return None
        lanes.append({"lane_id": row["lane_id"], "agent_id": row["agent_id"]})
    lanes.sort(key=lambda row: row["lane_id"])
    if (
        [row["lane_id"] for row in lanes] != expected
        or len({row["agent_id"] for row in lanes}) != len(lanes)
    ):
        return None
    return {"schema": NATIVE_SPAWN_RESULT_SCHEMA, "lanes": lanes}


def continue_result_binding(
    value: Any, expected_lane_ids: Any
) -> dict[str, Any] | None:
    expected = _expected_lanes(expected_lane_ids)
    if (
        expected is None
        or not isinstance(value, Mapping)
        or set(value) != {"schema", "submissions"}
        or value.get("schema") != NATIVE_CONTINUE_RESULT_SCHEMA
        or not isinstance(value.get("submissions"), list)
    ):
        return None
    submissions: list[dict[str, Any]] = []
    submission_ids: list[str] = []
    for row in value["submissions"]:
        submission = row.get("submission") if isinstance(row, Mapping) else None
        if (
            not isinstance(row, Mapping)
            or set(row) != {"lane_id", "submission"}
            or not _identifier(row.get("lane_id"))
            or not isinstance(submission, Mapping)
            or set(submission) != {"submission_id"}
            or not _identifier(submission.get("submission_id"))
        ):
            return None
        submissions.append(
            {
                "lane_id": row["lane_id"],
                "submission": {"submission_id": submission["submission_id"]},
            }
        )
        submission_ids.append(submission["submission_id"])
    submissions.sort(key=lambda row: row["lane_id"])
    if (
        [row["lane_id"] for row in submissions] != expected
        or len(submission_ids) != len(set(submission_ids))
    ):
        return None
    return {"schema": NATIVE_CONTINUE_RESULT_SCHEMA, "submissions": submissions}


def _stop_status_valid(value: Any) -> bool:
    if isinstance(value, str):
        return value in _SCALAR_STOP_STATUSES
    if not isinstance(value, Mapping):
        return False
    if set(value) == {"completed"}:
        return value.get("completed") is None or isinstance(
            value.get("completed"), str
        )
    return set(value) == {"errored"} and isinstance(value.get("errored"), str)


def stop_result_binding(
    value: Any, expected_lane_ids: Any
) -> dict[str, Any] | None:
    expected = _expected_lanes(expected_lane_ids)
    if (
        expected is None
        or not isinstance(value, Mapping)
        or set(value) != {"schema", "closed"}
        or value.get("schema") != NATIVE_STOP_RESULT_SCHEMA
        or not isinstance(value.get("closed"), list)
    ):
        return None
    closed: list[dict[str, Any]] = []
    for row in value["closed"]:
        result = row.get("result") if isinstance(row, Mapping) else None
        previous_status = (
            result.get("previous_status") if isinstance(result, Mapping) else None
        )
        if (
            not isinstance(row, Mapping)
            or set(row) != {"lane_id", "result"}
            or not _identifier(row.get("lane_id"))
            or not isinstance(result, Mapping)
            or set(result) != {"previous_status"}
            or not _stop_status_valid(previous_status)
        ):
            return None
        closed.append(
            {
                "lane_id": row["lane_id"],
                "result": {
                    "previous_status": (
                        dict(previous_status)
                        if isinstance(previous_status, Mapping)
                        else previous_status
                    )
                },
            }
        )
    closed.sort(key=lambda row: row["lane_id"])
    if [row["lane_id"] for row in closed] != expected:
        return None
    return {"schema": NATIVE_STOP_RESULT_SCHEMA, "closed": closed}


def direct_result_binding(
    value: Any, *, action_kind: Any, expected_lane_ids: Any
) -> dict[str, Any] | None:
    """Normalize one official direct collaboration-tool result.

    Governed native actions publish exactly one local function call per lane.
    The Codex collaboration tools return their native result object directly,
    without the JSON text envelope formerly produced by ``functions.exec``.
    """

    expected = _expected_lanes(expected_lane_ids)
    if expected is None or len(expected) != 1 or not isinstance(value, Mapping):
        return None
    lane_id = expected[0]
    if action_kind == "spawn":
        if (
            set(value) != DIRECT_RESULT_KEY_SETS["spawn"]
            or not _identifier(value.get("agent_id"))
            or not (
                value.get("nickname") is None
                or isinstance(value.get("nickname"), str)
            )
        ):
            return None
        return {
            "schema": NATIVE_SPAWN_RESULT_SCHEMA,
            "lanes": [{"lane_id": lane_id, "agent_id": value["agent_id"]}],
        }
    if action_kind == "continue":
        if set(value) != DIRECT_RESULT_KEY_SETS["continue"] or not _identifier(
            value.get("submission_id")
        ):
            return None
        return {
            "schema": NATIVE_CONTINUE_RESULT_SCHEMA,
            "submissions": [
                {
                    "lane_id": lane_id,
                    "submission": {"submission_id": value["submission_id"]},
                }
            ],
        }
    if action_kind == "stop":
        if set(value) != DIRECT_RESULT_KEY_SETS["stop"] or not _stop_status_valid(
            value.get("previous_status")
        ):
            return None
        previous_status = value["previous_status"]
        return {
            "schema": NATIVE_STOP_RESULT_SCHEMA,
            "closed": [
                {
                    "lane_id": lane_id,
                    "result": {
                        "previous_status": (
                            dict(previous_status)
                            if isinstance(previous_status, Mapping)
                            else previous_status
                        )
                    },
                }
            ],
        }
    return None


def normalize_native_result(
    value: Any,
    *,
    action_kind: Any,
    expected_lane_ids: Any,
    outcome: Any,
) -> dict[str, Any] | None:
    if outcome != "completed":
        return None
    normalizers = {
        "spawn": spawn_result_binding,
        "continue": continue_result_binding,
        "stop": stop_result_binding,
    }
    normalizer = normalizers.get(action_kind)
    normalized = (
        normalizer(value, expected_lane_ids) if normalizer is not None else None
    )
    return normalized or direct_result_binding(
        value,
        action_kind=action_kind,
        expected_lane_ids=expected_lane_ids,
    )


# Kinds whose completed wire result carries data the app-server thread
# projection never shows the retained owner: a continuation's submission id
# and a stop's previous-status message.  For these the owner's normalized
# binding is a witness of the same call, not a second seal of its result.
OWNER_PROJECTION_WITNESS_KINDS = frozenset({"continue", "stop"})


def retained_owner_projection_compatible(
    hook_binding: Any,
    owner_binding: Any,
    *,
    action_kind: Any,
    expected_lane_ids: Any,
    tool_use_id: Any,
) -> bool:
    """Decide whether the retained owner witnessed the call the hook sealed.

    PostToolUse seals the raw wire response; the retained owner sees only the
    thread projection of the same call.  For spawn both rails see the created
    worker id, so the two normalized bindings must be identical.  Generation
    48 showed that a completed ``sendInput`` projects no submission id (the
    owner substitutes the app-server call id it did observe) and a completed
    ``closeAgent`` projects the worker status without the wire message, so
    for those kinds the owner witnesses the same call when it normalizes for
    the same lanes in the same order and, for a continuation, names the call
    id.  The hook's binding stays the retained evidence in every case.
    """

    hook = normalize_native_result(
        hook_binding,
        action_kind=action_kind,
        expected_lane_ids=expected_lane_ids,
        outcome="completed",
    )
    owner = normalize_native_result(
        owner_binding,
        action_kind=action_kind,
        expected_lane_ids=expected_lane_ids,
        outcome="completed",
    )
    if hook is None or owner is None or hook != hook_binding:
        return False
    if hook == owner:
        return True
    if action_kind == "continue":
        return _identifier(tool_use_id) and [
            row["lane_id"] for row in hook["submissions"]
        ] == [row["lane_id"] for row in owner["submissions"]] and all(
            row["submission"]["submission_id"] == tool_use_id
            for row in owner["submissions"]
        )
    if action_kind == "stop":
        return [row["lane_id"] for row in hook["closed"]] == [
            row["lane_id"] for row in owner["closed"]
        ]
    return False


__all__ = [
    "DIRECT_RESULT_KEY_SETS",
    "NATIVE_CONTINUE_RESULT_SCHEMA",
    "NATIVE_SPAWN_RESULT_SCHEMA",
    "NATIVE_STOP_RESULT_SCHEMA",
    "OWNER_PROJECTION_WITNESS_KINDS",
    "continue_result_binding",
    "direct_result_binding",
    "normalize_native_result",
    "retained_owner_projection_compatible",
    "spawn_result_binding",
    "stop_result_binding",
]
