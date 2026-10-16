#!/usr/bin/env python3
"""Own the exact Issue 94 idle-task, pre-SessionStart caller chain.

The Local app-server owner calls this driver after ``thread/start`` has
created the idle task and before it calls ``turn/start``.  Codex runs the real
``SessionStart`` hook as part of that first turn, so this driver first verifies
the exact idle owner and terminal predecessor, constructs every qualification
artifact through repository APIs, settles only the exact unmaterialized
terminal Issue 94 wave when present, performs the single route canary, activates
the successor controller, advances it to capacity admission, and returns one
sealed readiness report for that hook.  Callers supply identities and roots;
they never translate report fields between stages.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, MutableMapping
from copy import deepcopy
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
from typing import Any
import weakref


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from orch_dork_hostile_input import MCP_ACTION_ADVANCE_RESPONSE_BUDGET_BYTES  # noqa: E402

import orch_dork_live_zero_tool_qualification as transport_qualification  # noqa: E402
import orch_dork_governed_attempt as governed_attempt  # noqa: E402
import orch_dork_governed_native_controller as native_controller  # noqa: E402
import orch_dork_local_task_runtime as local_task_runtime  # noqa: E402
import orch_dork_native_result as native_result  # noqa: E402
import orch_dork_native_worker_finals as native_worker_finals  # noqa: E402
import orch_dork_native_grant_store as native_grant_store  # noqa: E402
import orch_dork_observer_receipt as observer_receipt  # noqa: E402
import orch_dork_owned_file as owned_file  # noqa: E402
import orch_dork_qualification_activation as activation  # noqa: E402
import orch_dork_qualification_bootstrap as bootstrap  # noqa: E402
import orch_dork_qualification_governed_inputs as governed_inputs  # noqa: E402
import orch_dork_qualification_rehearsal as rehearsal  # noqa: E402
import orch_dork_qualification_results as qualification_results  # noqa: E402
import orch_dork_qualification_review as qualification_review  # noqa: E402
import orch_dork_qualification_route_canary as route_canary  # noqa: E402
import orch_dork_route_policy as route_policy  # noqa: E402
import orch_dork_routing_verify as routing_verify  # noqa: E402
import orch_dork_shared_capacity as shared_capacity  # noqa: E402
import orch_dork_worker_default as worker_default  # noqa: E402


PREACTIVATION_REPORT_SCHEMA = (
    "orch-dork/qualification-successor-preactivation/v1"
)
REPORT_SCHEMA = "orch-dork/qualification-successor-pre-turn/v5"
DECISION_READY = "READY_FOR_SESSION_START"
PREDECESSOR_SETTLEMENT_REPORT_SCHEMA = (
    "orch-dork/qualification-predecessor-capacity-settlement/v2"
)
PRE_NATIVE_FAILURE_SETTLEMENT_REPORT_SCHEMA = (
    "orch-dork/qualification-pre-native-failure-settlement/v1"
)
PARTIAL_NATIVE_FAILURE_RECOVERY_REPORT_SCHEMA = (
    "orch-dork/qualification-partial-native-failure-recovery/v1"
)
POST_SPAWN_FAILURE_RECOVERY_REPORT_SCHEMA = (
    "orch-dork/qualification-post-spawn-failure-recovery/v1"
)
POST_ACK_BRIDGE_FAILURE_RECOVERY_REPORT_SCHEMA = (
    "orch-dork/qualification-post-ack-bridge-failure-recovery/v1"
)
FIRST_ACTION_REPORT_SCHEMA = (
    "orch-dork/qualification-successor-first-action/v1"
)
ACTION_ADVANCE_REPORT_SCHEMA = (
    "orch-dork/qualification-successor-action-advance/v5"
)
BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA = "orch-dork/qualification-bootstrap-action-advance/v1"
REVIEW_ACTION_ADVANCE_REPORT_SCHEMA = "orch-dork/qualification-successor-action-advance/v4"
SPAWN_COMPENSATION_EVIDENCE_SCHEMA = (
    "orch-dork/qualification-spawn-compensation-evidence/v1"
)
SPAWN_COMPENSATION_WITNESS_PAYLOAD_SCHEMA = (
    "orch-dork/qualification-spawn-compensation-witness-payload/v1"
)
SPAWN_COMPENSATION_WITNESS_KIND = (
    "qualification-spawn-compensation"
)
_SPAWN_COMPENSATION_EVIDENCE_CORE_FIELDS = frozenset({
    "schema",
    "batch_id",
    "action_evidence",
    "durable_history",
    "durable_history_sha256",
})
_SPAWN_COMPENSATION_EVIDENCE_FIELDS = (
    _SPAWN_COMPENSATION_EVIDENCE_CORE_FIELDS
    | {"owner_witness", "evidence_sha256"}
)
ACTION_ADVANCE_RESULT_ARTIFACT_SCHEMA = "orch-dork/qualification-successor-action-advance-artifact/v1"
_ACTION_RESULT_ARTIFACT_COMMON_FIELDS = {
    "schema", "status", "decision", "controller_id", "root_task_id", "path", "artifact_sha256", "report_sha256",
    "report_schema", "boundary", "provider_free", "counters", "receipt_sha256",
}
_ACTION_RESULT_ARTIFACT_FIELDS = _ACTION_RESULT_ARTIFACT_COMMON_FIELDS | {"action"}
ACTION_ADVANCE_RESULT_ARTIFACT_V2_SCHEMA = (
    "orch-dork/qualification-successor-action-advance-artifact/v2"
)
_ACTION_RESULT_ARTIFACT_V2_FIELDS = _ACTION_RESULT_ARTIFACT_COMMON_FIELDS | {"action_projection"}
# Conservative finite budget for a serialized MCP response carrying a v2 receipt.
# 8192 bytes keeps the response clear of every documented transport ceiling
# (MCP frame 4 MiB, profile.max_string_bytes 65536). Compact receipts never exceed it.
ACTION_ADVANCE_RESULT_ARTIFACT_RESPONSE_BUDGET = MCP_ACTION_ADVANCE_RESPONSE_BUDGET_BYTES
RESULT_ACTION_ADVANCE_REPORT_SCHEMA = "orch-dork/qualification-successor-action-advance/v3"
LEGACY_ACTION_ADVANCE_REPORT_SCHEMA = "orch-dork/qualification-successor-action-advance/v2"
_RESULT_DECISIONS = {
    "AWAITING_WORKER_RESULTS", "AWAITING_RESULT_AGGREGATION",
    "WORKER_RESULTS_FAILED", "WORKER_RESULT_EVIDENCE_REQUIRED", "AWAITING_SOL_REVIEW", "AWAITING_SOL_REVIEW_OBSERVATION",
    "AWAITING_TERMINAL_VERIFICATION", "SOL_REVIEW_EVIDENCE_REQUIRED", "AWAITING_LIFECYCLE_CLEANUP", "AWAITING_ATTEMPT_QUALIFICATION", "AWAITING_FAILURE_CLOSURE",
}
WORKER_ACKNOWLEDGEMENTS_SCHEMA = (
    "orch-dork/qualification-worker-pre-work-acknowledgements/v1"
)
FIRST_ACTION_PREPARATION_REPORT_SCHEMA = (
    "orch-dork/qualification-successor-first-action-preparation/v1"
)
FIRST_ACTION_PREPARATION_DECISION_READY = "PREPARED_FOR_SESSION_START"
FIRST_ACTION_DECISION_READY = "READY_FOR_ONE_ATTEMPT"
RETAINED_OWNER_STARTUP_BINDING_SCHEMA = (
    "orch-dork/retained-owner-startup-binding/v1"
)
MAX_REPORT_BYTES = 4_194_304
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_RUNTIME_ZERO_COUNTERS = (
    "model_calls",
    "hosted_calls",
    "credential_reads",
    "network_calls",
    "task_creations",
    "native_calls",
)
_REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "case_id",
        "evaluation_time",
        "preactivation_report",
        "predecessor_settlement_report",
        "artifacts",
        "artifact_receipts",
        "controller",
        "boundary",
        "provider_free",
        "counters",
        "report_sha256",
    }
)
_SETTLEMENT_REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "evaluation_time",
        "predecessor",
        "capacity_authority_before",
        "pre_native_failure_settlement_report",
        "capacity_admission_report",
        "failed_settlement_report",
        "settlement_program",
        "settlement_report",
        "capacity_authority_after",
        "released_authority_lane_ids",
        "released_logical_lane_ids",
        "boundary",
        "provider_free",
        "counters",
        "report_sha256",
    }
)
_PRE_NATIVE_FAILURE_SETTLEMENT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "evaluation_time",
        "controller_program",
        "controller_report",
        "predecessor_authority_before",
        "predecessor_authority_after",
        "boundary",
        "provider_free",
        "counters",
        "report_sha256",
    }
)
_PARTIAL_NATIVE_FAILURE_RECOVERY_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "evaluation_time",
        "controller_program",
        "controller_report",
        "predecessor_authority_before",
        "predecessor_authority_after",
        "capacity_authority_before",
        "release_receipts",
        "settlement_program",
        "settlement_report",
        "capacity_authority_after",
        "boundary",
        "provider_free",
        "counters",
        "report_sha256",
    }
)
_POST_SPAWN_FAILURE_RECOVERY_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "evaluation_time",
        "controller_program",
        "controller_report",
        "predecessor_authority_before",
        "predecessor_authority_after",
        "capacity_authority_before",
        "release_receipts",
        "settlement_program",
        "settlement_report",
        "capacity_authority_after",
        "boundary",
        "provider_free",
        "counters",
        "report_sha256",
    }
)
_POST_ACK_BRIDGE_FAILURE_RECOVERY_FIELDS = (
    _POST_SPAWN_FAILURE_RECOVERY_FIELDS
)
_SETTLEMENT_ZERO_COUNTERS = {
    "capacity_lanes_released": 0,
    "cleanup_observer_receipts_issued": 0,
    "host_seed_credential_reads": 0,
    "hosted_calls": 0,
    "model_calls": 0,
    "native_actions": 0,
    "network_calls": 0,
    "pre_native_failures_terminalized": 0,
    "provider_calls": 0,
    "task_creations": 0,
    "worker_creations": 0,
}
_FIRST_ACTION_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "pre_turn_report_sha256",
        "startup_observation",
        "source_roots",
        "controller_program",
        "controller_report",
        "action",
        "boundary",
        "provider_free",
        "counters",
        "report_sha256",
    }
)
_ACTION_ADVANCE_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "pre_turn_report_sha256",
        "source_roots",
        "authority_before",
        "durable_hook_report",
        "controller_transitions",
        "acknowledgements",
        "action",
        "boundary",
        "provider_free",
        "counters",
        "report_sha256",
    }
)
_FIRST_ACTION_PREPARATION_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "bootstrap_report_sha256",
        "controller",
        "source_roots",
        "controller_program",
        "boundary",
        "provider_free",
        "counters",
        "report_sha256",
    }
)
_FIRST_ACTION_PREPARATION_COUNTERS = {
    "capacity_reservations": 0,
    "controller_stages": 0,
    "hosted_calls": 0,
    "model_calls": 0,
    "native_actions": 0,
    "network_calls": 0,
    "provider_calls": 0,
    "task_creations": 0,
    "worker_creations": 0,
}
_FIRST_ACTION_COUNTERS = {
    "authority_grants_minted": 0,
    "capacity_reservations": 2,
    "controller_stages": 1,
    "hosted_calls": 0,
    "model_calls": 0,
    "native_actions": 0,
    "native_action_authorizations": 1,
    "network_calls": 0,
    "provider_calls": 0,
    "task_creations": 0,
    "worker_creations": 0,
}
_ACTION_ADVANCE_COUNTER_KEYS = frozenset(
    {
        "controller_observations",
        "controller_stages",
        "session_runtime_observations",
        "hosted_calls",
        "model_calls",
        "native_actions",
        "network_calls",
        "provider_calls",
        "task_creations",
        "worker_creations",
    }
)


class QualificationSuccessorError(ValueError):
    """Stable refusal before the successor's first turn.

    ``issues`` carries the judging boundary's own codes (a controller
    report's issues plus its decision) so the owner's terminal can record
    why a refusal happened beside its enumerable code.  Generation 48 ended
    on ``native_observation_refused`` with the controller's
    ``grant:observation_conflict`` discarded.  It confers nothing.
    """

    def __init__(self, message: str = "", *, issues: Any = ()) -> None:
        super().__init__(message)
        self.issues = [str(issue) for issue in issues]


_OWNER_HANDOFF_AUTHORITY = object()
_OWNER_HANDOFFS: dict[int, tuple[weakref.ReferenceType[Any], int, tuple[Any, ...]]] = {}
_OWNER_HANDOFF_CLOSE_LOCKS: dict[int, threading.Lock] = {}
_HANDOFF_CLOSE_OPEN = "open"
_HANDOFF_CLOSE_CLOSING = "closing"
_HANDOFF_CLOSE_CLOSED = "closed"
_HANDOFF_CLOSE_FAILED = "cleanup_failed"
_HANDOFF_CLOSE_STATES = frozenset({
    _HANDOFF_CLOSE_OPEN,
    _HANDOFF_CLOSE_CLOSING,
    _HANDOFF_CLOSE_CLOSED,
    _HANDOFF_CLOSE_FAILED,
})


class Issue94SuccessorOwnerHandoff:
    """One process-local continuation from pre-turn through final settlement.

    The ordinary MCP path deliberately reopens the canonical controller for
    each native action.  Final qualification needs the same source-owned
    controller after the app-server process has been cleaned up.  This object
    keeps that controller and the exact persisted pre-turn reference alive;
    it is evidence custody, not a serializable authority token.
    """

    __slots__ = (
        "_pre_turn_report", "pre_turn_report_path", "pre_turn_report_sha256",
        "_controller", "_identity", "_pre_spawn_program", "_context",
        "_authority", "_closed", "_close_state", "__weakref__",
    )

    def __init__(
        self,
        authority: object,
        *,
        pre_turn_report: dict[str, Any],
        pre_turn_report_path: str,
        pre_turn_report_sha256: str,
        controller: Any,
        identity: dict[str, Any],
        pre_spawn_program: dict[str, Any],
        context: Any,
    ) -> None:
        if authority is not _OWNER_HANDOFF_AUTHORITY:
            raise QualificationSuccessorError("successor_owner_handoff:factory_required")
        self._pre_turn_report = deepcopy(pre_turn_report)
        self.pre_turn_report_path = pre_turn_report_path
        self.pre_turn_report_sha256 = pre_turn_report_sha256
        self._controller = controller
        self._identity = deepcopy(identity)
        self._pre_spawn_program = deepcopy(pre_spawn_program)
        self._context = context
        self._authority = authority
        self._closed = False
        self._close_state = _HANDOFF_CLOSE_OPEN

    @property
    def pre_turn_report(self) -> dict[str, Any]:
        _require_issue94_successor_owner_handoff(self)
        return deepcopy(self._pre_turn_report)

    @property
    def controller(self) -> Any:
        _require_issue94_successor_owner_handoff(self)
        return self._controller

    @property
    def identity(self) -> dict[str, Any]:
        _require_issue94_successor_owner_handoff(self)
        return deepcopy(self._identity)

    @property
    def pre_spawn_program(self) -> dict[str, Any]:
        _require_issue94_successor_owner_handoff(self)
        return deepcopy(self._pre_spawn_program)

    def observe_native_action(
        self,
        *,
        action: Mapping[str, Any],
        task_id: str,
        turn_id: str,
        thread_read_sha256: str,
        tool_use_id: str,
        result_binding: Mapping[str, Any],
        outcome: str = "completed",
    ) -> dict[str, Any]:
        """Advance one real call observed on this retained owner connection."""

        _require_issue94_successor_owner_handoff(self)
        if (
            not isinstance(action, Mapping)
            or task_id != self._identity.get("root_task_id")
            or not _text(turn_id)
            or not _is_sha(thread_read_sha256)
            or not _text(tool_use_id)
            or not isinstance(result_binding, Mapping)
            or outcome != "completed"
        ):
            raise QualificationSuccessorError(
                "successor_owner_handoff:native_observation_invalid"
            )
        receipt = {
            "schema": native_controller.NATIVE_ACTION_RECEIPT_SCHEMA,
            "action_id": action.get("action_id"),
            "outcome": outcome,
            "tool_name": action.get("tool_name"),
            "tool_input_sha256": action.get("tool_input_sha256"),
            "tool_use_id": tool_use_id,
            "result_sha256": _sha(result_binding),
            "result_binding": deepcopy(dict(result_binding)),
            "source_pointer": "retained-owner-thread-read#" + thread_read_sha256,
        }
        observation_core = {
            "schema": native_controller.RETAINED_OWNER_OBSERVATION_SCHEMA,
            "status": "OBSERVED",
            "task_id": task_id,
            "session_id": task_id,
            "turn_id": turn_id,
            "thread_read_sha256": thread_read_sha256,
            "tool_call_id": tool_use_id,
            "native_receipt_sha256": _sha(receipt),
        }
        owner_observation = {
            **observation_core,
            "report_sha256": _sha(observation_core),
        }
        authority = self._controller.grants.canonical_authority()
        tip = authority.get("tip") if isinstance(authority, Mapping) else None
        owner = (
            authority.get("owner") if isinstance(authority, Mapping) else None
        )
        if (
            authority.get("status") != "VERIFIED"
            or not isinstance(tip, Mapping)
            or not isinstance(owner, Mapping)
            or owner.get("controller_id") != self._identity.get("controller_id")
        ):
            raise QualificationSuccessorError(
                "successor_owner_handoff:controller_unavailable"
            )
        program = {
            "schema": native_controller.PROGRAM_SCHEMA,
            "controller_id": owner["controller_id"],
            "operation": "observe",
            "expected_cursor": deepcopy(dict(tip)),
            "payload": {
                "schema": native_controller.ACTION_OBSERVATION_SCHEMA,
                "action_id": action.get("action_id"),
                "tool_name": action.get("tool_name"),
                "tool_input_sha256": action.get("tool_input_sha256"),
                "tool_use_id": tool_use_id,
                "outcome": outcome,
                "retained_owner_observation": owner_observation,
                "native_receipt": receipt,
            },
        }
        report = self._controller.advance(program)
        if (
            not isinstance(report, Mapping)
            or report.get("status") != "PASS"
            or report.get("decision")
            not in {"ACTION_AUTHORIZED", "ACTION_OBSERVED"}
            or report.get("issues") != []
        ):
            raise QualificationSuccessorError(
                "successor_owner_handoff:native_observation_refused",
                issues=(
                    [str(issue) for issue in report.get("issues", [])]
                    + ["decision:" + str(report.get("decision"))]
                    if isinstance(report, Mapping)
                    else ["report:invalid"]
                ),
            )
        return deepcopy(dict(report))

    def terminal_ready(self, report: Any) -> bool:
        """Accept only the source reader's final pre-qualification frontier.

        The dispatched MCP response may carry either the historical
        ``ACTION_ADVANCE_RESULT_ARTIFACT_SCHEMA`` (v1, full action embedded)
        or the current-generation
        ``ACTION_ADVANCE_RESULT_ARTIFACT_V2_SCHEMA`` (digest-only
        ``action_projection``). Both forms round-trip through the same
        :func:`resolve_issue94_action_advance_mcp_result` resolver, which
        reads the create-only artifact and reconstructs the canonical full
        v5 report back; that close dispatch is independent of the receipt
        schema field so a transport-time v2 receipt does not change the
        terminal-frontier semantic gate.
        """

        _require_issue94_successor_owner_handoff(self)
        try:
            value = report
            if is_issue94_action_advance_result_artifact_receipt(report):
                value = resolve_issue94_action_advance_mcp_result(
                    dict(report),
                    pre_turn_report_path=self.pre_turn_report_path,
                    expected_report_sha256=self.pre_turn_report_sha256,
                    current_task_id=str(self._identity["root_task_id"]),
                )
            validation = validate_issue94_successor_action_advance_report(value)
            return bool(
                validation.get("valid") is True
                and isinstance(value, Mapping)
                and value.get("status") == "PASS"
                and value.get("decision") == "AWAITING_ATTEMPT_QUALIFICATION"
                and value.get("action") is None
                and value.get("pre_turn_report_sha256")
                == self.pre_turn_report_sha256
            )
        except (KeyError, TypeError, ValueError, OSError):
            return False

    def close(self) -> None:
        """Close the retained controller once and make teardown terminal."""

        close_lock = _owner_handoff_close_lock(self)
        with close_lock:
            _require_issue94_successor_owner_handoff(self, allow_closed=True)
            if self._close_state == _HANDOFF_CLOSE_CLOSED:
                return
            if self._close_state == _HANDOFF_CLOSE_FAILED:
                raise QualificationSuccessorError(
                    "successor_owner_handoff:cleanup_failed"
                )
            if self._close_state == _HANDOFF_CLOSE_CLOSING:
                raise QualificationSuccessorError(
                    "successor_owner_handoff:close_in_progress"
                )
            if self._close_state != _HANDOFF_CLOSE_OPEN:
                raise QualificationSuccessorError(
                    "successor_owner_handoff:close_state_invalid"
                )

            context = self._context
            self._controller = None
            self._context = None
            self._closed = True
            self._close_state = _HANDOFF_CLOSE_CLOSING
            _refresh_issue94_successor_owner_handoff(self)
        try:
            context.__exit__(None, None, None)
        except BaseException:
            # The retained controller is a generator context manager.  Once
            # its teardown raises, it is exhausted, so a second __exit__ would
            # not retry cleanup.  Keep that outcome visible and terminal.
            with close_lock:
                _require_issue94_successor_owner_handoff(
                    self, allow_closed=True
                )
                if self._close_state != _HANDOFF_CLOSE_CLOSING:
                    raise QualificationSuccessorError(
                        "successor_owner_handoff:close_state_invalid"
                    )
                self._close_state = _HANDOFF_CLOSE_FAILED
                _refresh_issue94_successor_owner_handoff(self)
            raise
        with close_lock:
            _require_issue94_successor_owner_handoff(self, allow_closed=True)
            if self._close_state != _HANDOFF_CLOSE_CLOSING:
                raise QualificationSuccessorError(
                    "successor_owner_handoff:close_state_invalid"
                )
            self._close_state = _HANDOFF_CLOSE_CLOSED
            _refresh_issue94_successor_owner_handoff(self)


def _owner_handoff_fingerprint(value: Issue94SuccessorOwnerHandoff) -> tuple[Any, ...]:
    return (
        value.pre_turn_report_path,
        value.pre_turn_report_sha256,
        _sha(value._pre_turn_report),
        id(value._controller),
        _sha(value._identity),
        _sha(value._pre_spawn_program),
        id(value._context),
        id(value._authority),
        value._closed,
        value._close_state,
    )


def _forget_issue94_successor_owner_handoff(identity: int) -> None:
    _OWNER_HANDOFFS.pop(identity, None)
    _OWNER_HANDOFF_CLOSE_LOCKS.pop(identity, None)


def _issue_owner_handoff(value: Issue94SuccessorOwnerHandoff) -> Issue94SuccessorOwnerHandoff:
    identity = id(value)
    _OWNER_HANDOFFS[identity] = (
        weakref.ref(
            value,
            lambda _: _forget_issue94_successor_owner_handoff(identity),
        ),
        os.getpid(),
        _owner_handoff_fingerprint(value),
    )
    _OWNER_HANDOFF_CLOSE_LOCKS[identity] = threading.Lock()
    return value


def _owner_handoff_close_lock(
    value: Any,
) -> threading.Lock:
    """Return the original process-local close lock for one issued handoff."""

    identity = id(value)
    record = _OWNER_HANDOFFS.get(identity)
    close_lock = _OWNER_HANDOFF_CLOSE_LOCKS.get(identity)
    if (
        type(value) is not Issue94SuccessorOwnerHandoff
        or record is None
        or record[0]() is not value
        or record[1] != os.getpid()
        or close_lock is None
    ):
        raise QualificationSuccessorError(
            "successor_owner_handoff:issued_object_required"
        )
    return close_lock


def _refresh_issue94_successor_owner_handoff(
    value: Issue94SuccessorOwnerHandoff,
) -> None:
    """Keep the exact issued-object record bound through terminal teardown."""

    identity = id(value)
    record = _OWNER_HANDOFFS.get(identity)
    if (
        record is None
        or record[0]() is not value
        or record[1] != os.getpid()
    ):
        raise QualificationSuccessorError(
            "successor_owner_handoff:issued_object_required"
        )
    _OWNER_HANDOFFS[identity] = (
        record[0],
        record[1],
        _owner_handoff_fingerprint(value),
    )


def _require_issue94_successor_owner_handoff(
    value: Any, *, allow_closed: bool = False
) -> Issue94SuccessorOwnerHandoff:
    record = _OWNER_HANDOFFS.get(id(value))
    if (
        type(value) is not Issue94SuccessorOwnerHandoff
        or record is None
        or record[0]() is not value
        or record[1] != os.getpid()
        or record[2] != _owner_handoff_fingerprint(value)
        or value._authority is not _OWNER_HANDOFF_AUTHORITY
        or type(value._closed) is not bool
        or type(value._close_state) is not str
        or value._close_state not in _HANDOFF_CLOSE_STATES
        or value._closed != (value._close_state != _HANDOFF_CLOSE_OPEN)
        or (value._close_state != _HANDOFF_CLOSE_OPEN and not allow_closed)
    ):
        raise QualificationSuccessorError("successor_owner_handoff:issued_object_required")
    return value


def _clear_owner_handoffs_after_fork() -> None:
    _OWNER_HANDOFFS.clear()
    _OWNER_HANDOFF_CLOSE_LOCKS.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_clear_owner_handoffs_after_fork)


@dataclass(frozen=True, slots=True)
class QualificationPreNativeFailureSettlementArtifact:
    """Strict whole-report handoff for one abandoned pre-native turn."""

    report: dict[str, Any]
    report_sha256: str
    predecessor_controller_id: str
    failure_evidence_sha256: str

    @classmethod
    def from_report(
        cls, report: Any
    ) -> "QualificationPreNativeFailureSettlementArtifact":
        if (
            not isinstance(report, Mapping)
            or set(report) != _PRE_NATIVE_FAILURE_SETTLEMENT_FIELDS
        ):
            raise QualificationSuccessorError(
                "pre_native_failure_settlement:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        program = value.get("controller_program")
        controller_report = value.get("controller_report")
        before = value.get("predecessor_authority_before")
        after = value.get("predecessor_authority_after")
        boundary = value.get("boundary")
        counters = value.get("counters")
        evidence = (
            program.get("failure_evidence")
            if isinstance(program, Mapping)
            else None
        )
        controller_id = (
            program.get("controller_id")
            if isinstance(program, Mapping)
            else None
        )
        before_lifecycle = (
            before.get("lifecycle")
            if isinstance(before, Mapping)
            and isinstance(before.get("lifecycle"), Mapping)
            else None
        )
        after_lifecycle = (
            after.get("lifecycle")
            if isinstance(after, Mapping)
            and isinstance(after.get("lifecycle"), Mapping)
            else None
        )
        controller_state = (
            controller_report.get("controller_state")
            if isinstance(controller_report, Mapping)
            and isinstance(controller_report.get("controller_state"), Mapping)
            else None
        )
        if (
            value.get("schema")
            != PRE_NATIVE_FAILURE_SETTLEMENT_REPORT_SCHEMA
            or value.get("status") != "PASS"
            or value.get("decision")
            != "PRE_NATIVE_FAILURE_TERMINALIZED"
            or value.get("issues") != []
            or not _text(value.get("evaluation_time"))
            or not isinstance(program, Mapping)
            or set(program)
            != {
                "schema",
                "controller_id",
                "expected_cursor",
                "failure_evidence",
            }
            or program.get("schema")
            != native_controller.PRE_NATIVE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA
            or not _text(controller_id)
            or not isinstance(evidence, Mapping)
            or not _is_sha(evidence.get("evidence_sha256"))
            or not isinstance(before, Mapping)
            or before.get("status") != "VERIFIED"
            or before.get("tip") != program.get("expected_cursor")
            or not isinstance(before_lifecycle, Mapping)
            or before_lifecycle.get("expected_binding_status") != "WAITING"
            or before_lifecycle.get("terminal") is not False
            or before_lifecycle.get("pending_intent") is not False
            or before_lifecycle.get("cleanup_required") is not False
            or before_lifecycle.get("action_sha256") is not None
            or before_lifecycle.get("grant_state") is not None
            or before_lifecycle.get("tool_use_id") is not None
            or not isinstance(after, Mapping)
            or after.get("status") != "VERIFIED"
            or not isinstance(after_lifecycle, Mapping)
            or after_lifecycle.get("expected_binding_status") != "TERMINAL"
            or after_lifecycle.get("terminal") is not True
            or after_lifecycle.get("pending_intent") is not False
            or after_lifecycle.get("cleanup_required") is not False
            or after_lifecycle.get("action_sha256") is not None
            or after_lifecycle.get("grant_state") is not None
            or after_lifecycle.get("tool_use_id") is not None
            or not isinstance(controller_report, Mapping)
            or controller_report.get("schema") != native_controller.REPORT_SCHEMA
            or controller_report.get("status") != "PASS"
            or controller_report.get("decision")
            != "PRE_NATIVE_FAILURE_TERMINALIZED"
            or controller_report.get("controller_id") != controller_id
            or controller_report.get("issues") != []
            or controller_report.get("cursor") != after.get("tip")
            or not isinstance(controller_state, Mapping)
            or controller_state.get("terminal") is not True
            or controller_state.get("pending_intent") is not False
            or controller_state.get("cleanup_required") is not False
            or controller_state.get("action_authorized") is not False
            or controller_report.get("action") is not None
            or controller_report.get("provider_free") is not True
            or not _sealed(controller_report, "report_sha256")
            or boundary
            != {
                "native_action_called": False,
                "next_transition": "terminal_predecessor_capacity_check",
                "provider_boundary_crossed": False,
                "successor_activation_started": False,
                "task_created": False,
                "worker_created": False,
            }
            or value.get("provider_free") is not True
            or counters
            != {
                "hosted_calls": 0,
                "model_calls": 0,
                "native_actions": 0,
                "network_calls": 0,
                "provider_calls": 0,
                "task_creations": 0,
                "terminalizations": 1,
                "worker_creations": 0,
            }
            or not _sealed(value, "report_sha256")
        ):
            raise QualificationSuccessorError(
                "pre_native_failure_settlement:report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            predecessor_controller_id=str(controller_id),
            failure_evidence_sha256=str(evidence["evidence_sha256"]),
        )


@dataclass(frozen=True, slots=True)
class QualificationPartialNativeFailureRecoveryArtifact:
    """Strict whole-report recovery for one interrupted partial batch."""

    report: dict[str, Any]
    report_sha256: str
    predecessor_controller_id: str
    released_authority_lane_ids: list[str]

    @classmethod
    def from_report(
        cls, report: Any
    ) -> "QualificationPartialNativeFailureRecoveryArtifact":
        if (
            not isinstance(report, Mapping)
            or set(report) != _PARTIAL_NATIVE_FAILURE_RECOVERY_FIELDS
        ):
            raise QualificationSuccessorError(
                "partial_native_failure_recovery:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        program = value.get("controller_program")
        controller = value.get("controller_report")
        before = value.get("predecessor_authority_before")
        after = value.get("predecessor_authority_after")
        before_lifecycle = (
            before.get("lifecycle")
            if isinstance(before, Mapping)
            and isinstance(before.get("lifecycle"), Mapping)
            else None
        )
        after_lifecycle = (
            after.get("lifecycle")
            if isinstance(after, Mapping)
            and isinstance(after.get("lifecycle"), Mapping)
            else None
        )
        capacity_before = value.get("capacity_authority_before")
        capacity_after = value.get("capacity_authority_after")
        before_active = _capacity_active_lane_ids(capacity_before)
        after_active = _capacity_active_lane_ids(capacity_after)
        receipts = value.get("release_receipts")
        settlement_program = value.get("settlement_program")
        settlement = value.get("settlement_report")
        controller_id = (
            program.get("controller_id")
            if isinstance(program, Mapping)
            else None
        )
        if (
            value.get("schema")
            != PARTIAL_NATIVE_FAILURE_RECOVERY_REPORT_SCHEMA
            or value.get("status") != "PASS"
            or value.get("decision") != "PARTIAL_NATIVE_FAILURE_RECOVERED"
            or value.get("issues") != []
            or not _text(value.get("evaluation_time"))
            or not isinstance(program, Mapping)
            or program.get("schema")
            != native_controller.PARTIAL_NATIVE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA
            or not _text(controller_id)
            or not isinstance(controller, Mapping)
            or controller.get("schema") != native_controller.REPORT_SCHEMA
            or controller.get("status") != "PASS"
            or controller.get("decision")
            != "PARTIAL_NATIVE_FAILURE_TERMINALIZED"
            or controller.get("controller_id") != controller_id
            or controller.get("issues") != []
            or controller.get("action") is not None
            or not _sealed(controller, "report_sha256")
            or not isinstance(before_lifecycle, Mapping)
            or before_lifecycle.get("expected_binding_status") != "BLOCKED"
            or before_lifecycle.get("grant_state") != "OUTCOME_UNKNOWN"
            or before_lifecycle.get("terminal") is not False
            or not isinstance(after_lifecycle, Mapping)
            or after_lifecycle.get("expected_binding_status") != "TERMINAL"
            or after_lifecycle.get("terminal") is not True
            or after_lifecycle.get("action_sha256") is not None
            or after_lifecycle.get("grant_state") is not None
            or not isinstance(before_active, list)
            or len(before_active) != 2
            or after_active != []
            or not isinstance(receipts, list)
            or len(receipts) != 2
            or sorted(
                receipt.get("lane_id")
                for receipt in receipts
                if isinstance(receipt, Mapping)
            )
            != before_active
            or not all(
                shared_capacity.validate_release_receipt(
                    receipt,
                    lane_id=receipt.get("lane_id"),
                    run_id=receipt.get("run_id"),
                    route="native_luna",
                    terminal_state="failed",
                )
                for receipt in receipts
                if isinstance(receipt, Mapping)
            )
            or not isinstance(settlement_program, Mapping)
            or settlement_program.get("schema")
            != governed_attempt.PROGRAM_SCHEMA
            or settlement_program.get("operation")
            != "capacity_settlement"
            or not isinstance(settlement, Mapping)
            or settlement.get("schema") != governed_attempt.REPORT_SCHEMA
            or settlement.get("status") != "PASS"
            or settlement.get("disposition") != "CAPACITY_RELEASED"
            or settlement.get("issues") != []
            or value.get("boundary")
            != {
                "native_action_called": False,
                "next_transition": "fresh_successor_activation",
                "provider_boundary_crossed": False,
                "successor_activation_started": False,
                "task_created": False,
                "worker_created": False,
            }
            or value.get("provider_free") is not True
            or value.get("counters")
            != {
                "capacity_lanes_released": 2,
                "cleanup_observer_receipts_issued": 2,
                "host_seed_credential_reads": 1,
                "hosted_calls": 0,
                "model_calls": 0,
                "native_actions": 0,
                "network_calls": 0,
                "provider_calls": 0,
                "task_creations": 0,
                "terminalizations": 1,
                "worker_creations": 0,
            }
            or not _sealed(value, "report_sha256")
        ):
            raise QualificationSuccessorError(
                "partial_native_failure_recovery:report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            predecessor_controller_id=str(controller_id),
            released_authority_lane_ids=list(before_active),
        )


@dataclass(frozen=True, slots=True)
class QualificationPostSpawnFailureRecoveryArtifact:
    """Strict whole-report recovery for the Cycle 31 two-worker deadlock."""

    report: dict[str, Any]
    report_sha256: str
    predecessor_controller_id: str
    released_authority_lane_ids: list[str]

    @classmethod
    def from_report(
        cls, report: Any
    ) -> "QualificationPostSpawnFailureRecoveryArtifact":
        if (
            not isinstance(report, Mapping)
            or set(report) != _POST_SPAWN_FAILURE_RECOVERY_FIELDS
        ):
            raise QualificationSuccessorError(
                "post_spawn_failure_recovery:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        program = value.get("controller_program")
        controller = value.get("controller_report")
        before = value.get("predecessor_authority_before")
        after = value.get("predecessor_authority_after")
        before_lifecycle = (
            before.get("lifecycle")
            if isinstance(before, Mapping)
            and isinstance(before.get("lifecycle"), Mapping)
            else None
        )
        after_lifecycle = (
            after.get("lifecycle")
            if isinstance(after, Mapping)
            and isinstance(after.get("lifecycle"), Mapping)
            else None
        )
        capacity_before = value.get("capacity_authority_before")
        capacity_after = value.get("capacity_authority_after")
        before_active = _capacity_active_lane_ids(capacity_before)
        after_active = _capacity_active_lane_ids(capacity_after)
        receipts = value.get("release_receipts")
        settlement_program = value.get("settlement_program")
        settlement = value.get("settlement_report")
        controller_id = (
            program.get("controller_id")
            if isinstance(program, Mapping)
            else None
        )
        if (
            value.get("schema")
            != POST_SPAWN_FAILURE_RECOVERY_REPORT_SCHEMA
            or value.get("status") != "PASS"
            or value.get("decision")
            != "POST_SPAWN_FAILURE_RECOVERED"
            or value.get("issues") != []
            or not _text(value.get("evaluation_time"))
            or not isinstance(program, Mapping)
            or program.get("schema")
            != native_controller.POST_SPAWN_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA
            or not _text(controller_id)
            or not isinstance(controller, Mapping)
            or controller.get("schema") != native_controller.REPORT_SCHEMA
            or controller.get("status") != "PASS"
            or controller.get("decision")
            != "POST_SPAWN_FAILURE_TERMINALIZED"
            or controller.get("controller_id") != controller_id
            or controller.get("issues") != []
            or controller.get("action") is not None
            or not _sealed(controller, "report_sha256")
            or not isinstance(before_lifecycle, Mapping)
            or before_lifecycle.get("expected_binding_status") != "WAITING"
            or before_lifecycle.get("cleanup_required") is not True
            or before_lifecycle.get("grant_state") is not None
            or before_lifecycle.get("terminal") is not False
            or not isinstance(after_lifecycle, Mapping)
            or after_lifecycle.get("expected_binding_status") != "TERMINAL"
            or after_lifecycle.get("terminal") is not True
            or after_lifecycle.get("cleanup_required") is not False
            or after_lifecycle.get("action_sha256") is not None
            or after_lifecycle.get("grant_state") is not None
            or not isinstance(before_active, list)
            or len(before_active) != 2
            or after_active != []
            or not isinstance(receipts, list)
            or len(receipts) != 2
            or sorted(
                receipt.get("lane_id")
                for receipt in receipts
                if isinstance(receipt, Mapping)
            )
            != before_active
            or any(
                not isinstance(receipt, Mapping)
                or receipt.get("cleanup_status") != "complete"
                or not shared_capacity.validate_release_receipt(
                    receipt,
                    lane_id=receipt.get("lane_id"),
                    run_id=receipt.get("run_id"),
                    route="native_luna",
                    terminal_state="failed",
                )
                for receipt in receipts
            )
            or not isinstance(settlement_program, Mapping)
            or settlement_program.get("schema")
            != governed_attempt.PROGRAM_SCHEMA
            or settlement_program.get("operation")
            != "capacity_settlement"
            or not isinstance(settlement, Mapping)
            or settlement.get("schema") != governed_attempt.REPORT_SCHEMA
            or settlement.get("status") != "PASS"
            or settlement.get("disposition") != "CAPACITY_RELEASED"
            or settlement.get("issues") != []
            or value.get("boundary")
            != {
                "native_action_called": False,
                "next_transition": "fresh_successor_activation",
                "provider_boundary_crossed": False,
                "successor_activation_started": False,
                "task_created": False,
                "worker_created": False,
            }
            or value.get("provider_free") is not True
            or value.get("counters")
            != {
                "capacity_lanes_released": 2,
                "cleanup_observer_receipts_issued": 2,
                "host_seed_credential_reads": 1,
                "hosted_calls": 0,
                "model_calls": 0,
                "native_actions": 0,
                "network_calls": 0,
                "provider_calls": 0,
                "task_creations": 0,
                "terminalizations": 1,
                "worker_creations": 0,
            }
            or not _sealed(value, "report_sha256")
        ):
            raise QualificationSuccessorError(
                "post_spawn_failure_recovery:report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            predecessor_controller_id=str(controller_id),
            released_authority_lane_ids=list(before_active),
        )


@dataclass(frozen=True, slots=True)
class QualificationPostAckBridgeFailureRecoveryArtifact:
    """Strict whole-report recovery for a profiled ACK bridge failure."""

    report: dict[str, Any]
    report_sha256: str
    predecessor_controller_id: str
    released_authority_lane_ids: list[str]

    @classmethod
    def from_report(
        cls, report: Any
    ) -> "QualificationPostAckBridgeFailureRecoveryArtifact":
        if (
            not isinstance(report, Mapping)
            or set(report) != _POST_ACK_BRIDGE_FAILURE_RECOVERY_FIELDS
        ):
            raise QualificationSuccessorError(
                "post_ack_bridge_failure_recovery:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        program = value.get("controller_program")
        controller = value.get("controller_report")
        before = value.get("predecessor_authority_before")
        after = value.get("predecessor_authority_after")
        before_lifecycle = (
            before.get("lifecycle")
            if isinstance(before, Mapping)
            and isinstance(before.get("lifecycle"), Mapping)
            else None
        )
        after_lifecycle = (
            after.get("lifecycle")
            if isinstance(after, Mapping)
            and isinstance(after.get("lifecycle"), Mapping)
            else None
        )
        capacity_before = value.get("capacity_authority_before")
        capacity_after = value.get("capacity_authority_after")
        before_active = _capacity_active_lane_ids(capacity_before)
        after_active = _capacity_active_lane_ids(capacity_after)
        receipts = value.get("release_receipts")
        settlement_program = value.get("settlement_program")
        settlement = value.get("settlement_report")
        controller_id = (
            program.get("controller_id")
            if isinstance(program, Mapping)
            else None
        )
        failure_evidence = (
            program.get("failure_evidence")
            if isinstance(program, Mapping)
            and isinstance(program.get("failure_evidence"), Mapping)
            else {}
        )
        pending_continuation_denial = (
            failure_evidence.get("schema")
            == native_controller.POST_ACK_BRIDGE_FAILURE_EVIDENCE_SCHEMA_V2
        )
        before_lifecycle_valid = bool(
            isinstance(before_lifecycle, Mapping)
            and before_lifecycle.get("cleanup_required") is False
            and before_lifecycle.get("terminal") is False
            and before_lifecycle.get("tool_use_id") is None
            and (
                (
                    not pending_continuation_denial
                    and before_lifecycle.get("expected_binding_status")
                    == "WAITING"
                    and before_lifecycle.get("grant_state") is None
                    and before_lifecycle.get("action_sha256") is None
                )
                or (
                    pending_continuation_denial
                    and before_lifecycle.get("expected_binding_status")
                    == "ACTIVE"
                    and before_lifecycle.get("grant_state") == "AUTHORIZED"
                    and _is_sha(before_lifecycle.get("action_sha256"))
                )
            )
        )
        if (
            value.get("schema")
            != POST_ACK_BRIDGE_FAILURE_RECOVERY_REPORT_SCHEMA
            or value.get("status") != "PASS"
            or value.get("decision")
            != "POST_ACK_BRIDGE_FAILURE_RECOVERED"
            or value.get("issues") != []
            or not _text(value.get("evaluation_time"))
            or not isinstance(program, Mapping)
            or program.get("schema")
            != native_controller.POST_ACK_BRIDGE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA
            or not _text(controller_id)
            or not isinstance(controller, Mapping)
            or controller.get("schema") != native_controller.REPORT_SCHEMA
            or controller.get("status") != "PASS"
            or controller.get("decision")
            != "POST_ACK_BRIDGE_FAILURE_TERMINALIZED"
            or controller.get("controller_id") != controller_id
            or controller.get("issues") != []
            or controller.get("action") is not None
            or not _sealed(controller, "report_sha256")
            or not before_lifecycle_valid
            or not isinstance(after_lifecycle, Mapping)
            or after_lifecycle.get("expected_binding_status") != "TERMINAL"
            or after_lifecycle.get("terminal") is not True
            or after_lifecycle.get("cleanup_required") is not False
            or after_lifecycle.get("action_sha256") is not None
            or after_lifecycle.get("grant_state") is not None
            or not isinstance(before_active, list)
            or len(before_active) != 2
            or after_active != []
            or not isinstance(receipts, list)
            or len(receipts) != 2
            or sorted(
                receipt.get("lane_id")
                for receipt in receipts
                if isinstance(receipt, Mapping)
            )
            != before_active
            or any(
                not isinstance(receipt, Mapping)
                or receipt.get("cleanup_status") != "complete"
                or not shared_capacity.validate_release_receipt(
                    receipt,
                    lane_id=receipt.get("lane_id"),
                    run_id=receipt.get("run_id"),
                    route="native_luna",
                    terminal_state="failed",
                )
                for receipt in receipts
            )
            or not isinstance(settlement_program, Mapping)
            or settlement_program.get("schema")
            != governed_attempt.PROGRAM_SCHEMA
            or settlement_program.get("operation")
            != "capacity_settlement"
            or not isinstance(settlement, Mapping)
            or settlement.get("schema") != governed_attempt.REPORT_SCHEMA
            or settlement.get("status") != "PASS"
            or settlement.get("disposition") != "CAPACITY_RELEASED"
            or settlement.get("issues") != []
            or value.get("boundary")
            != {
                "native_action_called": False,
                "next_transition": "fresh_successor_activation",
                "provider_boundary_crossed": False,
                "successor_activation_started": False,
                "task_created": False,
                "worker_created": False,
            }
            or value.get("provider_free") is not True
            or value.get("counters")
            != {
                "capacity_lanes_released": 2,
                "cleanup_observer_receipts_issued": 2,
                "host_seed_credential_reads": 1,
                "hosted_calls": 0,
                "model_calls": 0,
                "native_actions": 0,
                "network_calls": 0,
                "provider_calls": 0,
                "task_creations": 0,
                "terminalizations": 1,
                "worker_creations": 0,
            }
            or not _sealed(value, "report_sha256")
        ):
            raise QualificationSuccessorError(
                "post_ack_bridge_failure_recovery:report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            predecessor_controller_id=str(controller_id),
            released_authority_lane_ids=list(before_active),
        )


@dataclass(frozen=True, slots=True)
class QualificationPredecessorSettlementArtifact:
    """Strict whole-report handoff for terminal predecessor settlement."""

    report: dict[str, Any]
    report_sha256: str
    decision: str
    predecessor_controller_id: str
    released_authority_lane_ids: list[str]
    released_logical_lane_ids: list[str]

    @classmethod
    def from_report(
        cls, report: Any
    ) -> "QualificationPredecessorSettlementArtifact":
        if (
            not isinstance(report, Mapping)
            or set(report) != _SETTLEMENT_REPORT_FIELDS
        ):
            raise QualificationSuccessorError(
                "predecessor_settlement:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        predecessor = value.get("predecessor")
        before = value.get("capacity_authority_before")
        after = value.get("capacity_authority_after")
        decision = value.get("decision")
        released_authority = value.get("released_authority_lane_ids")
        released_logical = value.get("released_logical_lane_ids")
        boundary = value.get("boundary")
        counters = value.get("counters")
        before_active = _capacity_active_lane_ids(before)
        after_active = _capacity_active_lane_ids(after)
        expected_counters = dict(_SETTLEMENT_ZERO_COUNTERS)
        if decision == "SETTLED" and isinstance(released_authority, list):
            expected_counters.update(
                {
                    "capacity_lanes_released": len(released_authority),
                    "cleanup_observer_receipts_issued": len(
                        released_authority
                    ),
                    "host_seed_credential_reads": 1,
                }
            )
        terminalization_report = value.get(
            "pre_native_failure_settlement_report"
        )
        terminalization = (
            QualificationPreNativeFailureSettlementArtifact.from_report(
                terminalization_report
            )
            if isinstance(terminalization_report, Mapping)
            else None
        )
        if decision == "TERMINALIZED":
            expected_counters["pre_native_failures_terminalized"] = 1
        admission = value.get("capacity_admission_report")
        failed = value.get("failed_settlement_report")
        program = value.get("settlement_program")
        settled = value.get("settlement_report")
        settled_valid = bool(
            decision == "SETTLED"
            and isinstance(admission, Mapping)
            and terminalization is None
            and admission.get("schema") == governed_attempt.REPORT_SCHEMA
            and admission.get("status") == "PASS"
            and admission.get("operation") == "capacity_admission"
            and admission.get("disposition") == "SPAWN_AUTHORIZED"
            and admission.get("issues") == []
            and isinstance(failed, Mapping)
            and failed.get("schema") == governed_attempt.REPORT_SCHEMA
            and failed.get("status") == "BLOCKED"
            and failed.get("operation") == "capacity_settlement"
            and failed.get("issues")
            == ["shared_capacity:release_receipt_set_invalid"]
            and isinstance(program, Mapping)
            and program.get("schema") == governed_attempt.PROGRAM_SCHEMA
            and program.get("operation") == "capacity_settlement"
            and isinstance(settled, Mapping)
            and settled.get("schema") == governed_attempt.REPORT_SCHEMA
            and settled.get("status") == "PASS"
            and settled.get("operation") == "capacity_settlement"
            and settled.get("disposition") == "CAPACITY_RELEASED"
            and settled.get("issues") == []
            and before_active == released_authority
            and after_active == []
            and isinstance(released_logical, list)
            and released_logical == [
                lane.rsplit(":", 1)[-1] for lane in released_authority
            ]
        )
        not_required_valid = bool(
            decision == "NOT_REQUIRED"
            and admission is None
            and terminalization is None
            and failed is None
            and program is None
            and settled is None
            and before == after
            and before_active == []
            and after_active == []
            and released_authority == []
            and released_logical == []
        )
        terminalized_valid = bool(
            decision == "TERMINALIZED"
            and terminalization is not None
            and admission is None
            and failed is None
            and program is None
            and settled is None
            and before == after
            and before_active == []
            and after_active == []
            and released_authority == []
            and released_logical == []
            and isinstance(predecessor, Mapping)
            and terminalization.predecessor_controller_id
            == predecessor.get("controller_id")
        )
        if (
            value.get("schema")
            != PREDECESSOR_SETTLEMENT_REPORT_SCHEMA
            or value.get("status") != "PASS"
            or decision not in {"SETTLED", "NOT_REQUIRED", "TERMINALIZED"}
            or value.get("issues") != []
            or not _text(value.get("evaluation_time"))
            or not isinstance(predecessor, Mapping)
            or set(predecessor)
            != {
                "controller_id",
                "controller_run_id",
                "root_task_id",
                "attempt_id",
                "run_id",
                "binding_sha256",
                "authority_sha256",
            }
            or not all(
                _text(predecessor.get(field))
                for field in (
                    "controller_id",
                    "controller_run_id",
                    "root_task_id",
                    "attempt_id",
                    "run_id",
                )
            )
            or not _is_sha(predecessor.get("binding_sha256"))
            or not _is_sha(predecessor.get("authority_sha256"))
            or before_active is None
            or after_active is None
            or not isinstance(released_authority, list)
            or released_authority != sorted(set(released_authority))
            or any(not _text(lane) for lane in released_authority)
            or not isinstance(released_logical, list)
            or released_logical != sorted(set(released_logical))
            or any(not _text(lane) for lane in released_logical)
            or not (settled_valid or not_required_valid or terminalized_valid)
            or boundary
            != {
                "native_action_called": False,
                "next_transition": "successor_activation",
                "provider_boundary_crossed": False,
                "successor_activation_started": False,
                "task_created": False,
                "worker_created": False,
            }
            or value.get("provider_free") is not True
            or counters != expected_counters
            or not _sealed(value, "report_sha256")
        ):
            raise QualificationSuccessorError(
                "predecessor_settlement:report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            decision=str(decision),
            predecessor_controller_id=str(predecessor["controller_id"]),
            released_authority_lane_ids=list(released_authority),
            released_logical_lane_ids=list(released_logical),
        )


@dataclass(frozen=True, slots=True)
class QualificationSuccessorArtifact:
    """Strict access to one complete, pre-turn successor report."""

    report: dict[str, Any]
    report_sha256: str
    root_task_id: str
    root_session_id: str
    root_model: str
    controller_id: str
    next_stage_action: str
    artifacts: dict[str, dict[str, Any]]

    @classmethod
    def from_report(cls, report: Any) -> "QualificationSuccessorArtifact":
        if not isinstance(report, Mapping) or set(report) != _REPORT_FIELDS:
            raise QualificationSuccessorError(
                "successor_pre_turn:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        preactivation = value.get("preactivation_report")
        settlement_report = value.get("predecessor_settlement_report")
        settlement = (
            QualificationPredecessorSettlementArtifact.from_report(
                settlement_report
            )
            if isinstance(settlement_report, Mapping)
            else None
        )
        controller = value.get("controller")
        boundary = value.get("boundary")
        artifacts = value.get("artifacts")
        receipts = value.get("artifact_receipts")
        counters = value.get("counters")
        artifact_names = {
            "qualification",
            "governed_inputs",
            "canary",
            "predecessor_settlement",
            "bootstrap",
            "first_action_preparation",
        }
        valid_references = isinstance(artifacts, Mapping) and set(artifacts) == artifact_names
        if valid_references:
            valid_references = all(
                isinstance(reference, Mapping)
                and set(reference)
                == {"path", "artifact_sha256", "report_sha256"}
                and Path(str(reference.get("path", ""))).is_absolute()
                and _is_sha(reference.get("artifact_sha256"))
                and _is_sha(reference.get("report_sha256"))
                for reference in artifacts.values()
            )
        if (
            value.get("schema") != REPORT_SCHEMA
            or value.get("status") != "PASS"
            or value.get("decision") != DECISION_READY
            or value.get("issues") != []
            or not _text(value.get("case_id"))
            or not isinstance(preactivation, Mapping)
            or preactivation.get("schema") != PREACTIVATION_REPORT_SCHEMA
            or preactivation.get("status") != "PASS"
            or preactivation.get("issues") != []
            or preactivation.get("session_start_observed") is not False
            or preactivation.get("next_required_transition")
            != "turn/start:SessionStart"
            or not _sealed(preactivation, "report_sha256")
            or settlement is None
            or settlement.predecessor_controller_id
            != preactivation.get("predecessor_controller_id")
            or not isinstance(controller, Mapping)
            or set(controller)
            != {
                "controller_id",
                "root_thread_id",
                "root_session_id",
                "root_model",
                "expected_binding_status",
                "next_stage_action",
                "authority_sha256",
            }
            or controller.get("root_thread_id")
            != preactivation.get("root_task_id")
            or controller.get("root_session_id")
            != preactivation.get("root_session_id")
            or controller.get("root_model") != preactivation.get("root_model")
            or controller.get("expected_binding_status") != "WAITING"
            or controller.get("next_stage_action") != "capacity_admission"
            or not _is_sha(controller.get("authority_sha256"))
            or not isinstance(boundary, Mapping)
            or boundary
            != {
                "turn_started": False,
                "next_owner_action": "turn/start",
                "required_hook_event": "SessionStart",
                "live_boundary_crossed": not bool(value.get("provider_free")),
                "native_action_authorized": False,
                "worker_created": False,
            }
            or not isinstance(value.get("provider_free"), bool)
            or not valid_references
            or not isinstance(receipts, Mapping)
            or set(receipts) != artifact_names
            or not isinstance(counters, Mapping)
            or counters
            != {
                "controller_activations": 1,
                "controller_stages": 1,
                "native_actions": 0,
                "predecessor_capacity_settlements": (
                    1 if settlement.decision == "SETTLED" else 0
                ),
                "pre_native_failure_terminalizations": (
                    1 if settlement.decision == "TERMINALIZED" else 0
                ),
                "task_creations": 0,
                "worker_creations": 0,
            }
            or not _sealed(value, "report_sha256")
        ):
            raise QualificationSuccessorError(
                "successor_pre_turn:report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            root_task_id=str(controller["root_thread_id"]),
            root_session_id=str(controller["root_session_id"]),
            root_model=str(controller["root_model"]),
            controller_id=str(controller["controller_id"]),
            next_stage_action=str(controller["next_stage_action"]),
            artifacts={
                name: deepcopy(dict(reference))
                for name, reference in artifacts.items()
            },
        )


@dataclass(frozen=True, slots=True)
class QualificationSuccessorFirstActionPreparationArtifact:
    """Strict prepared controller call consumed after real SessionStart."""

    report: dict[str, Any]
    report_sha256: str
    bootstrap_report_sha256: str
    controller_id: str
    root_task_id: str
    root_model: str
    source_roots: dict[str, str]
    controller_program: dict[str, Any]

    @classmethod
    def from_report(
        cls, report: Any
    ) -> "QualificationSuccessorFirstActionPreparationArtifact":
        if (
            not isinstance(report, Mapping)
            or set(report) != _FIRST_ACTION_PREPARATION_FIELDS
        ):
            raise QualificationSuccessorError(
                "successor_first_action_preparation:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        controller = value.get("controller")
        roots = value.get("source_roots")
        program = value.get("controller_program")
        cursor = (
            program.get("expected_cursor")
            if isinstance(program, Mapping)
            else None
        )
        payload = (
            program.get("payload")
            if isinstance(program, Mapping)
            else None
        )
        stage_program = (
            payload.get("stage_program")
            if isinstance(payload, Mapping)
            else None
        )
        proposal = (
            payload.get("proposed_action")
            if isinstance(payload, Mapping)
            else None
        )
        identity = (
            stage_program.get("identity")
            if isinstance(stage_program, Mapping)
            else None
        )
        predecessor = (
            stage_program.get("predecessor_receipt")
            if isinstance(stage_program, Mapping)
            else None
        )
        task_specs = (
            predecessor.get("bindings", {}).get("task_specs")
            if isinstance(predecessor, Mapping)
            and isinstance(predecessor.get("bindings"), Mapping)
            else None
        )
        expected_action_id = (
            _first_action_action_id(
                bootstrap_report_sha256=value.get(
                    "bootstrap_report_sha256"
                ),
                controller_id=controller.get("controller_id"),
                expected_cursor=cursor,
            )
            if isinstance(controller, Mapping)
            else None
        )
        if (
            value.get("schema")
            != FIRST_ACTION_PREPARATION_REPORT_SCHEMA
            or value.get("status") != "PASS"
            or value.get("decision")
            != FIRST_ACTION_PREPARATION_DECISION_READY
            or value.get("issues") != []
            or not _is_sha(value.get("bootstrap_report_sha256"))
            or not isinstance(controller, Mapping)
            or set(controller)
            != {
                "controller_id",
                "root_task_id",
                "root_model",
                "expected_binding_status",
                "next_stage_action",
                "native_adapter_sha256",
                "expected_cursor_sha256",
            }
            or not all(
                _text(controller.get(field))
                for field in (
                    "controller_id",
                    "root_task_id",
                    "root_model",
                )
            )
            or controller.get("expected_binding_status") != "WAITING"
            or controller.get("next_stage_action")
            != "capacity_admission"
            or not _is_sha(controller.get("native_adapter_sha256"))
            or not _is_sha(controller.get("expected_cursor_sha256"))
            or not isinstance(roots, Mapping)
            or set(roots) != {"evidence", "source"}
            or any(
                not isinstance(root, str) or not Path(root).is_absolute()
                for root in roots.values()
            )
            or not isinstance(program, Mapping)
            or set(program)
            != {
                "schema",
                "controller_id",
                "operation",
                "expected_cursor",
                "payload",
            }
            or program.get("schema") != native_controller.PROGRAM_SCHEMA
            or program.get("controller_id")
            != controller.get("controller_id")
            or program.get("operation") != "stage"
            or not isinstance(cursor, Mapping)
            or controller.get("expected_cursor_sha256") != _sha(cursor)
            or not isinstance(stage_program, Mapping)
            or stage_program.get("schema")
            != governed_attempt.PROGRAM_SCHEMA
            or stage_program.get("operation") != "capacity_admission"
            or not isinstance(identity, Mapping)
            or identity.get("root_task_id")
            != controller.get("root_task_id")
            or identity.get("root_model") != controller.get("root_model")
            or not isinstance(predecessor, Mapping)
            or predecessor.get("next_action") != "capacity_admission"
            or not isinstance(task_specs, list)
            or len(task_specs) != 2
            or not all(isinstance(row, Mapping) for row in task_specs)
            or sorted(
                row.get("logical_worker_id")
                for row in task_specs
                if isinstance(row, Mapping)
            )
            != ["spec", "standards"]
            or not isinstance(proposal, Mapping)
            or set(proposal)
            != {
                "schema",
                "action_id",
                "kind",
                "actor_thread_id",
                "adapter_sha256",
            }
            or proposal.get("schema")
            != native_controller.ACTION_PROPOSAL_SCHEMA
            or proposal.get("action_id") != expected_action_id
            or proposal.get("kind") != "spawn"
            or proposal.get("actor_thread_id")
            != controller.get("root_task_id")
            or proposal.get("adapter_sha256")
            != controller.get("native_adapter_sha256")
            or value.get("boundary")
            != {
                "controller_advanced": False,
                "native_action_called": False,
                "next_consumer": (
                    "authorize_issue94_successor_first_action"
                ),
                "session_start_observed": False,
            }
            or value.get("provider_free") is not True
            or value.get("counters")
            != _FIRST_ACTION_PREPARATION_COUNTERS
            or not _sealed(value, "report_sha256")
        ):
            raise QualificationSuccessorError(
                "successor_first_action_preparation:report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            bootstrap_report_sha256=str(
                value["bootstrap_report_sha256"]
            ),
            controller_id=str(controller["controller_id"]),
            root_task_id=str(controller["root_task_id"]),
            root_model=str(controller["root_model"]),
            source_roots={
                str(name): str(root) for name, root in roots.items()
            },
            controller_program=deepcopy(dict(program)),
        )


@dataclass(frozen=True, slots=True)
class QualificationSuccessorFirstActionArtifact:
    """Strict whole-report handoff immediately before the native spawn."""

    report: dict[str, Any]
    report_sha256: str
    controller_program: dict[str, Any]
    controller_report: dict[str, Any]
    action: dict[str, Any]

    @classmethod
    def from_report(
        cls, report: Any
    ) -> "QualificationSuccessorFirstActionArtifact":
        if not isinstance(report, Mapping) or set(report) != _FIRST_ACTION_FIELDS:
            raise QualificationSuccessorError(
                "successor_first_action:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        startup = value.get("startup_observation")
        source_roots = value.get("source_roots")
        program = value.get("controller_program")
        controller = value.get("controller_report")
        action = value.get("action")
        boundary = value.get("boundary")
        controller_state = (
            controller.get("controller_state")
            if isinstance(controller, Mapping)
            else None
        )
        proposal = (
            program.get("payload", {}).get("proposed_action")
            if isinstance(program, Mapping)
            and isinstance(program.get("payload"), Mapping)
            else None
        )
        stage_program = (
            program.get("payload", {}).get("stage_program")
            if isinstance(program, Mapping)
            and isinstance(program.get("payload"), Mapping)
            else None
        )
        predecessor_receipt = (
            stage_program.get("predecessor_receipt")
            if isinstance(stage_program, Mapping)
            else None
        )
        receipt_bindings = (
            predecessor_receipt.get("bindings")
            if isinstance(predecessor_receipt, Mapping)
            else None
        )
        task_specs = (
            receipt_bindings.get("task_specs")
            if isinstance(receipt_bindings, Mapping)
            else None
        )
        spec_route = next(
            (
                candidate
                for candidate in task_specs
                if isinstance(candidate, Mapping)
                and candidate.get("logical_worker_id") == "spec"
            ),
            None,
        ) if isinstance(task_specs, list) else None
        action_core = (
            {key: child for key, child in action.items() if key != "action_sha256"}
            if isinstance(action, Mapping)
            else {}
        )
        startup_controller = (
            startup.get("controller")
            if isinstance(startup, Mapping)
            else None
        )
        startup_continuation = (
            startup.get("continuation")
            if isinstance(startup, Mapping)
            else None
        )
        if (
            value.get("schema") != FIRST_ACTION_REPORT_SCHEMA
            or value.get("status") != "PASS"
            or value.get("decision") != FIRST_ACTION_DECISION_READY
            or value.get("issues") != []
            or not _is_sha(value.get("pre_turn_report_sha256"))
            or not isinstance(startup, Mapping)
            or startup.get("schema")
            != RETAINED_OWNER_STARTUP_BINDING_SCHEMA
            or startup.get("status") != "PASS"
            or startup.get("decision") != "READY_FOR_CAPACITY_ADMISSION"
            or startup.get("pre_turn_report_sha256")
            != value.get("pre_turn_report_sha256")
            or not isinstance(startup_controller, Mapping)
            or set(startup_controller)
            != {
                "authority_sha256",
                "controller_id",
                "expected_binding_status",
                "next_stage_action",
            }
            or not _is_sha(startup_controller.get("authority_sha256"))
            or startup_controller.get("expected_binding_status")
            != "WAITING"
            or startup_controller.get("next_stage_action")
            != "capacity_admission"
            or not isinstance(startup_continuation, Mapping)
            or set(startup_continuation)
            != {
                "additional_session_start_required",
                "model",
                "owner_connection",
                "reconnect_allowed",
                "root_session_id",
                "root_thread_id",
            }
            or startup_continuation.get("root_thread_id")
            != startup_continuation.get("root_session_id")
            or not _text(startup_continuation.get("root_thread_id"))
            or not _text(startup_continuation.get("model"))
            or startup_continuation.get("owner_connection") != "retained"
            or startup_continuation.get("reconnect_allowed") is not False
            or startup_continuation.get(
                "additional_session_start_required"
            )
            is not False
            or not _sealed(startup, "report_sha256")
            or not isinstance(source_roots, Mapping)
            or set(source_roots) != {"evidence", "source"}
            or not all(
                isinstance(root, str) and Path(root).is_absolute()
                for root in source_roots.values()
            )
            or not isinstance(program, Mapping)
            or set(program)
            != {
                "schema",
                "controller_id",
                "operation",
                "expected_cursor",
                "payload",
            }
            or program.get("schema") != native_controller.PROGRAM_SCHEMA
            or program.get("operation") != "stage"
            or startup_controller.get("controller_id")
            != program.get("controller_id")
            or not isinstance(program.get("expected_cursor"), Mapping)
            or not isinstance(stage_program, Mapping)
            or stage_program.get("schema") != governed_attempt.PROGRAM_SCHEMA
            or stage_program.get("operation") != "capacity_admission"
            or not isinstance(spec_route, Mapping)
            or not _text(spec_route.get("model"))
            or not _text(spec_route.get("effort"))
            or not isinstance(proposal, Mapping)
            or proposal.get("schema")
            != native_controller.ACTION_PROPOSAL_SCHEMA
            or proposal.get("kind") != "spawn"
            or not isinstance(controller, Mapping)
            or controller.get("schema") != native_controller.REPORT_SCHEMA
            or controller.get("status") != "PASS"
            or controller.get("decision") != "ACTION_AUTHORIZED"
            or controller.get("issues") != []
            or controller.get("controller_id") != program.get("controller_id")
            or controller.get("next_stage_action") != "spawn"
            or controller.get("action") != action
            or controller.get("provider_free") is not True
            or any(
                controller.get(counter) != 0
                for counter in (
                    "hosted_calls",
                    "model_calls",
                    "native_calls",
                    "task_creations",
                    "worker_creations",
                    "credential_reads",
                )
            )
            or controller.get("authority_grants_minted") != 0
            or controller.get("native_action_authorizations") != 1
            or not _sealed(controller, "report_sha256")
            or not isinstance(controller_state, Mapping)
            or controller_state.get("action_authorized") is not True
            or controller_state.get("grant_state") != "AUTHORIZED"
            or controller_state.get("terminal") is not False
            or controller_state.get("pending_intent") is not False
            or controller_state.get("cleanup_required") is not False
            or not isinstance(action, Mapping)
            or action.get("schema") != native_controller.ACTION_SCHEMA
            or action.get("controller_id") != program.get("controller_id")
            or action.get("kind") != "spawn"
            or action.get("actor_thread_id")
            != startup_continuation.get("root_thread_id")
            or action.get("tool_name") != "multi_agent_v1__spawn_agent"
            or action.get("batch_lane_ids") != ["spec", "standards"]
            or action.get("batch_size") != 2
            or action.get("batch_index") != 0
            or action.get("lane_ids") != ["spec"]
            or not isinstance(action.get("tool_input"), Mapping)
            or set(action["tool_input"])
            != {
                "fork_context",
                "message",
                "model",
                "reasoning_effort",
            }
            or action["tool_input"].get("fork_context") is not False
            or action["tool_input"].get("model")
            != spec_route.get("model")
            or action["tool_input"].get("reasoning_effort")
            != spec_route.get("effort")
            or action.get("tool_input_sha256") != _sha(action["tool_input"])
            or action.get("action_sha256") != _sha(action_core)
            or boundary
            != {
                "native_action_called": False,
                "next_action": "multi_agent_v1__spawn_agent",
                "task_created": False,
                "worker_created": False,
            }
            or value.get("provider_free") is not True
            or value.get("counters") != _FIRST_ACTION_COUNTERS
            or not _sealed(value, "report_sha256")
        ):
            raise QualificationSuccessorError(
                "successor_first_action:report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            controller_program=deepcopy(dict(program)),
            controller_report=deepcopy(dict(controller)),
            action=deepcopy(dict(action)),
        )


def _retained_authorized_continuation(
    action: Any,
    lifecycle: Any,
    *,
    controller_id: Any,
    actor_thread_id: Any,
) -> bool:
    """Accept a later batch action already authorized by canonical state."""

    batch = native_controller.GovernedNativeController._batch_fields(action)
    if not isinstance(action, Mapping) or not isinstance(batch, Mapping):
        return False
    action_core = {
        key: child for key, child in action.items() if key != "action_sha256"
    }
    return bool(
        isinstance(lifecycle, Mapping)
        and lifecycle.get("expected_binding_status") == "ACTIVE"
        and lifecycle.get("grant_state") == "AUTHORIZED"
        and lifecycle.get("tool_use_id") is None
        and lifecycle.get("action_sha256") == action.get("action_sha256")
        and action.get("schema") == native_controller.ACTION_SCHEMA
        and action.get("controller_id") == controller_id
        and action.get("actor_thread_id") == actor_thread_id
        and action.get("tool_input_sha256") == _sha(action.get("tool_input"))
        and action.get("action_sha256") == _sha(action_core)
        and action.get("batch_phase") == "primary"
        and type(action.get("batch_index")) is int
        and action["batch_index"] > 0
        and (
            (
                action.get("kind") == "continue"
                and action.get("tool_name")
                == "multi_agent_v1__send_input"
                and batch.get("batch_kind") == "continue"
            )
            or (
                action.get("kind") == "stop"
                and action.get("tool_name")
                == "multi_agent_v1__close_agent"
                and batch.get("batch_kind") == "stop"
            )
            or (
                action.get("kind") == "spawn"
                and action.get("tool_name")
                == "multi_agent_v1__spawn_agent"
                and batch.get("batch_kind") == "spawn"
            )
        )
    )


@dataclass(frozen=True, slots=True)
class QualificationSuccessorActionAdvanceArtifact:
    """Strict whole-report handoff after one durable native observation."""

    report: dict[str, Any]
    report_sha256: str
    controller_report: dict[str, Any] | None
    action: dict[str, Any] | None

    @classmethod
    def from_report(
        cls, report: Any
    ) -> "QualificationSuccessorActionAdvanceArtifact":
        bootstrap_origin = bool(isinstance(report, Mapping) and report.get("schema") == BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA)
        expected_fields = ((_ACTION_ADVANCE_FIELDS - {"pre_turn_report_sha256"}) | {"bootstrap_report_sha256"} if bootstrap_origin else _ACTION_ADVANCE_FIELDS)
        if isinstance(report, Mapping):
            if report.get("schema") in {ACTION_ADVANCE_REPORT_SCHEMA, BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA, REVIEW_ACTION_ADVANCE_REPORT_SCHEMA, RESULT_ACTION_ADVANCE_REPORT_SCHEMA}:
                expected_fields = expected_fields | {"worker_results"}
            if report.get("schema") in {ACTION_ADVANCE_REPORT_SCHEMA, BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA, REVIEW_ACTION_ADVANCE_REPORT_SCHEMA}:
                expected_fields = expected_fields | {"review_packet"}
            candidate_action = report.get("action")
            if (
                isinstance(candidate_action, Mapping)
                and candidate_action.get("batch_kind") == "spawn"
                and candidate_action.get("batch_phase") == "compensation"
            ) or report.get("decision") == "ACTION_TERMINAL_FAILURE":
                expected_fields = expected_fields | {
                    "spawn_compensation_evidence"
                }
        if not isinstance(report, Mapping) or set(report) != expected_fields:
            raise QualificationSuccessorError(
                "successor_action_advance:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        decision = value.get("decision")
        roots = value.get("source_roots")
        authority = value.get("authority_before")
        authority_owner = (
            authority.get("owner")
            if isinstance(authority, Mapping)
            and isinstance(authority.get("owner"), Mapping)
            else {}
        )
        lifecycle = (
            authority.get("lifecycle")
            if isinstance(authority, Mapping)
            and isinstance(authority.get("lifecycle"), Mapping)
            else None
        )
        durable = value.get("durable_hook_report")
        native = (
            durable.get("native_controller")
            if isinstance(durable, Mapping)
            and isinstance(durable.get("native_controller"), Mapping)
            else None
        )
        transitions = value.get("controller_transitions")
        acknowledgements = value.get("acknowledgements")
        action = value.get("action")
        boundary = value.get("boundary")
        counters = value.get("counters")
        transition_values = (
            transitions if isinstance(transitions, list) else []
        )
        checkpoint_stage = _has_checkpoint_stage(transition_values)
        cleanup_stage = _has_cleanup_stage(transition_values)
        transition_issues: list[str] = []
        previous_cursor = (
            authority.get("tip") if isinstance(authority, Mapping) else None
        )
        operations: list[str] = []
        controller: Mapping[str, Any] | None = None
        for index, transition in enumerate(transition_values):
            if (
                not isinstance(transition, Mapping)
                or set(transition) != {"program", "report"}
            ):
                transition_issues.append(
                    f"controller_transition:{index}:shape_invalid"
                )
                continue
            program = transition.get("program")
            controller = transition.get("report")
            if (
                not isinstance(program, Mapping)
                or set(program)
                != {
                    "schema",
                    "controller_id",
                    "operation",
                    "expected_cursor",
                    "payload",
                }
                or program.get("schema") != native_controller.PROGRAM_SCHEMA
                or program.get("controller_id")
                != authority_owner.get("controller_id")
                or program.get("operation") not in {"observe", "stage", "inspect"}
                or (
                    program.get("operation") == "inspect"
                    and (
                        (decision not in _RESULT_DECISIONS
                         and decision != "AWAITING_WORKER_CHECKPOINTS"
                         and not (decision == "READY_FOR_NEXT_ACTION" and (checkpoint_stage or cleanup_stage)))
                        or program.get("payload") != {}
                    )
                )
                or program.get("expected_cursor") != previous_cursor
            ):
                transition_issues.append(
                    f"controller_transition:{index}:program_invalid"
                )
            else:
                operations.append(str(program["operation"]))
            if (
                not isinstance(controller, Mapping)
                or controller.get("schema") not in {native_controller.REPORT_SCHEMA, native_controller.REVIEW_WAIT_REPORT_SCHEMA}
                or not (
                    (
                        controller.get("status") == "PASS"
                        and controller.get("issues") == []
                    )
                    or (
                        decision == "ACTION_TERMINAL_FAILURE"
                        and controller.get("status") == "BLOCKED"
                        and controller.get("decision")
                        == "ACTION_TERMINAL_FAILURE"
                        and controller.get("issues")
                        == ["native_action:failed"]
                    )
                )
                or controller.get("provider_free") is not True
                or controller.get("controller_id") != authority_owner.get("controller_id")
                or not _sealed(controller, "report_sha256")
                or not isinstance(controller.get("cursor"), Mapping)
            ):
                transition_issues.append(
                    f"controller_transition:{index}:report_invalid"
                )
            else:
                if (isinstance(program, Mapping)
                        and (program.get("operation") == "inspect"
                             or controller.get("decision") in {"REVIEW_OBSERVATION_PENDING", "CHECKPOINT_OBSERVATION_PENDING"})
                        and _canonical(controller["cursor"]) != _canonical(program.get("expected_cursor"))):
                    transition_issues.append(f"controller_transition:{index}:read_cursor_changed")
                previous_cursor = controller.get("cursor")

        ack_valid = False
        ack_state = None
        expected_lanes: list[str] = []
        observed_lanes: list[str] = []
        pending_lanes: list[str] = []
        if isinstance(acknowledgements, Mapping):
            ack_core = {
                key: child
                for key, child in acknowledgements.items()
                if key != "acknowledgements_sha256"
            }
            ack_state = acknowledgements.get("state")
            expected_lanes = acknowledgements.get("expected_lane_ids", [])
            observed_lanes = acknowledgements.get("observed_lane_ids", [])
            pending_lanes = acknowledgements.get("pending_lane_ids", [])
            runtime_rows = acknowledgements.get("runtime_observations")
            ack_valid = bool(
                set(acknowledgements)
                == {
                    "schema",
                    "state",
                    "expected_lane_ids",
                    "observed_lane_ids",
                    "pending_lane_ids",
                    "runtime_observations",
                    "acknowledgements_sha256",
                }
                and acknowledgements.get("schema")
                == WORKER_ACKNOWLEDGEMENTS_SCHEMA
                and ack_state in {"NOT_APPLICABLE", "AWAITING", "ACCEPTED"}
                and acknowledgements.get("acknowledgements_sha256")
                == _sha(ack_core)
                and all(
                    isinstance(items, list)
                    and items == sorted(items)
                    and len(items) == len(set(items))
                    and all(_text(item) for item in items)
                    for items in (
                        expected_lanes,
                        observed_lanes,
                        pending_lanes,
                    )
                )
                and set(observed_lanes).isdisjoint(pending_lanes)
                and sorted([*observed_lanes, *pending_lanes])
                == expected_lanes
                and isinstance(runtime_rows, list)
                and [
                    row.get("logical_worker_id")
                    for row in runtime_rows
                    if isinstance(row, Mapping)
                ]
                == observed_lanes
                and all(
                    isinstance(row, Mapping)
                    and set(row)
                    == {
                        "logical_worker_id",
                        "worker_id",
                        "session_id",
                        "observation",
                    }
                    and routing_verify.validate_session_runtime_observation(
                        row.get("observation")
                    ).get("valid")
                    is True
                    for row in runtime_rows
                )
                and (
                    ack_state != "NOT_APPLICABLE"
                    or not expected_lanes
                )
                and (ack_state != "AWAITING" or bool(pending_lanes))
                and (ack_state != "ACCEPTED" or not pending_lanes)
            )

        native_observed = "observe" in operations
        pending_reads = sum(isinstance(row, Mapping) and isinstance(row.get("report"), Mapping)
                            and row["report"].get("decision") in {"REVIEW_OBSERVATION_PENDING", "CHECKPOINT_OBSERVATION_PENDING"}
                            for row in transition_values)
        actual_stages = operations.count("stage") - pending_reads
        stage_advanced = actual_stages > 0
        expected_next_action = (
            action.get("tool_name")
            if isinstance(action, Mapping)
            else (
                "mcp__orch_dork__" + (
                    "advance_issue94_bootstrapped_after_native_action"
                    if value.get("schema") == BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA
                    else "advance_issue94_successor_after_native_action")
                if decision in {
                    "AWAITING_WORKER_ACKNOWLEDGEMENTS",
                    "AWAITING_WORKER_CHECKPOINTS",
                    "AWAITING_WORKER_RESULTS",
                    "AWAITING_RESULT_AGGREGATION",
                    "AWAITING_SOL_REVIEW_OBSERVATION",
                } or (decision == "AWAITING_TERMINAL_VERIFICATION" and value.get("schema") in {ACTION_ADVANCE_REPORT_SCHEMA, BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA})
                else None
            )
        )
        boundary_valid = boundary == {
            "native_action_called_by_bridge": False,
            "native_action_observed_by_bridge": native_observed,
            "worker_acknowledgements_observed": len(observed_lanes),
            "controller_stage_advanced": stage_advanced,
            "next_action": expected_next_action,
        }
        continued_batch = (
            native_controller.GovernedNativeController._batch_fields(action)
            if isinstance(action, Mapping)
            else None
        )
        authority_identity = (
            authority.get("identity")
            if isinstance(authority, Mapping)
            and isinstance(authority.get("identity"), Mapping)
            else {}
        )
        retained_ready = bool(
            transition_values == []
            and ack_state == "NOT_APPLICABLE"
            and _retained_authorized_continuation(
                action,
                lifecycle,
                controller_id=authority_owner.get("controller_id"),
                actor_thread_id=authority_identity.get("root_thread_id"),
            )
        )
        ready = bool(
            decision == "READY_FOR_NEXT_ACTION"
            and isinstance(action, Mapping)
            and (
                (
                    isinstance(controller, Mapping)
                    and controller.get("decision") == "ACTION_AUTHORIZED"
                    and controller.get("action") == action
                )
                or retained_ready
            )
            and (
                (not checkpoint_stage and ((
                    action.get("tool_name")
                    == "multi_agent_v1__spawn_agent"
                    and ack_state == "NOT_APPLICABLE"
                )
                or (
                    action.get("tool_name")
                    == "multi_agent_v1__send_input"
                    and ack_state == "ACCEPTED"
                    and stage_advanced
                )
                or (
                    action.get("tool_name")
                    == "multi_agent_v1__send_input"
                    and ack_state == "NOT_APPLICABLE"
                    and native_observed
                    and not stage_advanced
                    and isinstance(continued_batch, Mapping)
                    and continued_batch.get("batch_kind") == "continue"
                    and continued_batch.get("batch_phase") == "primary"
                    and type(continued_batch.get("batch_index")) is int
                    and continued_batch["batch_index"] > 0
                )
                or (
                    retained_ready
                    and ack_state == "NOT_APPLICABLE"
                    and not stage_advanced
                )))
                or (checkpoint_stage and ack_state == "NOT_APPLICABLE"
                    and _valid_checkpoint_stage(transition_values, authority, roots))
                or (cleanup_stage and ack_state == "NOT_APPLICABLE"
                    and _valid_cleanup_stage(transition_values, authority))
                or (ack_state == "NOT_APPLICABLE" and operations == ["observe"]
                    and (_valid_stop_advance(value)
                         or _valid_spawn_compensation_advance(value)))
            )
        )
        awaiting = bool(
            decision == "AWAITING_WORKER_ACKNOWLEDGEMENTS"
            and action is None
            and ack_state == "AWAITING"
            and not stage_advanced
        )
        complete = bool(
            decision == "ACTION_BATCH_OBSERVED"
            and action is None
            and ack_state == "NOT_APPLICABLE"
            and isinstance(controller, Mapping)
            and controller.get("decision") == "ACTION_OBSERVED"
        )
        terminal_failure = bool(
            decision == "ACTION_TERMINAL_FAILURE"
            and action is None
            and ack_state == "NOT_APPLICABLE"
            and operations == ["observe"]
            and isinstance(controller, Mapping)
            and _valid_spawn_compensation_terminal(value)
        )
        result_wait = bool(
            decision in _RESULT_DECISIONS
            and action is None
            and ack_state == "NOT_APPLICABLE"
            and operations in (["observe"], ["inspect"], ["observe", "stage"], ["inspect", "stage"])
            and isinstance(authority, Mapping)
            and isinstance(controller, Mapping)
            and _is_worker_result_wait(controller)
            and (
                (operations == ["observe"] and controller.get("decision") == "ACTION_OBSERVED")
                or (
                    operations == ["inspect"]
                    and controller.get("decision") == "WAITING_FOR_STAGE"
                    and controller.get("cursor") == authority.get("tip")
                )
                or (
                    operations in (["observe", "stage"], ["inspect", "stage"])
                    and controller.get("decision") in {"STAGE_ADVANCED", "REVIEW_OBSERVATION_PENDING"}
                    and _valid_worker_result_stage(transition_values)
                )
            )
        )
        cleanup_complete = bool(
            decision == "AWAITING_ATTEMPT_QUALIFICATION"
            and action is None
            and ack_state == "NOT_APPLICABLE"
            and operations == ["inspect"]
            and isinstance(authority, Mapping)
            and isinstance(controller, Mapping)
            and controller.get("cursor") == authority.get("tip")
            and _is_completed_cleanup_wait(controller)
        )
        checkpoint_wait = bool(
            decision == "AWAITING_WORKER_CHECKPOINTS"
            and value.get("schema") in {ACTION_ADVANCE_REPORT_SCHEMA, BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA}
            and action is None and ack_state == "NOT_APPLICABLE"
            and not stage_advanced and isinstance(controller, Mapping)
            and _is_worker_checkpoint_wait(controller)
            and (
                (operations in (["observe"], ["inspect"])
                 and controller.get("decision") in {"ACTION_OBSERVED", "WAITING_FOR_STAGE"})
                or (checkpoint_stage and _valid_checkpoint_stage(transition_values, authority, roots))
            )
        )
        worker_results = value.get("worker_results", [])
        if value.get("schema") in {ACTION_ADVANCE_REPORT_SCHEMA, BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA, REVIEW_ACTION_ADVANCE_REPORT_SCHEMA, RESULT_ACTION_ADVANCE_REPORT_SCHEMA}:
            if result_wait:
                result_wait = _worker_results_decision(worker_results, controller, authority) == decision
            elif cleanup_stage:
                if _canonical(worker_results) != _canonical(controller["stage_report"]["receipt"]["bindings"]["worker_results"]):
                    raise QualificationSuccessorError("successor_action_advance:cleanup_results_changed")
            elif worker_results != []:
                raise QualificationSuccessorError("successor_action_advance:unexpected_worker_results")
        elif decision in _RESULT_DECISIONS:
            # V2 remains historical transport evidence; it never contained the
            # collected result reports needed by the new join dispositions.
            result_wait = False
        if value.get("schema") in {ACTION_ADVANCE_REPORT_SCHEMA, BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA, REVIEW_ACTION_ADVANCE_REPORT_SCHEMA}:
            expected_packet = (_review_packet_for_controller(controller)
                               if decision in {"AWAITING_SOL_REVIEW", "AWAITING_SOL_REVIEW_OBSERVATION", "AWAITING_TERMINAL_VERIFICATION", "SOL_REVIEW_EVIDENCE_REQUIRED", "AWAITING_LIFECYCLE_CLEANUP", "AWAITING_ATTEMPT_QUALIFICATION", "AWAITING_FAILURE_CLOSURE"} else None)
            if _canonical(value.get("review_packet")) != _canonical(expected_packet):
                raise QualificationSuccessorError("successor_action_advance:review_packet_invalid")
        counters_valid = bool(
            isinstance(counters, Mapping)
            and set(counters) == _ACTION_ADVANCE_COUNTER_KEYS
            and all(type(item) is int and item >= 0 for item in counters.values())
            and all(
                counters.get(field) == 0
                for field in (
                    "hosted_calls",
                    "model_calls",
                    "native_actions",
                    "network_calls",
                    "provider_calls",
                    "task_creations",
                    "worker_creations",
                )
            )
            and counters.get("controller_observations")
            == operations.count("observe")
            and counters.get("controller_stages")
            == actual_stages
            and counters.get("session_runtime_observations")
            == (3 if checkpoint_stage else 0) + len(observed_lanes) + sum(
                row.get("runtime_observation") is not None
                for row in worker_results
            )
        )
        if (
            value.get("schema") not in {ACTION_ADVANCE_REPORT_SCHEMA, BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA, REVIEW_ACTION_ADVANCE_REPORT_SCHEMA, RESULT_ACTION_ADVANCE_REPORT_SCHEMA, LEGACY_ACTION_ADVANCE_REPORT_SCHEMA}
            or (decision in {"AWAITING_LIFECYCLE_CLEANUP", "AWAITING_ATTEMPT_QUALIFICATION", "AWAITING_FAILURE_CLOSURE"} and value.get("schema") not in {ACTION_ADVANCE_REPORT_SCHEMA, BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA})
            or value.get("status") != "PASS"
            or value.get("issues") != []
            or not (
                ready or awaiting or complete or terminal_failure
                or result_wait or checkpoint_wait or cleanup_complete
            )
            or not _is_sha(value.get("bootstrap_report_sha256" if bootstrap_origin else "pre_turn_report_sha256"))
            or not isinstance(roots, Mapping)
            or set(roots) != {"evidence", "source"}
            or not all(
                isinstance(root, str) and Path(root).is_absolute()
                for root in roots.values()
            )
            or not isinstance(authority, Mapping)
            or authority.get("status") != "VERIFIED"
            or not isinstance(lifecycle, Mapping)
            or lifecycle.get("expected_binding_status")
            not in {"ACTIVE", "WAITING"}
            or lifecycle.get("pending_intent") is not False
            or lifecycle.get("terminal") is not False
            or lifecycle.get("cleanup_required") is not False
            or bool(durable) != native_observed
            or (
                native_observed
                and (
                    not isinstance(durable, Mapping)
                    or durable.get("schema")
                    != "orch-dork/project-ground-durable-event/v1"
                    or durable.get("status") != "PASS"
                    or durable.get("decision") != "OBSERVED"
                    or not _sealed(durable, "durable_record_sha256")
                    or not isinstance(native, Mapping)
                    or native.get("grant_state") != "POST_OBSERVED"
                )
            )
            or transition_issues
            or operations not in ([], ["observe"], ["stage"], ["observe", "stage"], ["inspect"], ["inspect", "stage"])
            or not ack_valid
            or not boundary_valid
            or value.get("provider_free") is not True
            or not counters_valid
            or not _sealed(value, "report_sha256")
        ):
            raise QualificationSuccessorError(
                "successor_action_advance:report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            controller_report=(
                deepcopy(dict(controller))
                if isinstance(controller, Mapping)
                else None
            ),
            action=deepcopy(dict(action)) if isinstance(action, Mapping) else None,
        )


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


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sealed(value: Mapping[str, Any], field: str) -> bool:
    return bool(
        _is_sha(value.get(field))
        and value.get(field)
        == _sha({key: child for key, child in value.items() if key != field})
    )


def _first_action_action_id(
    *,
    bootstrap_report_sha256: Any,
    controller_id: Any,
    expected_cursor: Any,
) -> str | None:
    if (
        not _is_sha(bootstrap_report_sha256)
        or not _text(controller_id)
        or not isinstance(expected_cursor, Mapping)
    ):
        return None
    binding = {
        "bootstrap_report_sha256": bootstrap_report_sha256,
        "controller_id": controller_id,
        "expected_cursor": deepcopy(dict(expected_cursor)),
    }
    return "issue94-first-spawn-" + _sha(binding)[:24]


def build_issue94_successor_first_action_preparation(
    bootstrapped: Any,
) -> dict[str, Any]:
    """Prepare the exact post-SessionStart controller call pre-turn."""

    if not isinstance(
        bootstrapped, bootstrap.Issue94ControllerBootstrapArtifact
    ):
        raise QualificationSuccessorError(
            "successor_first_action_preparation:bootstrap_invalid"
        )
    stage_report = bootstrapped.pre_spawn_stage_report
    activation_payload = (
        bootstrapped.activation_handoff_artifact
        .activation_preparation_report["prepared_activation_payload"]
    )
    identity = activation_payload.get("identity")
    cursor = stage_report.get("cursor")
    if (
        not isinstance(identity, Mapping)
        or not isinstance(cursor, Mapping)
        or stage_report.get("status") != "PASS"
        or stage_report.get("decision") != "STAGE_ADVANCED"
        or stage_report.get("next_stage_action") != "capacity_admission"
        or stage_report.get("action") is not None
        or not _is_sha(stage_report.get("report_sha256"))
    ):
        raise QualificationSuccessorError(
            "successor_first_action_preparation:stage_invalid"
        )
    capacity_program = governed_attempt.build_capacity_admission_program(
        bootstrapped.pre_spawn_artifact.pre_spawn_program,
        stage_report["stage_report"],
    )
    action_id = _first_action_action_id(
        bootstrap_report_sha256=bootstrapped.report_sha256,
        controller_id=stage_report.get("controller_id"),
        expected_cursor=cursor,
    )
    proposal = {
        "schema": native_controller.ACTION_PROPOSAL_SCHEMA,
        "action_id": action_id,
        "kind": "spawn",
        "actor_thread_id": identity.get("root_thread_id"),
        "adapter_sha256": identity.get("native_adapter_sha256"),
    }
    controller_program = (
        native_controller.build_governed_native_stage_program(
            controller_id=str(stage_report.get("controller_id")),
            expected_cursor=cursor,
            stage_program=capacity_program,
            proposed_action=proposal,
        )
    )
    core = {
        "schema": FIRST_ACTION_PREPARATION_REPORT_SCHEMA,
        "status": "PASS",
        "decision": FIRST_ACTION_PREPARATION_DECISION_READY,
        "issues": [],
        "bootstrap_report_sha256": bootstrapped.report_sha256,
        "controller": {
            "controller_id": stage_report.get("controller_id"),
            "root_task_id": identity.get("root_thread_id"),
            "root_model": identity.get("root_model"),
            "expected_binding_status": "WAITING",
            "next_stage_action": "capacity_admission",
            "native_adapter_sha256": identity.get(
                "native_adapter_sha256"
            ),
            "expected_cursor_sha256": _sha(cursor),
        },
        "source_roots": deepcopy(bootstrapped.source_roots),
        "controller_program": controller_program,
        "boundary": {
            "controller_advanced": False,
            "native_action_called": False,
            "next_consumer": "authorize_issue94_successor_first_action",
            "session_start_observed": False,
        },
        "provider_free": True,
        "counters": dict(_FIRST_ACTION_PREPARATION_COUNTERS),
    }
    report = {**core, "report_sha256": _sha(core)}
    if len(_canonical(report)) > MAX_REPORT_BYTES:
        raise QualificationSuccessorError(
            "successor_first_action_preparation:report_too_large"
        )
    return QualificationSuccessorFirstActionPreparationArtifact.from_report(
        report
    ).report


def _capacity_active_lane_ids(value: Any) -> list[str] | None:
    if (
        not isinstance(value, Mapping)
        or value.get("status") != "VERIFIED"
        or value.get("continuity_verified") is not True
        or value.get("reason_codes") != []
        or not isinstance(value.get("state"), Mapping)
        or value.get("state_sha256")
        != value.get("state", {}).get("state_sha256")
    ):
        return None
    try:
        validated = shared_capacity.validate_authority_state(value["state"])
    except (TypeError, ValueError):
        return None
    active = value["state"].get("active_lane_ids")
    if (
        validated.get("status") != "RESOLVED"
        or not isinstance(active, list)
        or active != sorted(set(active))
        or set(active) != validated.get("active_lane_ids")
    ):
        return None
    return list(active)


def _session_key(task_id: str) -> str:
    return hashlib.sha256(task_id.encode("utf-8")).hexdigest()


def _runtime_root(value: str | Path, *, label: str) -> Path:
    """Resolve an owner-controlled runtime tree; group-writable is allowed."""

    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise QualificationSuccessorError(label + ":unsafe")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
    except OSError as error:
        raise QualificationSuccessorError(label + ":unavailable") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or resolved.is_symlink()
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        or stat.S_IMODE(info.st_mode) & 0o002
    ):
        raise QualificationSuccessorError(label + ":unsafe")
    return resolved


def _runtime_report(value: Any, *, task_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise QualificationSuccessorError("successor_runtime:not_object")
    report = deepcopy(dict(value))
    if (
        report.get("schema") != local_task_runtime.SCHEMA
        or report.get("status") != "PASS"
        or report.get("disposition") != "CURRENT_TASK_RUNTIME_VERIFIED"
        or report.get("task_owner_verified") is not True
        or report.get("task_loaded") is not True
        or report.get("task_status") != "idle"
        or report.get("descendant_count") != 0
        or not _is_sha(report.get("owner_identity_sha256"))
        or report.get("issues") != []
        or report.get("provider_free") is not True
        or any(report.get(name) != 0 for name in _RUNTIME_ZERO_COUNTERS)
        or not _sealed(report, "report_sha256")
    ):
        raise QualificationSuccessorError(
            "successor_runtime:owner_observation_invalid"
        )
    if not _text(task_id):
        raise QualificationSuccessorError("successor_runtime:task_id_invalid")
    return report


def _clean_terminal_authority(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise QualificationSuccessorError(
            "successor_startup:predecessor_authority_invalid"
        )
    authority = deepcopy(dict(value))
    identity = authority.get("identity")
    lifecycle = authority.get("lifecycle")
    if (
        authority.get("status") != "VERIFIED"
        or not isinstance(authority.get("owner"), Mapping)
        or not isinstance(identity, Mapping)
        or not isinstance(lifecycle, Mapping)
        or lifecycle.get("expected_binding_status") != "TERMINAL"
        or lifecycle.get("terminal") is not True
        or lifecycle.get("pending_intent") is not False
        or lifecycle.get("cleanup_required") is not False
        or lifecycle.get("action_sha256") is not None
        or lifecycle.get("tool_use_id") is not None
        or not _text(identity.get("controller_id"))
    ):
        raise QualificationSuccessorError(
            "successor_startup:predecessor_not_clean_terminal"
        )
    return authority


def terminalize_issue94_pre_native_failure(
    *,
    plugin_data: str | Path,
    source_roots: Mapping[str, str | Path],
    failure_report_path: str | Path,
    expected_failure_artifact_sha256: str,
    predecessor_authority_path: str | Path,
    expected_authority_artifact_sha256: str,
    historical_runtime_plugin_root: str | Path,
    expected_historical_package_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Terminalize one exact interrupted turn that never reached native work."""

    data = _runtime_root(
        plugin_data,
        label="pre_native_failure_settlement:plugin_data",
    )
    historical = _runtime_root(
        historical_runtime_plugin_root,
        label="pre_native_failure_settlement:historical_runtime",
    )
    if (
        not isinstance(source_roots, Mapping)
        or set(source_roots) != {"evidence", "source"}
    ):
        raise QualificationSuccessorError(
            "pre_native_failure_settlement:source_roots_invalid"
        )
    roots = {
        name: _runtime_root(
            path,
            label="pre_native_failure_settlement:" + name + "_root",
        )
        for name, path in source_roots.items()
    }
    hook_path = historical / "hooks" / "project_ground_hook.py"
    evaluation_time = (now or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    try:
        controller = native_controller.GovernedNativeController(
            plugin_data=data,
            hook_definition_path=hook_path,
            source_roots=roots,
            now=evaluation_time,
        )
    except (OSError, TypeError, ValueError) as error:
        raise QualificationSuccessorError(
            "pre_native_failure_settlement:controller_unavailable"
        ) from error
    try:
        before = controller.grants.canonical_authority()
        owner = before.get("owner") if isinstance(before, Mapping) else None
        lifecycle = (
            before.get("lifecycle")
            if isinstance(before, Mapping)
            and isinstance(before.get("lifecycle"), Mapping)
            else None
        )
        if (
            before.get("status") != "VERIFIED"
            or not isinstance(owner, Mapping)
            or not _text(owner.get("controller_id"))
            or not isinstance(before.get("tip"), Mapping)
            or not isinstance(lifecycle, Mapping)
            or lifecycle.get("expected_binding_status") != "WAITING"
            or lifecycle.get("terminal") is not False
            or lifecycle.get("pending_intent") is not False
            or lifecycle.get("cleanup_required") is not False
            or lifecycle.get("action_sha256") is not None
            or lifecycle.get("grant_state") is not None
            or lifecycle.get("tool_use_id") is not None
        ):
            raise QualificationSuccessorError(
                "pre_native_failure_settlement:waiting_predecessor_required"
            )
        try:
            program = (
                native_controller
                .build_pre_native_failure_terminalization_program(
                    controller_id=str(owner["controller_id"]),
                    expected_cursor=before["tip"],
                    failure_report_path=failure_report_path,
                    expected_failure_artifact_sha256=(
                        expected_failure_artifact_sha256
                    ),
                    predecessor_authority_path=(
                        predecessor_authority_path
                    ),
                    expected_authority_artifact_sha256=(
                        expected_authority_artifact_sha256
                    ),
                    historical_runtime_root=historical,
                    expected_package_digest=(
                        expected_historical_package_digest
                    ),
                )
            )
        except (OSError, TypeError, ValueError) as error:
            raise QualificationSuccessorError(
                "pre_native_failure_settlement:evidence_invalid"
            ) from error
        controller_report = controller.terminalize_pre_native_failure(
            program
        )
        after = controller.grants.canonical_authority()
        if (
            controller_report.get("status") != "PASS"
            or controller_report.get("decision")
            != "PRE_NATIVE_FAILURE_TERMINALIZED"
            or controller_report.get("issues") != []
        ):
            raise QualificationSuccessorError(
                "pre_native_failure_settlement:terminalization_refused"
            )
        _clean_terminal_authority(after)
        core = {
            "schema": PRE_NATIVE_FAILURE_SETTLEMENT_REPORT_SCHEMA,
            "status": "PASS",
            "decision": "PRE_NATIVE_FAILURE_TERMINALIZED",
            "issues": [],
            "evaluation_time": evaluation_time.isoformat(),
            "controller_program": program,
            "controller_report": deepcopy(dict(controller_report)),
            "predecessor_authority_before": deepcopy(dict(before)),
            "predecessor_authority_after": deepcopy(dict(after)),
            "boundary": {
                "native_action_called": False,
                "next_transition": "terminal_predecessor_capacity_check",
                "provider_boundary_crossed": False,
                "successor_activation_started": False,
                "task_created": False,
                "worker_created": False,
            },
            "provider_free": True,
            "counters": {
                "hosted_calls": 0,
                "model_calls": 0,
                "native_actions": 0,
                "network_calls": 0,
                "provider_calls": 0,
                "task_creations": 0,
                "terminalizations": 1,
                "worker_creations": 0,
            },
        }
        report = {**core, "report_sha256": _sha(core)}
        if len(_canonical(report)) > MAX_REPORT_BYTES:
            raise QualificationSuccessorError(
                "pre_native_failure_settlement:report_too_large"
            )
        return QualificationPreNativeFailureSettlementArtifact.from_report(
            report
        ).report
    finally:
        controller.store.close()


def recover_issue94_partial_native_failure(
    *,
    plugin_data: str | Path,
    source_roots: Mapping[str, str | Path],
    terminal_snapshot_path: str | Path,
    expected_terminal_snapshot_artifact_sha256: str,
    worker_state_path: str | Path,
    expected_worker_state_artifact_sha256: str,
    worker_rollout_path: str | Path,
    expected_worker_rollout_artifact_sha256: str,
    historical_runtime_plugin_root: str | Path,
    expected_historical_package_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Terminalize and release one evidence-proven partial native batch."""

    data = _runtime_root(
        plugin_data,
        label="partial_native_failure_recovery:plugin_data",
    )
    historical = _runtime_root(
        historical_runtime_plugin_root,
        label="partial_native_failure_recovery:historical_runtime",
    )
    if (
        not isinstance(source_roots, Mapping)
        or set(source_roots) != {"evidence", "source"}
    ):
        raise QualificationSuccessorError(
            "partial_native_failure_recovery:source_roots_invalid"
        )
    roots = {
        name: _runtime_root(
            path,
            label="partial_native_failure_recovery:" + name + "_root",
        )
        for name, path in source_roots.items()
    }
    evaluation_time = (now or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    hook_path = historical / "hooks/project_ground_hook.py"
    try:
        controller = native_controller.GovernedNativeController(
            plugin_data=data,
            hook_definition_path=hook_path,
            source_roots=roots,
            now=evaluation_time,
        )
    except (OSError, TypeError, ValueError) as error:
        raise QualificationSuccessorError(
            "partial_native_failure_recovery:controller_unavailable"
        ) from error
    try:
        before = controller.grants.canonical_authority()
        owner = before.get("owner") if isinstance(before, Mapping) else None
        lifecycle = (
            before.get("lifecycle")
            if isinstance(before, Mapping)
            and isinstance(before.get("lifecycle"), Mapping)
            else None
        )
        if (
            before.get("status") != "VERIFIED"
            or not isinstance(owner, Mapping)
            or not _text(owner.get("controller_id"))
            or not isinstance(before.get("tip"), Mapping)
            or not isinstance(lifecycle, Mapping)
            or lifecycle.get("expected_binding_status") != "BLOCKED"
            or lifecycle.get("grant_state") != "OUTCOME_UNKNOWN"
            or lifecycle.get("terminal") is not False
            or lifecycle.get("pending_intent") is not False
            or lifecycle.get("cleanup_required") is not False
        ):
            raise QualificationSuccessorError(
                "partial_native_failure_recovery:blocked_predecessor_required"
            )
        try:
            prior_state, prior_rows = controller._state(
                str(owner["controller_run_id"])
            )
            prior_events = native_controller._controller_events(
                list(prior_rows)
            )
            capacity_before = (
                controller.tower.read_shared_capacity_authority()
            )
            program = (
                native_controller
                .build_partial_native_failure_terminalization_program(
                    controller_id=str(owner["controller_id"]),
                    expected_cursor=before["tip"],
                    terminal_snapshot_path=terminal_snapshot_path,
                    expected_terminal_snapshot_artifact_sha256=(
                        expected_terminal_snapshot_artifact_sha256
                    ),
                    worker_state_path=worker_state_path,
                    expected_worker_state_artifact_sha256=(
                        expected_worker_state_artifact_sha256
                    ),
                    worker_rollout_path=worker_rollout_path,
                    expected_worker_rollout_artifact_sha256=(
                        expected_worker_rollout_artifact_sha256
                    ),
                    historical_runtime_root=historical,
                    expected_package_digest=(
                        expected_historical_package_digest
                    ),
                )
            )
        except (OSError, TypeError, ValueError) as error:
            raise QualificationSuccessorError(
                "partial_native_failure_recovery:evidence_invalid"
            ) from error
        controller_report = controller.terminalize_partial_native_failure(
            program
        )
        authority_after = controller.grants.canonical_authority()
        if (
            controller_report.get("status") != "PASS"
            or controller_report.get("decision")
            != "PARTIAL_NATIVE_FAILURE_TERMINALIZED"
            or controller_report.get("issues") != []
        ):
            raise QualificationSuccessorError(
                "partial_native_failure_recovery:terminalization_refused"
            )
        _clean_terminal_authority(authority_after)
        admission_reports = [
            deepcopy(dict(event["payload"]["stage_report"]))
            for event in prior_events
            if event.get("event_type") == "stage_result"
            and isinstance(event.get("payload"), Mapping)
            and isinstance(event["payload"].get("stage_report"), Mapping)
            and event["payload"]["stage_report"].get("operation")
            == "capacity_admission"
            and event["payload"]["stage_report"].get("status") == "PASS"
            and event["payload"]["stage_report"].get("disposition")
            == "SPAWN_AUTHORIZED"
        ]
        active = _capacity_active_lane_ids(capacity_before)
        terminal_stage = controller_report.get("stage_report")
        terminal_receipt = (
            terminal_stage.get("receipt")
            if isinstance(terminal_stage, Mapping)
            and isinstance(terminal_stage.get("receipt"), Mapping)
            else None
        )
        if (
            len(admission_reports) != 1
            or not isinstance(active, list)
            or len(active) != 2
            or not isinstance(terminal_receipt, Mapping)
        ):
            raise QualificationSuccessorError(
                "partial_native_failure_recovery:capacity_binding_invalid"
            )
        admission = admission_reports[0]
        admission_receipt = admission.get("receipt")
        bindings = (
            admission_receipt.get("bindings")
            if isinstance(admission_receipt, Mapping)
            and isinstance(admission_receipt.get("bindings"), Mapping)
            else None
        )
        logical_lanes = (
            bindings.get("current_wave_logical_lane_ids")
            if isinstance(bindings, Mapping)
            else None
        )
        authority_lanes = (
            bindings.get("capacity_authority_lane_ids")
            if isinstance(bindings, Mapping)
            else None
        )
        created_lane = terminal_receipt.get("created_logical_lane_id")
        unmaterialized = terminal_receipt.get(
            "unmaterialized_logical_lane_ids"
        )
        if (
            not isinstance(logical_lanes, list)
            or len(logical_lanes) != 2
            or authority_lanes != active
            or created_lane != logical_lanes[0]
            or unmaterialized != [logical_lanes[1]]
        ):
            raise QualificationSuccessorError(
                "partial_native_failure_recovery:lane_binding_mismatch"
            )
        activation_payload = prior_state.get("activation")
        attempt_identity = (
            activation_payload.get("identity")
            if isinstance(activation_payload, Mapping)
            and isinstance(activation_payload.get("identity"), Mapping)
            else None
        )
        if not isinstance(attempt_identity, Mapping):
            raise QualificationSuccessorError(
                "partial_native_failure_recovery:identity_invalid"
            )
        governed_identity = {
            "run_id": attempt_identity.get("run_id"),
            "attempt_id": attempt_identity.get("attempt_id"),
            "root_task_id": attempt_identity.get("root_thread_id"),
            "root_model": attempt_identity.get("root_model"),
            "root_effort": attempt_identity.get("root_effort"),
            "source_version": attempt_identity.get("source_version"),
            "installed_version": attempt_identity.get(
                "installed_plugin_version"
            ),
            "task_loaded_version": attempt_identity.get(
                "task_loaded_version"
            ),
            "fresh_task": attempt_identity.get("fresh_task"),
        }
        try:
            current = owned_file.read_owned_json(
                data / "project-ground/current.json",
                max_bytes=native_controller.MAX_RUNTIME_FILE_BYTES,
            )
            binding = (
                current.get("native_controller")
                if isinstance(current, Mapping)
                and isinstance(current.get("native_controller"), Mapping)
                else None
            )
            if not isinstance(binding, Mapping):
                raise ValueError("terminal binding missing")
            _host_identity, signer, _trust = activation._authority()
            release_receipts: list[dict[str, Any]] = []
            for lane_id, logical_lane in zip(active, logical_lanes):
                cleanup_status = (
                    "complete"
                    if logical_lane == created_lane
                    else "not_required"
                )
                payload = shared_capacity.cleanup_observer_payload(
                    lane_id=lane_id,
                    run_id=str(governed_identity["run_id"]),
                    route="native_luna",
                    terminal_state="failed",
                    cleanup_status=cleanup_status,
                    owned_descendants=0,
                    terminal_evidence_sha256=str(
                        binding["binding_sha256"]
                    ),
                )
                signed = signer.issue(
                    "lane-cleanup-observation",
                    payload,
                    issued_at=(
                        evaluation_time - timedelta(seconds=1)
                    ).isoformat(),
                    valid_until=(
                        evaluation_time + timedelta(minutes=4)
                    ).isoformat(),
                    nonce=(
                        "issue94-partial-native-"
                        + _sha(payload)[:24]
                    ),
                )
                release_receipt = shared_capacity.release(
                    {
                        "lane_id": lane_id,
                        "run_id": governed_identity["run_id"],
                        "route": "native_luna",
                        "state": "failed",
                        "cleanup_status": cleanup_status,
                        "terminal_evidence_sha256": binding[
                            "binding_sha256"
                        ],
                        "cleanup_evidence_sha256": _sha(signed),
                        "cleanup_observer_receipt": signed,
                    },
                    0,
                )
                if release_receipt.get("status") != "RELEASED":
                    raise ValueError("release receipt refused")
                release_receipts.append(release_receipt)
            settlement_program = (
                governed_attempt.build_capacity_settlement_program(
                    governed_identity,
                    admission,
                    release_receipts,
                )
            )
            settlement_report = governed_attempt.evaluate_governed_attempt(
                settlement_program,
                source_roots=roots,
                now=evaluation_time,
                observer=controller._attempt_observer,
                capacity_authority=controller.tower,
            )
            capacity_after = (
                controller.tower.read_shared_capacity_authority()
            )
        except (OSError, TypeError, ValueError, shared_capacity.CapacityError) as error:
            raise QualificationSuccessorError(
                "partial_native_failure_recovery:capacity_settlement_refused"
            ) from error
        if (
            settlement_report.get("status") != "PASS"
            or settlement_report.get("disposition") != "CAPACITY_RELEASED"
            or settlement_report.get("issues") != []
            or _capacity_active_lane_ids(capacity_after) != []
            or not controller._terminal_run_closed(binding)
        ):
            raise QualificationSuccessorError(
                "partial_native_failure_recovery:settlement_readback_invalid"
            )
        core = {
            "schema": PARTIAL_NATIVE_FAILURE_RECOVERY_REPORT_SCHEMA,
            "status": "PASS",
            "decision": "PARTIAL_NATIVE_FAILURE_RECOVERED",
            "issues": [],
            "evaluation_time": evaluation_time.isoformat(),
            "controller_program": program,
            "controller_report": deepcopy(dict(controller_report)),
            "predecessor_authority_before": deepcopy(dict(before)),
            "predecessor_authority_after": deepcopy(
                dict(authority_after)
            ),
            "capacity_authority_before": deepcopy(
                dict(capacity_before)
            ),
            "release_receipts": deepcopy(release_receipts),
            "settlement_program": settlement_program,
            "settlement_report": deepcopy(dict(settlement_report)),
            "capacity_authority_after": deepcopy(dict(capacity_after)),
            "boundary": {
                "native_action_called": False,
                "next_transition": "fresh_successor_activation",
                "provider_boundary_crossed": False,
                "successor_activation_started": False,
                "task_created": False,
                "worker_created": False,
            },
            "provider_free": True,
            "counters": {
                "capacity_lanes_released": 2,
                "cleanup_observer_receipts_issued": 2,
                "host_seed_credential_reads": 1,
                "hosted_calls": 0,
                "model_calls": 0,
                "native_actions": 0,
                "network_calls": 0,
                "provider_calls": 0,
                "task_creations": 0,
                "terminalizations": 1,
                "worker_creations": 0,
            },
        }
        report = {**core, "report_sha256": _sha(core)}
        if len(_canonical(report)) > MAX_REPORT_BYTES:
            raise QualificationSuccessorError(
                "partial_native_failure_recovery:report_too_large"
            )
        return QualificationPartialNativeFailureRecoveryArtifact.from_report(
            report
        ).report
    finally:
        controller.store.close()


def recover_issue94_post_spawn_failure(
    *,
    plugin_data: str | Path,
    source_roots: Mapping[str, str | Path],
    dedicated_run_path: str | Path,
    expected_dedicated_run_artifact_sha256: str,
    attempt_envelope_path: str | Path,
    expected_attempt_envelope_artifact_sha256: str,
    pre_turn_report_path: str | Path,
    expected_pre_turn_artifact_sha256: str,
    root_rollout_path: str | Path,
    expected_root_rollout_artifact_sha256: str,
    worker_rollout_paths: Mapping[str, str | Path],
    expected_worker_rollout_artifact_sha256: Mapping[str, str],
    historical_runtime_plugin_root: str | Path,
    expected_historical_package_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Terminalize and release the exact Cycle 31 two-worker deadlock."""

    data = _runtime_root(
        plugin_data,
        label="post_spawn_failure_recovery:plugin_data",
    )
    historical = _runtime_root(
        historical_runtime_plugin_root,
        label="post_spawn_failure_recovery:historical_runtime",
    )
    if (
        not isinstance(source_roots, Mapping)
        or set(source_roots) != {"evidence", "source"}
    ):
        raise QualificationSuccessorError(
            "post_spawn_failure_recovery:source_roots_invalid"
        )
    roots = {
        name: _runtime_root(
            path,
            label="post_spawn_failure_recovery:" + name + "_root",
        )
        for name, path in source_roots.items()
    }
    evaluation_time = (now or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    try:
        controller = native_controller.GovernedNativeController(
            plugin_data=data,
            hook_definition_path=(
                historical / "hooks/project_ground_hook.py"
            ),
            source_roots=roots,
            now=evaluation_time,
        )
    except (OSError, TypeError, ValueError) as error:
        raise QualificationSuccessorError(
            "post_spawn_failure_recovery:controller_unavailable"
        ) from error
    try:
        before = controller.grants.canonical_authority()
        owner = before.get("owner") if isinstance(before, Mapping) else None
        lifecycle = (
            before.get("lifecycle")
            if isinstance(before, Mapping)
            and isinstance(before.get("lifecycle"), Mapping)
            else None
        )
        if (
            before.get("status") != "VERIFIED"
            or not isinstance(owner, Mapping)
            or not _text(owner.get("controller_id"))
            or not isinstance(before.get("tip"), Mapping)
            or not isinstance(lifecycle, Mapping)
            or lifecycle.get("expected_binding_status") != "WAITING"
            or lifecycle.get("grant_state") is not None
            or lifecycle.get("terminal") is not False
            or lifecycle.get("pending_intent") is not False
            or lifecycle.get("cleanup_required") is not True
            or lifecycle.get("action_sha256") is not None
            or lifecycle.get("tool_use_id") is not None
        ):
            raise QualificationSuccessorError(
                "post_spawn_failure_recovery:blocked_predecessor_required"
            )
        try:
            prior_state, prior_rows = controller._state(
                str(owner["controller_run_id"])
            )
            prior_events = native_controller._controller_events(
                list(prior_rows)
            )
            capacity_before = controller.tower.read_shared_capacity_authority()
            program = (
                native_controller
                .build_post_spawn_failure_terminalization_program(
                    controller_id=str(owner["controller_id"]),
                    expected_cursor=before["tip"],
                    dedicated_run_path=dedicated_run_path,
                    expected_dedicated_run_artifact_sha256=(
                        expected_dedicated_run_artifact_sha256
                    ),
                    attempt_envelope_path=attempt_envelope_path,
                    expected_attempt_envelope_artifact_sha256=(
                        expected_attempt_envelope_artifact_sha256
                    ),
                    pre_turn_report_path=pre_turn_report_path,
                    expected_pre_turn_artifact_sha256=(
                        expected_pre_turn_artifact_sha256
                    ),
                    root_rollout_path=root_rollout_path,
                    expected_root_rollout_artifact_sha256=(
                        expected_root_rollout_artifact_sha256
                    ),
                    worker_rollout_paths=worker_rollout_paths,
                    expected_worker_rollout_artifact_sha256=(
                        expected_worker_rollout_artifact_sha256
                    ),
                    historical_runtime_root=historical,
                    expected_package_digest=(
                        expected_historical_package_digest
                    ),
                )
            )
        except (OSError, TypeError, ValueError) as error:
            raise QualificationSuccessorError(
                "post_spawn_failure_recovery:evidence_invalid"
            ) from error
        controller_report = controller.terminalize_post_spawn_failure(program)
        authority_after = controller.grants.canonical_authority()
        if (
            controller_report.get("status") != "PASS"
            or controller_report.get("decision")
            != "POST_SPAWN_FAILURE_TERMINALIZED"
            or controller_report.get("issues") != []
        ):
            raise QualificationSuccessorError(
                "post_spawn_failure_recovery:terminalization_refused"
            )
        _clean_terminal_authority(authority_after)

        admission_reports = [
            deepcopy(dict(event["payload"]["stage_report"]))
            for event in prior_events
            if event.get("event_type") == "stage_result"
            and isinstance(event.get("payload"), Mapping)
            and isinstance(event["payload"].get("stage_report"), Mapping)
            and event["payload"]["stage_report"].get("operation")
            == "capacity_admission"
            and event["payload"]["stage_report"].get("status") == "PASS"
            and event["payload"]["stage_report"].get("disposition")
            == "SPAWN_AUTHORIZED"
        ]
        active = _capacity_active_lane_ids(capacity_before)
        terminal_stage = controller_report.get("stage_report")
        terminal_receipt = (
            terminal_stage.get("receipt")
            if isinstance(terminal_stage, Mapping)
            and isinstance(terminal_stage.get("receipt"), Mapping)
            else None
        )
        if (
            len(admission_reports) != 1
            or not isinstance(active, list)
            or len(active) != 2
            or not isinstance(terminal_receipt, Mapping)
        ):
            raise QualificationSuccessorError(
                "post_spawn_failure_recovery:capacity_binding_invalid"
            )
        admission = admission_reports[0]
        admission_receipt = admission.get("receipt")
        bindings = (
            admission_receipt.get("bindings")
            if isinstance(admission_receipt, Mapping)
            and isinstance(admission_receipt.get("bindings"), Mapping)
            else None
        )
        logical_lanes = (
            bindings.get("current_wave_logical_lane_ids")
            if isinstance(bindings, Mapping)
            else None
        )
        authority_lanes = (
            bindings.get("capacity_authority_lane_ids")
            if isinstance(bindings, Mapping)
            else None
        )
        created_workers = terminal_receipt.get("created_workers")
        if (
            not isinstance(logical_lanes, list)
            or len(logical_lanes) != 2
            or authority_lanes != active
            or not isinstance(created_workers, list)
            or [
                row.get("logical_lane_id")
                for row in created_workers
                if isinstance(row, Mapping)
            ]
            != logical_lanes
        ):
            raise QualificationSuccessorError(
                "post_spawn_failure_recovery:lane_binding_mismatch"
            )
        activation_payload = prior_state.get("activation")
        attempt_identity = (
            activation_payload.get("identity")
            if isinstance(activation_payload, Mapping)
            and isinstance(activation_payload.get("identity"), Mapping)
            else None
        )
        if not isinstance(attempt_identity, Mapping):
            raise QualificationSuccessorError(
                "post_spawn_failure_recovery:identity_invalid"
            )
        governed_identity = {
            "run_id": attempt_identity.get("run_id"),
            "attempt_id": attempt_identity.get("attempt_id"),
            "root_task_id": attempt_identity.get("root_thread_id"),
            "root_model": attempt_identity.get("root_model"),
            "root_effort": attempt_identity.get("root_effort"),
            "source_version": attempt_identity.get("source_version"),
            "installed_version": attempt_identity.get(
                "installed_plugin_version"
            ),
            "task_loaded_version": attempt_identity.get(
                "task_loaded_version"
            ),
            "fresh_task": attempt_identity.get("fresh_task"),
        }
        try:
            current = owned_file.read_owned_json(
                data / "project-ground/current.json",
                max_bytes=native_controller.MAX_RUNTIME_FILE_BYTES,
            )
            binding = (
                current.get("native_controller")
                if isinstance(current, Mapping)
                and isinstance(current.get("native_controller"), Mapping)
                else None
            )
            if not isinstance(binding, Mapping):
                raise ValueError("terminal binding missing")
            _host_identity, signer, _trust = activation._authority()
            release_receipts: list[dict[str, Any]] = []
            for lane_id in active:
                payload = shared_capacity.cleanup_observer_payload(
                    lane_id=lane_id,
                    run_id=str(governed_identity["run_id"]),
                    route="native_luna",
                    terminal_state="failed",
                    cleanup_status="complete",
                    owned_descendants=0,
                    terminal_evidence_sha256=str(
                        binding["binding_sha256"]
                    ),
                )
                signed = signer.issue(
                    "lane-cleanup-observation",
                    payload,
                    issued_at=(
                        evaluation_time - timedelta(seconds=1)
                    ).isoformat(),
                    valid_until=(
                        evaluation_time + timedelta(minutes=4)
                    ).isoformat(),
                    nonce="issue94-post-spawn-" + _sha(payload)[:24],
                )
                release_receipt = shared_capacity.release(
                    {
                        "lane_id": lane_id,
                        "run_id": governed_identity["run_id"],
                        "route": "native_luna",
                        "state": "failed",
                        "cleanup_status": "complete",
                        "terminal_evidence_sha256": binding[
                            "binding_sha256"
                        ],
                        "cleanup_evidence_sha256": _sha(signed),
                        "cleanup_observer_receipt": signed,
                    },
                    0,
                )
                if release_receipt.get("status") != "RELEASED":
                    raise ValueError("release receipt refused")
                release_receipts.append(release_receipt)
            settlement_program = governed_attempt.build_capacity_settlement_program(
                governed_identity,
                admission,
                release_receipts,
            )
            settlement_report = governed_attempt.evaluate_governed_attempt(
                settlement_program,
                source_roots=roots,
                now=evaluation_time,
                observer=controller._attempt_observer,
                capacity_authority=controller.tower,
            )
            capacity_after = controller.tower.read_shared_capacity_authority()
        except (
            OSError,
            TypeError,
            ValueError,
            shared_capacity.CapacityError,
        ) as error:
            raise QualificationSuccessorError(
                "post_spawn_failure_recovery:capacity_settlement_refused"
            ) from error
        if (
            settlement_report.get("status") != "PASS"
            or settlement_report.get("disposition")
            != "CAPACITY_RELEASED"
            or settlement_report.get("issues") != []
            or _capacity_active_lane_ids(capacity_after) != []
            or not controller._terminal_run_closed(binding)
        ):
            raise QualificationSuccessorError(
                "post_spawn_failure_recovery:settlement_readback_invalid"
            )
        core = {
            "schema": POST_SPAWN_FAILURE_RECOVERY_REPORT_SCHEMA,
            "status": "PASS",
            "decision": "POST_SPAWN_FAILURE_RECOVERED",
            "issues": [],
            "evaluation_time": evaluation_time.isoformat(),
            "controller_program": program,
            "controller_report": deepcopy(dict(controller_report)),
            "predecessor_authority_before": deepcopy(dict(before)),
            "predecessor_authority_after": deepcopy(dict(authority_after)),
            "capacity_authority_before": deepcopy(dict(capacity_before)),
            "release_receipts": deepcopy(release_receipts),
            "settlement_program": settlement_program,
            "settlement_report": deepcopy(dict(settlement_report)),
            "capacity_authority_after": deepcopy(dict(capacity_after)),
            "boundary": {
                "native_action_called": False,
                "next_transition": "fresh_successor_activation",
                "provider_boundary_crossed": False,
                "successor_activation_started": False,
                "task_created": False,
                "worker_created": False,
            },
            "provider_free": True,
            "counters": {
                "capacity_lanes_released": 2,
                "cleanup_observer_receipts_issued": 2,
                "host_seed_credential_reads": 1,
                "hosted_calls": 0,
                "model_calls": 0,
                "native_actions": 0,
                "network_calls": 0,
                "provider_calls": 0,
                "task_creations": 0,
                "terminalizations": 1,
                "worker_creations": 0,
            },
        }
        report = {**core, "report_sha256": _sha(core)}
        if len(_canonical(report)) > MAX_REPORT_BYTES:
            raise QualificationSuccessorError(
                "post_spawn_failure_recovery:report_too_large"
            )
        return QualificationPostSpawnFailureRecoveryArtifact.from_report(
            report
        ).report
    finally:
        controller.store.close()


def recover_issue94_post_ack_bridge_failure(
    *,
    plugin_data: str | Path,
    source_roots: Mapping[str, str | Path],
    dedicated_run_path: str | Path,
    expected_dedicated_run_artifact_sha256: str,
    attempt_envelope_path: str | Path,
    expected_attempt_envelope_artifact_sha256: str,
    pre_turn_report_path: str | Path,
    expected_pre_turn_artifact_sha256: str,
    root_rollout_path: str | Path,
    expected_root_rollout_artifact_sha256: str,
    worker_rollout_paths: Mapping[str, str | Path],
    expected_worker_rollout_artifact_sha256: Mapping[str, str],
    historical_runtime_plugin_root: str | Path,
    expected_historical_package_digest: str,
    pretool_denial_path: str | Path | None = None,
    expected_pretool_denial_artifact_sha256: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Terminalize and release one exact profiled ACK bridge failure."""

    prefix = "post_ack_bridge_failure_recovery:"
    data = _runtime_root(plugin_data, label=prefix + "plugin_data")
    historical = _runtime_root(
        historical_runtime_plugin_root,
        label=prefix + "historical_runtime",
    )
    if (
        not isinstance(source_roots, Mapping)
        or set(source_roots) != {"evidence", "source"}
    ):
        raise QualificationSuccessorError(prefix + "source_roots_invalid")
    roots = {
        name: _runtime_root(path, label=prefix + name + "_root")
        for name, path in source_roots.items()
    }
    evaluation_time = (now or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    pending_continuation_denial = bool(
        pretool_denial_path is not None
        and expected_pretool_denial_artifact_sha256 is not None
    )
    if (pretool_denial_path is None) != (
        expected_pretool_denial_artifact_sha256 is None
    ):
        raise QualificationSuccessorError(prefix + "denial_evidence_invalid")
    try:
        _host_identity, signer, _cleanup_trust = activation._authority()
    except (OSError, TypeError, ValueError) as error:
        raise QualificationSuccessorError(
            prefix + "observer_authority_unavailable"
        ) from error
    try:
        controller = native_controller.GovernedNativeController(
            plugin_data=data,
            hook_definition_path=(
                historical / "hooks/project_ground_hook.py"
            ),
            source_roots=roots,
            now=evaluation_time,
        )
    except (OSError, TypeError, ValueError) as error:
        raise QualificationSuccessorError(
            prefix + "controller_unavailable"
        ) from error
    try:
        before = controller.grants.canonical_authority()
        owner = before.get("owner") if isinstance(before, Mapping) else None
        lifecycle = (
            before.get("lifecycle")
            if isinstance(before, Mapping)
            and isinstance(before.get("lifecycle"), Mapping)
            else None
        )
        waiting_lifecycle = bool(
            isinstance(lifecycle, Mapping)
            and lifecycle.get("expected_binding_status") == "WAITING"
            and lifecycle.get("grant_state") is None
            and lifecycle.get("action_sha256") is None
        )
        pending_lifecycle = bool(
            isinstance(lifecycle, Mapping)
            and lifecycle.get("expected_binding_status") == "ACTIVE"
            and lifecycle.get("grant_state") == "AUTHORIZED"
            and _is_sha(lifecycle.get("action_sha256"))
        )
        if (
            before.get("status") != "VERIFIED"
            or not isinstance(owner, Mapping)
            or not _text(owner.get("controller_id"))
            or not isinstance(before.get("tip"), Mapping)
            or not isinstance(lifecycle, Mapping)
            or lifecycle.get("terminal") is not False
            or lifecycle.get("pending_intent") is not False
            or lifecycle.get("cleanup_required") is not False
            or lifecycle.get("tool_use_id") is not None
            or (
                pending_continuation_denial
                and not pending_lifecycle
            )
            or (
                not pending_continuation_denial
                and not waiting_lifecycle
            )
        ):
            raise QualificationSuccessorError(
                prefix + "exact_predecessor_required"
            )
        try:
            prior_state, prior_rows = controller._state(
                str(owner["controller_run_id"])
            )
            prior_events = native_controller._controller_events(
                list(prior_rows)
            )
            capacity_before = controller.tower.read_shared_capacity_authority()
            program = (
                native_controller
                .build_post_ack_bridge_failure_terminalization_program(
                    controller_id=str(owner["controller_id"]),
                    expected_cursor=before["tip"],
                    dedicated_run_path=dedicated_run_path,
                    expected_dedicated_run_artifact_sha256=(
                        expected_dedicated_run_artifact_sha256
                    ),
                    attempt_envelope_path=attempt_envelope_path,
                    expected_attempt_envelope_artifact_sha256=(
                        expected_attempt_envelope_artifact_sha256
                    ),
                    pre_turn_report_path=pre_turn_report_path,
                    expected_pre_turn_artifact_sha256=(
                        expected_pre_turn_artifact_sha256
                    ),
                    root_rollout_path=root_rollout_path,
                    expected_root_rollout_artifact_sha256=(
                        expected_root_rollout_artifact_sha256
                    ),
                    worker_rollout_paths=worker_rollout_paths,
                    expected_worker_rollout_artifact_sha256=(
                        expected_worker_rollout_artifact_sha256
                    ),
                    historical_runtime_root=historical,
                    expected_package_digest=(
                        expected_historical_package_digest
                    ),
                    pretool_denial_path=pretool_denial_path,
                    expected_pretool_denial_artifact_sha256=(
                        expected_pretool_denial_artifact_sha256
                    ),
                )
            )
        except (OSError, TypeError, ValueError) as error:
            raise QualificationSuccessorError(
                prefix + "evidence_invalid"
            ) from error
        controller_report = (
            controller.terminalize_post_ack_bridge_failure(program)
        )
        authority_after = controller.grants.canonical_authority()
        if (
            controller_report.get("status") != "PASS"
            or controller_report.get("decision")
            != "POST_ACK_BRIDGE_FAILURE_TERMINALIZED"
            or controller_report.get("issues") != []
        ):
            raise QualificationSuccessorError(
                prefix + "terminalization_refused"
            )
        _clean_terminal_authority(authority_after)

        admission_reports = [
            deepcopy(dict(event["payload"]["stage_report"]))
            for event in prior_events
            if event.get("event_type") == "stage_result"
            and isinstance(event.get("payload"), Mapping)
            and isinstance(event["payload"].get("stage_report"), Mapping)
            and event["payload"]["stage_report"].get("operation")
            == "capacity_admission"
            and event["payload"]["stage_report"].get("status") == "PASS"
            and event["payload"]["stage_report"].get("disposition")
            == "SPAWN_AUTHORIZED"
        ]
        active = _capacity_active_lane_ids(capacity_before)
        terminal_stage = controller_report.get("stage_report")
        terminal_receipt = (
            terminal_stage.get("receipt")
            if isinstance(terminal_stage, Mapping)
            and isinstance(terminal_stage.get("receipt"), Mapping)
            else None
        )
        if (
            len(admission_reports) != 1
            or not isinstance(active, list)
            or len(active) != 2
            or not isinstance(terminal_receipt, Mapping)
        ):
            raise QualificationSuccessorError(
                prefix + "capacity_binding_invalid"
            )
        admission = admission_reports[0]
        admission_receipt = admission.get("receipt")
        bindings = (
            admission_receipt.get("bindings")
            if isinstance(admission_receipt, Mapping)
            and isinstance(admission_receipt.get("bindings"), Mapping)
            else None
        )
        logical_lanes = (
            bindings.get("current_wave_logical_lane_ids")
            if isinstance(bindings, Mapping)
            else None
        )
        authority_lanes = (
            bindings.get("capacity_authority_lane_ids")
            if isinstance(bindings, Mapping)
            else None
        )
        created_workers = terminal_receipt.get("created_workers")
        if (
            not isinstance(logical_lanes, list)
            or len(logical_lanes) != 2
            or authority_lanes != active
            or not isinstance(created_workers, list)
            or [
                row.get("logical_lane_id")
                for row in created_workers
                if isinstance(row, Mapping)
            ]
            != logical_lanes
            or any(
                not isinstance(row, Mapping)
                or row.get("terminal_task_complete_count") != 1
                or not _is_sha(row.get("pre_work_receipt_sha256"))
                for row in created_workers
            )
        ):
            raise QualificationSuccessorError(prefix + "lane_binding_mismatch")
        activation_payload = prior_state.get("activation")
        attempt_identity = (
            activation_payload.get("identity")
            if isinstance(activation_payload, Mapping)
            and isinstance(activation_payload.get("identity"), Mapping)
            else None
        )
        if not isinstance(attempt_identity, Mapping):
            raise QualificationSuccessorError(prefix + "identity_invalid")
        governed_identity = {
            "run_id": attempt_identity.get("run_id"),
            "attempt_id": attempt_identity.get("attempt_id"),
            "root_task_id": attempt_identity.get("root_thread_id"),
            "root_model": attempt_identity.get("root_model"),
            "root_effort": attempt_identity.get("root_effort"),
            "source_version": attempt_identity.get("source_version"),
            "installed_version": attempt_identity.get(
                "installed_plugin_version"
            ),
            "task_loaded_version": attempt_identity.get(
                "task_loaded_version"
            ),
            "fresh_task": attempt_identity.get("fresh_task"),
        }
        try:
            current = owned_file.read_owned_json(
                data / "project-ground/current.json",
                max_bytes=native_controller.MAX_RUNTIME_FILE_BYTES,
            )
            binding = (
                current.get("native_controller")
                if isinstance(current, Mapping)
                and isinstance(current.get("native_controller"), Mapping)
                else None
            )
            if not isinstance(binding, Mapping):
                raise ValueError("terminal binding missing")
            release_receipts: list[dict[str, Any]] = []
            for lane_id in active:
                payload = shared_capacity.cleanup_observer_payload(
                    lane_id=lane_id,
                    run_id=str(governed_identity["run_id"]),
                    route="native_luna",
                    terminal_state="failed",
                    cleanup_status="complete",
                    owned_descendants=0,
                    terminal_evidence_sha256=str(binding["binding_sha256"]),
                )
                signed = signer.issue(
                    "lane-cleanup-observation",
                    payload,
                    issued_at=(
                        evaluation_time - timedelta(seconds=1)
                    ).isoformat(),
                    valid_until=(
                        evaluation_time + timedelta(minutes=4)
                    ).isoformat(),
                    nonce="issue94-post-ack-" + _sha(payload)[:24],
                )
                release_receipt = shared_capacity.release(
                    {
                        "lane_id": lane_id,
                        "run_id": governed_identity["run_id"],
                        "route": "native_luna",
                        "state": "failed",
                        "cleanup_status": "complete",
                        "terminal_evidence_sha256": binding[
                            "binding_sha256"
                        ],
                        "cleanup_evidence_sha256": _sha(signed),
                        "cleanup_observer_receipt": signed,
                    },
                    0,
                )
                if release_receipt.get("status") != "RELEASED":
                    raise ValueError("release receipt refused")
                release_receipts.append(release_receipt)
            settlement_program = governed_attempt.build_capacity_settlement_program(
                governed_identity,
                admission,
                release_receipts,
            )
            settlement_report = governed_attempt.evaluate_governed_attempt(
                settlement_program,
                source_roots=roots,
                now=evaluation_time,
                observer=controller._attempt_observer,
                capacity_authority=controller.tower,
            )
            capacity_after = controller.tower.read_shared_capacity_authority()
        except (
            OSError,
            TypeError,
            ValueError,
            shared_capacity.CapacityError,
        ) as error:
            raise QualificationSuccessorError(
                prefix + "capacity_settlement_refused"
            ) from error
        if (
            settlement_report.get("status") != "PASS"
            or settlement_report.get("disposition") != "CAPACITY_RELEASED"
            or settlement_report.get("issues") != []
            or _capacity_active_lane_ids(capacity_after) != []
            or not controller._terminal_run_closed(binding)
        ):
            raise QualificationSuccessorError(
                prefix + "settlement_readback_invalid"
            )
        if pending_continuation_denial:
            capacity_tip = controller.grants.verified_tip(
                str(capacity_after.get("store_id"))
            )
            grant_settlement = (
                controller.grants.terminalize_pretool_denied_action(
                    expected_owner=owner,
                    terminal_binding=binding,
                    capacity_tip=capacity_tip or {},
                    capacity_authority=capacity_after,
                )
            )
            if (
                grant_settlement.get("status") != "TERMINALIZED"
                or grant_settlement.get("state")
                != "TERMINAL_PRETOOL_DENIED"
                or grant_settlement.get("historical_outcome")
                != "not_executed"
            ):
                raise QualificationSuccessorError(
                    prefix + "grant_settlement_refused"
                )
            authority_after = controller.grants.canonical_authority()
            _clean_terminal_authority(authority_after)
        core = {
            "schema": POST_ACK_BRIDGE_FAILURE_RECOVERY_REPORT_SCHEMA,
            "status": "PASS",
            "decision": "POST_ACK_BRIDGE_FAILURE_RECOVERED",
            "issues": [],
            "evaluation_time": evaluation_time.isoformat(),
            "controller_program": program,
            "controller_report": deepcopy(dict(controller_report)),
            "predecessor_authority_before": deepcopy(dict(before)),
            "predecessor_authority_after": deepcopy(dict(authority_after)),
            "capacity_authority_before": deepcopy(dict(capacity_before)),
            "release_receipts": deepcopy(release_receipts),
            "settlement_program": settlement_program,
            "settlement_report": deepcopy(dict(settlement_report)),
            "capacity_authority_after": deepcopy(dict(capacity_after)),
            "boundary": {
                "native_action_called": False,
                "next_transition": "fresh_successor_activation",
                "provider_boundary_crossed": False,
                "successor_activation_started": False,
                "task_created": False,
                "worker_created": False,
            },
            "provider_free": True,
            "counters": {
                "capacity_lanes_released": 2,
                "cleanup_observer_receipts_issued": 2,
                "host_seed_credential_reads": 1,
                "hosted_calls": 0,
                "model_calls": 0,
                "native_actions": 0,
                "network_calls": 0,
                "provider_calls": 0,
                "task_creations": 0,
                "terminalizations": 1,
                "worker_creations": 0,
            },
        }
        report = {**core, "report_sha256": _sha(core)}
        if len(_canonical(report)) > MAX_REPORT_BYTES:
            raise QualificationSuccessorError(prefix + "report_too_large")
        return QualificationPostAckBridgeFailureRecoveryArtifact.from_report(
            report
        ).report
    finally:
        controller.store.close()


def settle_issue94_terminal_predecessor_capacity(
    *,
    plugin_data: str | Path,
    hook_definition_path: str | Path,
    source_roots: Mapping[str, str | Path],
    now: datetime | None = None,
    pre_native_failure_report_path: str | Path | None = None,
    expected_pre_native_failure_artifact_sha256: str | None = None,
    predecessor_authority_path: str | Path | None = None,
    expected_predecessor_authority_artifact_sha256: str | None = None,
    historical_runtime_plugin_root: str | Path | None = None,
    expected_historical_package_digest: str | None = None,
) -> dict[str, Any]:
    """Settle only the exact terminal, action-null Issue 94 predecessor."""

    data = _runtime_root(
        plugin_data,
        label="predecessor_settlement:plugin_data",
    )
    hook_path = Path(hook_definition_path)
    if (
        not hook_path.is_absolute()
        or hook_path.is_symlink()
        or not hook_path.is_file()
    ):
        raise QualificationSuccessorError(
            "predecessor_settlement:hook_definition_invalid"
        )
    if (
        not isinstance(source_roots, Mapping)
        or set(source_roots) != {"evidence", "source"}
    ):
        raise QualificationSuccessorError(
            "predecessor_settlement:source_roots_invalid"
        )
    roots = {
        name: _runtime_root(
            path,
            label="predecessor_settlement:" + name + "_root",
        )
        for name, path in source_roots.items()
    }
    evaluation_time = (now or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    recovery_inputs = (
        pre_native_failure_report_path,
        expected_pre_native_failure_artifact_sha256,
        predecessor_authority_path,
        expected_predecessor_authority_artifact_sha256,
        historical_runtime_plugin_root,
        expected_historical_package_digest,
    )
    if any(value is not None for value in recovery_inputs) and not all(
        value is not None for value in recovery_inputs
    ):
        raise QualificationSuccessorError(
            "predecessor_settlement:pre_native_failure_reference_incomplete"
        )
    pre_native_failure_settlement: dict[str, Any] | None = None
    if all(value is not None for value in recovery_inputs):
        pre_native_failure_settlement = terminalize_issue94_pre_native_failure(
            plugin_data=data,
            source_roots=roots,
            failure_report_path=pre_native_failure_report_path,
            expected_failure_artifact_sha256=str(
                expected_pre_native_failure_artifact_sha256
            ),
            predecessor_authority_path=predecessor_authority_path,
            expected_authority_artifact_sha256=str(
                expected_predecessor_authority_artifact_sha256
            ),
            historical_runtime_plugin_root=historical_runtime_plugin_root,
            expected_historical_package_digest=str(
                expected_historical_package_digest
            ),
            now=evaluation_time,
        )
    try:
        controller = native_controller.GovernedNativeController(
            plugin_data=data,
            hook_definition_path=hook_path,
            source_roots=roots,
            now=evaluation_time,
        )
    except (OSError, TypeError, ValueError) as error:
        raise QualificationSuccessorError(
            "predecessor_settlement:controller_unavailable"
        ) from error
    try:
        authority = _clean_terminal_authority(
            controller.grants.canonical_authority()
        )
        owner = authority.get("owner")
        authority_identity = authority.get("identity")
        lifecycle = authority.get("lifecycle")
        if (
            not isinstance(owner, Mapping)
            or not isinstance(authority_identity, Mapping)
            or not isinstance(lifecycle, Mapping)
        ):
            raise QualificationSuccessorError(
                "predecessor_settlement:owner_invalid"
            )
        controller_id = owner.get("controller_id")
        controller_run_id = owner.get("controller_run_id")
        if not _text(controller_id) or not _text(controller_run_id):
            raise QualificationSuccessorError(
                "predecessor_settlement:owner_invalid"
            )
        try:
            state, rows = controller._state(str(controller_run_id))
            events = native_controller._controller_events(list(rows))
            cursor = native_controller._cursor(list(rows))
        except (KeyError, TypeError, ValueError) as error:
            raise QualificationSuccessorError(
                "predecessor_settlement:controller_stream_invalid"
            ) from error
        activation_payload = state.get("activation")
        attempt_identity = (
            activation_payload.get("identity")
            if isinstance(activation_payload, Mapping)
            else None
        )
        try:
            current = owned_file.read_owned_json(
                data / "project-ground/current.json",
                max_bytes=native_controller.MAX_RUNTIME_FILE_BYTES,
            )
        except (OSError, json.JSONDecodeError, ValueError) as error:
            raise QualificationSuccessorError(
                "predecessor_settlement:binding_unavailable"
            ) from error
        binding = (
            current.get("native_controller")
            if isinstance(current, Mapping)
            else None
        )
        binding_core = (
            {
                key: child
                for key, child in binding.items()
                if key != "binding_sha256"
            }
            if isinstance(binding, Mapping)
            else {}
        )
        if (
            not isinstance(attempt_identity, Mapping)
            or not isinstance(binding, Mapping)
            or not isinstance(cursor, Mapping)
            or binding.get("status") != "TERMINAL"
            or binding.get("controller_id") != controller_id
            or binding.get("controller_run_id") != controller_run_id
            or binding.get("controller_seq") != cursor.get("seq")
            or binding.get("controller_event_hash")
            != cursor.get("event_hash")
            or binding.get("action") is not None
            or binding.get("binding_sha256") != _sha(binding_core)
            or state.get("terminal") is not True
            or state.get("pending_intent") is not None
            or state.get("action") is not None
            or state.get("cleanup_required") is not False
            or authority_identity.get("controller_id") != controller_id
            or authority_identity.get("controller_run_id")
            != controller_run_id
            or authority_identity.get("root_thread_id")
            != attempt_identity.get("root_thread_id")
            or authority_identity.get("root_session_id")
            != attempt_identity.get("root_session_id")
        ):
            raise QualificationSuccessorError(
                "predecessor_settlement:terminal_binding_invalid"
            )
        try:
            before = controller.tower.read_shared_capacity_authority()
        except (OSError, TypeError, ValueError) as error:
            raise QualificationSuccessorError(
                "predecessor_settlement:capacity_authority_unverified"
            ) from error
        active = _capacity_active_lane_ids(before)
        if active is None:
            raise QualificationSuccessorError(
                "predecessor_settlement:capacity_authority_unverified"
            )

        stage_reports = [
            deepcopy(dict(event["payload"]["stage_report"]))
            for event in events
            if event.get("event_type") == "stage_result"
            and isinstance(event.get("payload"), Mapping)
            and isinstance(event["payload"].get("stage_report"), Mapping)
        ]
        capacity_reports = [
            report
            for report in stage_reports
            if report.get("operation") == "capacity_admission"
            and report.get("status") == "PASS"
            and report.get("disposition") == "SPAWN_AUTHORIZED"
        ]
        detected_failed_settlement = (
            deepcopy(dict(state["stage_report"]))
            if isinstance(state.get("stage_report"), Mapping)
            and state["stage_report"].get("operation")
            == "capacity_settlement"
            and state["stage_report"].get("status") == "BLOCKED"
            and state["stage_report"].get("issues")
            == ["shared_capacity:release_receipt_set_invalid"]
            else None
        )
        settlement_program: dict[str, Any] | None = None
        settlement_report: dict[str, Any] | None = None
        admission_report: dict[str, Any] | None = None
        failed_settlement: dict[str, Any] | None = None
        released_authority: list[str] = []
        released_logical: list[str] = []
        credential_reads = 0
        receipt_count = 0
        after = deepcopy(dict(before))
        decision = (
            "TERMINALIZED"
            if pre_native_failure_settlement is not None
            else "NOT_REQUIRED"
        )

        if active:
            if (
                len(capacity_reports) != 1
                or [report.get("operation") for report in stage_reports]
                != ["pre_spawn", "capacity_admission", "capacity_settlement"]
                or detected_failed_settlement is None
                or state.get("seen_action_ids") != []
                or state.get("grant") is not None
                or state.get("grant_state") is not None
                or lifecycle.get("grant_state") is not None
            ):
                raise QualificationSuccessorError(
                    "predecessor_settlement:not_unmaterialized_terminal"
                )
            admission_report = capacity_reports[0]
            failed_settlement = detected_failed_settlement
            admission_receipt = admission_report.get("receipt")
            bindings = (
                admission_receipt.get("bindings")
                if isinstance(admission_receipt, Mapping)
                and isinstance(admission_receipt.get("bindings"), Mapping)
                else None
            )
            logical = (
                bindings.get("current_wave_logical_lane_ids")
                if isinstance(bindings, Mapping)
                else None
            )
            authority_lanes = (
                bindings.get("capacity_authority_lane_ids")
                if isinstance(bindings, Mapping)
                else None
            )
            governed_identity = {
                "run_id": attempt_identity.get("run_id"),
                "attempt_id": attempt_identity.get("attempt_id"),
                "root_task_id": attempt_identity.get("root_thread_id"),
                "root_model": attempt_identity.get("root_model"),
                "root_effort": attempt_identity.get("root_effort"),
                "source_version": attempt_identity.get("source_version"),
                "installed_version": attempt_identity.get(
                    "installed_plugin_version"
                ),
                "task_loaded_version": attempt_identity.get(
                    "task_loaded_version"
                ),
                "fresh_task": attempt_identity.get("fresh_task"),
            }
            expected_authority_lanes = [
                str(governed_identity["run_id"]) + ":" + lane
                for lane in ["spec", "standards"]
            ]
            if (
                logical != ["spec", "standards"]
                or authority_lanes != expected_authority_lanes
                or active != expected_authority_lanes
                or bindings.get("capacity_authority_state_sha256")
                != before.get("state_sha256")
            ):
                raise QualificationSuccessorError(
                    "predecessor_settlement:lane_binding_mismatch"
                )
            try:
                _host_identity, signer, _trust = activation._authority()
            except (OSError, TypeError, ValueError) as error:
                raise QualificationSuccessorError(
                    "predecessor_settlement:signing_authority_unavailable"
                ) from error
            credential_reads = 1
            release_receipts: list[dict[str, Any]] = []
            try:
                for lane_id in active:
                    payload = shared_capacity.cleanup_observer_payload(
                        lane_id=lane_id,
                        run_id=str(governed_identity["run_id"]),
                        route="native_luna",
                        terminal_state="failed",
                        cleanup_status="not_required",
                        owned_descendants=0,
                        terminal_evidence_sha256=str(
                            binding["binding_sha256"]
                        ),
                    )
                    signed = signer.issue(
                        "lane-cleanup-observation",
                        payload,
                        issued_at=(
                            evaluation_time - timedelta(seconds=1)
                        ).isoformat(),
                        valid_until=(
                            evaluation_time + timedelta(minutes=4)
                        ).isoformat(),
                        nonce=(
                            "issue94-terminal-capacity-"
                            + _sha(payload)[:24]
                        ),
                    )
                    release_receipt = shared_capacity.release(
                        {
                            "lane_id": lane_id,
                            "run_id": governed_identity["run_id"],
                            "route": "native_luna",
                            "state": "failed",
                            "cleanup_status": "not_required",
                            "terminal_evidence_sha256": binding[
                                "binding_sha256"
                            ],
                            "cleanup_evidence_sha256": _sha(signed),
                            "cleanup_observer_receipt": signed,
                        },
                        0,
                    )
                    if (
                        release_receipt.get("status") != "RELEASED"
                        or release_receipt.get("released") is not True
                    ):
                        raise QualificationSuccessorError(
                            "predecessor_settlement:release_receipt_invalid"
                        )
                    release_receipts.append(release_receipt)
                receipt_count = len(release_receipts)
                settlement_program = (
                    governed_attempt.build_capacity_settlement_program(
                        governed_identity,
                        admission_report,
                        release_receipts,
                    )
                )
                evaluated = governed_attempt.evaluate_governed_attempt(
                    settlement_program,
                    source_roots=roots,
                    now=evaluation_time,
                    observer=controller._attempt_observer,
                    capacity_authority=controller.tower,
                )
            except QualificationSuccessorError:
                raise
            except (
                OSError,
                TypeError,
                ValueError,
                shared_capacity.CapacityError,
            ) as error:
                raise QualificationSuccessorError(
                    "predecessor_settlement:operation_refused"
                ) from error
            settlement_report = (
                deepcopy(dict(evaluated))
                if isinstance(evaluated, Mapping)
                else {}
            )
            try:
                after = controller.tower.read_shared_capacity_authority()
            except (OSError, TypeError, ValueError) as error:
                raise QualificationSuccessorError(
                    "predecessor_settlement:readback_unverified"
                ) from error
            after_active = _capacity_active_lane_ids(after)
            released_from_report = (
                settlement_report.get("receipt", {})
                .get("bindings", {})
                .get("failed_logical_lane_ids")
                if isinstance(settlement_report.get("receipt"), Mapping)
                else None
            )
            if (
                settlement_report.get("status") != "PASS"
                or settlement_report.get("disposition")
                != "CAPACITY_RELEASED"
                or settlement_report.get("issues") != []
                or after_active != []
                or released_from_report != ["spec", "standards"]
            ):
                raise QualificationSuccessorError(
                    "predecessor_settlement:settlement_refused"
                )
            released_authority = list(active)
            released_logical = ["spec", "standards"]
            decision = "SETTLED"

        if not controller._terminal_run_closed(binding):
            raise QualificationSuccessorError(
                "predecessor_settlement:terminal_readback_invalid"
            )
        predecessor = {
            "controller_id": str(controller_id),
            "controller_run_id": str(controller_run_id),
            "root_task_id": str(attempt_identity.get("root_thread_id")),
            "attempt_id": str(attempt_identity.get("attempt_id")),
            "run_id": str(attempt_identity.get("run_id")),
            "binding_sha256": str(binding["binding_sha256"]),
            "authority_sha256": _sha(authority),
        }
        counters = dict(_SETTLEMENT_ZERO_COUNTERS)
        counters.update(
            {
                "capacity_lanes_released": len(released_authority),
                "cleanup_observer_receipts_issued": receipt_count,
                "host_seed_credential_reads": credential_reads,
                "pre_native_failures_terminalized": (
                    1 if pre_native_failure_settlement is not None else 0
                ),
            }
        )
        core = {
            "schema": PREDECESSOR_SETTLEMENT_REPORT_SCHEMA,
            "status": "PASS",
            "decision": decision,
            "issues": [],
            "evaluation_time": evaluation_time.isoformat(),
            "predecessor": predecessor,
            "capacity_authority_before": deepcopy(dict(before)),
            "pre_native_failure_settlement_report": (
                deepcopy(dict(pre_native_failure_settlement))
                if pre_native_failure_settlement is not None
                else None
            ),
            "capacity_admission_report": admission_report,
            "failed_settlement_report": failed_settlement,
            "settlement_program": settlement_program,
            "settlement_report": settlement_report,
            "capacity_authority_after": deepcopy(dict(after)),
            "released_authority_lane_ids": released_authority,
            "released_logical_lane_ids": released_logical,
            "boundary": {
                "native_action_called": False,
                "next_transition": "successor_activation",
                "provider_boundary_crossed": False,
                "successor_activation_started": False,
                "task_created": False,
                "worker_created": False,
            },
            "provider_free": True,
            "counters": counters,
        }
        report = {**core, "report_sha256": _sha(core)}
        if len(_canonical(report)) > MAX_REPORT_BYTES:
            raise QualificationSuccessorError(
                "predecessor_settlement:report_too_large"
            )
        return QualificationPredecessorSettlementArtifact.from_report(
            report
        ).report
    finally:
        controller.store.close()


def observe_idle_successor_preactivation(
    *,
    plugin_data: str | Path,
    root_task_id: str,
    root_model: str,
    source_root: str | Path,
    runtime_report: Any | None = None,
    env: MutableMapping[str, str] | Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Seal the idle owner and clean predecessor before first-turn startup."""

    if not _text(root_task_id) or not _text(root_model):
        raise QualificationSuccessorError("successor_startup:identity_invalid")
    root = _runtime_root(source_root, label="successor_startup:source_root")
    data = bootstrap._owned_evidence_root(plugin_data)
    observed_runtime = _runtime_report(
        runtime_report
        if runtime_report is not None
        else local_task_runtime.observe_local_task_pre_turn_runtime(
            task_id=root_task_id,
            env=env,
        ),
        task_id=root_task_id,
    )
    grants = native_grant_store.NativeGrantStore(
        native_grant_store.canonical_database_path(data)
    )
    authority = _clean_terminal_authority(grants.canonical_authority())
    predecessor_identity = authority["identity"]
    if root_task_id in {
        predecessor_identity.get("root_thread_id"),
        predecessor_identity.get("root_session_id"),
    }:
        raise QualificationSuccessorError(
            "successor_preparation:task_not_distinct"
        )
    core = {
        "schema": PREACTIVATION_REPORT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "root_task_id": root_task_id,
        "root_session_id": root_task_id,
        "root_model": root_model,
        "source_root": str(root),
        "owner_runtime_report": observed_runtime,
        "predecessor_authority_sha256": _sha(authority),
        "predecessor_controller_id": predecessor_identity["controller_id"],
        "session_start_observed": False,
        "next_required_transition": "turn/start:SessionStart",
        "provider_free": True,
        "hosted_calls": 0,
        "model_calls": 0,
        "native_calls": 0,
        "task_creations": 0,
        "worker_creations": 0,
    }
    return {**core, "report_sha256": _sha(core)}


def _artifact_reference(path: Path, report_sha256: str) -> dict[str, Any]:
    raw = owned_file.read_owned_bytes(
        path,
        max_bytes=MAX_REPORT_BYTES,
        required_mode=0o600,
    )
    return {
        "path": str(path),
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "report_sha256": report_sha256,
    }


def read_issue94_successor_pre_turn_artifact(
    path: str | Path,
    *,
    expected_report_sha256: str,
) -> QualificationSuccessorArtifact:
    """Read one canonical mode-0600 pre-turn report without aliases."""

    candidate = Path(path)
    if (
        not candidate.is_absolute()
        or candidate.is_symlink()
        or not _is_sha(expected_report_sha256)
    ):
        raise QualificationSuccessorError(
            "successor_pre_turn:artifact_reference_invalid"
        )
    try:
        raw = owned_file.read_owned_bytes(
            candidate,
            max_bytes=MAX_REPORT_BYTES,
            required_mode=0o600,
        )
        report = json.loads(raw.decode("utf-8"))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        raise QualificationSuccessorError(
            "successor_pre_turn:artifact_unavailable"
        ) from error
    artifact = QualificationSuccessorArtifact.from_report(report)
    if (
        artifact.report_sha256 != expected_report_sha256
        or raw != _canonical(artifact.report) + b"\n"
    ):
        raise QualificationSuccessorError(
            "successor_pre_turn:artifact_reference_invalid"
        )
    return artifact


def _read_successor_bootstrap_report(
    artifact: QualificationSuccessorArtifact,
    pre_turn_report_path: Path,
) -> dict[str, Any]:
    reference = artifact.artifacts["bootstrap"]
    bootstrap_path = Path(reference["path"])
    evidence_root = bootstrap._owned_evidence_root(
        pre_turn_report_path.parent
    )
    try:
        bootstrap_reference_valid = bool(
            bootstrap_path.is_absolute()
            and bootstrap_path.parent.resolve(strict=True) == evidence_root
            and not bootstrap_path.is_symlink()
        )
    except OSError:
        bootstrap_reference_valid = False
    if not bootstrap_reference_valid:
        raise QualificationSuccessorError(
            "successor_first_action:bootstrap_reference_invalid"
        )
    try:
        raw = owned_file.read_owned_bytes(
            bootstrap_path,
            max_bytes=bootstrap.MAX_ARTIFACT_BYTES,
            required_mode=0o600,
        )
        bootstrap_report = json.loads(raw.decode("utf-8"))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        raise QualificationSuccessorError(
            "successor_first_action:bootstrap_unavailable"
        ) from error
    if (
        hashlib.sha256(raw).hexdigest() != reference["artifact_sha256"]
        or not isinstance(bootstrap_report, Mapping)
        or bootstrap_report.get("report_sha256")
        != reference["report_sha256"]
        or bootstrap_report.get("schema") != bootstrap.REPORT_SCHEMA
        or bootstrap_report.get("status") != "PASS"
        or bootstrap_report.get("issues") != []
        or not _sealed(bootstrap_report, "report_sha256")
        or raw != _canonical(bootstrap_report) + b"\n"
    ):
        raise QualificationSuccessorError(
            "successor_first_action:bootstrap_reference_invalid"
        )
    return deepcopy(dict(bootstrap_report))


def _read_successor_first_action_preparation(
    artifact: QualificationSuccessorArtifact,
    pre_turn_report_path: Path,
) -> QualificationSuccessorFirstActionPreparationArtifact:
    bootstrap_report = _read_successor_bootstrap_report(
        artifact, pre_turn_report_path
    )
    reference = artifact.artifacts["first_action_preparation"]
    preparation_path = Path(reference["path"])
    evidence_root = bootstrap._owned_evidence_root(
        pre_turn_report_path.parent
    )
    try:
        preparation_reference_valid = bool(
            preparation_path.is_absolute()
            and preparation_path.parent.resolve(strict=True)
            == evidence_root
            and not preparation_path.is_symlink()
        )
    except OSError:
        preparation_reference_valid = False
    if not preparation_reference_valid:
        raise QualificationSuccessorError(
            "successor_first_action:preparation_reference_invalid"
        )
    try:
        raw = owned_file.read_owned_bytes(
            preparation_path,
            max_bytes=MAX_REPORT_BYTES,
            required_mode=0o600,
        )
        preparation_report = json.loads(raw.decode("utf-8"))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        raise QualificationSuccessorError(
            "successor_first_action:preparation_unavailable"
        ) from error
    try:
        preparation = (
            QualificationSuccessorFirstActionPreparationArtifact.from_report(
                preparation_report
            )
        )
    except (TypeError, ValueError) as error:
        raise QualificationSuccessorError(
            "successor_first_action:preparation_invalid"
        ) from error
    expected_roots = {
        "evidence": str(evidence_root),
        "source": artifact.report["preactivation_report"]["source_root"],
    }
    if (
        hashlib.sha256(raw).hexdigest()
        != reference["artifact_sha256"]
        or preparation.report_sha256 != reference["report_sha256"]
        or raw != _canonical(preparation.report) + b"\n"
        or preparation.bootstrap_report_sha256
        != bootstrap_report["report_sha256"]
        or bootstrap_report.get("controller_id")
        != artifact.controller_id
        or bootstrap_report.get("source_roots") != expected_roots
        or preparation.controller_id != artifact.controller_id
        or preparation.root_task_id != artifact.root_task_id
        or preparation.root_model != artifact.root_model
        or preparation.source_roots != expected_roots
    ):
        raise QualificationSuccessorError(
            "successor_first_action:preparation_reference_invalid"
        )
    return preparation


_OWNER_CONTROL_STEP_FIELDS = frozenset({"schema", "tool", "pre_turn_report_sha256", "step"})
_OWNER_CONTROL_STEP_NAME = re.compile(r"[0-9]{4}-[a-z0-9_]+[.]open[.]json\Z")


def claim_owner_control_step(
    *,
    pre_turn_report_path: str | Path,
    expected_report_sha256: str,
    tool: str,
) -> dict[str, Any] | None:
    """Admit one control call only inside a step its qualification owner opened.

    An owner that gates its control calls creates the steps directory beside
    the pre-turn report and writes one open record before each control turn.
    The first matching call claims that record by moving it aside. Any other
    call, including a second call in the same turn or one made while the
    owner waits for a native action, gets the refusal report before the
    controller is read, so it has no effect. A flow without the directory is
    not gated. Returns None to admit the call, or the refusal report.
    """

    if (
        tool not in native_controller.QUALIFICATION_OWNER_CONTROL_STEP_TOOLS
        or not _is_sha(expected_report_sha256)
    ):
        raise QualificationSuccessorError("successor_control:owner_step_input_invalid")
    directory = (
        Path(pre_turn_report_path).parent
        / native_controller.QUALIFICATION_OWNER_CONTROL_STEPS_DIRECTORY
    )
    if not directory.exists() and not directory.is_symlink():
        return None
    if directory.is_symlink() or not directory.is_dir():
        raise QualificationSuccessorError("successor_control:owner_steps_invalid")
    refusal = native_controller.qualification_owner_control_step_refusal(
        tool, expected_report_sha256
    )
    matches = []
    for path in sorted(directory.iterdir()):
        if not _OWNER_CONTROL_STEP_NAME.fullmatch(path.name):
            continue
        try:
            record = json.loads(
                owned_file.read_owned_bytes(path, max_bytes=4096, required_mode=0o600)
            )
        except (OSError, ValueError) as error:
            raise QualificationSuccessorError(
                "successor_control:owner_step_invalid"
            ) from error
        if (
            not isinstance(record, Mapping)
            or set(record) != _OWNER_CONTROL_STEP_FIELDS
            or record.get("schema")
            != native_controller.QUALIFICATION_OWNER_CONTROL_STEP_SCHEMA
        ):
            raise QualificationSuccessorError("successor_control:owner_step_invalid")
        if (
            record["tool"] == tool
            and record["pre_turn_report_sha256"] == expected_report_sha256
        ):
            matches.append(path)
    if len(matches) != 1:
        return refusal
    opened = matches[0]
    claimed = opened.with_name(opened.name[: -len(".open.json")] + ".claimed.json")
    try:
        # The link refuses an existing claim; the unlink closes the step.
        os.link(opened, claimed)
        os.unlink(opened)
    except FileExistsError:
        return refusal
    except FileNotFoundError:
        return refusal
    return None


def authorize_issue94_successor_first_action(
    *,
    pre_turn_report_path: str | Path,
    expected_report_sha256: str,
    plugin_data: str | Path,
    hook_definition_path: str | Path,
    current_task_id: str,
) -> dict[str, Any]:
    """Atomically reserve capacity and publish the exact first spawn action."""

    if not _text(current_task_id):
        raise QualificationSuccessorError(
            "successor_first_action:task_identity_invalid"
        )
    report_path = Path(pre_turn_report_path)
    artifact = read_issue94_successor_pre_turn_artifact(
        report_path,
        expected_report_sha256=expected_report_sha256,
    )
    if (
        artifact.root_task_id != current_task_id
        or artifact.root_session_id != current_task_id
    ):
        raise QualificationSuccessorError(
            "successor_first_action:task_identity_mismatch"
        )
    data = _runtime_root(
        plugin_data,
        label="successor_first_action:plugin_data",
    )
    hook_path = Path(hook_definition_path)
    if (
        not hook_path.is_absolute()
        or hook_path.is_symlink()
        or not hook_path.is_file()
    ):
        raise QualificationSuccessorError(
            "successor_first_action:hook_definition_invalid"
        )
    preparation = _read_successor_first_action_preparation(
        artifact, report_path
    )
    grants = native_grant_store.NativeGrantStore(
        native_grant_store.canonical_database_path(data)
    )
    authority = grants.canonical_authority()
    authority_identity = authority.get("identity")
    authority_lifecycle = authority.get("lifecycle")
    if (
        authority.get("status") != "VERIFIED"
        or not isinstance(authority_identity, Mapping)
        or authority_identity.get("controller_id")
        != artifact.controller_id
        or authority_identity.get("root_thread_id")
        != artifact.root_task_id
        or authority_identity.get("root_session_id")
        != artifact.root_session_id
        or authority_identity.get("root_model") != artifact.root_model
        or not isinstance(authority_lifecycle, Mapping)
        or authority_lifecycle.get("expected_binding_status")
        != "WAITING"
        or authority_lifecycle.get("terminal") is not False
        or authority_lifecycle.get("pending_intent") is not False
        or authority_lifecycle.get("cleanup_required") is not False
        or authority_lifecycle.get("action_sha256") is not None
        or authority_lifecycle.get("tool_use_id") is not None
    ):
        raise QualificationSuccessorError(
            "successor_first_action:retained_owner_not_waiting"
        )
    startup_core = {
        "schema": RETAINED_OWNER_STARTUP_BINDING_SCHEMA,
        "status": "PASS",
        "decision": "READY_FOR_CAPACITY_ADMISSION",
        "issues": [],
        "pre_turn_report_sha256": artifact.report_sha256,
        "controller": {
            "authority_sha256": _sha(authority),
            "controller_id": artifact.controller_id,
            "expected_binding_status": "WAITING",
            "next_stage_action": artifact.next_stage_action,
        },
        "continuation": {
            "root_thread_id": artifact.root_task_id,
            "root_session_id": artifact.root_session_id,
            "model": artifact.root_model,
            "owner_connection": "retained",
            "reconnect_allowed": False,
            "additional_session_start_required": False,
        },
        "provider_free": True,
    }
    startup = {**startup_core, "report_sha256": _sha(startup_core)}
    controller_program = deepcopy(preparation.controller_program)
    controller_report = (
        native_controller.advance_governed_native_controller(
            controller_program,
            plugin_data=data,
            hook_definition_path=hook_path,
            source_roots=preparation.source_roots,
        )
    )
    action = (
        controller_report.get("action")
        if isinstance(controller_report, Mapping)
        and isinstance(controller_report.get("action"), Mapping)
        else {}
    )
    core = {
        "schema": FIRST_ACTION_REPORT_SCHEMA,
        "status": "PASS",
        "decision": FIRST_ACTION_DECISION_READY,
        "issues": [],
        "pre_turn_report_sha256": artifact.report_sha256,
        "startup_observation": startup,
        "source_roots": deepcopy(preparation.source_roots),
        "controller_program": controller_program,
        "controller_report": deepcopy(dict(controller_report)),
        "action": deepcopy(dict(action)),
        "boundary": {
            "native_action_called": False,
            "next_action": "multi_agent_v1__spawn_agent",
            "task_created": False,
            "worker_created": False,
        },
        "provider_free": True,
        "counters": dict(_FIRST_ACTION_COUNTERS),
    }
    report = {**core, "report_sha256": _sha(core)}
    if len(_canonical(report)) > MAX_REPORT_BYTES:
        raise QualificationSuccessorError(
            "successor_first_action:report_too_large"
        )
    return QualificationSuccessorFirstActionArtifact.from_report(
        report
    ).report


def validate_issue94_successor_first_action_report(
    report: Any,
) -> dict[str, Any]:
    """Return a small typed validation result for the MCP host bridge."""

    try:
        artifact = QualificationSuccessorFirstActionArtifact.from_report(
            report
        )
    except (TypeError, ValueError):
        return {"valid": False, "issues": ["first_action:report_invalid"]}
    return {
        "valid": True,
        "issues": [],
        "report_sha256": artifact.report_sha256,
    }


def _worker_codex_home() -> Path:
    codex_home_value = os.environ.get("CODEX_HOME")
    if not _text(codex_home_value):
        home_value = os.environ.get("HOME")
        if not _text(home_value):
            raise QualificationSuccessorError(
                "successor_action_advance:codex_home_unavailable"
            )
        codex_home_value = str(Path(str(home_value)).expanduser() / ".codex")
    return Path(str(codex_home_value)).expanduser()


def _worker_rollout_path(session_id: str) -> Path | None:
    """Resolve one exact child rollout without trusting a caller path."""

    codex_home = _worker_codex_home()
    if not codex_home.is_absolute() or codex_home.is_symlink():
        raise QualificationSuccessorError(
            "successor_action_advance:codex_home_invalid"
        )
    sessions = codex_home / "sessions"
    if sessions.is_symlink():
        raise QualificationSuccessorError(
            "successor_action_advance:codex_home_invalid"
        )
    if not sessions.exists():
        return None
    try:
        codex_home_root = codex_home.resolve(strict=True)
        codex_home_metadata = codex_home.lstat()
        if (
            not stat.S_ISDIR(codex_home_metadata.st_mode)
            or (
                hasattr(os, "getuid")
                and codex_home_metadata.st_uid != os.getuid()
            )
            or stat.S_IMODE(codex_home_metadata.st_mode) & 0o077
        ):
            raise ValueError("unsafe Codex home")
        sessions_root = sessions.resolve(strict=True)
        if (
            not sessions_root.is_dir()
            or not sessions_root.is_relative_to(codex_home_root)
        ):
            raise ValueError("unsafe sessions root")
    except (OSError, RuntimeError, ValueError) as error:
        raise QualificationSuccessorError(
            "successor_action_advance:codex_home_invalid"
        ) from error
    try:
        candidates = sorted(
            sessions_root.rglob(f"*-{session_id}.jsonl")
        )
    except OSError as error:
        raise QualificationSuccessorError(
            "successor_action_advance:worker_rollout_unavailable"
        ) from error
    safe: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            metadata = candidate.lstat()
        except OSError:
            continue
        if (
            candidate.is_symlink()
            or not resolved.is_relative_to(sessions_root)
            or not resolved.is_file()
            or resolved.stat().st_size > 128 * 1024 * 1024
            or (
                hasattr(os, "getuid")
                and metadata.st_uid != os.getuid()
            )
            or stat.S_IMODE(metadata.st_mode) & 0o002
        ):
            raise QualificationSuccessorError(
                "successor_action_advance:worker_rollout_invalid"
            )
        safe.append(resolved)
    if not safe:
        return None
    if len(safe) != 1:
        raise QualificationSuccessorError(
            "successor_action_advance:worker_rollout_ambiguous"
        )
    return safe[0]


def _worker_acknowledgements(
    *,
    state: Mapping[str, Any],
    preparation: QualificationSuccessorFirstActionPreparationArtifact,
    current_task_id: str,
    controller_id: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Observe the frozen worker receipts and derive one worker-start stage."""

    batch = state.get("last_batch_result")
    stage_report = state.get("stage_report")
    predecessor = (
        stage_report.get("receipt")
        if isinstance(stage_report, Mapping)
        and isinstance(stage_report.get("receipt"), Mapping)
        else None
    )
    bindings = (
        predecessor.get("bindings")
        if isinstance(predecessor, Mapping)
        and isinstance(predecessor.get("bindings"), Mapping)
        else None
    )
    expected_lane_ids = (
        bindings.get("current_wave_logical_lane_ids")
        if isinstance(bindings, Mapping)
        else None
    )
    normalized_spawn = (
        native_result.spawn_result_binding(
            batch.get("result_binding"), batch.get("lane_ids")
        )
        if isinstance(batch, Mapping) and batch.get("kind") == "spawn"
        else None
    )
    spec_rows = (
        bindings.get("task_specs")
        if isinstance(bindings, Mapping)
        else None
    )
    if (
        not isinstance(predecessor, Mapping)
        or predecessor.get("stage") != "capacity_admission"
        or predecessor.get("next_action") != "spawn"
        or not isinstance(expected_lane_ids, list)
        or expected_lane_ids != sorted(set(expected_lane_ids))
        or not expected_lane_ids
        or normalized_spawn is None
        or normalized_spawn.get("lanes")
        != sorted(
            normalized_spawn.get("lanes", []),
            key=lambda row: row.get("lane_id", ""),
        )
        or [row.get("lane_id") for row in normalized_spawn["lanes"]]
        != expected_lane_ids
        or not isinstance(spec_rows, list)
    ):
        raise QualificationSuccessorError(
            "successor_action_advance:spawn_batch_state_invalid"
        )
    specs = {
        str(row.get("logical_worker_id")): row
        for row in spec_rows
        if isinstance(row, Mapping)
    }
    if set(specs) != set(expected_lane_ids):
        raise QualificationSuccessorError(
            "successor_action_advance:spawn_task_specs_invalid"
        )

    runtime_rows: list[dict[str, Any]] = []
    pending_lane_ids: list[str] = []
    creations: list[dict[str, Any]] = []
    deliveries: list[dict[str, Any]] = []
    for lane in normalized_spawn["lanes"]:
        lane_id = str(lane["lane_id"])
        worker_id = str(lane["agent_id"])
        spec = specs[lane_id]
        task_spec_sha256 = spec.get("task_spec_sha256")
        expected_receipt = route_policy.task_spec_pre_work_receipt(
            logical_lane_id=lane_id,
            task_spec_sha256=str(task_spec_sha256),
        )
        rollout_path = _worker_rollout_path(worker_id)
        if rollout_path is None:
            pending_lane_ids.append(lane_id)
            continue
        observation = routing_verify.observe_session_runtime(
            str(rollout_path),
            session_id=worker_id,
            observer_id=current_task_id,
        )
        observation_issues = observation.get("issues")
        if observation.get("status") != "PASS":
            pending_issues = {
                "routing:no_turn_context",
                "terminal:json_missing",
                "usage:exact_record_missing",
            }
            if (
                isinstance(observation_issues, list)
                and observation_issues
                and set(observation_issues).issubset(pending_issues)
            ):
                pending_lane_ids.append(lane_id)
                continue
            raise QualificationSuccessorError(
                "successor_action_advance:worker_acknowledgement_invalid"
            )
        route_validation = (
            routing_verify.validate_session_runtime_observation(observation)
        )
        route = observation.get("route")
        usage = observation.get("usage")
        if (
            route_validation.get("valid") is not True
            or not isinstance(route, Mapping)
            or route.get("session_id") != worker_id
            or route.get("model") != spec.get("model")
            or route.get("effort") != spec.get("effort")
            or route.get("context_policy") != "none"
            or route.get("inherited_history") is not False
            or observation.get("terminal_schema")
            != route_policy.TASK_SPEC_PRE_WORK_RECEIPT_SCHEMA
            or observation.get("terminal_json_sha256")
            != route_policy.canonical_sha256(expected_receipt)
            or not isinstance(usage, Mapping)
            or usage.get("status") != "observed"
            or usage.get("tool_calls") != 0
        ):
            raise QualificationSuccessorError(
                "successor_action_advance:worker_acknowledgement_invalid"
            )
        runtime_rows.append(
            {
                "logical_worker_id": lane_id,
                "worker_id": worker_id,
                "session_id": worker_id,
                "observation": observation,
            }
        )
        creations.append(
            {
                "logical_worker_id": lane_id,
                "worker_id": worker_id,
                "session_id": worker_id,
                "status": "created",
                "fresh": True,
                "parent_thread_id": current_task_id,
            }
        )
        acknowledgement = {
            "schema": route_policy.TASK_SPEC_ACK_SCHEMA,
            "ack_id": "issue94-pre-work-"
            + _sha(
                {
                    "receipt": expected_receipt,
                    "worker_id": worker_id,
                    "session_id": worker_id,
                }
            )[:24],
            "task_spec_sha256": task_spec_sha256,
            "logical_lane_id": lane_id,
            "native_worker_id": worker_id,
            "session_id": worker_id,
            "acknowledged_seq": 1,
            "first_substantial_work_seq": 2,
        }
        deliveries.append(
            {
                "schema": route_policy.PROGRAM_SCHEMA,
                "operation": "task_spec_delivery",
                "payload": {
                    "schema": route_policy.TASK_SPEC_DELIVERY_SCHEMA,
                    "expected_task_spec_sha256": task_spec_sha256,
                    "expected_lane_id": lane_id,
                    "expected_native_worker_id": worker_id,
                    "expected_session_id": worker_id,
                    "prior_ack_ids": [],
                    "acknowledgement": acknowledgement,
                },
            }
        )

    observed_lane_ids = [
        row["logical_worker_id"] for row in runtime_rows
    ]
    ack_core = {
        "schema": WORKER_ACKNOWLEDGEMENTS_SCHEMA,
        "state": "AWAITING" if pending_lane_ids else "ACCEPTED",
        "expected_lane_ids": list(expected_lane_ids),
        "observed_lane_ids": observed_lane_ids,
        "pending_lane_ids": sorted(pending_lane_ids),
        "runtime_observations": runtime_rows,
    }
    acknowledgement_report = {
        **ack_core,
        "acknowledgements_sha256": _sha(ack_core),
    }
    if pending_lane_ids:
        return acknowledgement_report, None

    prepared_stage = preparation.controller_program.get("payload", {}).get(
        "stage_program"
    )
    identity = (
        prepared_stage.get("identity")
        if isinstance(prepared_stage, Mapping)
        and isinstance(prepared_stage.get("identity"), Mapping)
        else None
    )
    if not isinstance(identity, Mapping):
        raise QualificationSuccessorError(
            "successor_action_advance:worker_start_identity_invalid"
        )
    worker_start_program = {
        "schema": governed_attempt.PROGRAM_SCHEMA,
        "operation": "worker_start",
        "identity": deepcopy(dict(identity)),
        "predecessor_receipt": deepcopy(dict(predecessor)),
        "payload": {
            "creations": creations,
            "deliveries": deliveries,
            "route_observations": runtime_rows,
            "tool_events": [],
        },
    }
    return acknowledgement_report, worker_start_program


def _not_applicable_acknowledgements() -> dict[str, Any]:
    core = {
        "schema": WORKER_ACKNOWLEDGEMENTS_SCHEMA,
        "state": "NOT_APPLICABLE",
        "expected_lane_ids": [],
        "observed_lane_ids": [],
        "pending_lane_ids": [],
        "runtime_observations": [],
    }
    return {**core, "acknowledgements_sha256": _sha(core)}


def _is_worker_result_wait(report: Mapping[str, Any]) -> bool:
    """An unchanged complete controller report retains the exact result join."""

    stage = report.get("stage_report")
    receipt = stage.get("receipt") if isinstance(stage, Mapping) else None
    result_stage = isinstance(receipt, Mapping) and receipt.get("stage") in {"worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification", "capacity_settlement"}
    try:
        _worker_result_bindings(stage, stage["root_task_id"])
    except (KeyError, TypeError, QualificationSuccessorError):
        return False
    return bool(
        native_controller.validate_governed_native_controller_report(report).get("valid") is True
        and report.get("action") is None
        and report.get("controller_state") == {
            "action_authorized": False,
            "action_outcome": None if result_stage else "completed",
            "cleanup_required": False,
            "grant_state": None,
            "pending_intent": False,
            "terminal": False,
        }
        and isinstance(receipt, Mapping)
        and (
            receipt.get("stage") in {"worker_start", "progress"} and receipt.get("next_action") == "continue"
            or result_stage and governed_attempt.validate_post_batch_report(stage).get("valid") is True
        )
    )


def _is_completed_cleanup_wait(report: Mapping[str, Any]) -> bool:
    """Recognize the clean owner frontier after both authorized closes."""

    try:
        return bool(
            native_controller.validate_governed_native_controller_report(
                report
            ).get("valid")
            is True
            and report.get("status") == "PASS"
            and report.get("decision") == "WAITING_FOR_STAGE"
            and report.get("issues") == []
            and report.get("action") is None
            and report.get("controller_state")
            == {
                "action_authorized": False,
                "action_outcome": "completed",
                "cleanup_required": False,
                "grant_state": None,
                "pending_intent": False,
                "terminal": False,
            }
            and report.get("next_stage_action") == "stop"
            and governed_attempt.validate_verified_cleanup_report(
                report.get("stage_report")
            ).get("valid")
            is True
        )
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return False


def _valid_worker_result_stage(transitions: list[dict[str, Any]]) -> bool:
    """Bind the new durable receipt to its whole constructor/evaluator inputs."""
    try:
        before, after = transitions
        payload = after["program"]["payload"]
        if set(payload) != {"stage_program", "proposed_action"} or payload["proposed_action"] is not None:
            return False
        stage = payload["stage_program"]
        if stage["operation"] == "worker_results":
            expected = governed_attempt.build_worker_results_program(
                stage["identity"], before["report"]["stage_report"], stage["payload"]["worker_results"])
        elif stage["operation"] == "result_aggregation":
            expected = governed_attempt.build_result_aggregation_program(
                stage["identity"], before["report"]["stage_report"])
        elif stage["operation"] == "terminal_verification":
            expected = governed_attempt.build_terminal_verification_program(
                stage["identity"], before["report"]["stage_report"])
        elif stage["operation"] == "semantic_review":
            # Retained observation transport is deterministic. Re-reading the
            # owner here would produce a different observation and lose custody.
            if after["report"].get("decision") == "REVIEW_OBSERVATION_PENDING":
                expected = governed_attempt.build_semantic_review_program(stage["identity"], before["report"]["stage_report"])
                return (_canonical(expected) == _canonical(stage)
                        and native_controller.validate_governed_native_controller_report(after["report"]).get("valid") is True
                        and _canonical(before["report"]["stage_report"]) == _canonical(after["report"]["stage_report"])
                        and _canonical(before["report"]["cursor"]) == _canonical(after["report"]["cursor"]))
            if after["report"]["stage_report"]["receipt"]["bindings"].get("review_outcome") == "pending":
                return False
            return governed_attempt.validate_semantic_review_transition(
                stage["identity"], before["report"]["stage_report"], stage, after["report"]["stage_report"]
            ).get("valid") is True
        else:
            return False
        return (_canonical(expected) == _canonical(stage)
                and _canonical(governed_attempt.evaluate_governed_attempt(expected)) == _canonical(after["report"]["stage_report"]))
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def _is_worker_checkpoint_wait(report: Mapping[str, Any]) -> bool:
    try:
        receipt = report["stage_report"]["receipt"]
        return (_is_worker_result_wait(report) and receipt["stage"] == "worker_start"
                and receipt["bindings"].get("worker_checkpoint_profile") == governed_attempt.WORKER_CHECKPOINT_PROFILE)
    except (KeyError, TypeError):
        return False


def _has_checkpoint_stage(transitions: list[dict[str, Any]]) -> bool:
    try:
        return (len(transitions) == 2 and transitions[-1]["program"]["operation"] == "stage"
                and transitions[-1]["program"]["payload"]["stage_program"]["operation"] == "progress")
    except (KeyError, TypeError):
        return False


def _checkpoint_proposal(controller_id: str, cursor: Any, program: Any) -> dict[str, Any] | None:
    """Propose only the deterministic evaluator disposition; mint no grant."""
    if "checkpoint_accounting_policy" in program["predecessor_receipt"]["bindings"]:
        # The native controller samples its clock after the owned source reread
        # and selects the actual continuation/stop disposition itself.
        return None
    evaluated = governed_attempt.evaluate_governed_attempt(program)
    if not ((evaluated.get("status") == "PASS" and evaluated.get("next_action") == "continue")
            or (evaluated.get("disposition") == "STOP_REQUIRED" and evaluated.get("next_action") == "stop")):
        raise QualificationSuccessorError("successor_action_advance:checkpoint_disposition_invalid")
    return {"schema":native_controller.ACTION_PROPOSAL_SCHEMA,
        "action_id":"checkpoint:" + _sha({"controller_id":controller_id,"cursor":cursor,"program":program}),
        "kind":evaluated["next_action"],"actor_thread_id":program["identity"]["root_task_id"],
        "adapter_sha256":native_controller.CLOSED_NATIVE_ACTION_ADAPTER_SHA256}


def _closed_action_validation_identity(authority: Any) -> dict[str, Any]:
    """Adapt the owner projection to the fixed closed-action reconstruction.

    Canonical grant-store authority omits the activation's adapter digest.
    Reconstructing a report uses this runtime's closed adapter constant; it
    does not add an authority field or mint a grant. Older whole-activation
    fixtures may include the digest, but a contradictory value still refuses.
    """
    identity = authority["identity"]
    digest = native_controller.CLOSED_NATIVE_ACTION_ADAPTER_SHA256
    if not isinstance(identity, Mapping) or identity.get("native_adapter_sha256", digest) != digest:
        raise ValueError("successor_action_advance:adapter_identity_mismatch")
    return {"root_thread_id": identity["root_thread_id"], "native_adapter_sha256": digest}


def _valid_checkpoint_stage(transitions: list[dict[str, Any]], authority: Any, roots: Any) -> bool:
    """Validate the whole checkpoint transition without owner reads or grants."""
    import orch_dork_qualification_progress as progress
    try:
        before, after = transitions
        if not _is_worker_checkpoint_wait(before["report"]):return False
        payload = after["program"]["payload"]
        if set(payload) != {"stage_program", "proposed_action"}:return False
        program = payload["stage_program"]
        sources = program["payload"]["checkpoint_sources"]
        expected = progress.build_checkpoint_stage_program(program["identity"], before["report"]["stage_report"], sources)
        proposal = _checkpoint_proposal(after["program"]["controller_id"], before["report"]["cursor"], expected)
        report = after["report"]
        if (_canonical(expected) != _canonical(program) or _canonical(payload["proposed_action"]) != _canonical(proposal)
                or native_controller.validate_governed_native_controller_report(report).get("valid") is not True
                or program["identity"]["root_task_id"] != authority["identity"]["root_thread_id"]):
            return False
        if report["decision"] == "CHECKPOINT_OBSERVATION_PENDING":
            return (_canonical(report["cursor"]) == _canonical(before["report"]["cursor"])
                    and _canonical(report["stage_report"]) == _canonical(before["report"]["stage_report"]))
        observed_budget = report["stage_report"]["receipt"]["bindings"].get("checkpoint_budget_observation")
        evaluation_time = datetime.fromisoformat(observed_budget["observed_at"]) if observed_budget is not None else None
        evaluated = governed_attempt.evaluate_governed_attempt(expected,now=evaluation_time)
        if _canonical(report["stage_report"]) != _canonical(evaluated):return False
        if proposal is None:
            proposal = native_controller._checkpoint_action_proposal(after["program"]["controller_id"],
                before["report"]["cursor"],expected,evaluated["next_action"])
        tasks = [{"logical_worker_id":lane,"task_spec":sources["workers"]["evidence"]["workers"][lane]["progress_report"]["task_spec"]}
                 for lane in ("spec", "standards")]
        action, issues = native_controller.ClosedNativeActionAdapter.authorize(proposal,
            next_action=evaluated["next_action"], receipt=evaluated["receipt"],
            activation={"identity":_closed_action_validation_identity(authority),"task_specs":native_controller.normalized_task_specs(tasks)},
            controller_id=after["program"]["controller_id"],seen_action_ids=[],source_roots=roots)
        return not issues and _canonical(action) == _canonical(report["action"])
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return False


def _has_cleanup_stage(transitions: Any) -> bool:
    try:
        return (len(transitions) == 2 and transitions[-1]["program"]["operation"] == "stage"
                and transitions[-1]["program"]["payload"]["stage_program"]["operation"] == "cleanup")
    except (KeyError, TypeError):
        return False


def _cleanup_proposal(controller_id: str, cursor: Any, program: Any) -> dict[str, Any]:
    return {"schema":native_controller.ACTION_PROPOSAL_SCHEMA,
        "action_id":"cleanup:" + _sha({"controller_id":controller_id,"cursor":cursor,"program":program}),
        "kind":"stop","actor_thread_id":program["identity"]["root_task_id"],
        "adapter_sha256":native_controller.CLOSED_NATIVE_ACTION_ADAPTER_SHA256}


def _valid_cleanup_stage(transitions: Any, authority: Any) -> bool:
    """Bind separate cleanup authorization to complete prior verification."""
    try:
        before,after = transitions
        payload = after["program"]["payload"];program = payload["stage_program"]
        if not _is_worker_result_wait(before["report"]) or set(payload) != {"stage_program", "proposed_action"}:
            return False
        expected = governed_attempt.build_verified_cleanup_program(program["identity"],before["report"]["stage_report"])
        proposal = _cleanup_proposal(after["program"]["controller_id"],before["report"]["cursor"],expected)
        evaluated = governed_attempt.evaluate_governed_attempt(expected)
        report = after["report"]
        if (_canonical(program) != _canonical(expected) or _canonical(payload["proposed_action"]) != _canonical(proposal)
                or _canonical(report["stage_report"]) != _canonical(evaluated)
                or native_controller.validate_governed_native_controller_report(report).get("valid") is not True):
            return False
        action,issues = native_controller.ClosedNativeActionAdapter.authorize(proposal,next_action="stop",receipt=evaluated["receipt"],
            activation={"identity":_closed_action_validation_identity(authority),"task_specs":[]},controller_id=after["program"]["controller_id"],seen_action_ids=[])
        return not issues and _canonical(action) == _canonical(report["action"])
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return False


def _spawn_compensation_witness_payload(
    report: Any,
) -> dict[str, Any] | None:
    """Bind every unsigned wrapper field to one host-authenticated subject."""

    try:
        if not isinstance(report, Mapping):
            return None
        unsigned = deepcopy(dict(report))
        unsigned.pop("report_sha256", None)
        evidence = unsigned["spawn_compensation_evidence"]
        evidence_fields = (
            frozenset(evidence) if isinstance(evidence, Mapping) else frozenset()
        )
        if evidence_fields not in {
            _SPAWN_COMPENSATION_EVIDENCE_CORE_FIELDS,
            _SPAWN_COMPENSATION_EVIDENCE_FIELDS,
        }:
            return None
        evidence_core = {
            field: deepcopy(evidence[field])
            for field in _SPAWN_COMPENSATION_EVIDENCE_CORE_FIELDS
        }
        unsigned["spawn_compensation_evidence"] = evidence_core
        authority = unsigned["authority_before"]
        owner = authority["owner"]
        identity = authority["identity"]
        provenance_field = (
            "bootstrap_report_sha256"
            if unsigned["schema"] == BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA
            else "pre_turn_report_sha256"
        )
        payload = {
            "schema": SPAWN_COMPENSATION_WITNESS_PAYLOAD_SCHEMA,
            "report_schema": unsigned["schema"],
            "controller_id": owner["controller_id"],
            "root_task_id": identity["root_thread_id"],
            "provenance_field": provenance_field,
            "provenance_sha256": unsigned[provenance_field],
            "batch_id": evidence_core["batch_id"],
            "durable_history_sha256": evidence_core[
                "durable_history_sha256"
            ],
            "unsigned_report_sha256": _sha(unsigned),
        }
        if (
            evidence_core["schema"]
            != SPAWN_COMPENSATION_EVIDENCE_SCHEMA
            or not all(
                _text(payload[field])
                for field in (
                    "controller_id", "root_task_id", "provenance_field",
                    "batch_id",
                )
            )
            or not all(
                _is_sha(payload[field])
                for field in (
                    "provenance_sha256", "durable_history_sha256",
                    "unsigned_report_sha256",
                )
            )
        ):
            return None
        return payload
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return None


def _valid_spawn_compensation_owner_witness(
    report: Any,
    *,
    archival: bool,
) -> bool:
    """Authenticate one live or explicitly non-authorizing archival report."""

    try:
        evidence = report["spawn_compensation_evidence"]
        if (
            not isinstance(evidence, Mapping)
            or set(evidence) != _SPAWN_COMPENSATION_EVIDENCE_FIELDS
            or not _sealed(evidence, "evidence_sha256")
        ):
            return False
        expected = _spawn_compensation_witness_payload(report)
        witness = evidence["owner_witness"]
        if expected is None or not isinstance(witness, Mapping):
            return False
        verification_inputs: dict[str, Any] = {
            "expected_kind": SPAWN_COMPENSATION_WITNESS_KIND,
            "expected_payload": expected,
            "evaluation_time": (
                witness.get("issued_at")
                if archival
                else _spawn_compensation_live_evaluation_time()
            ),
        }
        if archival:
            verification_inputs["replay_guard"] = (
                observer_receipt.MemoryReplayGuard()
            )
        verified = observer_receipt.verify_signed_receipt(
            witness,
            **verification_inputs,
        )
        return bool(
            verified.get("status") == "PASS"
            and _canonical(verified.get("payload")) == _canonical(expected)
        )
    except (
        KeyError, TypeError, ValueError, OverflowError, RecursionError,
        observer_receipt.ObserverReceiptError,
    ):
        return False


def _spawn_compensation_live_evaluation_time() -> datetime:
    """Return host time for an action-authorizing witness decision."""

    return datetime.now(timezone.utc)


def _valid_compensation_durable_history(
    evidence_rows: Any,
    durable_history: Any,
) -> bool:
    """Bind each retained action row to its complete durable hook pair."""
    try:
        if (
            not isinstance(evidence_rows, list)
            or not isinstance(durable_history, list)
            or len(durable_history) != len(evidence_rows)
        ):
            return False
        for evidence, pair in zip(evidence_rows, durable_history, strict=True):
            if not isinstance(evidence, Mapping) or not isinstance(pair, Mapping):
                return False
            if set(pair) != {"pretool", "posttool"}:
                return False
            action = evidence["action"]
            pretool = pair["pretool"]
            posttool = pair["posttool"]
            if (
                not isinstance(action, Mapping)
                or not isinstance(pretool, Mapping)
                or not isinstance(posttool, Mapping)
                or set(pretool) != native_controller.DURABLE_HOOK_EVENT_FIELDS
                or set(posttool) != native_controller.DURABLE_HOOK_EVENT_FIELDS
            ):
                return False
            for durable in (pretool, posttool):
                if (
                    durable["schema"]
                    != native_controller.DURABLE_HOOK_EVENT_SCHEMA
                    or durable["report_schema"]
                    != native_controller.ground_enforcement.REPORT_SCHEMA
                    or not _sealed(durable, "durable_record_sha256")
                ):
                    return False
            pre_native = pretool["native_controller"]
            post_native = posttool["native_controller"]
            if not (
                pretool["hook_event_name"] == "PreToolUse"
                and pretool["status"] == "PASS"
                and pretool["decision"] == "ALLOW"
                and pretool["mutating"] is True
                and posttool["hook_event_name"] == "PostToolUse"
                and posttool["status"] == "PASS"
                and posttool["decision"] == "OBSERVED"
                and pretool["report_sha256"]
                == evidence["pretool_report_sha256"]
                and pretool["durable_record_sha256"]
                == evidence["pretool_durable_record_sha256"]
                and posttool["report_sha256"]
                == evidence["posttool_report_sha256"]
                and posttool["durable_record_sha256"]
                == evidence["posttool_durable_record_sha256"]
                and pretool["tool_input_sha256"]
                == posttool["tool_input_sha256"]
                == action["tool_input_sha256"]
                and set(pretool["identity"])
                == native_controller.DURABLE_HOOK_IDENTITY_FIELDS
                and _canonical(pretool["identity"])
                == _canonical(posttool["identity"])
                and pretool["identity"]["session_id"]
                == action["actor_thread_id"]
                and pretool["identity"]["current_thread_id"]
                == action["actor_thread_id"]
                and set(pre_native)
                == native_controller.DURABLE_PRETOOL_NATIVE_FIELDS
                and set(post_native)
                == native_controller.DURABLE_POSTTOOL_NATIVE_FIELDS
                and pre_native["present"] is True
                and pre_native["matched"] is True
                and pre_native["status"] == "ACTIVE"
                and pre_native["grant_state"] == "DISPATCHED"
                and post_native["present"] is True
                and post_native["matched"] is True
                and post_native["status"] == "ACTIVE"
                and post_native["grant_state"] == "POST_OBSERVED"
                and pre_native["controller_id"]
                == post_native["controller_id"]
                == action["controller_id"]
                and pre_native["controller_seq"]
                == post_native["controller_seq"]
                and pre_native["action_id"]
                == post_native["action_id"]
                == action["action_id"]
                and pre_native["tool_use_id"]
                == post_native["tool_use_id"]
                and post_native["pretool_report_sha256"]
                == pretool["report_sha256"]
                and _canonical(post_native["result_binding"])
                == _canonical(evidence["result_binding"])
                and _is_sha(pre_native["pretool_event_sha256"])
                and _is_sha(post_native["result_sha256"])
            ):
                return False
        return True
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return False


def _spawn_compensation_history(report: Any, failure: str) -> dict[str, Any] | None:
    """Rebuild the one exact compensation action from retained spawn evidence."""
    try:
        evidence = report["spawn_compensation_evidence"]
        evidence_rows = evidence["action_evidence"]
        durable_history = evidence["durable_history"]
        if not isinstance(evidence_rows, list) or len(evidence_rows) not in {2, 3}:
            return None
        first_evidence, failed_evidence = evidence_rows[:2]
        first = first_evidence["action"]
        failed = failed_evidence["action"]
        row_fields = {
            "action", "pretool_report_sha256",
            "pretool_durable_record_sha256", "posttool_report_sha256",
            "posttool_durable_record_sha256", "result_binding",
        }
        digest_fields = row_fields - {"action", "result_binding"}

        def rebuild(candidate: Mapping[str, Any]) -> dict[str, Any]:
            return native_controller._direct_batch_action(
                controller_id=candidate["controller_id"],
                batch_id=candidate["batch_id"],
                batch_kind=candidate["batch_kind"],
                batch_lane_ids=candidate["batch_lane_ids"],
                requests=candidate["batch_requests"],
                index=candidate["batch_index"],
                phase=candidate["batch_phase"],
                actor_thread_id=candidate["actor_thread_id"],
                adapter_sha256=candidate["adapter_sha256"],
                predecessor_receipt_sha256=(
                    candidate["predecessor_receipt_sha256"]
                ),
                failure_outcome=candidate["batch_failure_outcome"],
            )

        first_binding = native_result.spawn_result_binding(
            first_evidence["result_binding"], ["spec"]
        )
        expected_requests = (
            native_controller.GovernedNativeController
            ._successful_spawn_compensation_requests(evidence_rows[:2], failed)
        )
        expected = native_controller._direct_batch_action(
            controller_id=failed["controller_id"],
            batch_id=failed["batch_id"],
            batch_kind=failed["batch_kind"],
            batch_lane_ids=failed["batch_lane_ids"],
            requests=expected_requests,
            index=0,
            phase="compensation",
            actor_thread_id=failed["actor_thread_id"],
            adapter_sha256=failed["adapter_sha256"],
            predecessor_receipt_sha256=failed["predecessor_receipt_sha256"],
            failure_outcome=failure,
        )
        common = (
            "controller_id", "actor_thread_id", "adapter_sha256",
            "predecessor_receipt_sha256", "batch_schema", "batch_id",
            "batch_kind", "batch_size", "batch_lane_ids", "batch_requests",
            "batch_requests_sha256", "batch_phase", "batch_failure_outcome",
        )
        if not (
            failure == "failed"
            and set(evidence) == _SPAWN_COMPENSATION_EVIDENCE_FIELDS
            and evidence["schema"] == SPAWN_COMPENSATION_EVIDENCE_SCHEMA
            and evidence["batch_id"] == first["batch_id"]
            and evidence["durable_history_sha256"] == _sha(durable_history)
            and _sealed(evidence, "evidence_sha256")
            and all(
                isinstance(row, Mapping)
                and set(row) == row_fields
                and all(_is_sha(row[field]) for field in digest_fields)
                for row in evidence_rows
            )
            and _valid_compensation_durable_history(
                evidence_rows, durable_history
            )
            and _canonical(first) == _canonical(rebuild(first))
            and _canonical(failed) == _canonical(rebuild(failed))
            and first["kind"] == failed["kind"] == "spawn"
            and first["tool_name"] == failed["tool_name"]
            == "multi_agent_v1__spawn_agent"
            and first["lane_ids"] == ["spec"]
            and failed["lane_ids"] == ["standards"]
            and first["batch_index"] == 0
            and failed["batch_index"] == 1
            and first["batch_lane_ids"] == ["spec", "standards"]
            and first["batch_kind"] == "spawn"
            and first["batch_phase"] == "primary"
            and first["batch_failure_outcome"] is None
            and all(first[field] == failed[field] for field in common)
            and first_binding is not None
            and first_binding["lanes"][0]["lane_id"] == "spec"
            and failed_evidence["result_binding"] is None
            and expected_requests == [{
                "lane_id": "spec", "kind": "stop",
                "tool_name": "multi_agent_v1__close_agent",
                "tool_input": {
                    "target": first_binding["lanes"][0]["agent_id"],
                },
            }]
        ):
            return None
        return {
            "rows": evidence_rows,
            "first": first,
            "failed": failed,
            "failed_evidence": failed_evidence,
            "expected": expected,
        }
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return None


def _valid_spawn_compensation_advance(report: Any) -> bool:
    """Bind a failed second spawn to its one known-worker compensation close."""
    try:
        transition, = report["controller_transitions"]
        program = transition["program"]
        controller = transition["report"]
        action = controller["action"]
        authority = report["authority_before"]
        lifecycle = authority["lifecycle"]
        durable_report = report["durable_hook_report"]
        durable = durable_report["native_controller"]
        observation = program["payload"]
        native = observation["native_receipt"]
        stage = controller["stage_report"]
        receipt = stage["receipt"]
        history = _spawn_compensation_history(report, observation["outcome"])
        if history is None or len(history["rows"]) != 2:
            return False
        failed = history["failed"]
        failed_evidence = history["failed_evidence"]
        return (
            program["operation"] == "observe"
            and native_controller.validate_governed_native_controller_report(
                controller
            ).get("valid") is True
            and controller["decision"] == "ACTION_AUTHORIZED"
            and _canonical(action) == _canonical(history["expected"])
            and action["actor_thread_id"]
            == authority["identity"]["root_thread_id"]
            and action["controller_id"] == authority["owner"]["controller_id"]
            and stage["status"] == "PASS"
            and stage["operation"] == "capacity_admission"
            and stage["next_action"] == "spawn"
            and receipt["stage"] == "capacity_admission"
            and receipt["status"] == "AUTHORIZED"
            and receipt["next_action"] == "spawn"
            and _sealed(receipt, "receipt_sha256")
            and action["predecessor_receipt_sha256"]
            == receipt["receipt_sha256"]
            and receipt["bindings"]["current_wave_logical_lane_ids"]
            == action["batch_lane_ids"]
            and lifecycle["expected_binding_status"] == "ACTIVE"
            and lifecycle["grant_state"] == "POST_OBSERVED"
            and lifecycle["action_sha256"] == failed["action_sha256"]
            and lifecycle["tool_use_id"] == observation["tool_use_id"]
            and failed_evidence["pretool_report_sha256"]
            == durable["pretool_report_sha256"]
            and failed_evidence["posttool_report_sha256"]
            == durable_report["report_sha256"]
            and failed_evidence["posttool_durable_record_sha256"]
            == durable_report["durable_record_sha256"]
            and set(observation) == {
                "schema", "action_id", "tool_name", "tool_input_sha256",
                "tool_use_id", "outcome", "hook_report_sha256",
                "native_receipt",
            }
            and observation["schema"]
            == native_controller.ACTION_OBSERVATION_SCHEMA
            and observation["action_id"] == failed["action_id"]
            and observation["tool_name"] == failed["tool_name"]
            and observation["tool_input_sha256"]
            == failed["tool_input_sha256"]
            and set(native) == {
                "schema", "action_id", "outcome", "tool_name",
                "tool_input_sha256", "tool_use_id", "result_sha256",
                "result_binding", "source_pointer",
            }
            and native["schema"]
            == native_controller.NATIVE_ACTION_RECEIPT_SCHEMA
            and all(observation[field] == native[field] == durable[field]
                    for field in ("action_id", "outcome", "tool_use_id"))
            and observation["tool_name"] == native["tool_name"]
            and observation["tool_input_sha256"]
            == native["tool_input_sha256"]
            == durable_report["tool_input_sha256"]
            and observation["hook_report_sha256"]
            == durable_report["report_sha256"]
            and native["source_pointer"]
            == "project-ground-durable-event#"
            + durable_report["durable_record_sha256"]
            and _is_sha(native["result_sha256"])
            and native["result_sha256"] == durable["result_sha256"]
            and native["result_binding"] is None
            and durable["result_binding"] is None
        )
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return False


def _valid_spawn_compensation_terminal(report: Any) -> bool:
    """Bind a completed compensation close to the retained failed spawn batch."""
    try:
        transition, = report["controller_transitions"]
        program = transition["program"]
        controller = transition["report"]
        authority = report["authority_before"]
        lifecycle = authority["lifecycle"]
        durable_report = report["durable_hook_report"]
        durable = durable_report["native_controller"]
        observation = program["payload"]
        native = observation["native_receipt"]
        history = _spawn_compensation_history(report, "failed")
        if history is None or len(history["rows"]) != 3:
            return False
        close_evidence = history["rows"][2]
        close = close_evidence["action"]
        stop_binding = native_result.stop_result_binding(
            close_evidence["result_binding"], ["spec"]
        )
        return (
            program["operation"] == "observe"
            and native_controller.validate_governed_native_controller_report(
                controller
            ).get("valid") is True
            and controller["status"] == "BLOCKED"
            and controller["decision"] == "ACTION_TERMINAL_FAILURE"
            and controller["issues"] == ["native_action:failed"]
            and controller["action"] is None
            and controller["controller_state"] == {
                "terminal": False, "pending_intent": False,
                "action_outcome": "failed", "action_authorized": False,
                "grant_state": None, "cleanup_required": True,
            }
            and _canonical(close) == _canonical(history["expected"])
            and lifecycle["expected_binding_status"] == "ACTIVE"
            and lifecycle["grant_state"] == "POST_OBSERVED"
            and lifecycle["action_sha256"] == close["action_sha256"]
            and lifecycle["tool_use_id"] == observation["tool_use_id"]
            and close_evidence["pretool_report_sha256"]
            == durable["pretool_report_sha256"]
            and close_evidence["posttool_report_sha256"]
            == durable_report["report_sha256"]
            and close_evidence["posttool_durable_record_sha256"]
            == durable_report["durable_record_sha256"]
            and set(observation) == {
                "schema", "action_id", "tool_name", "tool_input_sha256",
                "tool_use_id", "outcome", "hook_report_sha256",
                "native_receipt",
            }
            and observation["schema"]
            == native_controller.ACTION_OBSERVATION_SCHEMA
            and observation["action_id"] == close["action_id"]
            and observation["tool_name"] == close["tool_name"]
            and observation["tool_input_sha256"]
            == close["tool_input_sha256"]
            and observation["outcome"] == "completed"
            and set(native) == {
                "schema", "action_id", "outcome", "tool_name",
                "tool_input_sha256", "tool_use_id", "result_sha256",
                "result_binding", "source_pointer",
            }
            and native["schema"]
            == native_controller.NATIVE_ACTION_RECEIPT_SCHEMA
            and all(observation[field] == native[field] == durable[field]
                    for field in ("action_id", "outcome", "tool_use_id"))
            and observation["tool_name"] == native["tool_name"]
            and observation["tool_input_sha256"]
            == native["tool_input_sha256"]
            == durable_report["tool_input_sha256"]
            and observation["hook_report_sha256"]
            == durable_report["report_sha256"]
            and native["source_pointer"]
            == "project-ground-durable-event#"
            + durable_report["durable_record_sha256"]
            and _is_sha(native["result_sha256"])
            and native["result_sha256"] == durable["result_sha256"]
            and _canonical(native["result_binding"])
            == _canonical(durable["result_binding"])
            == _canonical(stop_binding)
        )
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return False


def _valid_stop_advance(report: Any) -> bool:
    """Join the first observed close to the second retained cleanup request."""
    try:
        transition, = report["controller_transitions"]
        controller = transition["report"];action = controller["action"]
        authority = report["authority_before"];receipt = controller["stage_report"]["receipt"]
        checkpoint_stop = (receipt["stage"] == "stopped" and receipt["status"] == "STOP_REQUIRED"
            and receipt["bindings"].get("worker_checkpoint_profile") == governed_attempt.WORKER_CHECKPOINT_PROFILE)
        verified_stop = (receipt["stage"] == "cleanup" and governed_attempt.validate_verified_cleanup_report(controller["stage_report"])["valid"])
        if (native_controller.validate_governed_native_controller_report(controller).get("valid") is not True
                or not (checkpoint_stop or verified_stop)
                or type(action["batch_index"]) is not int or action["batch_index"] != 1):return False
        proposal = {"schema":native_controller.ACTION_PROPOSAL_SCHEMA,"action_id":action["batch_id"],
            "kind":"stop","actor_thread_id":authority["identity"]["root_thread_id"],
            "adapter_sha256":native_controller.CLOSED_NATIVE_ACTION_ADAPTER_SHA256}
        first, issues = native_controller.ClosedNativeActionAdapter.authorize(proposal,next_action="stop",receipt=receipt,
            activation={"identity":_closed_action_validation_identity(authority),"task_specs":[]},controller_id=controller["controller_id"],seen_action_ids=[])
        if issues or first["batch_lane_ids"] != ["spec", "standards"]:return False
        expected = native_controller._direct_batch_action(controller_id=first["controller_id"],batch_id=first["batch_id"],
            batch_kind="stop",batch_lane_ids=first["batch_lane_ids"],requests=first["batch_requests"],index=1,phase="primary",
            actor_thread_id=first["actor_thread_id"],adapter_sha256=first["adapter_sha256"],predecessor_receipt_sha256=receipt["receipt_sha256"])
        observation = transition["program"]["payload"];native = observation["native_receipt"]
        durable = report["durable_hook_report"]["native_controller"]
        return (_canonical(action) == _canonical(expected)
            and authority["lifecycle"]["action_sha256"] == first["action_sha256"]
            and observation["action_id"] == native["action_id"] == first["action_id"]
            and observation["tool_name"] == native["tool_name"] == first["tool_name"]
            and observation["tool_input_sha256"] == native["tool_input_sha256"] == first["tool_input_sha256"]
            and observation["outcome"] == native["outcome"] == durable["outcome"] == "completed"
            and observation["tool_use_id"] == native["tool_use_id"] == durable["tool_use_id"] == authority["lifecycle"]["tool_use_id"]
            and native["result_sha256"] == durable["result_sha256"]
            and _canonical(native["result_binding"]) == _canonical(durable["result_binding"])
            and native_result.stop_result_binding(native["result_binding"], ["spec"]) is not None)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return False


def _worker_result_bindings(stage_report: Any, root_task_id: Any) -> list[dict[str, Any]]:
    """Resolve the exact admitted task/route/worker join from its owner receipt."""
    try:
        receipt = stage_report["receipt"]
        if receipt["stage"] not in {"worker_start", "progress", "worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification", "capacity_settlement"}:
            raise ValueError("invalid result stage")
        return qualification_results.join_bindings(receipt["bindings"], root_task_id)
    except (KeyError, TypeError, ValueError) as error:
        raise QualificationSuccessorError("successor_action_advance:result_join_invalid") from error


def _worker_results_decision(reports: Any, controller_report: Mapping[str, Any],
                             authority: Mapping[str, Any]) -> str:
    """Check complete observation reports against the current owned result join."""
    identity = authority.get("identity")
    if not isinstance(identity, Mapping):
        raise QualificationSuccessorError("successor_action_advance:result_identity_invalid")
    _worker_result_bindings(controller_report.get("stage_report"), identity.get("root_thread_id"))
    try:
        receipt = controller_report["stage_report"]["receipt"]
        decision = qualification_results.join_decision(reports,
            bindings=receipt["bindings"], root_task_id=identity["root_thread_id"])
        if receipt["stage"] not in {"worker_start", "progress"}:
            if _canonical(receipt["bindings"].get("worker_results")) != _canonical(reports):
                raise ValueError("retained result mismatch")
            if governed_attempt.validate_post_batch_report(controller_report["stage_report"]).get("valid") is not True:
                raise ValueError("post-batch report invalid")
            expected_action = governed_attempt.post_batch_next_action(identity["root_thread_id"], receipt)
            if receipt.get("next_action") != expected_action or controller_report["stage_report"].get("next_action") != expected_action:
                raise ValueError("retained result action mismatch")
            if expected_action == "sol_review":
                return "AWAITING_SOL_REVIEW"
            if expected_action == "observe_sol_review":
                return "AWAITING_SOL_REVIEW_OBSERVATION"
            if expected_action == "verify":
                return "AWAITING_TERMINAL_VERIFICATION"
            if expected_action == "failure_closure":
                return "AWAITING_FAILURE_CLOSURE"
            if expected_action == "final_qualification":
                return "AWAITING_ATTEMPT_QUALIFICATION"
            if expected_action == "cleanup":
                return "AWAITING_LIFECYCLE_CLEANUP"
            if expected_action == "review_evidence":
                return "SOL_REVIEW_EVIDENCE_REQUIRED"
        return decision
    except (KeyError, TypeError, ValueError) as error:
        raise QualificationSuccessorError("successor_action_advance:result_report_binding_invalid") from error


def _review_packet_for_controller(controller_report: Any) -> dict[str, Any]:
    try:
        stage = controller_report["stage_report"]
        if governed_attempt.validate_post_batch_report(stage).get("valid") is not True:
            raise ValueError("invalid review predecessor")
        bindings = stage["receipt"]["bindings"]
        if bindings.get("quality_phase") in {"review_submission", "semantic_review", "terminal_verification"}:
            packet = bindings["review_packet"]
            if qualification_review.validate_review_packet(packet).get("valid") is not True:
                raise ValueError("invalid retained packet")
            return deepcopy(packet)
        return qualification_review.build_review_packet(stage)
    except (KeyError, TypeError, ValueError) as error:
        raise QualificationSuccessorError("successor_action_advance:review_packet_invalid") from error


def _read_worker_results(state: Mapping[str, Any], current_task_id: str, *,
                         controller: native_controller.GovernedNativeController | None = None,
                         native_request_meta: Any = None) -> list[dict[str, Any]]:
    bindings = _worker_result_bindings(state.get("stage_report"), current_task_id)
    try:
        receipt_bindings = state["stage_report"]["receipt"]["bindings"]
        previous = receipt_bindings.get("worker_results")
        if previous is not None:
            qualification_results.join_decision(previous, bindings=receipt_bindings, root_task_id=current_task_id)
        specs = state["activation"]["task_specs"]
        if (not isinstance(specs, list)
                or [row["logical_worker_id"] for row in specs] != ["spec", "standards"]):
            raise ValueError("invalid frozen tasks")
        profile = receipt_bindings.get("worker_checkpoint_profile")
        if "worker_checkpoint_profile" in receipt_bindings and profile != governed_attempt.WORKER_CHECKPOINT_PROFILE:
            raise ValueError("unsupported checkpoint profile")
        final_sources = None
        if profile is not None:
            if previous is not None:
                if any(row["status"] != "OBSERVED" for row in previous):
                    raise ValueError("unowned partial final results")
            else:
                if controller is None:
                    raise ValueError("owned final reader required")
                final_sources = controller._observe_worker_finals(state, native_request_meta)
                if final_sources["status"] not in {"OBSERVED", "PENDING"}:
                    raise ValueError("owned final sources refused")
                if (final_sources["status"] == "OBSERVED"
                        and final_sources.get("schema")
                        == native_worker_finals.ARRIVAL_SCHEMA
                        and (native_worker_finals
                             .validate_native_worker_final_arrivals(
                                 final_sources,
                                 state["checkpoint_sources"])["valid"]
                             is not True
                             or final_sources["completed_lane_ids"]
                             != ["spec"]
                             or final_sources["pending_lane_ids"]
                             != ["standards"])):
                    raise ValueError("unexpected partial final lane")
        reports = []
        for index, (task, expected) in enumerate(zip(specs, bindings)):
            if (task["task_spec_sha256"] != expected["task_spec_sha256"]
                    or task["task_spec"]["task_spec_sha256"] != expected["task_spec_sha256"]):
                raise ValueError("invalid frozen task binding")
            binding = expected["binding"]
            if previous is not None and previous[index]["status"] == "OBSERVED":
                reports.append(deepcopy(previous[index]))
                continue
            if final_sources is not None:
                observed_workers = (
                    final_sources["evidence"]["workers"]
                    if final_sources["status"] == "OBSERVED"
                    else {}
                )
                lane = binding["logical_worker_id"]
                reports.append(
                    deepcopy(observed_workers[lane]["result_report"])
                    if lane in observed_workers
                    else qualification_results.observe_worker_result(
                        None, task_spec=task["task_spec"], binding=binding)
                )
                continue
            reports.append(qualification_results.observe_worker_result(
                _worker_rollout_path(binding["worker_id"]), task_spec=task["task_spec"], binding=binding,
                private_root=_worker_codex_home()))
        return qualification_results.merge_results(previous, reports, bindings=receipt_bindings, root_task_id=current_task_id)
    except (KeyError, TypeError, ValueError) as error:
        raise QualificationSuccessorError("successor_action_advance:result_observation_invalid") from error


def _worker_results_ready_to_retain(state: Mapping[str, Any], reports: list[dict[str, Any]]) -> bool:
    """Checkpoint final collection waits without committing placeholder results."""
    return (state["stage_report"]["receipt"]["bindings"].get("worker_checkpoint_profile")
            != governed_attempt.WORKER_CHECKPOINT_PROFILE
            or len(reports) == 2 and all(row["status"] == "OBSERVED" for row in reports))


def _worker_start_action_id(
    *, controller_id: str, cursor: Mapping[str, Any], acknowledgements: Mapping[str, Any]
) -> str:
    return "issue94-worker-start-" + _sha(
        {
            "controller_id": controller_id,
            "cursor": dict(cursor),
            "acknowledgements_sha256": acknowledgements.get(
                "acknowledgements_sha256"
            ),
        }
    )[:24]


@contextmanager
def _successor_action_controller(
    *,
    pre_turn_report_path: str | Path,
    expected_report_sha256: str,
    plugin_data: str | Path,
    hook_definition_path: str | Path,
    current_task_id: str,
):
    """Open and validate the existing producer-owned controller at one exact tip."""

    if not _text(current_task_id):
        raise QualificationSuccessorError(
            "successor_action_advance:task_identity_invalid"
        )
    report_path = Path(pre_turn_report_path)
    artifact = read_issue94_successor_pre_turn_artifact(
        report_path,
        expected_report_sha256=expected_report_sha256,
    )
    if (
        artifact.root_task_id != current_task_id
        or artifact.root_session_id != current_task_id
    ):
        raise QualificationSuccessorError(
            "successor_action_advance:task_identity_mismatch"
        )
    preparation = _read_successor_first_action_preparation(
        artifact, report_path
    )
    data = _runtime_root(
        plugin_data,
        label="successor_action_advance:plugin_data",
    )
    hook_path = Path(hook_definition_path)
    if (
        not hook_path.is_absolute()
        or hook_path.is_symlink()
        or not hook_path.is_file()
    ):
        raise QualificationSuccessorError(
            "successor_action_advance:hook_definition_invalid"
        )
    try:
        controller = native_controller.GovernedNativeController(
            plugin_data=data,
            hook_definition_path=hook_path,
            source_roots=preparation.source_roots,
        )
    except (OSError, TypeError, ValueError) as error:
        raise QualificationSuccessorError(
            "successor_action_advance:controller_unavailable"
        ) from error
    try:
        authority = controller.grants.canonical_authority()
        owner = authority.get("owner") if isinstance(authority, Mapping) else None
        identity = (
            authority.get("identity")
            if isinstance(authority, Mapping)
            and isinstance(authority.get("identity"), Mapping)
            else None
        )
        lifecycle = (
            authority.get("lifecycle")
            if isinstance(authority, Mapping)
            and isinstance(authority.get("lifecycle"), Mapping)
            else None
        )
        if (
            not isinstance(authority, Mapping)
            or authority.get("status") != "VERIFIED"
            or not isinstance(owner, Mapping)
            or owner.get("controller_id") != artifact.controller_id
            or not isinstance(identity, Mapping)
            or identity.get("root_thread_id") != current_task_id
            or identity.get("root_session_id") != current_task_id
            or identity.get("root_model") != artifact.root_model
            or not isinstance(lifecycle, Mapping)
            or lifecycle.get("expected_binding_status")
            not in {"ACTIVE", "WAITING"}
            or lifecycle.get("pending_intent") is not False
            or lifecycle.get("terminal") is not False
            or lifecycle.get("cleanup_required") is not False
            or not isinstance(authority.get("tip"), Mapping)
        ):
            raise QualificationSuccessorError(
                "successor_action_advance:owned_authority_required"
            )
        try:
            state, rows = controller._state(str(owner["controller_run_id"]))
            cursor = native_controller._cursor(list(rows))
        except (KeyError, TypeError, ValueError) as error:
            raise QualificationSuccessorError(
                "successor_action_advance:controller_state_invalid"
            ) from error
        if cursor != authority.get("tip"):
            raise QualificationSuccessorError(
                "successor_action_advance:controller_tip_mismatch"
            )

        yield artifact, preparation, controller, authority, owner, state, cursor
    finally:
        controller.store.close()


@dataclass(frozen=True)
class _BootstrapActionOrigin:
    controller_id: str
    report_sha256: str


@contextmanager
def _bootstrap_action_controller(*, bootstrap_artifact_path: str | Path,
        expected_bootstrap_report_sha256: str, source_root: str | Path,
        evidence_root: str | Path, enrollment_registry_root: str | Path,
        plugin_data: str | Path, hook_definition_path: str | Path,
        current_task_id: str):
    """Re-read canonical bootstrap bytes and derive the exact preparation."""
    try:
        bootstrapped = bootstrap.read_issue94_controller_bootstrap_artifact(
            bootstrap_artifact_path, source_root, evidence_root,
            enrollment_registry_root)
        preparation = QualificationSuccessorFirstActionPreparationArtifact.from_report(
            build_issue94_successor_first_action_preparation(bootstrapped))
    except (bootstrap.QualificationBootstrapError, TypeError, ValueError) as error:
        raise QualificationSuccessorError("bootstrap_action_advance:bootstrap_invalid") from error
    if (bootstrapped.report_sha256 != expected_bootstrap_report_sha256
            or preparation.bootstrap_report_sha256 != bootstrapped.report_sha256
            or preparation.controller_id != bootstrapped.report["controller_id"]
            or preparation.root_task_id != current_task_id
            or preparation.source_roots != bootstrapped.source_roots):
        raise QualificationSuccessorError("bootstrap_action_advance:context_mismatch")
    data = _runtime_root(plugin_data, label="bootstrap_action_advance:plugin_data")
    hook_path = Path(hook_definition_path)
    if not hook_path.is_absolute() or hook_path.is_symlink() or not hook_path.is_file():
        raise QualificationSuccessorError("bootstrap_action_advance:hook_definition_invalid")
    try:
        controller = native_controller.GovernedNativeController(
            plugin_data=data, hook_definition_path=hook_path,
            source_roots=preparation.source_roots)
    except (OSError, TypeError, ValueError) as error:
        raise QualificationSuccessorError("bootstrap_action_advance:controller_unavailable") from error
    try:
        authority = controller.grants.canonical_authority()
        owner = authority.get("owner") if isinstance(authority, Mapping) else None
        identity = authority.get("identity") if isinstance(authority, Mapping) else None
        lifecycle = authority.get("lifecycle") if isinstance(authority, Mapping) else None
        if (not isinstance(authority, Mapping) or authority.get("status") != "VERIFIED"
                or not isinstance(owner, Mapping) or owner.get("controller_id") != preparation.controller_id
                or not isinstance(identity, Mapping)
                or identity.get("root_thread_id") != current_task_id
                or identity.get("root_session_id") != current_task_id
                or identity.get("root_model") != preparation.root_model
                or not isinstance(lifecycle, Mapping)
                or lifecycle.get("expected_binding_status") not in {"ACTIVE", "WAITING"}
                or lifecycle.get("pending_intent") is not False
                or lifecycle.get("terminal") is not False
                or lifecycle.get("cleanup_required") is not False
                or not isinstance(authority.get("tip"), Mapping)):
            raise QualificationSuccessorError("bootstrap_action_advance:owned_authority_required")
        state, rows = controller._state(str(owner["controller_run_id"]))
        cursor = native_controller._cursor(list(rows))
        if cursor != authority["tip"]:
            raise QualificationSuccessorError("bootstrap_action_advance:controller_tip_mismatch")
        yield _BootstrapActionOrigin(preparation.controller_id, bootstrapped.report_sha256), preparation, controller, authority, owner, state, cursor
    finally:
        controller.store.close()


def advance_issue94_successor_after_native_action(
    *,
    pre_turn_report_path: str | Path,
    expected_report_sha256: str,
    plugin_data: str | Path,
    hook_definition_path: str | Path,
    current_task_id: str,
    native_request_meta: Any = None,
) -> dict[str, Any]:
    """Use the original successor context and report contract."""
    return _advance_issue94_after_native_action(
        pre_turn_report_path=pre_turn_report_path,
        expected_report_sha256=expected_report_sha256,
        plugin_data=plugin_data,
        hook_definition_path=hook_definition_path,
        current_task_id=current_task_id,
        native_request_meta=native_request_meta,
    )


def _advance_issue94_after_native_action(
    *,
    pre_turn_report_path: str | Path,
    expected_report_sha256: str,
    plugin_data: str | Path,
    hook_definition_path: str | Path,
    current_task_id: str,
    native_request_meta: Any = None, _controller_context: Any = None,
    _report_schema: str = ACTION_ADVANCE_REPORT_SCHEMA,
    _provenance_field: str = "pre_turn_report_sha256",
    _provenance_sha256: str | None = None,
) -> dict[str, Any]:
    """Observe one native action and advance its owned checkpoint/result phase."""

    context = (_controller_context if _controller_context is not None else
        _successor_action_controller(pre_turn_report_path=pre_turn_report_path,
            expected_report_sha256=expected_report_sha256, plugin_data=plugin_data,
            hook_definition_path=hook_definition_path, current_task_id=current_task_id))
    with context as (artifact, preparation, controller, authority, owner, state, cursor):
        lifecycle = authority["lifecycle"]
        durable: Mapping[str, Any] | None = None
        transitions: list[dict[str, Any]] = []
        next_action: dict[str, Any] | None = None
        observed_action: dict[str, Any] | None = None
        terminal_batch_failure = False
        retained_action = state.get("action")
        retained_grant = state.get("grant")
        if (
            _retained_authorized_continuation(
                retained_action,
                lifecycle,
                controller_id=owner.get("controller_id"),
                actor_thread_id=authority.get("identity", {}).get(
                    "root_thread_id"
                ),
            )
            and isinstance(retained_grant, Mapping)
            and retained_grant.get("state") == "AUTHORIZED"
            and retained_grant.get("action_sha256")
            == retained_action.get("action_sha256")
        ):
            # The retained owner may have observed one direct collaboration
            # call and atomically authorized the next lane before this MCP
            # read. Return that already-authorized action; do not demand a
            # second PostTool hook that Codex never emitted.
            next_action = deepcopy(dict(retained_action))
        elif lifecycle.get("expected_binding_status") == "ACTIVE":
            action = state.get("action")
            grant = state.get("grant")
            if (
                lifecycle.get("grant_state") != "POST_OBSERVED"
                or not _is_sha(lifecycle.get("action_sha256"))
                or not _text(lifecycle.get("tool_use_id"))
                or not isinstance(action, Mapping)
                or action.get("action_sha256")
                != lifecycle.get("action_sha256")
                or not isinstance(grant, Mapping)
                or grant.get("state") != "POST_OBSERVED"
                or grant.get("tool_use_id")
                != lifecycle.get("tool_use_id")
                or not _is_sha(grant.get("posttool_report_sha256"))
            ):
                raise QualificationSuccessorError(
                    "successor_action_advance:posttool_grant_invalid"
                )
            observed_action = deepcopy(dict(action))
            durable, durable_issues = controller._validate_hook_action_report(
                str(grant["posttool_report_sha256"]), action
            )
            native = (
                durable.get("native_controller")
                if isinstance(durable, Mapping)
                and isinstance(durable.get("native_controller"), Mapping)
                else None
            )
            if (
                durable_issues
                or not isinstance(durable, Mapping)
                or not isinstance(native, Mapping)
            ):
                raise QualificationSuccessorError(
                    "successor_action_advance:durable_posttool_invalid"
                )
            receipt = {
                "schema": native_controller.NATIVE_ACTION_RECEIPT_SCHEMA,
                "action_id": action["action_id"],
                "outcome": native.get("outcome"),
                "tool_name": action["tool_name"],
                "tool_input_sha256": action["tool_input_sha256"],
                "tool_use_id": native.get("tool_use_id"),
                "result_sha256": native.get("result_sha256"),
                "result_binding": deepcopy(native.get("result_binding")),
                "source_pointer": (
                    "project-ground-durable-event#"
                    + str(durable.get("durable_record_sha256"))
                ),
            }
            observation = {
                "schema": native_controller.ACTION_OBSERVATION_SCHEMA,
                "action_id": action["action_id"],
                "tool_name": action["tool_name"],
                "tool_input_sha256": action["tool_input_sha256"],
                "tool_use_id": native.get("tool_use_id"),
                "outcome": native.get("outcome"),
                "hook_report_sha256": grant["posttool_report_sha256"],
                "native_receipt": receipt,
            }
            observation_program = {
                "schema": native_controller.PROGRAM_SCHEMA,
                "controller_id": artifact.controller_id,
                "operation": "observe",
                "expected_cursor": deepcopy(dict(cursor)),
                "payload": observation,
            }
            observation_report = controller.advance(observation_program)
            terminal_batch_failure = bool(
                isinstance(observation_report, Mapping)
                and observation_report.get("status") == "BLOCKED"
                and observation_report.get("decision")
                == "ACTION_TERMINAL_FAILURE"
                and observation_report.get("issues")
                == ["native_action:failed"]
                and action.get("batch_kind") == "spawn"
                and action.get("batch_phase") == "compensation"
                and action.get("batch_failure_outcome") == "failed"
                and native.get("outcome") == "completed"
            )
            if (
                not isinstance(observation_report, Mapping)
                or not (
                    (
                        observation_report.get("status") == "PASS"
                        and observation_report.get("decision")
                        in {"ACTION_AUTHORIZED", "ACTION_OBSERVED"}
                        and observation_report.get("issues") == []
                    )
                    or terminal_batch_failure
                )
            ):
                raise QualificationSuccessorError(
                    "successor_action_advance:observation_refused"
                )
            transitions.append(
                {
                    "program": observation_program,
                    "report": deepcopy(dict(observation_report)),
                }
            )
            next_action = (
                deepcopy(dict(observation_report["action"]))
                if isinstance(observation_report.get("action"), Mapping)
                else None
            )
            try:
                state, rows = controller._state(
                    str(owner["controller_run_id"])
                )
                cursor = native_controller._cursor(list(rows))
            except (KeyError, TypeError, ValueError) as error:
                raise QualificationSuccessorError(
                    "successor_action_advance:controller_state_invalid"
                ) from error
        elif (
            lifecycle.get("grant_state") is not None
            or lifecycle.get("action_sha256") is not None
            or lifecycle.get("tool_use_id") is not None
            or state.get("action") is not None
            or (
                state.get("action_outcome") != "completed"
                and not (state.get("action_outcome") is None
                         and state.get("stage_report", {}).get("receipt", {}).get("stage") in {"worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification", "capacity_settlement"})
            )
        ):
            raise QualificationSuccessorError(
                "successor_action_advance:worker_ack_wait_state_required"
            )

        acknowledgements = _not_applicable_acknowledgements()
        cleanup_complete = False
        if (not transitions and state.get("action") is None
                and isinstance(state.get("last_batch_result"), Mapping)
                and state["last_batch_result"].get("kind") == "stop"):
            inspection_program = {
                "schema": native_controller.PROGRAM_SCHEMA,
                "controller_id": artifact.controller_id,
                "operation": "inspect",
                "expected_cursor": deepcopy(dict(cursor)),
                "payload": {},
            }
            inspection = controller.advance(inspection_program)
            if not isinstance(inspection, Mapping) or not _is_completed_cleanup_wait(
                inspection
            ):
                raise QualificationSuccessorError(
                    "successor_action_advance:cleanup_completion_invalid"
                )
            transitions.append(
                {
                    "program": inspection_program,
                    "report": deepcopy(dict(inspection)),
                }
            )
            cleanup_complete = True
        if (
            next_action is None
            and isinstance(state.get("last_batch_result"), Mapping)
            and state["last_batch_result"].get("kind") == "spawn"
        ):
            acknowledgements, worker_start_program = (
                _worker_acknowledgements(
                    state=state,
                    preparation=preparation,
                    current_task_id=current_task_id,
                    controller_id=artifact.controller_id,
                )
            )
            if worker_start_program is not None:
                activation_identity = state.get("activation", {}).get(
                    "identity"
                )
                if not isinstance(activation_identity, Mapping):
                    raise QualificationSuccessorError(
                        "successor_action_advance:activation_identity_invalid"
                    )
                proposal = {
                    "schema": native_controller.ACTION_PROPOSAL_SCHEMA,
                    "action_id": _worker_start_action_id(
                        controller_id=artifact.controller_id,
                        cursor=cursor,
                        acknowledgements=acknowledgements,
                    ),
                    "kind": "continue",
                    "actor_thread_id": current_task_id,
                    "adapter_sha256": activation_identity.get(
                        "native_adapter_sha256"
                    ),
                }
                stage_program = (
                    native_controller.build_governed_native_stage_program(
                        controller_id=artifact.controller_id,
                        expected_cursor=cursor,
                        stage_program=worker_start_program,
                        proposed_action=proposal,
                    )
                )
                stage_report = controller.advance(stage_program)
                if (
                    not isinstance(stage_report, Mapping)
                    or stage_report.get("status") != "PASS"
                    or stage_report.get("decision") != "ACTION_AUTHORIZED"
                    or stage_report.get("issues") != []
                    or not isinstance(stage_report.get("action"), Mapping)
                    or stage_report["action"].get("tool_name")
                    != "multi_agent_v1__send_input"
                ):
                    raise QualificationSuccessorError(
                        "successor_action_advance:worker_start_refused"
                    )
                transitions.append(
                    {
                        "program": stage_program,
                        "report": deepcopy(dict(stage_report)),
                    }
                )
                next_action = deepcopy(dict(stage_report["action"]))

        waiting_for_results = bool(
            next_action is None
            and isinstance(state.get("last_batch_result"), Mapping)
            and state["last_batch_result"].get("kind") == "continue"
        )
        checkpoint_wait = False
        if (waiting_for_results
                and state["stage_report"]["receipt"]["stage"] == "worker_start"
                and state["stage_report"]["receipt"]["bindings"].get("worker_checkpoint_profile")
                    == governed_attempt.WORKER_CHECKPOINT_PROFILE):
            import orch_dork_qualification_progress as progress
            waiting_for_results = False
            if not transitions:
                inspection_program = {"schema":native_controller.PROGRAM_SCHEMA,"controller_id":artifact.controller_id,
                    "operation":"inspect","expected_cursor":deepcopy(dict(cursor)),"payload":{}}
                transitions.append({"program":inspection_program,"report":controller.advance(inspection_program)})
            if not _is_worker_checkpoint_wait(transitions[-1]["report"]):
                raise QualificationSuccessorError("successor_action_advance:checkpoint_wait_invalid")
            try:
                observed, sources = controller._collect_worker_checkpoints(state, native_request_meta)
            except (KeyError, TypeError, ValueError) as error:
                raise QualificationSuccessorError("successor_action_advance:checkpoint_sources_unavailable") from error
            if observed == "PENDING":
                checkpoint_wait = True
            elif observed == "OBSERVED":
                program = progress.build_checkpoint_stage_program(
                    preparation.controller_program["payload"]["stage_program"]["identity"], state["stage_report"], sources)
                stage_program = native_controller.build_governed_native_stage_program(
                    controller_id=artifact.controller_id, expected_cursor=cursor, stage_program=program,
                    proposed_action=_checkpoint_proposal(artifact.controller_id, cursor, program))
                checkpoint_report = controller.advance(stage_program, native_request_meta=native_request_meta)
                if (checkpoint_report.get("status") != "PASS"
                        or checkpoint_report.get("decision") not in {"ACTION_AUTHORIZED", "CHECKPOINT_OBSERVATION_PENDING"}):
                    raise QualificationSuccessorError("successor_action_advance:checkpoint_admission_refused")
                transitions.append({"program":stage_program,"report":checkpoint_report})
                checkpoint_wait = checkpoint_report["decision"] == "CHECKPOINT_OBSERVATION_PENDING"
                next_action = deepcopy(checkpoint_report["action"])
            else:
                raise QualificationSuccessorError("successor_action_advance:checkpoint_sources_unavailable")
        worker_results: list[dict[str, Any]] = []
        if waiting_for_results:
            if not transitions:
                inspection_program = {
                    "schema": native_controller.PROGRAM_SCHEMA,
                    "controller_id": artifact.controller_id,
                    "operation": "inspect",
                    "expected_cursor": deepcopy(dict(cursor)),
                    "payload": {},
                }
                inspection = controller.advance(inspection_program)
                transitions.append({"program": inspection_program, "report": inspection})
            if not _is_worker_result_wait(transitions[-1]["report"]):
                raise QualificationSuccessorError(
                    "successor_action_advance:unexpected_post_batch_stage"
                )
            worker_results = _read_worker_results(state, current_task_id, controller=controller,
                                                 native_request_meta=native_request_meta)
            previous_results = state["stage_report"]["receipt"]["bindings"].get("worker_results")
            result_program = None
            if worker_results != previous_results:
                if _worker_results_ready_to_retain(state, worker_results):
                    result_program = governed_attempt.build_worker_results_program(
                        preparation.controller_program["payload"]["stage_program"]["identity"],
                        state["stage_report"], worker_results)
            elif governed_attempt.post_batch_next_action(current_task_id, state["stage_report"]["receipt"]) == "aggregate":
                # Aggregation is its own durable transition. It schedules no
                # native call and supplies no semantic review evidence.
                result_program = governed_attempt.build_result_aggregation_program(
                    preparation.controller_program["payload"]["stage_program"]["identity"],
                    state["stage_report"])
            elif governed_attempt.post_batch_next_action(current_task_id, state["stage_report"]["receipt"]) == "verify":
                result_program = governed_attempt.build_terminal_verification_program(
                    preparation.controller_program["payload"]["stage_program"]["identity"], state["stage_report"])
            elif governed_attempt.post_batch_next_action(current_task_id, state["stage_report"]["receipt"]) == "observe_sol_review":
                result_program = governed_attempt.build_semantic_review_program(
                    preparation.controller_program["payload"]["stage_program"]["identity"], state["stage_report"])
            elif governed_attempt.post_batch_next_action(current_task_id, state["stage_report"]["receipt"]) == "cleanup":
                result_program = governed_attempt.build_verified_cleanup_program(
                    preparation.controller_program["payload"]["stage_program"]["identity"], state["stage_report"])
            if result_program is not None:
                cleanup_stage = result_program["operation"] == "cleanup"
                stage_program = native_controller.build_governed_native_stage_program(
                    controller_id=artifact.controller_id, expected_cursor=cursor,
                    stage_program=result_program, proposed_action=(_cleanup_proposal(artifact.controller_id,cursor,result_program) if cleanup_stage else None))
                result_report = controller.advance(stage_program, native_request_meta=native_request_meta)
                valid_result = (result_report.get("decision") == "ACTION_AUTHORIZED"
                    and governed_attempt.validate_verified_cleanup_report(result_report.get("stage_report"))["valid"]
                    and isinstance(result_report.get("action"), Mapping)
                    and result_report["action"].get("kind") == "stop") if cleanup_stage else (
                        result_report.get("decision") in {"STAGE_ADVANCED", "REVIEW_OBSERVATION_PENDING"} and _is_worker_result_wait(result_report))
                if result_report.get("status") != "PASS" or not valid_result:
                    raise QualificationSuccessorError("successor_action_advance:result_retention_refused")
                transitions.append({"program": stage_program, "report": result_report})
                worker_results = deepcopy(result_report["stage_report"]["receipt"]["bindings"]["worker_results"])
                if cleanup_stage:next_action = deepcopy(result_report["action"])

        if terminal_batch_failure:
            decision = "ACTION_TERMINAL_FAILURE"
        elif next_action is not None:
            decision = "READY_FOR_NEXT_ACTION"
        elif checkpoint_wait:
            decision = "AWAITING_WORKER_CHECKPOINTS"
        elif acknowledgements.get("state") == "AWAITING":
            decision = "AWAITING_WORKER_ACKNOWLEDGEMENTS"
        elif cleanup_complete:
            decision = "AWAITING_ATTEMPT_QUALIFICATION"
        elif waiting_for_results:
            decision = _worker_results_decision(worker_results, transitions[-1]["report"], authority)
        else:
            decision = "ACTION_BATCH_OBSERVED"
        operations = [
            transition["program"]["operation"]
            for transition in transitions
        ]
        actual_stages = operations.count("stage") - sum(
            row["report"].get("decision") in {"REVIEW_OBSERVATION_PENDING", "CHECKPOINT_OBSERVATION_PENDING"} for row in transitions)
        counters = {
            "controller_observations": operations.count("observe"),
            "controller_stages": actual_stages,
            # Observation records validated and carried by this report, including
            # retained results; this is not a filesystem-read or provider-call count.
            "session_runtime_observations": len(
                acknowledgements["observed_lane_ids"]
            ) + sum(row["runtime_observation"] is not None for row in worker_results)
              + (3 if _has_checkpoint_stage(transitions) else 0),
            "hosted_calls": 0,
            "model_calls": 0,
            "native_actions": 0,
            "network_calls": 0,
            "provider_calls": 0,
            "task_creations": 0,
            "worker_creations": 0,
        }
        core = {
            "schema": _report_schema,
            "status": "PASS",
            "decision": decision,
            "issues": [],
            _provenance_field: (_provenance_sha256 or artifact.report_sha256),
            "source_roots": deepcopy(preparation.source_roots),
            "authority_before": deepcopy(dict(authority)),
            "durable_hook_report": (
                deepcopy(dict(durable))
                if isinstance(durable, Mapping)
                else None
            ),
            "controller_transitions": transitions,
            "acknowledgements": acknowledgements,
            "worker_results": worker_results,
            "review_packet": (_review_packet_for_controller(transitions[-1]["report"])
                              if decision in {"AWAITING_SOL_REVIEW", "AWAITING_SOL_REVIEW_OBSERVATION", "AWAITING_TERMINAL_VERIFICATION", "SOL_REVIEW_EVIDENCE_REQUIRED", "AWAITING_LIFECYCLE_CLEANUP", "AWAITING_ATTEMPT_QUALIFICATION", "AWAITING_FAILURE_CLOSURE"} else None),
            "action": next_action,
            "boundary": {
                "native_action_called_by_bridge": False,
                "native_action_observed_by_bridge": "observe" in operations,
                "worker_acknowledgements_observed": len(
                    acknowledgements["observed_lane_ids"]
                ),
                "controller_stage_advanced": actual_stages > 0,
                "next_action": (
                    next_action.get("tool_name")
                    if isinstance(next_action, Mapping)
                    else (
                        "mcp__orch_dork__" + (
                            "advance_issue94_bootstrapped_after_native_action"
                            if _report_schema == BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA
                            else "advance_issue94_successor_after_native_action")
                        if decision in {
                            "AWAITING_WORKER_ACKNOWLEDGEMENTS",
                            "AWAITING_WORKER_CHECKPOINTS",
                            "AWAITING_WORKER_RESULTS",
                            "AWAITING_RESULT_AGGREGATION",
                            "AWAITING_SOL_REVIEW_OBSERVATION",
                            "AWAITING_TERMINAL_VERIFICATION",
                        }
                        else None
                    )
                ),
            },
            "provider_free": True,
            "counters": counters,
        }
        compensation_action = (
            next_action
            if isinstance(next_action, Mapping)
            and next_action.get("batch_kind") == "spawn"
            and next_action.get("batch_phase") == "compensation"
            else observed_action
            if terminal_batch_failure
            and isinstance(observed_action, Mapping)
            else None
        )
        if isinstance(compensation_action, Mapping):
            evidence_rows = state.get("action_evidence")
            if not isinstance(evidence_rows, list):
                raise QualificationSuccessorError(
                    "successor_action_advance:compensation_evidence_unavailable"
                )
            identity = state.get("activation", {}).get("identity", {})
            if (
                not isinstance(identity, Mapping)
                or not controller._retained_hook_evidence_valid(state)
            ):
                raise QualificationSuccessorError(
                    "successor_action_advance:compensation_history_unavailable"
                )
            durable_history = []
            for evidence_row in evidence_rows:
                pretool, pretool_issue = controller._read_hook_event(
                    evidence_row.get("pretool_report_sha256"), identity
                )
                posttool, posttool_issues = (
                    controller._validate_hook_action_report(
                        evidence_row.get("posttool_report_sha256"),
                        evidence_row.get("action"),
                    )
                )
                if (
                    pretool_issue is not None
                    or posttool_issues
                    or not isinstance(pretool, Mapping)
                    or not isinstance(posttool, Mapping)
                ):
                    raise QualificationSuccessorError(
                        "successor_action_advance:compensation_history_unavailable"
                    )
                durable_history.append({
                    "pretool": deepcopy(dict(pretool)),
                    "posttool": deepcopy(dict(posttool)),
                })
            evidence_core = {
                "schema": SPAWN_COMPENSATION_EVIDENCE_SCHEMA,
                "batch_id": compensation_action.get("batch_id"),
                "action_evidence": deepcopy(evidence_rows),
                "durable_history": durable_history,
                "durable_history_sha256": _sha(durable_history),
            }
            core["spawn_compensation_evidence"] = evidence_core
            witness_payload = _spawn_compensation_witness_payload(core)
            observed_at = (
                controller.now()
                if callable(controller.now)
                else controller.now
            )
            if (
                witness_payload is None
                or not isinstance(observed_at, datetime)
                or observed_at.tzinfo is None
            ):
                raise QualificationSuccessorError(
                    "successor_action_advance:compensation_witness_unavailable"
                )
            evaluation_time = observed_at.astimezone(timezone.utc)
            try:
                _authority_identity, signer, _trust_store = activation._authority()
                owner_witness = signer.issue(
                    SPAWN_COMPENSATION_WITNESS_KIND,
                    witness_payload,
                    issued_at=(
                        evaluation_time - timedelta(seconds=1)
                    ).isoformat(),
                    valid_until=(
                        evaluation_time + timedelta(minutes=4)
                    ).isoformat(),
                    nonce=(
                        "successor-spawn-compensation-"
                        + _sha(witness_payload)[:24]
                    ),
                )
            except (
                activation.QualificationActivationError,
                observer_receipt.ObserverReceiptError,
            ) as error:
                raise QualificationSuccessorError(
                    "successor_action_advance:compensation_witness_unavailable"
                ) from error
            witnessed_evidence = {
                **evidence_core,
                "owner_witness": owner_witness,
            }
            core["spawn_compensation_evidence"] = {
                **witnessed_evidence,
                "evidence_sha256": _sha(witnessed_evidence),
            }
        report = {**core, "report_sha256": _sha(core)}
        if len(_canonical(report)) > MAX_REPORT_BYTES:
            raise QualificationSuccessorError(
                "successor_action_advance:report_too_large"
            )
        return QualificationSuccessorActionAdvanceArtifact.from_report(
            report
        ).report


def advance_issue94_bootstrapped_after_native_action(*,
        bootstrap_artifact_path: str | Path, expected_bootstrap_report_sha256: str,
        source_root: str | Path, evidence_root: str | Path,
        enrollment_registry_root: str | Path, plugin_data: str | Path,
        hook_definition_path: str | Path, current_task_id: str,
        native_request_meta: Any = None) -> dict[str, Any]:
    """Advance canonical bootstrap-origin state without successor provenance."""
    context = _bootstrap_action_controller(
        bootstrap_artifact_path=bootstrap_artifact_path,
        expected_bootstrap_report_sha256=expected_bootstrap_report_sha256,
        source_root=source_root, evidence_root=evidence_root,
        enrollment_registry_root=enrollment_registry_root, plugin_data=plugin_data,
        hook_definition_path=hook_definition_path, current_task_id=current_task_id)
    return _advance_issue94_after_native_action(
        pre_turn_report_path="", expected_report_sha256="", plugin_data=plugin_data,
        hook_definition_path=hook_definition_path, current_task_id=current_task_id,
        native_request_meta=native_request_meta, _controller_context=context,
        _report_schema=BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA,
        _provenance_field="bootstrap_report_sha256",
        _provenance_sha256=expected_bootstrap_report_sha256)


def submit_issue94_semantic_review(
    *, pre_turn_report_path: str | Path, expected_report_sha256: str, subject_sha256: str,
    verifications: Any, native_request_meta: Any, plugin_data: str | Path,
    hook_definition_path: str | Path, current_task_id: str,
) -> dict[str, Any]:
    """Use the original successor context and report contract."""
    return _submit_issue94_semantic_review(
        pre_turn_report_path=pre_turn_report_path,
        expected_report_sha256=expected_report_sha256,
        subject_sha256=subject_sha256,
        verifications=verifications,
        native_request_meta=native_request_meta,
        plugin_data=plugin_data,
        hook_definition_path=hook_definition_path,
        current_task_id=current_task_id,
    )


def _submit_issue94_semantic_review(
    *, pre_turn_report_path: str | Path, expected_report_sha256: str, subject_sha256: str,
    verifications: Any, native_request_meta: Any, plugin_data: str | Path,
    hook_definition_path: str | Path, current_task_id: str,
    _controller_context: Any = None, _review_origin: Any = None,
) -> dict[str, Any]:
    """Retain raw review content and host MCP provenance; grant no acceptance.

    The native request metadata is supplied by the MCP dispatcher, outside the
    tool's model-visible arguments. A subsequent owner read must independently
    reconcile this small acknowledgement with the whole completed native call.
    """
    from lifecycle_conformance.host_adapter import mcp_call_context

    try:
        native_call = mcp_call_context(native_request_meta)
    except (TypeError, ValueError) as error:
        raise QualificationSuccessorError("successor_review:native_context_invalid") from error
    if native_call["task_id"] != current_task_id:
        raise QualificationSuccessorError("successor_review:root_mismatch")
    context_owner = (_controller_context if _controller_context is not None else
        _successor_action_controller(pre_turn_report_path=pre_turn_report_path,
            expected_report_sha256=expected_report_sha256, plugin_data=plugin_data,
            hook_definition_path=hook_definition_path, current_task_id=current_task_id))
    with context_owner as (artifact, preparation, controller, authority, owner, state, cursor):
        lifecycle = authority["lifecycle"]
        if (lifecycle.get("expected_binding_status") != "WAITING" or state.get("action") is not None
                or lifecycle.get("grant_state") is not None or lifecycle.get("tool_use_id") is not None):
            raise QualificationSuccessorError("successor_review:quiescent_controller_required")
        try:
            packet = qualification_review.build_review_packet(state["stage_report"])
            if packet["subject_sha256"] != subject_sha256:
                raise ValueError("review subject mismatch")
            submission = qualification_review.build_review_submission(packet, verifications)
            inventory = local_task_runtime.observe_qualification_host_hooks(
                socket_path=os.environ.get(local_task_runtime.OWNER_SOCKET_ENV, ""), cwd=preparation.source_roots["source"])
            local_task_runtime.OwnerHookInventoryArtifact.from_report(inventory)
            if inventory["report_sha256"] != state["activation"]["hook_trust"]["hook_inventory_report_sha256"]:
                raise ValueError("review owner mismatch")
            origin = (_review_origin if _review_origin is not None else {
                "schema": qualification_review.CONTEXT_SCHEMA,
                "pre_turn_report_path": str(pre_turn_report_path),
                "pre_turn_report_sha256": expected_report_sha256})
            context = {**deepcopy(dict(origin)), "controller_id": artifact.controller_id,
                "native_call": native_call, "owner_hook_inventory_report": inventory}
            stage = governed_attempt.build_review_submission_program(
                preparation.controller_program["payload"]["stage_program"]["identity"],
                state["stage_report"], submission, context)
            acknowledgement = qualification_review.build_review_acknowledgement(packet, submission, context)
            program = native_controller.build_governed_native_stage_program(
                controller_id=artifact.controller_id, expected_cursor=cursor, stage_program=stage, proposed_action=None)
            result = controller.advance(program)
            if (result.get("status") != "PASS" or result.get("decision") != "STAGE_ADVANCED"
                    or result.get("action") is not None
                    or governed_attempt.validate_post_batch_report(result.get("stage_report")).get("valid") is not True
                    or result["stage_report"]["next_action"] != "observe_sol_review"):
                raise ValueError("review retention refused")
            return acknowledgement
        except (KeyError, TypeError, ValueError) as error:
            raise QualificationSuccessorError("successor_review:submission_refused") from error


def submit_issue94_bootstrapped_semantic_review(*,
        bootstrap_artifact_path: str | Path, expected_bootstrap_report_sha256: str,
        source_root: str | Path, evidence_root: str | Path,
        enrollment_registry_root: str | Path, subject_sha256: str,
        verifications: Any, native_request_meta: Any, plugin_data: str | Path,
        hook_definition_path: str | Path, current_task_id: str) -> dict[str, Any]:
    context = _bootstrap_action_controller(
        bootstrap_artifact_path=bootstrap_artifact_path,
        expected_bootstrap_report_sha256=expected_bootstrap_report_sha256,
        source_root=source_root, evidence_root=evidence_root,
        enrollment_registry_root=enrollment_registry_root, plugin_data=plugin_data,
        hook_definition_path=hook_definition_path, current_task_id=current_task_id)
    return _submit_issue94_semantic_review(pre_turn_report_path="",
        expected_report_sha256="", subject_sha256=subject_sha256,
        verifications=verifications, native_request_meta=native_request_meta,
        plugin_data=plugin_data, hook_definition_path=hook_definition_path,
        current_task_id=current_task_id, _controller_context=context,
        _review_origin={"schema": qualification_review.BOOTSTRAP_CONTEXT_SCHEMA,
            "bootstrap_artifact_path": str(bootstrap_artifact_path),
            "bootstrap_report_sha256": expected_bootstrap_report_sha256})


def validate_issue94_semantic_review_acknowledgement(
    report: Any, *, arguments: Any, native_request_meta: Any, current_task_id: str,
) -> dict[str, Any]:
    """Check dispatcher transport against submitted bytes, without acceptance."""
    from lifecycle_conformance.host_adapter import mcp_call_context

    try:
        context = mcp_call_context(native_request_meta)
        if (type(arguments) is not dict or set(arguments) != {
                "pre_turn_report_path", "pre_turn_report_sha256", "subject_sha256", "verifications"}
                or type(report) is not dict or not _text(report.get("controller_id"))
                or context["task_id"] != current_task_id):
            raise ValueError("invalid acknowledgement")
        submission_core = {"schema": qualification_review.SUBMISSION_SCHEMA, "subject_sha256": arguments["subject_sha256"],
                           "verifications": arguments["verifications"]}
        expected = {
            "schema": "orch-dork/qualification-review-acknowledgement/v1", "status": "PASS", "decision": "REVIEW_SUBMITTED",
            "controller_id": report["controller_id"], "subject_sha256": arguments["subject_sha256"],
            "submission_sha256": _sha(submission_core), "native_call": context,
        }
        expected["acknowledgement_sha256"] = _sha(expected)
        if _canonical(report) != _canonical(expected):
            raise ValueError("noncanonical acknowledgement")
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return {"valid": False, "issues": ["successor_review:acknowledgement_invalid"], "scope": "submitted_only"}
    return {"valid": True, "issues": [], "scope": "submitted_only"}


def validate_issue94_successor_action_advance_report(
    report: Any,
) -> dict[str, Any]:
    """Validate one bridge report against external host authority when needed."""

    try:
        artifact = QualificationSuccessorActionAdvanceArtifact.from_report(
            report
        )
    except (TypeError, ValueError):
        return {
            "valid": False,
            "issues": ["successor_action_advance:report_invalid"],
        }
    report_value = artifact.report
    if "spawn_compensation_evidence" in report_value and not (
        _valid_spawn_compensation_owner_witness(
            report_value,
            archival=(
                report_value.get("decision") == "ACTION_TERMINAL_FAILURE"
                and report_value.get("action") is None
            ),
        )
    ):
        return {
            "valid": False,
            "issues": [
                "successor_action_advance:owner_witness_invalid"
            ],
        }
    return {
        "valid": True,
        "issues": [],
        "report_sha256": artifact.report_sha256,
    }


def validate_issue94_successor_action_advance_evidence(
    report: Any,
) -> dict[str, Any]:
    """Authenticate historical compensation evidence without authorizing action."""

    scope = "archival_evidence_only"
    try:
        artifact = QualificationSuccessorActionAdvanceArtifact.from_report(
            report
        )
    except (TypeError, ValueError):
        return {
            "valid": False,
            "issues": ["successor_action_advance:report_invalid"],
            "scope": scope,
            "action_authorized": False,
        }
    if (
        "spawn_compensation_evidence" not in artifact.report
        or not _valid_spawn_compensation_owner_witness(
            artifact.report,
            archival=True,
        )
    ):
        return {
            "valid": False,
            "issues": [
                "successor_action_advance:owner_witness_invalid"
            ],
            "scope": scope,
            "action_authorized": False,
        }
    return {
        "valid": True,
        "issues": [],
        "report_sha256": artifact.report_sha256,
        "scope": scope,
        "action_authorized": False,
    }


@contextmanager
def _action_result_directory(evidence_root: str | Path, *, create: bool):
    """Hold every directory link; leaf I/O never resolves the checked path again."""
    root = Path(evidence_root)
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise QualificationSuccessorError("action_result_artifact:root_invalid")
    directory = root / "action-advance-reports"
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = [os.open(root.anchor, flags)]
    links = []

    def check():
        for parent, name, descriptor in links:
            named, held = os.stat(name, dir_fd=parent, follow_symlinks=False), os.fstat(descriptor)
            if not stat.S_ISDIR(named.st_mode) or (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
                raise QualificationSuccessorError("action_result_artifact:directory_changed")
        for descriptor, private in ((root_descriptor, False), (descriptors[-1], True)):
            info = os.fstat(descriptor)
            if (info.st_uid != os.getuid() or info.st_mode & 0o022
                    or private and stat.S_IMODE(info.st_mode) != 0o700):
                raise QualificationSuccessorError("action_result_artifact:directory_custody_invalid")

    try:
        for name in root.parts[1:]:
            parent = descriptors[-1]
            descriptor = os.open(name, flags, dir_fd=parent)
            descriptors.append(descriptor)
            links.append((parent, name, descriptor))
        root_descriptor = descriptors[-1]
        info = os.fstat(root_descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise QualificationSuccessorError("action_result_artifact:root_custody_invalid")
        if create:
            try:
                os.mkdir(directory.name, mode=0o700, dir_fd=root_descriptor)
            except FileExistsError:
                pass
            os.fsync(root_descriptor)
        descriptor = os.open(directory.name, flags, dir_fd=root_descriptor)
        descriptors.append(descriptor)
        links.append((root_descriptor, directory.name, descriptor))
        check()
        yield directory, descriptor
        check()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_action_result_bytes(directory_descriptor: int, name: str) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=directory_descriptor)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_REPORT_BYTES):
            raise QualificationSuccessorError("action_result_artifact:file_custody_invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_REPORT_BYTES + 1)
        after = os.fstat(descriptor)
        if (len(payload) > MAX_REPORT_BYTES
                or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise QualificationSuccessorError("action_result_artifact:file_changed")
        return payload
    finally:
        os.close(descriptor)


def _action_result_artifact_action_projection(report: Mapping[str, Any]) -> dict[str, Any] | None:
    """Build the v2 receipt's digest-only projection of one action.

    Returns ``None`` when the canonical action is null; otherwise
    ``{"action_sha256": <canonical action's declared action_sha256>}`` whose
    declared digest is exactly the SHA-256 the action advertised. The full
    action bytes stay in the create-only artifact; only this projection rides
    on the bounded MCP frame.
    """
    action = report.get("action")
    if action is None:
        return None
    if not isinstance(action, Mapping):
        raise QualificationSuccessorError("action_result_artifact:action_projection_invalid")
    declared = action.get("action_sha256")
    if not isinstance(declared, str) or _SHA256.fullmatch(declared) is None:
        raise QualificationSuccessorError("action_result_artifact:action_projection_invalid")
    return {"action_sha256": declared}


def is_issue94_action_advance_result_artifact_receipt(value: Any) -> bool:
    """Recognize the two closed schemas; this grants no artifact authority."""
    schema = value.get("schema") if isinstance(value, Mapping) else None
    return isinstance(schema, str) and schema in (
        ACTION_ADVANCE_RESULT_ARTIFACT_SCHEMA,
        ACTION_ADVANCE_RESULT_ARTIFACT_V2_SCHEMA,
    )


def _action_result_artifact_receipt_core(
    report: Mapping[str, Any], path: Path, payload: bytes,
) -> dict[str, Any]:
    """Build the receipt facts shared by the two closed transport schemas."""
    owner = report["authority_before"]["owner"]
    return {
        "status": "PASS", "decision": report["decision"],
        "controller_id": owner["controller_id"], "root_task_id": report["authority_before"]["identity"]["root_thread_id"],
        "path": str(path), "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "report_sha256": report["report_sha256"], "report_schema": report["schema"],
        "boundary": deepcopy(report["boundary"]),
        "provider_free": True, "counters": deepcopy(report["counters"]),
    }


def _action_result_artifact_v1_receipt(report: Mapping[str, Any], path: Path, payload: bytes) -> dict[str, Any]:
    core = {
        **_action_result_artifact_receipt_core(report, path, payload),
        "schema": ACTION_ADVANCE_RESULT_ARTIFACT_SCHEMA,
        "action": deepcopy(report["action"]),
    }
    return {**core, "receipt_sha256": _sha(core)}


def _action_result_artifact_v2_receipt(report: Mapping[str, Any], path: Path, payload: bytes) -> dict[str, Any]:
    core = {
        **_action_result_artifact_receipt_core(report, path, payload),
        "schema": ACTION_ADVANCE_RESULT_ARTIFACT_V2_SCHEMA,
        "action_projection": _action_result_artifact_action_projection(report),
    }
    return {**core, "receipt_sha256": _sha(core)}


# Historical v1 factory name retained for existing replay callers.
_action_result_artifact_receipt = _action_result_artifact_v1_receipt


def persist_issue94_action_advance_result(
    report: Any, *, receipt_schema: str = ACTION_ADVANCE_RESULT_ARTIFACT_SCHEMA,
) -> dict[str, Any]:
    """Retain a whole generated result outside the bounded MCP frame, once.

    The ``receipt_schema`` parameter selects between the historical v1 receipt
    (full action embedded; preserved for byte-exact historical compatibility)
    and the v2 receipt that carries only a digest projection of the action and
    keeps the create-only artifact as the sole location of the full action and
    report bytes. The full report and the full action are written to the
    create-only artifact unchanged regardless of the receipt schema, so any
    read round-trip recovers the exact bytes that originally persisted.
    """
    from orch_dork_hostile_input import PROFILE, canonicalize_bounded_json

    if receipt_schema == ACTION_ADVANCE_RESULT_ARTIFACT_SCHEMA:
        receipt_factory = _action_result_artifact_v1_receipt
    elif receipt_schema == ACTION_ADVANCE_RESULT_ARTIFACT_V2_SCHEMA:
        receipt_factory = _action_result_artifact_v2_receipt
    else:
        raise QualificationSuccessorError("action_result_artifact:receipt_schema_invalid")
    artifact = QualificationSuccessorActionAdvanceArtifact.from_report(report)
    value = artifact.report
    if value["schema"] != ACTION_ADVANCE_REPORT_SCHEMA:
        raise QualificationSuccessorError("action_result_artifact:report_version_invalid")
    payload = _canonical(value) + b"\n"
    if len(payload) > MAX_REPORT_BYTES:
        raise QualificationSuccessorError("action_result_artifact:report_too_large")
    with _action_result_directory(value["source_roots"]["evidence"], create=True) as (directory, descriptor):
        path = directory / (hashlib.sha256(payload).hexdigest() + ".json")
        receipt = receipt_factory(value, path, payload)
        canonicalize_bounded_json(_canonical(receipt))
        try:
            os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            with os.scandir(descriptor) as entries:
                for count, _entry in enumerate(entries, 1):
                    if count >= PROFILE.registry_artifacts:
                        raise QualificationSuccessorError("action_result_artifact:directory_full")
            created = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=descriptor)
            with os.fdopen(created, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(descriptor)
        retained = _read_action_result_bytes(descriptor, path.name)
        if retained != payload:
            raise QualificationSuccessorError("action_result_artifact:readback_mismatch")
    return receipt


def read_issue94_action_advance_result(
    receipt: Any, *, evidence_root: str | Path, controller_id: str, root_task_id: str,
) -> dict[str, Any]:
    """Read exact result bytes within an independent root; confer no dispatch authority.

    Accepts both v1 (full action embedded in the receipt) and v2 (digest-only
    action_projection in the receipt) receipt shapes. The persisted full report
    is read once via the create-only artifact and is reconstructed exactly; the
    canonical strict equality check then verifies the caller's receipt bytes
    against the canonical reconstruction of either the v1 or v2 receipt, so no
    third-party caller can desynchronise the receipt shape or the action's
    declared digest from the artifact on disk.
    """
    from orch_dork_hostile_input import canonicalize_bounded_json

    canonicalize_bounded_json(_canonical(receipt))
    receipt_schema = receipt.get("schema") if isinstance(receipt, dict) else None
    if receipt_schema == ACTION_ADVANCE_RESULT_ARTIFACT_V2_SCHEMA:
        expected_fields = _ACTION_RESULT_ARTIFACT_V2_FIELDS
    elif receipt_schema == ACTION_ADVANCE_RESULT_ARTIFACT_SCHEMA:
        expected_fields = _ACTION_RESULT_ARTIFACT_FIELDS
    else:
        raise QualificationSuccessorError("action_result_artifact:receipt_invalid")
    if (type(receipt) is not dict or set(receipt) != expected_fields
            or not _is_sha(receipt.get("artifact_sha256"))
            or receipt.get("controller_id") != controller_id or receipt.get("root_task_id") != root_task_id):
        raise QualificationSuccessorError("action_result_artifact:receipt_invalid")
    projection = receipt.get("action_projection")
    if projection is not None:
        if (not isinstance(projection, Mapping)
                or set(projection) != {"action_sha256"}
                or not _is_sha(projection.get("action_sha256"))):
            raise QualificationSuccessorError("action_result_artifact:action_projection_invalid")
    with _action_result_directory(evidence_root, create=False) as (directory, descriptor):
        expected = directory / (receipt["artifact_sha256"] + ".json")
        if receipt.get("path") != str(expected):
            raise QualificationSuccessorError("action_result_artifact:path_invalid")
        payload = _read_action_result_bytes(descriptor, expected.name)
    if hashlib.sha256(payload).hexdigest() != receipt["artifact_sha256"]:
        raise QualificationSuccessorError("action_result_artifact:digest_mismatch")
    value = QualificationSuccessorActionAdvanceArtifact.from_report(json.loads(payload)).report
    persisted_action = value.get("action")
    if receipt_schema == ACTION_ADVANCE_RESULT_ARTIFACT_V2_SCHEMA:
        if projection is None:
            if persisted_action is not None:
                raise QualificationSuccessorError("action_result_artifact:content_mismatch")
        else:
            if (not isinstance(persisted_action, Mapping)
                    or persisted_action.get("action_sha256") != projection["action_sha256"]):
                raise QualificationSuccessorError("action_result_artifact:content_mismatch")
        reconstructed = _action_result_artifact_v2_receipt(value, expected, payload)
    else:
        reconstructed = _action_result_artifact_v1_receipt(value, expected, payload)
    if (value["schema"] != ACTION_ADVANCE_REPORT_SCHEMA
            or _canonical(value) + b"\n" != payload or value["source_roots"]["evidence"] != str(directory.parent)
            or _canonical(receipt) != _canonical(reconstructed)):
        raise QualificationSuccessorError("action_result_artifact:content_mismatch")
    return value


def resolve_issue94_action_advance_mcp_result(
    receipt: Any, *, pre_turn_report_path: str | Path, expected_report_sha256: str, current_task_id: str,
) -> dict[str, Any]:
    """Resolve an MCP receipt using the pre-turn artifact's exact owner/root map."""
    path = Path(pre_turn_report_path)
    artifact = read_issue94_successor_pre_turn_artifact(path, expected_report_sha256=expected_report_sha256)
    if artifact.root_task_id != current_task_id or artifact.root_session_id != current_task_id:
        raise QualificationSuccessorError("action_result_artifact:task_identity_mismatch")
    preparation = _read_successor_first_action_preparation(artifact, path)
    value = read_issue94_action_advance_result(receipt, evidence_root=preparation.source_roots["evidence"],
        controller_id=artifact.controller_id, root_task_id=current_task_id)
    if value["pre_turn_report_sha256"] != artifact.report_sha256 or value["source_roots"] != preparation.source_roots:
        raise QualificationSuccessorError("action_result_artifact:pre_turn_mismatch")
    return value


def run_issue94_successor_pre_turn(
    *,
    case_id: str,
    plugin_root: str | Path,
    opencodex_root: str | Path,
    source_root: str | Path,
    evidence_root: str | Path,
    enrollment_registry_root: str | Path,
    root_task_id: str,
    root_model: str,
    controller_id: str,
    now: datetime | None = None,
    rehearsal_runner: Callable[..., Mapping[str, Any]] | None = None,
    readiness_runner: Callable[..., Any] | None = None,
    canary_post_once_factory: Callable[
        [rehearsal.QualificationArtifact], Callable[..., Mapping[str, Any]]
    ]
    | None = None,
    token_factory: Callable[[], str] | None = None,
    env: MutableMapping[str, str] | Mapping[str, str] | None = None,
    require_projected_runtime: bool = True,
    checkpoint_lifecycle: bool = False,
    controller_runtime_plugin_root: str | Path | None = None,
    pre_native_failure_report_path: str | Path | None = None,
    expected_pre_native_failure_artifact_sha256: str | None = None,
    predecessor_authority_path: str | Path | None = None,
    expected_predecessor_authority_artifact_sha256: str | None = None,
    historical_runtime_plugin_root: str | Path | None = None,
    expected_historical_package_digest: str | None = None,
) -> dict[str, Any]:
    """Reach one successor's capacity-admission boundary before its turn."""

    if type(checkpoint_lifecycle) is not bool:
        raise QualificationSuccessorError("successor_pre_turn:checkpoint_profile_invalid")
    if not all(_text(value) for value in (case_id, root_task_id, root_model, controller_id)):
        raise QualificationSuccessorError("successor_pre_turn:identity_invalid")
    plugin = _runtime_root(plugin_root, label="successor_pre_turn:plugin_root")
    controller_plugin = _runtime_root(
        controller_runtime_plugin_root
        if controller_runtime_plugin_root is not None
        else plugin,
        label="successor_pre_turn:controller_plugin_root",
    )
    opencodex = _runtime_root(
        opencodex_root,
        label="successor_pre_turn:opencodex_root",
    )
    source = _runtime_root(
        source_root,
        label="successor_pre_turn:source_root",
    )
    evidence = bootstrap._owned_evidence_root(evidence_root)
    registry = _runtime_root(
        enrollment_registry_root,
        label="successor_pre_turn:enrollment_registry_root",
    )
    plugin_data = activation._canonical_plugin_data(create=False)
    key = _session_key(root_task_id)[:24]
    paths = {
        "qualification": evidence / (key + "-qualification.json"),
        "governed_inputs": evidence / (key + "-governed-inputs.json"),
        "canary_response": evidence / (key + "-canary-response.json"),
        "canary": evidence / (key + "-canary.json"),
        "predecessor_settlement": (
            evidence / (key + "-predecessor-settlement.json")
        ),
        "pre_spawn": evidence / (key + "-pre-spawn.json"),
        "activation": evidence / (key + "-activation.json"),
        "bootstrap": evidence / (key + "-bootstrap.json"),
        "first_action_preparation": (
            evidence / (key + "-first-action-preparation.json")
        ),
        "report": evidence / (key + "-successor-pre-turn.json"),
    }
    if any(os.path.lexists(path) for path in paths.values()):
        raise QualificationSuccessorError(
            "successor_pre_turn:output_already_exists"
        )
    evaluation_time = (now or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    settlement_report = settle_issue94_terminal_predecessor_capacity(
        plugin_data=plugin_data,
        hook_definition_path=(
            controller_plugin / "hooks/project_ground_hook.py"
        ),
        source_roots={"evidence": evidence, "source": source},
        now=evaluation_time,
        pre_native_failure_report_path=pre_native_failure_report_path,
        expected_pre_native_failure_artifact_sha256=(
            expected_pre_native_failure_artifact_sha256
        ),
        predecessor_authority_path=predecessor_authority_path,
        expected_predecessor_authority_artifact_sha256=(
            expected_predecessor_authority_artifact_sha256
        ),
        historical_runtime_plugin_root=historical_runtime_plugin_root,
        expected_historical_package_digest=(
            expected_historical_package_digest
        ),
    )
    settlement = QualificationPredecessorSettlementArtifact.from_report(
        settlement_report
    )
    settlement_payload = _canonical(settlement.report) + b"\n"
    rehearsal._write_create_only(
        paths["predecessor_settlement"], settlement_payload
    )
    settlement_reference = _artifact_reference(
        paths["predecessor_settlement"], settlement.report_sha256
    )
    preactivation = observe_idle_successor_preactivation(
        plugin_data=plugin_data,
        root_task_id=root_task_id,
        root_model=root_model,
        source_root=source,
        env=env,
    )
    module_plugin_root = rehearsal._module_plugin_root()
    # The owner request's reviewer, sealed into the host environment, routes
    # the plan's standards lane to its onboarded profile (Issue 203).
    try:
        reviewer_route = worker_default.configured_reviewer_route(env)
    except ValueError as error:
        raise QualificationSuccessorError("successor_pre_turn:reviewer_route_incomplete") from error
    if require_projected_runtime and plugin != module_plugin_root:
        if rehearsal_runner is not None:
            raise QualificationSuccessorError(
                "successor_pre_turn:projected_runner_injection_forbidden"
            )
        command = [
            sys.executable,
            "-B",
            str(
                plugin
                / "skills/orch-dork/scripts/"
                "orch_dork_qualification_rehearsal.py"
            ),
            "--case",
            case_id,
            "--plugin-root",
            str(plugin),
            "--opencodex-root",
            str(opencodex),
            "--evidence-root",
            str(evidence),
            "--output",
            str(paths["qualification"]),
            "--worker-model",
            worker_default.configured_worker_model(env),
            "--worker-effort",
            worker_default.configured_worker_effort(env),
            "--root-model",
            root_model,
            *(
                ["--reviewer-model", reviewer_route[0], "--reviewer-effort", reviewer_route[1]]
                if reviewer_route is not None
                else []
            ),
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=plugin,
                env={
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": os.environ.get("PATH", os.defpath),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    # The projected rehearsal reads the same onboarded
                    # profiles the owner admitted.
                    **{
                        name: os.environ[name]
                        for name in (rehearsal.model_profiles.onboarded_profiles.STORE_ENV,)
                        if os.environ.get(name)
                    },
                },
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            qualification_receipt = json.loads(completed.stdout)
        except (
            OSError,
            subprocess.TimeoutExpired,
            UnicodeError,
            json.JSONDecodeError,
        ) as error:
            raise QualificationSuccessorError(
                "successor_pre_turn:projected_rehearsal_unavailable"
            ) from error
        if (
            completed.returncode != 0
            or completed.stderr
            or len(completed.stdout.encode("utf-8")) > 65_536
            or not isinstance(qualification_receipt, Mapping)
            or qualification_receipt.get("status") != "PASS"
            or qualification_receipt.get("runtime_projected") is not True
        ):
            raise QualificationSuccessorError(
                "successor_pre_turn:projected_rehearsal_refused"
            )
        qualification = rehearsal.read_qualification_artifact(
            paths["qualification"]
        )
    else:
        try:
            qualification_report = rehearsal.rehearse_replay_case(
                case_id,
                transport_qualification.TransportRuntime(plugin, opencodex),
                evidence_root=evidence,
                runner=rehearsal_runner,
                require_projected=require_projected_runtime,
                worker_model=worker_default.configured_worker_model(env),
                worker_effort=worker_default.configured_worker_effort(env),
                root_model=root_model,
                reviewer_model=reviewer_route[0] if reviewer_route is not None else None,
                reviewer_effort=reviewer_route[1] if reviewer_route is not None else None,
            )
            qualification = rehearsal.QualificationArtifact.from_report(
                qualification_report
            )
            qualification_receipt = rehearsal.persist_qualification_artifact(
                qualification.report,
                paths["qualification"],
            )
        except rehearsal.QualificationRehearsalError as error:
            # Preserve the exact provider-free replay refusal at the owner
            # boundary.  Without this translation an unsupported case is
            # flattened to the generic owner_session_failed terminal code.
            raise QualificationSuccessorError(str(error)) from error
    inputs_report = governed_inputs.build_issue94_governed_inputs_report(
        qualification,
        source,
    )
    inputs = governed_inputs.Issue94GovernedInputsArtifact.from_report(
        inputs_report,
        source,
    )
    planner = inputs.logical_plan.get("planner")
    if (
        not isinstance(planner, Mapping)
        or planner.get("model") != root_model
    ):
        raise QualificationSuccessorError(
            "successor_pre_turn:root_model_mismatch"
        )
    inputs_receipt = governed_inputs.persist_issue94_governed_inputs_artifact(
        inputs.report,
        paths["governed_inputs"],
        source,
    )
    approval = rehearsal.ApprovalPreflightReport.from_report(
        qualification.approval_preflight_report
    )
    post_once = (
        canary_post_once_factory(qualification)
        if canary_post_once_factory is not None
        else None
    )
    canary_report = route_canary.invoke_route_canary_from_artifact(
        qualification,
        opencodex_root=opencodex,
        evidence_root=evidence,
        response_path=paths["canary_response"],
        authorization_report_sha256=approval.digest,
        readiness_runner=readiness_runner,
        post_once=post_once,
        token_factory=token_factory,
    )
    canary = route_canary.RouteCanaryArtifact.from_report(canary_report)
    canary_receipt = route_canary.persist_route_canary_artifact(
        canary.report,
        paths["canary"],
    )
    try:
        bootstrap_receipt = bootstrap.materialize_issue94_controller_bootstrap(
            paths["qualification"],
            paths["governed_inputs"],
            paths["canary"],
            source,
            evidence_root=evidence,
            enrollment_registry_root=registry,
            root_task_id=root_task_id,
            controller_id=controller_id,
            pre_spawn_output_path=paths["pre_spawn"],
            activation_output_path=paths["activation"],
            output_path=paths["bootstrap"],
            now=evaluation_time,
            runtime_plugin_root=controller_plugin,
            pre_turn=True,
            checkpoint_lifecycle=checkpoint_lifecycle,
        )
    except (
        bootstrap.pre_spawn.QualificationPreSpawnError,
        activation.QualificationActivationError,
        bootstrap.QualificationBootstrapError,
    ) as error:
        # Keep the exact closed refusal code visible at the Issue 170 owner
        # boundary.  Letting these nested domain errors escape turns a precise
        # pre-turn failure into a generic owner-session terminal.
        raise QualificationSuccessorError(str(error)) from error
    bootstrapped = bootstrap.read_issue94_controller_bootstrap_artifact(
        paths["bootstrap"],
        source,
        evidence,
        registry,
    )
    expected_profile = (
        bootstrap.pre_spawn.CHECKPOINT_REPORT_SCHEMA
        if checkpoint_lifecycle
        else bootstrap.pre_spawn.REPORT_SCHEMA
    )
    if bootstrapped.pre_spawn_artifact.report["schema"] != expected_profile:
        raise QualificationSuccessorError("successor_pre_turn:checkpoint_profile_mismatch")
    identity = bootstrapped.activation_handoff_artifact.activation_preparation_report[
        "prepared_activation_payload"
    ]["identity"]
    if (
        identity.get("root_thread_id") != root_task_id
        or identity.get("root_session_id") != root_task_id
        or identity.get("root_model") != root_model
        or bootstrapped.pre_spawn_stage_report.get("next_stage_action")
        != "capacity_admission"
        or bootstrapped.pre_spawn_stage_report.get("action") is not None
    ):
        raise QualificationSuccessorError(
            "successor_pre_turn:controller_identity_invalid"
        )
    grants = native_grant_store.NativeGrantStore(
        native_grant_store.canonical_database_path(plugin_data)
    )
    authority = grants.canonical_authority()
    authority_identity = (
        authority.get("identity") if isinstance(authority, Mapping) else None
    )
    lifecycle = (
        authority.get("lifecycle") if isinstance(authority, Mapping) else None
    )
    if (
        authority.get("status") != "VERIFIED"
        or not isinstance(authority_identity, Mapping)
        or authority_identity.get("controller_id") != controller_id
        or authority_identity.get("root_thread_id") != root_task_id
        or authority_identity.get("root_session_id") != root_task_id
        or authority_identity.get("root_model") != root_model
        or not isinstance(lifecycle, Mapping)
        or lifecycle.get("expected_binding_status") != "WAITING"
        or lifecycle.get("terminal") is not False
        or lifecycle.get("pending_intent") is not False
        or lifecycle.get("action_sha256") is not None
    ):
        raise QualificationSuccessorError(
            "successor_pre_turn:controller_not_ready"
        )
    preparation_report = (
        build_issue94_successor_first_action_preparation(bootstrapped)
    )
    preparation = (
        QualificationSuccessorFirstActionPreparationArtifact.from_report(
            preparation_report
        )
    )
    preparation_payload = _canonical(preparation.report) + b"\n"
    rehearsal._write_create_only(
        paths["first_action_preparation"], preparation_payload
    )
    preparation_reference = _artifact_reference(
        paths["first_action_preparation"], preparation.report_sha256
    )
    provider_free = canary_post_once_factory is not None
    artifacts = {
        "qualification": _artifact_reference(
            paths["qualification"], qualification.report_sha256
        ),
        "governed_inputs": _artifact_reference(
            paths["governed_inputs"], inputs.report_sha256
        ),
        "canary": _artifact_reference(paths["canary"], canary.report_sha256),
        "predecessor_settlement": settlement_reference,
        "bootstrap": _artifact_reference(
            paths["bootstrap"], bootstrapped.report_sha256
        ),
        "first_action_preparation": preparation_reference,
    }
    core = {
        "schema": REPORT_SCHEMA,
        "status": "PASS",
        "decision": DECISION_READY,
        "issues": [],
        "case_id": case_id,
        "evaluation_time": evaluation_time.isoformat(),
        "preactivation_report": preactivation,
        "predecessor_settlement_report": settlement.report,
        "artifacts": artifacts,
        "artifact_receipts": {
            "qualification": qualification_receipt,
            "governed_inputs": inputs_receipt,
            "canary": canary_receipt,
            "predecessor_settlement": settlement_reference,
            "bootstrap": bootstrap_receipt,
            "first_action_preparation": preparation_reference,
        },
        "controller": {
            "controller_id": controller_id,
            "root_thread_id": root_task_id,
            "root_session_id": root_task_id,
            "root_model": root_model,
            "expected_binding_status": "WAITING",
            "next_stage_action": "capacity_admission",
            "authority_sha256": _sha(authority),
        },
        "boundary": {
            "turn_started": False,
            "next_owner_action": "turn/start",
            "required_hook_event": "SessionStart",
            "live_boundary_crossed": not provider_free,
            "native_action_authorized": False,
            "worker_created": False,
        },
        "provider_free": provider_free,
        "counters": {
            "controller_activations": 1,
            "controller_stages": 1,
            "native_actions": 0,
            "predecessor_capacity_settlements": (
                1 if settlement.decision == "SETTLED" else 0
            ),
            "pre_native_failure_terminalizations": (
                1 if settlement.decision == "TERMINALIZED" else 0
            ),
            "task_creations": 0,
            "worker_creations": 0,
        },
    }
    report = {**core, "report_sha256": _sha(core)}
    owned_report = QualificationSuccessorArtifact.from_report(report)
    payload = _canonical(report) + b"\n"
    if len(payload) > MAX_REPORT_BYTES:
        raise QualificationSuccessorError("successor_pre_turn:report_too_large")
    rehearsal._write_create_only(paths["report"], payload)
    persisted = owned_file.read_owned_json(
        paths["report"],
        max_bytes=MAX_REPORT_BYTES,
        required_mode=0o600,
    )
    persisted_artifact = QualificationSuccessorArtifact.from_report(
        persisted
    )
    if persisted_artifact.report != owned_report.report:
        raise QualificationSuccessorError(
            "successor_pre_turn:report_readback_mismatch"
        )
    return report


def run_issue94_successor_pre_turn_with_owner_handoff(
    *,
    case_id: str,
    plugin_root: str | Path,
    opencodex_root: str | Path,
    source_root: str | Path,
    evidence_root: str | Path,
    enrollment_registry_root: str | Path,
    root_task_id: str,
    root_model: str,
    controller_id: str,
    controller_runtime_plugin_root: str | Path | None = None,
) -> Issue94SuccessorOwnerHandoff:
    """Run pre-turn once and retain its exact source-owned continuation.

    This is the production owner seam.  It intentionally exposes no runner,
    route-canary, clock, token, or environment injection.  The ordinary
    pre-turn producer still owns every artifact; this wrapper only retains the
    already-created report path and opens the same canonical controller that
    the MCP action readers use.
    """

    report = run_issue94_successor_pre_turn(
        case_id=case_id,
        plugin_root=plugin_root,
        opencodex_root=opencodex_root,
        source_root=source_root,
        evidence_root=evidence_root,
        enrollment_registry_root=enrollment_registry_root,
        root_task_id=root_task_id,
        root_model=root_model,
        controller_id=controller_id,
        controller_runtime_plugin_root=controller_runtime_plugin_root,
    )
    return open_issue94_successor_owner_handoff(
        pre_turn_report=report,
        plugin_root=plugin_root,
        source_root=source_root,
        evidence_root=evidence_root,
        enrollment_registry_root=enrollment_registry_root,
        root_task_id=root_task_id,
        root_model=root_model,
        controller_id=controller_id,
        controller_runtime_plugin_root=controller_runtime_plugin_root,
    )


def open_issue94_successor_owner_handoff(
    *,
    pre_turn_report: Any,
    plugin_root: str | Path,
    source_root: str | Path,
    evidence_root: str | Path,
    enrollment_registry_root: str | Path,
    root_task_id: str,
    root_model: str,
    controller_id: str,
    controller_runtime_plugin_root: str | Path | None = None,
) -> Issue94SuccessorOwnerHandoff:
    """Retain the continuation for one already-produced exact pre-turn report."""

    if not isinstance(pre_turn_report, Mapping):
        raise QualificationSuccessorError(
            "successor_owner_handoff:pre_turn_report_invalid"
        )
    report = deepcopy(dict(pre_turn_report))
    evidence = bootstrap._owned_evidence_root(evidence_root)
    report_path = evidence / (
        _session_key(root_task_id)[:24] + "-successor-pre-turn.json"
    )
    persisted = read_issue94_successor_pre_turn_artifact(
        report_path, expected_report_sha256=str(report.get("report_sha256"))
    )
    if persisted.report != report:
        raise QualificationSuccessorError(
            "successor_owner_handoff:pre_turn_report_mismatch"
        )
    controller_plugin = _runtime_root(
        controller_runtime_plugin_root
        if controller_runtime_plugin_root is not None
        else plugin_root,
        label="successor_owner_handoff:controller_plugin_root",
    )
    hook_definition = controller_plugin / "hooks/project_ground_hook.py"
    plugin_data = activation._canonical_plugin_data(create=False)
    context = _successor_action_controller(
        pre_turn_report_path=report_path,
        expected_report_sha256=persisted.report_sha256,
        plugin_data=plugin_data,
        hook_definition_path=hook_definition,
        current_task_id=root_task_id,
    )
    entered = False
    try:
        (context_artifact, preparation, controller, authority, owner,
         _state, _cursor) = context.__enter__()
        entered = True
        bootstrap_report = _read_successor_bootstrap_report(
            context_artifact, report_path
        )
        bootstrapped = bootstrap.Issue94ControllerBootstrapArtifact.from_report(
            bootstrap_report,
            Path(source_root).resolve(strict=True),
            evidence,
            Path(enrollment_registry_root).resolve(strict=True),
        )
        authority_identity = authority.get("identity")
        activation_identity = (
            bootstrapped.activation_handoff_artifact
            .activation_preparation_report["prepared_activation_payload"]["identity"]
        )
        if (
            context_artifact.report != persisted.report
            or preparation.controller_id != controller_id
            or not isinstance(authority_identity, Mapping)
            or authority_identity.get("root_thread_id") != root_task_id
            or authority_identity.get("root_session_id") != root_task_id
            or authority_identity.get("root_model") != root_model
            or owner.get("controller_id") != controller_id
            or activation_identity.get("root_thread_id") != root_task_id
            or activation_identity.get("root_session_id") != root_task_id
            or activation_identity.get("root_model") != root_model
        ):
            raise QualificationSuccessorError(
                "successor_owner_handoff:controller_binding_invalid"
            )
        value = Issue94SuccessorOwnerHandoff(
            _OWNER_HANDOFF_AUTHORITY,
            pre_turn_report=persisted.report,
            pre_turn_report_path=str(report_path),
            pre_turn_report_sha256=persisted.report_sha256,
            controller=controller,
            identity={
                "controller_id": controller_id,
                "root_task_id": root_task_id,
                "root_session_id": root_task_id,
                "root_model": root_model,
            },
            pre_spawn_program=bootstrapped.pre_spawn_artifact.pre_spawn_program,
            context=context,
        )
        return _issue_owner_handoff(value)
    except BaseException:
        if entered:
            context.__exit__(*sys.exc_info())
        raise


def validate_issue94_successor_owner_handoff(value: Any) -> dict[str, Any]:
    """Re-read one live handoff without granting serializable authority."""

    try:
        handoff = _require_issue94_successor_owner_handoff(value)
        artifact = read_issue94_successor_pre_turn_artifact(
            handoff.pre_turn_report_path,
            expected_report_sha256=handoff.pre_turn_report_sha256,
        )
        authority = handoff.controller.grants.canonical_authority()
        owner = authority.get("owner") if isinstance(authority, Mapping) else None
        identity = authority.get("identity") if isinstance(authority, Mapping) else None
        expected = handoff._identity
        if (
            artifact.report != handoff._pre_turn_report
            or not isinstance(owner, Mapping)
            or owner.get("controller_id") != expected["controller_id"]
            or not isinstance(identity, Mapping)
            or identity.get("root_thread_id") != expected["root_task_id"]
            or identity.get("root_session_id") != expected["root_session_id"]
            or identity.get("root_model") != expected["root_model"]
        ):
            raise QualificationSuccessorError(
                "successor_owner_handoff:live_binding_invalid"
            )
    except (QualificationSuccessorError, KeyError, TypeError, ValueError, OSError):
        return {
            "valid": False,
            "issues": ["successor_owner_handoff:invalid"],
        }
    return {
        "valid": True,
        "issues": [],
        "pre_turn_report_path": handoff.pre_turn_report_path,
        "pre_turn_report_sha256": handoff.pre_turn_report_sha256,
        "controller_id": handoff._identity["controller_id"],
        "root_task_id": handoff._identity["root_task_id"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--plugin-root", type=Path, required=True)
    parser.add_argument("--opencodex-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--enrollment-registry-root", type=Path, required=True)
    parser.add_argument("--root-task-id", required=True)
    parser.add_argument("--root-model", required=True)
    parser.add_argument("--controller-id", required=True)
    parser.add_argument("--checkpoint-lifecycle", action="store_true")
    parser.add_argument("--pre-native-failure-report", type=Path)
    parser.add_argument("--pre-native-failure-artifact-sha256")
    parser.add_argument("--predecessor-authority-report", type=Path)
    parser.add_argument("--predecessor-authority-artifact-sha256")
    parser.add_argument("--historical-runtime-plugin-root", type=Path)
    parser.add_argument("--historical-runtime-package-digest")
    args = parser.parse_args(argv)
    try:
        report = run_issue94_successor_pre_turn(
            case_id=args.case_id,
            plugin_root=args.plugin_root,
            opencodex_root=args.opencodex_root,
            source_root=args.source_root,
            evidence_root=args.evidence_root,
            enrollment_registry_root=args.enrollment_registry_root,
            root_task_id=args.root_task_id,
            root_model=args.root_model,
            controller_id=args.controller_id,
            checkpoint_lifecycle=args.checkpoint_lifecycle,
            pre_native_failure_report_path=(
                args.pre_native_failure_report
            ),
            expected_pre_native_failure_artifact_sha256=(
                args.pre_native_failure_artifact_sha256
            ),
            predecessor_authority_path=(
                args.predecessor_authority_report
            ),
            expected_predecessor_authority_artifact_sha256=(
                args.predecessor_authority_artifact_sha256
            ),
            historical_runtime_plugin_root=(
                args.historical_runtime_plugin_root
            ),
            expected_historical_package_digest=(
                args.historical_runtime_package_digest
            ),
        )
    except Exception as error:
        issue = (
            str(error)
            if isinstance(error, (OSError, TypeError, ValueError))
            else "unexpected_failure:" + type(error).__name__
        )
        print(
            json.dumps(
                {
                    "schema": REPORT_SCHEMA,
                    "status": "FAIL",
                    "decision": "REFUSED",
                    "issues": [issue],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0

OBSERVED_SPAWN_STALL_SETTLEMENT_REPORT_SCHEMA = (
    "orch-dork/qualification-observed-spawn-stall-settlement/v1"
)
# The exact whole-report shape settle_observed_spawn_stall_capacity emits.
# lifecycle_conformance.action_host._PREDECESSOR_SETTLEMENT_FIELDS holds the
# same set for the Stage L acceptor; a test keeps the two copies equal.
_OBSERVED_SPAWN_STALL_SETTLEMENT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "issues",
        "evaluation_time",
        "predecessor",
        "closure_report",
        "capacity_admission_report",
        "settlement_program",
        "settlement_report",
        "capacity_authority_before",
        "capacity_authority_after",
        "released_authority_lane_ids",
        "released_logical_lane_ids",
        "started_logical_lane_id",
        "never_started_logical_lane_ids",
        "boundary",
        "provider_free",
        "counters",
        "report_sha256",
    }
)
_OBSERVED_SPAWN_STALL_SETTLEMENT_BOUNDARY = {
    "native_action_called": False,
    "next_transition": "successor_activation",
    "provider_boundary_crossed": False,
    "successor_activation_started": False,
    "task_created": False,
    "worker_created": False,
}


def _observed_spawn_stall_closure_valid(closure: Any) -> bool:
    """Check the closed terminal shape without granting settlement authority."""
    if not isinstance(closure, Mapping):
        return False
    receipt = closure.get("receipt")
    if not isinstance(receipt, Mapping):
        return False
    cut = native_grant_store.owner_closed_ack_cut_for_failure(receipt.get("failure_cut"))
    worker_terminal_observed = cut.worker_terminal_observed if cut else False
    return bool(
        closure.get("schema") == native_controller.OBSERVED_SPAWN_STALL_STAGE_REPORT_SCHEMA
        and closure.get("operation") == "observed_spawn_stall_terminalization"
        and closure.get("status") == "PASS"
        and closure.get("disposition") == "OBSERVED_SPAWN_STALL_TERMINALIZED"
        and closure.get("issues") == []
        and closure.get("next_action") == "terminal_capacity_settlement"
        and receipt.get("worker_terminal_receipt_observed") is worker_terminal_observed
        and receipt.get("worker_process_match_count") == 0
        and receipt.get("owner_process_match_count") == 0
        and receipt.get("owner_process_group_cleaned") is True
    )


@dataclass(frozen=True, slots=True)
class QualificationObservedSpawnStallSettlementArtifact:
    """Strict whole-report handoff for an observed-spawn-stall settlement.

    The settler emits the report, the recovery driver persists it and the
    Stage L gate binds the successor to it, so every consumer re-derives the
    same facts from the whole report: which predecessor it closes, which
    lanes the closing receipt named as started or never started, that the
    shared capacity authority released exactly those lanes, and that no
    provider, task or worker boundary was crossed.
    """

    report: dict[str, Any]
    report_sha256: str
    predecessor_controller_id: str
    released_authority_lane_ids: list[str]
    released_logical_lane_ids: list[str]
    started_logical_lane_id: str
    never_started_logical_lane_ids: list[str]

    @classmethod
    def from_report(
        cls, report: Any
    ) -> "QualificationObservedSpawnStallSettlementArtifact":
        if (
            not isinstance(report, Mapping)
            or set(report) != _OBSERVED_SPAWN_STALL_SETTLEMENT_FIELDS
        ):
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:report_shape_invalid"
            )
        value = deepcopy(dict(report))
        predecessor = value.get("predecessor")
        closure = value.get("closure_report")
        receipt = (
            closure.get("receipt")
            if isinstance(closure, Mapping)
            and isinstance(closure.get("receipt"), Mapping)
            else None
        )
        admission = value.get("capacity_admission_report")
        admission_bindings = (
            admission.get("receipt", {}).get("bindings")
            if isinstance(admission, Mapping)
            and isinstance(admission.get("receipt"), Mapping)
            else None
        )
        program = value.get("settlement_program")
        settled = value.get("settlement_report")
        settled_bindings = (
            settled.get("receipt", {}).get("bindings")
            if isinstance(settled, Mapping)
            and isinstance(settled.get("receipt"), Mapping)
            else None
        )
        before = value.get("capacity_authority_before")
        after = value.get("capacity_authority_after")
        before_active = _capacity_active_lane_ids(before)
        after_active = _capacity_active_lane_ids(after)
        released_authority = value.get("released_authority_lane_ids")
        released_logical = value.get("released_logical_lane_ids")
        started = value.get("started_logical_lane_id")
        never_started = value.get("never_started_logical_lane_ids")
        created_lanes = receipt.get("created_lanes") if receipt else None
        created_lane_ids = (
            [row["lane_id"] for row in created_lanes]
            if isinstance(created_lanes, list)
            and created_lanes
            and all(
                isinstance(row, Mapping)
                and set(row) == {"lane_id", "agent_id"}
                and _text(row.get("lane_id"))
                and _text(row.get("agent_id"))
                for row in created_lanes
            )
            else None
        )
        run_id = predecessor.get("run_id") if isinstance(predecessor, Mapping) else None
        lanes_valid = bool(
            created_lane_ids is not None
            and _text(started)
            and started in created_lane_ids
            and isinstance(never_started, list)
            and all(_text(lane) for lane in never_started)
            and receipt.get("created_logical_lane_id") == started
            and receipt.get("never_started_logical_lane_ids") == never_started
            and released_logical == created_lane_ids + never_started
            and len(set(released_logical)) == len(released_logical)
            and len(released_logical) >= 2
            and _text(run_id)
            and released_authority
            == sorted(str(run_id) + ":" + lane for lane in released_logical)
            and before_active == released_authority
            and after_active == []
        )
        expected_counters = dict(_SETTLEMENT_ZERO_COUNTERS)
        if isinstance(released_authority, list):
            expected_counters.update(
                {
                    "capacity_lanes_released": len(released_authority),
                    "cleanup_observer_receipts_issued": len(released_authority),
                    "host_seed_credential_reads": 1,
                }
            )
        if (
            value.get("schema") != OBSERVED_SPAWN_STALL_SETTLEMENT_REPORT_SCHEMA
            or value.get("status") != "PASS"
            or value.get("decision") != "SETTLED"
            or value.get("issues") != []
            or not _text(value.get("evaluation_time"))
            or not isinstance(predecessor, Mapping)
            or set(predecessor)
            != {
                "controller_id",
                "controller_run_id",
                "root_task_id",
                "attempt_id",
                "run_id",
                "binding_sha256",
                "authority_sha256",
            }
            or not all(
                _text(predecessor.get(field))
                for field in (
                    "controller_id",
                    "controller_run_id",
                    "root_task_id",
                    "attempt_id",
                    "run_id",
                )
            )
            or not _is_sha(predecessor.get("binding_sha256"))
            or not _is_sha(predecessor.get("authority_sha256"))
            or not _observed_spawn_stall_closure_valid(closure)
            or not lanes_valid
            or not isinstance(admission, Mapping)
            or admission.get("schema") != governed_attempt.REPORT_SCHEMA
            or admission.get("status") != "PASS"
            or admission.get("operation") != "capacity_admission"
            or admission.get("disposition") != "SPAWN_AUTHORIZED"
            or admission.get("issues") != []
            or not isinstance(admission_bindings, Mapping)
            or sorted(admission_bindings.get("current_wave_logical_lane_ids") or [])
            != sorted(released_logical)
            or sorted(admission_bindings.get("capacity_authority_lane_ids") or [])
            != released_authority
            or admission_bindings.get("capacity_authority_state_sha256")
            != before.get("state_sha256")
            or not isinstance(program, Mapping)
            or program.get("schema") != governed_attempt.PROGRAM_SCHEMA
            or program.get("operation") != "capacity_settlement"
            or not isinstance(settled, Mapping)
            or settled.get("schema") != governed_attempt.REPORT_SCHEMA
            or settled.get("status") != "PASS"
            or settled.get("operation") != "capacity_settlement"
            or settled.get("disposition") != "CAPACITY_RELEASED"
            or settled.get("issues") != []
            or not isinstance(settled_bindings, Mapping)
            or sorted(settled_bindings.get("failed_logical_lane_ids") or [])
            != sorted(released_logical)
            or value.get("boundary") != _OBSERVED_SPAWN_STALL_SETTLEMENT_BOUNDARY
            or value.get("provider_free") is not True
            or value.get("counters") != expected_counters
            or not _sealed(value, "report_sha256")
        ):
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(value["report_sha256"]),
            predecessor_controller_id=str(predecessor["controller_id"]),
            released_authority_lane_ids=list(released_authority),
            released_logical_lane_ids=list(released_logical),
            started_logical_lane_id=str(started),
            never_started_logical_lane_ids=list(never_started),
        )


def settle_observed_spawn_stall_capacity(
    *,
    plugin_data: str | Path,
    hook_definition_path: str | Path,
    source_roots: Mapping[str, str | Path],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Release the lanes an observed-complete spawn stall left reserved.

    Runs only after the controller closed that stall terminally.  The lanes
    come from the closing receipt -- the one lane that really started plus
    the lanes named there as never started -- so nothing is inferred from a
    batch result the failure never produced.
    """

    data = _runtime_root(
        plugin_data,
        label="observed_spawn_stall_settlement:plugin_data",
    )
    hook_path = Path(hook_definition_path)
    if (
        not hook_path.is_absolute()
        or hook_path.is_symlink()
        or not hook_path.is_file()
    ):
        raise QualificationSuccessorError(
            "observed_spawn_stall_settlement:hook_definition_invalid"
        )
    if not isinstance(source_roots, Mapping) or set(source_roots) != {
        "evidence",
        "source",
    }:
        raise QualificationSuccessorError(
            "observed_spawn_stall_settlement:source_roots_invalid"
        )
    roots = {
        name: _runtime_root(
            path,
            label="observed_spawn_stall_settlement:" + name + "_root",
        )
        for name, path in source_roots.items()
    }
    evaluation_time = (now or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    try:
        controller = native_controller.GovernedNativeController(
            plugin_data=data,
            hook_definition_path=hook_path,
            source_roots=roots,
            now=evaluation_time,
        )
    except (OSError, TypeError, ValueError) as error:
        raise QualificationSuccessorError(
            "observed_spawn_stall_settlement:controller_unavailable"
        ) from error
    try:
        authority = _clean_terminal_authority(
            controller.grants.canonical_authority()
        )
        owner = authority.get("owner")
        authority_identity = authority.get("identity")
        if not isinstance(owner, Mapping) or not isinstance(
            authority_identity, Mapping
        ):
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:owner_invalid"
            )
        controller_id = owner.get("controller_id")
        controller_run_id = owner.get("controller_run_id")
        if not _text(controller_id) or not _text(controller_run_id):
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:owner_invalid"
            )
        try:
            state, rows = controller._state(str(controller_run_id))
            events = native_controller._controller_events(list(rows))
            cursor = native_controller._cursor(list(rows))
        except (KeyError, TypeError, ValueError) as error:
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:controller_stream_invalid"
            ) from error
        activation_payload = state.get("activation")
        attempt_identity = (
            activation_payload.get("identity")
            if isinstance(activation_payload, Mapping)
            else None
        )
        try:
            current = owned_file.read_owned_json(
                data / "project-ground/current.json",
                max_bytes=native_controller.MAX_RUNTIME_FILE_BYTES,
            )
        except (OSError, json.JSONDecodeError, ValueError) as error:
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:binding_unavailable"
            ) from error
        binding = (
            current.get("native_controller")
            if isinstance(current, Mapping)
            else None
        )
        binding_core = (
            {
                key: child
                for key, child in binding.items()
                if key != "binding_sha256"
            }
            if isinstance(binding, Mapping)
            else {}
        )
        closure = state.get("stage_report")
        receipt = (
            closure.get("receipt")
            if isinstance(closure, Mapping)
            and isinstance(closure.get("receipt"), Mapping)
            else None
        )
        if (
            not isinstance(attempt_identity, Mapping)
            or not isinstance(binding, Mapping)
            or not isinstance(cursor, Mapping)
            or binding.get("status") != "TERMINAL"
            or binding.get("controller_id") != controller_id
            or binding.get("controller_run_id") != controller_run_id
            or binding.get("controller_seq") != cursor.get("seq")
            or binding.get("controller_event_hash")
            != cursor.get("event_hash")
            or binding.get("action") is not None
            or binding.get("binding_sha256") != _sha(binding_core)
            or state.get("terminal") is not True
            or state.get("pending_intent") is not None
            or state.get("action") is not None
            or state.get("cleanup_required") is not False
            or authority_identity.get("controller_id") != controller_id
            or authority_identity.get("controller_run_id")
            != controller_run_id
            or authority_identity.get("root_thread_id")
            != attempt_identity.get("root_thread_id")
            or authority_identity.get("root_session_id")
            != attempt_identity.get("root_session_id")
        ):
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:terminal_binding_invalid"
            )
        if not _observed_spawn_stall_closure_valid(closure):
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:closure_invalid"
            )
        started = receipt.get("created_logical_lane_id")
        never_started = receipt.get("never_started_logical_lane_ids")
        created_lanes = receipt.get("created_lanes")
        created_lane_ids = (
            [row.get("lane_id") for row in created_lanes]
            if isinstance(created_lanes, list)
            and created_lanes
            and all(
                isinstance(row, Mapping)
                and set(row) == {"lane_id", "agent_id"}
                and _text(row.get("lane_id"))
                and _text(row.get("agent_id"))
                for row in created_lanes
            )
            else None
        )
        if (
            not _text(started)
            or created_lane_ids is None
            or started not in created_lane_ids
            or not isinstance(never_started, list)
            or not all(_text(lane) for lane in never_started)
            or any(lane in never_started for lane in created_lane_ids)
            or len(set(created_lane_ids) | set(never_started))
            != len(created_lane_ids) + len(never_started)
            or len(created_lane_ids) + len(never_started) < 2
        ):
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:lane_receipt_invalid"
            )
        logical_lane_ids = [str(lane) for lane in created_lane_ids] + [
            str(lane) for lane in never_started
        ]
        try:
            before = controller.tower.read_shared_capacity_authority()
        except (OSError, TypeError, ValueError) as error:
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:capacity_authority_unverified"
            ) from error
        active = _capacity_active_lane_ids(before)
        if active is None:
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:capacity_authority_unverified"
            )
        governed_identity = {
            "run_id": attempt_identity.get("run_id"),
            "attempt_id": attempt_identity.get("attempt_id"),
            "root_task_id": attempt_identity.get("root_thread_id"),
            "root_model": attempt_identity.get("root_model"),
            "root_effort": attempt_identity.get("root_effort"),
            "source_version": attempt_identity.get("source_version"),
            "installed_version": attempt_identity.get(
                "installed_plugin_version"
            ),
            "task_loaded_version": attempt_identity.get(
                "task_loaded_version"
            ),
            "fresh_task": attempt_identity.get("fresh_task"),
        }
        expected_authority_lanes = sorted(
            str(governed_identity["run_id"]) + ":" + lane
            for lane in logical_lane_ids
        )
        if sorted(active) != expected_authority_lanes:
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:lane_binding_mismatch"
            )
        stage_reports = [
            deepcopy(dict(event["payload"]["stage_report"]))
            for event in events
            if event.get("event_type") == "stage_result"
            and isinstance(event.get("payload"), Mapping)
            and isinstance(event["payload"].get("stage_report"), Mapping)
        ]
        capacity_reports = [
            report
            for report in stage_reports
            if report.get("operation") == "capacity_admission"
            and report.get("status") == "PASS"
            and report.get("disposition") == "SPAWN_AUTHORIZED"
        ]
        if len(capacity_reports) != 1:
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:admission_report_invalid"
            )
        admission_report = capacity_reports[0]
        admission_receipt = admission_report.get("receipt")
        bindings = (
            admission_receipt.get("bindings")
            if isinstance(admission_receipt, Mapping)
            and isinstance(admission_receipt.get("bindings"), Mapping)
            else None
        )
        if (
            not isinstance(bindings, Mapping)
            or sorted(bindings.get("current_wave_logical_lane_ids") or [])
            != sorted(logical_lane_ids)
            or sorted(bindings.get("capacity_authority_lane_ids") or [])
            != expected_authority_lanes
            or bindings.get("capacity_authority_state_sha256")
            != before.get("state_sha256")
        ):
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:admission_binding_mismatch"
            )
        try:
            _host_identity, signer, _trust = activation._authority()
        except (OSError, TypeError, ValueError) as error:
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:signing_authority_unavailable"
            ) from error
        credential_reads = 1
        release_receipts: list[dict[str, Any]] = []
        cleanup_status = (
            "not_required"
            if receipt["owner_process_group_cleaned"]
            and receipt["worker_process_match_count"] == 0
            and receipt["owner_process_match_count"] == 0
            else "unknown"
        )
        owned_descendants = (
            receipt["worker_process_match_count"]
            + receipt["owner_process_match_count"]
        )
        try:
            for lane_id in active:
                payload = shared_capacity.cleanup_observer_payload(
                    lane_id=lane_id,
                    run_id=str(governed_identity["run_id"]),
                    route="native_luna",
                    terminal_state="failed",
                    cleanup_status=cleanup_status,
                    owned_descendants=owned_descendants,
                    terminal_evidence_sha256=str(
                        binding["binding_sha256"]
                    ),
                )
                signed = signer.issue(
                    "lane-cleanup-observation",
                    payload,
                    issued_at=(
                        evaluation_time - timedelta(seconds=1)
                    ).isoformat(),
                    valid_until=(
                        evaluation_time + timedelta(minutes=4)
                    ).isoformat(),
                    nonce=(
                        "issue170-observed-spawn-stall-"
                        + _sha(payload)[:24]
                    ),
                )
                release_receipt = shared_capacity.release(
                    {
                        "lane_id": lane_id,
                        "run_id": governed_identity["run_id"],
                        "route": "native_luna",
                        "state": "failed",
                        "cleanup_status": cleanup_status,
                        "terminal_evidence_sha256": binding[
                            "binding_sha256"
                        ],
                        "cleanup_evidence_sha256": _sha(signed),
                        "cleanup_observer_receipt": signed,
                    },
                    owned_descendants,
                )
                if (
                    release_receipt.get("status") != "RELEASED"
                    or release_receipt.get("released") is not True
                ):
                    raise QualificationSuccessorError(
                        "observed_spawn_stall_settlement:release_receipt_invalid"
                    )
                release_receipts.append(release_receipt)
            settlement_program = (
                governed_attempt.build_capacity_settlement_program(
                    governed_identity,
                    admission_report,
                    release_receipts,
                )
            )
            evaluated = governed_attempt.evaluate_governed_attempt(
                settlement_program,
                source_roots=roots,
                now=evaluation_time,
                observer=controller._attempt_observer,
                capacity_authority=controller.tower,
            )
        except QualificationSuccessorError:
            raise
        except (
            OSError,
            TypeError,
            ValueError,
            shared_capacity.CapacityError,
        ) as error:
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:operation_refused"
            ) from error
        settlement_report = (
            deepcopy(dict(evaluated)) if isinstance(evaluated, Mapping) else {}
        )
        try:
            after = controller.tower.read_shared_capacity_authority()
        except (OSError, TypeError, ValueError) as error:
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:readback_unverified"
            ) from error
        after_active = _capacity_active_lane_ids(after)
        released_from_report = (
            settlement_report.get("receipt", {})
            .get("bindings", {})
            .get("failed_logical_lane_ids")
            if isinstance(settlement_report.get("receipt"), Mapping)
            else None
        )
        if (
            settlement_report.get("status") != "PASS"
            or settlement_report.get("disposition") != "CAPACITY_RELEASED"
            or settlement_report.get("issues") != []
            or after_active != []
            or not isinstance(released_from_report, list)
            or sorted(released_from_report) != sorted(logical_lane_ids)
        ):
            settlement_issues = settlement_report.get("issues")
            detail = (
                ":" + ",".join(
                    str(issue) for issue in settlement_issues
                )
                if isinstance(settlement_issues, list)
                and settlement_issues
                else ""
            )
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:settlement_refused"
                + detail
            )
        if not controller._terminal_run_closed(binding):
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:terminal_readback_invalid"
            )
        counters = dict(_SETTLEMENT_ZERO_COUNTERS)
        counters.update(
            {
                "capacity_lanes_released": len(active),
                "cleanup_observer_receipts_issued": len(release_receipts),
                "host_seed_credential_reads": credential_reads,
            }
        )
        core = {
            "schema": OBSERVED_SPAWN_STALL_SETTLEMENT_REPORT_SCHEMA,
            "status": "PASS",
            "decision": "SETTLED",
            "issues": [],
            "evaluation_time": evaluation_time.isoformat(),
            "predecessor": {
                "controller_id": str(controller_id),
                "controller_run_id": str(controller_run_id),
                "root_task_id": str(attempt_identity.get("root_thread_id")),
                "attempt_id": str(attempt_identity.get("attempt_id")),
                "run_id": str(attempt_identity.get("run_id")),
                "binding_sha256": str(binding["binding_sha256"]),
                "authority_sha256": _sha(authority),
            },
            "closure_report": deepcopy(dict(closure)),
            "capacity_admission_report": admission_report,
            "settlement_program": settlement_program,
            "settlement_report": settlement_report,
            "capacity_authority_before": deepcopy(dict(before)),
            "capacity_authority_after": deepcopy(dict(after)),
            "released_authority_lane_ids": list(active),
            "released_logical_lane_ids": list(logical_lane_ids),
            "started_logical_lane_id": str(started),
            "never_started_logical_lane_ids": [
                str(lane) for lane in never_started
            ],
            "boundary": dict(_OBSERVED_SPAWN_STALL_SETTLEMENT_BOUNDARY),
            "provider_free": True,
            "counters": counters,
        }
        report = {**core, "report_sha256": _sha(core)}
        if len(_canonical(report)) > MAX_REPORT_BYTES:
            raise QualificationSuccessorError(
                "observed_spawn_stall_settlement:report_too_large"
            )
        return QualificationObservedSpawnStallSettlementArtifact.from_report(
            report
        ).report
    finally:
        controller.store.close()


__all__ = [
    "ACTION_ADVANCE_REPORT_SCHEMA",
    "BOOTSTRAP_ACTION_ADVANCE_REPORT_SCHEMA",
    "REVIEW_ACTION_ADVANCE_REPORT_SCHEMA",
    "ACTION_ADVANCE_RESULT_ARTIFACT_SCHEMA",
    "ACTION_ADVANCE_RESULT_ARTIFACT_V2_SCHEMA",
    "ACTION_ADVANCE_RESULT_ARTIFACT_RESPONSE_BUDGET",
    "persist_issue94_action_advance_result",
    "read_issue94_action_advance_result",
    "resolve_issue94_action_advance_mcp_result",
    "is_issue94_action_advance_result_artifact_receipt",
    "DECISION_READY",
    "FIRST_ACTION_DECISION_READY",
    "FIRST_ACTION_PREPARATION_DECISION_READY",
    "FIRST_ACTION_PREPARATION_REPORT_SCHEMA",
    "FIRST_ACTION_REPORT_SCHEMA",
    "PRE_NATIVE_FAILURE_SETTLEMENT_REPORT_SCHEMA",
    "PARTIAL_NATIVE_FAILURE_RECOVERY_REPORT_SCHEMA",
    "POST_ACK_BRIDGE_FAILURE_RECOVERY_REPORT_SCHEMA",
    "POST_SPAWN_FAILURE_RECOVERY_REPORT_SCHEMA",
    "PREDECESSOR_SETTLEMENT_REPORT_SCHEMA",
    "OBSERVED_SPAWN_STALL_SETTLEMENT_REPORT_SCHEMA",
    "QualificationObservedSpawnStallSettlementArtifact",
    "QualificationPreNativeFailureSettlementArtifact",
    "QualificationPartialNativeFailureRecoveryArtifact",
    "QualificationPostAckBridgeFailureRecoveryArtifact",
    "QualificationPostSpawnFailureRecoveryArtifact",
    "QualificationPredecessorSettlementArtifact",
    "QualificationSuccessorArtifact",
    "QualificationSuccessorActionAdvanceArtifact",
    "QualificationSuccessorError",
    "QualificationSuccessorFirstActionArtifact",
    "QualificationSuccessorFirstActionPreparationArtifact",
    "Issue94SuccessorOwnerHandoff",
    "REPORT_SCHEMA",
    "PREACTIVATION_REPORT_SCHEMA",
    "authorize_issue94_successor_first_action",
    "advance_issue94_successor_after_native_action",
    "advance_issue94_bootstrapped_after_native_action",
    "build_issue94_successor_first_action_preparation",
    "open_issue94_successor_owner_handoff",
    "observe_idle_successor_preactivation",
    "read_issue94_successor_pre_turn_artifact",
    "recover_issue94_partial_native_failure",
    "recover_issue94_post_ack_bridge_failure",
    "recover_issue94_post_spawn_failure",
    "run_issue94_successor_pre_turn",
    "run_issue94_successor_pre_turn_with_owner_handoff",
    "submit_issue94_bootstrapped_semantic_review",
    "settle_issue94_terminal_predecessor_capacity",
    "settle_observed_spawn_stall_capacity",
    "terminalize_issue94_pre_native_failure",
    "validate_issue94_successor_first_action_report",
    "validate_issue94_successor_action_advance_evidence",
    "validate_issue94_successor_action_advance_report",
    "validate_issue94_successor_owner_handoff",
]


if __name__ == "__main__":
    raise SystemExit(main())
