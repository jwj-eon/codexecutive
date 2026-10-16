#!/usr/bin/env python3
"""Durable host-owned bridge from governed decisions to exact native actions.

The controller is deliberately an execution *owner*, not an executor.  It
persists one strict-serial decision stream, commits shared capacity through the
canonical Control Tower adapter, and materializes a hook binding for at most
one exact root tool input.  It never invokes that tool, starts a worker, calls
a model/provider, or treats an emitted action as observed execution.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
from typing import Any, Callable, Iterator, Mapping, NamedTuple
import sys

import orch_dork_adaptive_contracts as adaptive_contracts
import orch_dork_attempt_observer as attempt_observer
import orch_dork_artifact_ledger as artifact_ledger
import orch_dork_control_tower as control_tower
import orch_dork_governed_attempt as governed_attempt
import orch_dork_project_ground as project_ground
import orch_dork_project_ground_enforcement as ground_enforcement
import orch_dork_route_policy as route_policy
import orch_dork_routing_verify as routing_verify
import orch_dork_run_engine as run_engine
import orch_dork_run_store as run_store
import orch_dork_observer_authority as observer_authority
import orch_dork_observer_receipt as observer_receipt
import orch_dork_native_grant_store as native_grant_store
import orch_dork_native_result as native_result
import orch_dork_owned_file as owned_file
import orch_dork_runtime_package as runtime_package


PROGRAM_SCHEMA = "orch-dork/governed-native-controller-program/v1"
REPORT_SCHEMA = "orch-dork/governed-native-controller-report/v1"
REVIEW_WAIT_REPORT_SCHEMA = "orch-dork/governed-native-controller-review-wait/v1"
EVENT_SCHEMA = "orch-dork/governed-native-controller-event/v1"
ACTION_PROPOSAL_SCHEMA = "orch-dork/governed-native-action-proposal/v1"
ACTION_SCHEMA = "orch-dork/governed-native-action/v1"
ACTION_OBSERVATION_SCHEMA = "orch-dork/governed-native-action-observation/v1"
NATIVE_ACTION_RECEIPT_SCHEMA = "orch-dork/native-action-receipt/v1"
RETAINED_OWNER_OBSERVATION_SCHEMA = (
    "orch-dork/retained-owner-native-observation/v1"
)
RETAINED_OWNER_ACTION_EVIDENCE_SCHEMA = (
    "orch-dork/retained-owner-native-action-evidence/v1"
)
HOOK_BINDING_SCHEMA = "orch-dork/governed-native-hook-binding/v1"
ACTION_ADAPTER_SCHEMA = "orch-dork/closed-native-action-adapter/v1"
CONTROLLER_POLICY_VERSION = "governed-native-controller-policy/v1"
ACTIVATION_PREPARATION_PROGRAM_SCHEMA = (
    "orch-dork/governed-native-activation-preparation-program/v1"
)
ACTIVATION_PREPARATION_REPORT_SCHEMA = (
    "orch-dork/governed-native-activation-preparation-report/v1"
)
ACTIVATION_PREPARATION_POLICY_VERSION = (
    "governed-native-activation-preparation-policy/v1"
)
PROJECT_ADAPTER_REPORT_SCHEMA = "orch-dork/project-adapter-report/v1"
ACTIVATION_PREPARATION_ZERO_COUNTERS = (
    "hosted_calls",
    "model_calls",
    "native_calls",
    "task_creations",
    "worker_creations",
    "credential_reads",
    "authority_grants_minted",
    "native_action_authorizations",
)

OPERATIONS = frozenset({"activate", "stage", "observe", "inspect"})
ACTION_KINDS = frozenset({"spawn", "continue", "stop"})
ACTION_OUTCOMES = frozenset(
    {"completed", "failed", "cancelled", "timed_out", "unknown"}
)
HOOK_TRUST_MODES = frozenset({"persisted", "one_invocation_bypass"})
HOOK_TRUST_RECEIPT_KIND = "hook-trust-observation"
HOOK_TRUST_PAYLOAD_SCHEMA = "orch-dork/hook-trust-observation/v2"
ATTEMPT_OBSERVATION_POINTER_SCHEMA = (
    "orch-dork/governed-native-attempt-observation-pointer/v1"
)
ATTEMPT_OBSERVATION_RECEIPT_KIND = "attempt-observation"
MAX_PROGRAM_BYTES = 1_000_000
MAX_TOOL_INPUT_BYTES = 100_000
MAX_EVENT_BYTES = 1_000_000
# The kernel JSON-encodes the whole event as a deliverable string. Escaping
# can double its bytes; the remaining allowance covers the fixed facts map.
MAX_STORE_PAYLOAD_BYTES = 2 * MAX_EVENT_BYTES + 1024
MAX_RUNTIME_FILE_BYTES = 1_000_000
MAX_DURABLE_FILE_BYTES = 131_072
# Whole-file read bound for the review documents (AGENTS.md, SPEC.md,
# TICKETS.md) the continuation corpus excerpts from.  The excerpts stay bounded
# at 48 KB each; this guards the read only.  TICKETS.md is the canonical
# ledger and crossed 2 MiB on 2026-10-02, which refused every review
# continuation; production_graph_evidence mirrors this bound exactly.
MAX_REVIEW_DOCUMENT_BYTES = 8_388_608
DURABLE_HOOK_EVENT_SCHEMA = "orch-dork/project-ground-durable-event/v1"
DURABLE_HOOK_EVENT_FIELDS = {
    "schema",
    "report_schema",
    "report_sha256",
    "hook_event_name",
    "decision",
    "status",
    "coverage_class",
    "mutating",
    "tool_input_sha256",
    "state_sha256",
    "completion_invalidated",
    "reason_codes",
    "identity",
    "native_controller",
    "durable_record_sha256",
}
DURABLE_HOOK_IDENTITY_FIELDS = {
    "project_id",
    "generation",
    "ticket_id",
    "admission_sha256",
    "lease_version",
    "lease_owner_thread_id",
    "current_thread_id",
    "session_id",
    "authority_scope_sha256",
    "workspace_baseline_sha256",
    "writable_scope_sha256",
    "adapter_snapshot_sha256",
    "active_controller_sha256",
    "capsule_sha256",
    "execution_readiness_sha256",
    "plan_sha256",
    "turn_id",
}
DURABLE_PRETOOL_NATIVE_FIELDS = {
    "present",
    "controller_id",
    "controller_seq",
    "status",
    "action_id",
    "matched",
    "grant_state",
    "pretool_event_sha256",
    "tool_use_id",
}
DURABLE_POSTTOOL_NATIVE_FIELDS = {
    "present",
    "controller_id",
    "controller_seq",
    "status",
    "action_id",
    "matched",
    "grant_state",
    "tool_use_id",
    "pretool_report_sha256",
    "outcome",
    "result_sha256",
    "result_binding",
}
CLOSED_READ_ONLY_TOOLS = frozenset({"view_image"})

_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_DIGEST = re.compile(r"\A[0-9a-f]{64}\Z")


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


CLOSED_NATIVE_ACTION_ADAPTER_SHA256 = _sha(
    {
        "schema": ACTION_ADAPTER_SCHEMA,
        "policy": CONTROLLER_POLICY_VERSION,
        "rules": [
            "root-only",
            "exact-next-action",
            "exact-current-wave-lanes",
            "one-direct-local-function-call-per-grant",
            "deterministic-sequential-batch",
            "complete-tool-input-hash",
            "single-use",
            "no-execution",
        ],
    }
)

DIRECT_NATIVE_TOOLS = {
    "spawn": "multi_agent_v1__spawn_agent",
    "continue": "multi_agent_v1__send_input",
    "stop": "multi_agent_v1__close_agent",
}
NATIVE_BATCH_SCHEMA = "orch-dork/governed-native-action-batch/v1"
PRE_NATIVE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA = (
    "orch-dork/pre-native-failure-terminalization-program/v1"
)
PRE_NATIVE_FAILURE_EVIDENCE_SCHEMA = (
    "orch-dork/pre-native-failure-evidence/v1"
)
PRE_NATIVE_FAILURE_RUNTIME_REPORT_SCHEMA = (
    "orch-dork/pre-native-failure-runtime/v1"
)
PRE_NATIVE_FAILURE_STAGE_REPORT_SCHEMA = (
    "orch-dork/pre-native-failure-terminalization-stage/v1"
)
# A second attestation of the same lifecycle class.  The Issue 163 cycle
# packet above attests an owner that interrupted its own root turn; this
# report attests the Issue 170 qualification owner refusing a root turn the
# app server reported failed, with the thread rollout as the record of the
# turn.  Generation v51 ended this way (a 429 on the first root turn, before
# any native action) and had no honest closer.
OWNER_TERMINAL_PRE_NATIVE_FAILURE_REPORT_SCHEMA = (
    "orch-dork/pre-native-failure-owner-terminal-report/v1"
)
ROOT_ROLLOUT_FAILURE_SUMMARY_SCHEMA = (
    "orch-dork/root-rollout-failure-summary/v1"
)
# orch_dork_issue170_qualification_owner.TERMINAL_SCHEMA and
# FAILURE_TERMINAL_FIELDS; the controller does not import the owner, so a
# test holds the two copies equal.
QUALIFICATION_OWNER_TERMINAL_SCHEMA = (
    "orch-dork/issue170-qualification-owner-terminal/v1"
)
QUALIFICATION_OWNER_TERMINAL_FIELDS = frozenset({
    "schema", "status", "disposition", "ticket_id", "repair_branch",
    "source_commit", "generation", "runtime_package_digest",
    "terminal_evidence_path", "phase", "issue", "issue_detail",
    "missing_seam", "terminal_order", "host_cleanup",
    "promotion_receipt_emitted", "partial_publication", "last_thread_read",
})
QUALIFICATION_OWNER_PARTIAL_PUBLICATION_SCHEMA = (
    "orch-dork/issue170-qualification-owner-partial-publication/v1"
)
# The owner's app-server clientInfo name
# (orch_dork_issue170_qualification_owner.OWNER_CLIENT_NAME).  The app server
# records it as the rollout's session_meta originator, which is what ties a
# rollout to the qualification owner's own host rather than to any other
# Codex client that may have run the same model and effort.
QUALIFICATION_OWNER_ORIGINATOR = "orch-dork-issue170-owner"
# The qualification owner opens one control step before each control turn; the
# successor bridge admits an authorize or advance call only by claiming it.
QUALIFICATION_OWNER_CONTROL_STEPS_DIRECTORY = "owner-control-steps"
QUALIFICATION_OWNER_CONTROL_STEP_SCHEMA = "orch-dork/issue170-owner-control-step/v1"
QUALIFICATION_OWNER_CONTROL_STEP_REFUSAL_SCHEMA = (
    "orch-dork/issue170-owner-control-step-refusal/v1"
)
QUALIFICATION_OWNER_CONTROL_STEP_TOOLS = frozenset({
    "authorize_issue94_successor_first_action",
    "advance_issue94_successor_after_native_action",
})


def qualification_owner_control_step_refusal(
    tool: str, pre_turn_report_sha256: str
) -> dict[str, Any]:
    """The exact report for a control call made outside an opened owner step.

    The bridge returns it before reading the controller, so the call has no
    effect, and the owner counts only this exact report as a call not run.
    """
    return {
        "schema": QUALIFICATION_OWNER_CONTROL_STEP_REFUSAL_SCHEMA,
        "status": "BLOCKED",
        "decision": "OWNER_STEP_NOT_OPEN",
        "issues": ["successor_control:owner_step_not_open"],
        "tool": tool,
        "pre_turn_report_sha256": pre_turn_report_sha256,
        "controller_effect": "none",
    }
QUALIFICATION_HOST_CLEANUP_SCHEMA = "orch-dork/qualification-host-cleanup/v1"
# orch_dork_qualification_host.HOST_CLEANUP_FIELDS: the exact shape of the
# host's cleanup report, held closed so a fabricated cleanup block cannot
# carry only the keys this module inspects.
QUALIFICATION_HOST_CLEANUP_FIELDS = frozenset({
    "schema", "status", "disposition", "pid", "pgid",
    "preparation_report_sha256", "app_server_argv_sha256",
    "owner_identity_sha256", "process_reaped", "process_group_absent",
    "process_group_members", "descendants_absent", "remaining_descendants",
    "descendant_escalation", "owner_socket_absent", "output_monitor_closed",
    "host_closed", "stdout_bytes", "stderr_bytes", "stdout_sha256",
    "stderr_sha256", "issues", "provider_free", "model_calls",
    "hosted_calls", "credential_reads", "network_calls", "task_creations",
    "native_calls", "report_sha256",
})
# The owner refusal that means "the turn/completed frame arrived with status
# failed".  The rollout of such a turn ends in one task_complete carrying the
# error, which is the only turn end the summary below accepts, so the
# summary's turn_status and the owner's refusal name the same outcome.  The
# owner's turn_reported_error (status completed with a non-null error) has
# no observed instance and no known rollout shape; it is not closed here
# until one exists.  Other turn_start refusals (timeouts, transport loss)
# leave the turn's end unobserved by the owner and are not closed here.
QUALIFICATION_OWNER_TURN_FAILURE_ISSUES = frozenset({
    "issue170_owner:turn_reported_failed",
})
_OWNER_TERMINAL_FAILURE_REPORT_FIELDS = frozenset({
    "schema", "owner_terminal_artifact", "owner_terminal",
    "root_rollout_artifact", "root_rollout_summary", "task_id", "turn_id",
    "turn_status", "turn_error_message", "owner_refusal_phase",
    "owner_refusal_issue", "owner_process_group_cleaned", "report_sha256",
})
MAX_ROOT_ROLLOUT_BYTES = 4_194_304
_ROLLOUT_ROW_REQUIRED_KEYS = frozenset({"ordinal", "payload", "timestamp", "type"})
_ROLLOUT_ROW_OPTIONAL_KEYS = frozenset({"metadata"})
_ROLLOUT_ROW_TYPES = frozenset({
    "session_meta", "event_msg", "response_item", "world_state",
    "turn_context", "token_usage_record",
})
# A root turn that never acted leaves only prompt and model text behind.  Any
# tool call, native or otherwise, is a different response item or a
# different item type and refuses this summary.
_ROLLOUT_INERT_RESPONSE_ITEM_TYPES = frozenset({"message", "reasoning"})
_ROLLOUT_INERT_ITEM_TYPES = frozenset({"UserMessage", "AgentMessage", "Reasoning"})
_ROLLOUT_ITEM_EVENTS = frozenset({"item_started", "item_completed"})
MAX_ROLLOUT_ERROR_MESSAGE_CHARS = 1024
ACTIVATION_ONLY_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA = (
    "orch-dork/activation-only-failure-terminalization-program/v1"
)
ACTIVATION_ONLY_FAILURE_EVIDENCE_SCHEMA = (
    "orch-dork/activation-only-failure-evidence/v1"
)
ACTIVATION_ABANDONMENT_RECEIPT_KIND = "activation-abandonment"
ACTIVATION_ABANDONMENT_PAYLOAD_SCHEMA = (
    "orch-dork/activation-abandonment/v1"
)
ACTIVATION_ONLY_FAILURE_STAGE_REPORT_SCHEMA = (
    "orch-dork/activation-only-failure-terminalization-stage/v1"
)
PARTIAL_NATIVE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA = (
    "orch-dork/partial-native-failure-terminalization-program/v1"
)
PARTIAL_NATIVE_FAILURE_EVIDENCE_SCHEMA = (
    "orch-dork/partial-native-failure-evidence/v1"
)
PARTIAL_NATIVE_FAILURE_STAGE_REPORT_SCHEMA = (
    "orch-dork/partial-native-failure-terminalization-stage/v1"
)
POST_SPAWN_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA = (
    "orch-dork/post-spawn-failure-terminalization-program/v1"
)
POST_SPAWN_FAILURE_EVIDENCE_SCHEMA = (
    "orch-dork/post-spawn-failure-evidence/v1"
)
POST_SPAWN_FAILURE_STAGE_REPORT_SCHEMA = (
    "orch-dork/post-spawn-failure-terminalization-stage/v1"
)
POST_ACK_BRIDGE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA = (
    "orch-dork/post-ack-bridge-failure-terminalization-program/v1"
)
POST_ACK_BRIDGE_FAILURE_EVIDENCE_SCHEMA = (
    "orch-dork/post-ack-bridge-failure-evidence/v1"
)
POST_ACK_BRIDGE_FAILURE_EVIDENCE_SCHEMA_V2 = (
    "orch-dork/post-ack-bridge-failure-evidence/v2"
)
POST_ACK_BRIDGE_FAILURE_STAGE_REPORT_SCHEMA = (
    "orch-dork/post-ack-bridge-failure-terminalization-stage/v1"
)
_POST_ACK_BRIDGE_FAILURE_PROFILES = {
    (
        "issue163/cycle32-owner-bound-attempt/v1",
        "issue163/cycle32-dedicated-app-server-run/v2",
    ): {
        "state_shape": "waiting_after_ack",
        "bridge_refusal_code": (
            "successor_action_advance:codex_home_unavailable"
        ),
        "bridge_refusal_invocation_count": 8,
        "blocked_bridge_invocation_count": 0,
        "send_input_call_count": 0,
        "stop_denial_count": 11,
        "denied_hook_tool_name": None,
    },
    (
        "issue163/cycle33-owner-bound-attempt/v1",
        "issue163/cycle33-dedicated-app-server-run/v2",
    ): {
        "state_shape": "waiting_after_ack",
        "bridge_refusal_code": (
            "successor_action_advance:worker_rollout_invalid"
        ),
        "bridge_refusal_invocation_count": 2,
        "blocked_bridge_invocation_count": 0,
        "send_input_call_count": 0,
        "stop_denial_count": 10,
        "denied_hook_tool_name": None,
    },
    (
        "issue163/cycle34-owner-bound-attempt/v1",
        "issue163/cycle34-dedicated-app-server-run/v2",
    ): {
        "state_shape": "pending_continuation_denied",
        "bridge_refusal_code": None,
        "bridge_refusal_invocation_count": 0,
        "blocked_bridge_invocation_count": 2,
        "send_input_call_count": 1,
        "stop_denial_count": 10,
        "denied_hook_tool_name": "multi_agent_v1send_input",
    },
}
_PRE_NATIVE_FAILURE_PACKET_FIELDS = frozenset(
    {
        "existing_server_restarted",
        "expected_app_server_argv_sha256",
        "hook_runs",
        "host_preparation_report_sha256",
        "issues",
        "last_message_present",
        "notification_counts",
        "owned_process_group_cleaned",
        "owner_socket_injected",
        "pre_turn_boundary",
        "pre_turn_controller_id",
        "pre_turn_decision",
        "pre_turn_evidence_root",
        "pre_turn_hook_count",
        "pre_turn_hook_inventory_report_sha256",
        "pre_turn_hooks_enabled",
        "pre_turn_report_path",
        "pre_turn_report_sha256",
        "pre_turn_successor_prepared",
        "schema",
        "server_output_exhausted",
        "server_returncode",
        "status",
        "task_id",
        "turn_id",
        "turn_started_after_pre_turn",
        "turn_status",
    }
)


def normalized_task_specs(task_specs: Any) -> list[dict[str, Any]]:
    """Return the closed canonical TaskSpecs used to derive native actions."""

    if not isinstance(task_specs, list):
        raise ValueError("task_specs must be an array")
    bindings: list[dict[str, Any]] = []
    for row in task_specs:
        if not isinstance(row, Mapping):
            raise ValueError("task spec binding must be an object")
        lane_id = row.get("logical_worker_id")
        report = adaptive_contracts.validate_task_spec(row.get("task_spec"))
        if (
            not isinstance(lane_id, str)
            or not report.get("valid")
            or report.get("normalized", {}).get("id") != lane_id
        ):
            raise ValueError("task spec binding is invalid")
        bindings.append({
            "logical_worker_id": lane_id,
            "task_spec_sha256": report["digest"],
            "task_spec": deepcopy(dict(report["normalized"])),
        })
    bindings.sort(key=lambda item: item["logical_worker_id"])
    if not bindings or len({row["logical_worker_id"] for row in bindings}) != len(
        bindings
    ):
        raise ValueError("task spec bindings must be non-empty and unique")
    return bindings


def task_specs_identity_sha256(task_specs: Any) -> str:
    """Bind lane IDs and canonical TaskSpec digests used at pre-spawn."""

    return _sha([
        {
            "logical_worker_id": row["logical_worker_id"],
            "task_spec_sha256": row["task_spec_sha256"],
        }
        for row in normalized_task_specs(task_specs)
    ])


class SignedAttemptObservationAdapter:
    """Verify one host-signed independent attempt observation by content hash."""

    def __init__(self, plugin_data: Path, now: Callable[[], datetime] | datetime) -> None:
        self.plugin_data = plugin_data
        self.now = now
        self.replay = observer_receipt.SQLiteReplayGuard(
            plugin_data / "governed-native" / "attempt-observation-replay.sqlite3"
        )

    def __call__(self, manifest: Any) -> Mapping[str, Any]:
        if (
            not isinstance(manifest, Mapping)
            or set(manifest) != {"schema", "attempt_id", "receipt_sha256"}
            or manifest.get("schema") != ATTEMPT_OBSERVATION_POINTER_SCHEMA
            or not _IDENTIFIER.fullmatch(str(manifest.get("attempt_id", "")))
            or not _DIGEST.fullmatch(str(manifest.get("receipt_sha256", "")))
        ):
            return {}
        receipt_sha256 = str(manifest["receipt_sha256"])
        path = (
            self.plugin_data
            / "governed-native"
            / "attempt-observations"
            / (receipt_sha256 + ".json")
        )
        try:
            metadata = path.lstat()
            if path.is_symlink() or metadata.st_size > 1_000_000 or metadata.st_mode & 0o022:
                return {}
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != receipt_sha256:
                return {}
            envelope = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {}
        evaluation_time = self.now() if callable(self.now) else self.now
        verified = observer_receipt.verify_signed_receipt(
            envelope,
            expected_kind=ATTEMPT_OBSERVATION_RECEIPT_KIND,
            expected_payload={
                "schema": attempt_observer.SCHEMA,
                "attempt_id": manifest["attempt_id"],
            },
            evaluation_time=evaluation_time,
            replay_guard=self.replay,
        )
        payload = verified.get("payload")
        return deepcopy(dict(payload)) if (
            verified.get("status") == "PASS" and isinstance(payload, Mapping)
        ) else {}


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, fields: set[str], path: str, issues: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, path + ":not_object")
        return {}
    keys = set(value)
    for field in sorted(fields - keys):
        _issue(issues, path + ":missing:" + field)
    for field in sorted(keys - fields):
        _issue(issues, path + ":unknown:" + field)
    return value


def _identifier(value: Any, path: str, issues: list[str]) -> bool:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _issue(issues, path + ":invalid")
        return False
    return True


def _digest(value: Any, path: str, issues: list[str]) -> bool:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _issue(issues, path + ":sha256_invalid")
        return False
    return True


def _activation_preparation_report(
    *,
    issues: list[str],
    project_adapter_report_sha256: Any = None,
    project_ground_report_sha256: Any = None,
    prepared_activation_payload: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    ready = not issues and prepared_activation_payload is not None
    adapter_sha256 = (
        project_adapter_report_sha256
        if isinstance(project_adapter_report_sha256, str)
        and _DIGEST.fullmatch(project_adapter_report_sha256)
        else None
    )
    ground_sha256 = (
        project_ground_report_sha256
        if isinstance(project_ground_report_sha256, str)
        and _DIGEST.fullmatch(project_ground_report_sha256)
        else None
    )
    core: dict[str, Any] = {
        "schema": ACTIVATION_PREPARATION_REPORT_SCHEMA,
        "policy_version": ACTIVATION_PREPARATION_POLICY_VERSION,
        "status": "PASS" if ready else "BLOCKED",
        "decision": "READY_FOR_ACTIVATION" if ready else "REFUSED",
        "issues": sorted(set(issues)),
        "project_adapter_report_sha256": adapter_sha256,
        "project_ground_report_sha256": ground_sha256,
        "provider_free": True,
        **{counter: 0 for counter in ACTIVATION_PREPARATION_ZERO_COUNTERS},
    }
    if ready:
        payload = deepcopy(dict(prepared_activation_payload))
        core["prepared_activation_payload"] = payload
        core["prepared_activation_payload_sha256"] = _sha(payload)
    return {**core, "report_sha256": _sha(core)}


def _validate_prepared_activation_payload(
    payload: Any,
    *,
    adapter_report_sha256: Any,
    issues: list[str],
) -> None:
    value = _exact(
        payload,
        {
            "identity",
            "enrollment_program",
            "project_ground_state",
            "hook_trust_receipt_sha256",
            "task_specs",
        },
        "report.prepared_activation_payload",
        issues,
    )
    identity = _exact(
        value.get("identity"),
        {
            "project_id",
            "enrollment_generation",
            "installed_plugin_version",
            "ticket_id",
            "admission_sha256",
            "authority_scope_sha256",
            "root_thread_id",
            "root_session_id",
            "run_id",
            "attempt_id",
            "root_model",
            "root_effort",
            "source_version",
            "task_loaded_version",
            "fresh_task",
            "plan_sha256",
            "task_specs_sha256",
            "hook_definition_sha256",
            "hook_registration_sha256",
            "native_adapter_sha256",
        },
        "report.prepared_activation_payload.identity",
        issues,
    )
    for field in ("ticket_id", "root_thread_id", "root_session_id"):
        _identifier(
            identity.get(field),
            "report.prepared_activation_payload.identity." + field,
            issues,
        )
    for field in ("admission_sha256", "plan_sha256", "task_specs_sha256"):
        _digest(
            identity.get(field),
            "report.prepared_activation_payload.identity." + field,
            issues,
        )
    if not isinstance(value.get("enrollment_program"), Mapping):
        _issue(issues, "report:prepared_enrollment_program_invalid")
    if not isinstance(value.get("task_specs"), list) or not value.get("task_specs"):
        _issue(issues, "report:prepared_task_specs_invalid")
    _digest(
        value.get("hook_trust_receipt_sha256"),
        "report.prepared_activation_payload.hook_trust_receipt_sha256",
        issues,
    )
    state_record = value.get("project_ground_state")
    if (
        not isinstance(state_record, Mapping)
        or set(state_record) != {"schema", "program", "program_sha256"}
        or state_record.get("schema") != ground_enforcement.HOOK_STATE_SCHEMA
    ):
        _issue(issues, "report:prepared_project_ground_state_invalid")
        ground_program: Mapping[str, Any] = {}
    else:
        ground_program = state_record.get("program", {})
        try:
            ground_sealed = state_record.get(
                "program_sha256"
            ) == ground_enforcement._sha(ground_program)
        except (TypeError, ValueError):
            ground_sealed = False
        if not ground_sealed:
            _issue(issues, "report:prepared_project_ground_state_invalid")
    ground_state = (
        ground_program.get("state", {})
        if isinstance(ground_program, Mapping)
        else {}
    )
    prerequisites = (
        ground_state.get("prerequisites", {})
        if isinstance(ground_state, Mapping)
        else {}
    )
    ticket_ground = prerequisites.get("ticket_admission")
    adapter_ground = prerequisites.get("adapter")
    if (
        not isinstance(ground_program.get("event"), Mapping)
        if isinstance(ground_program, Mapping)
        else True
    ):
        _issue(issues, "report:prepared_project_ground_event_invalid")
    if (
        not isinstance(ticket_ground, Mapping)
        or ticket_ground.get("ticket_id") != identity.get("ticket_id")
        or ticket_ground.get("admission_sha256")
        != identity.get("admission_sha256")
        or ticket_ground.get("plan_sha256") != identity.get("plan_sha256")
        or ticket_ground.get("implementation_permitted") is not True
    ):
        _issue(issues, "report:prepared_ticket_binding_invalid")
    if (
        not isinstance(adapter_ground, Mapping)
        or adapter_ground.get("status") != "PASS"
        or adapter_ground.get("decision") != "ALLOW"
        or adapter_ground.get("report_sha256") != adapter_report_sha256
        or not isinstance(adapter_ground.get("snapshot_sha256"), str)
        or _DIGEST.fullmatch(str(adapter_ground.get("snapshot_sha256", ""))) is None
    ):
        _issue(issues, "report:prepared_adapter_binding_invalid")


def validate_activation_preparation_report(report: Any) -> dict[str, Any]:
    """Validate the closed public report emitted by activation preparation."""

    issues: list[str] = []
    value = report if isinstance(report, Mapping) else {}
    if not isinstance(report, Mapping):
        _issue(issues, "report:not_object")
    common_fields = {
        "schema",
        "policy_version",
        "status",
        "decision",
        "issues",
        "project_adapter_report_sha256",
        "project_ground_report_sha256",
        "provider_free",
        *ACTIVATION_PREPARATION_ZERO_COUNTERS,
        "report_sha256",
    }
    ready = value.get("status") == "PASS" and value.get(
        "decision"
    ) == "READY_FOR_ACTIVATION"
    refused = value.get("status") == "BLOCKED" and value.get(
        "decision"
    ) == "REFUSED"
    expected_fields = set(common_fields)
    if ready:
        expected_fields.update(
            {"prepared_activation_payload", "prepared_activation_payload_sha256"}
        )
    _exact(value, expected_fields, "report", issues)
    if value.get("schema") != ACTIVATION_PREPARATION_REPORT_SCHEMA:
        _issue(issues, "report:schema_invalid")
    if value.get("policy_version") != ACTIVATION_PREPARATION_POLICY_VERSION:
        _issue(issues, "report:policy_version_invalid")
    if not ready and not refused:
        _issue(issues, "report:disposition_invalid")
    report_issues = value.get("issues")
    if (
        not isinstance(report_issues, list)
        or any(not isinstance(item, str) or not item for item in report_issues)
        or report_issues != sorted(set(report_issues))
        or (ready and report_issues)
        or (refused and not report_issues)
    ):
        _issue(issues, "report:issues_invalid")
    for field in (
        "project_adapter_report_sha256",
        "project_ground_report_sha256",
    ):
        digest = value.get(field)
        if digest is not None and (
            not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None
        ):
            _issue(issues, "report:" + field + "_invalid")
    if ready and (
        not isinstance(value.get("project_adapter_report_sha256"), str)
        or not isinstance(value.get("project_ground_report_sha256"), str)
    ):
        _issue(issues, "report:ready_evidence_missing")
    if value.get("provider_free") is not True:
        _issue(issues, "report:provider_free_invalid")
    for counter in ACTIVATION_PREPARATION_ZERO_COUNTERS:
        if value.get(counter) != 0:
            _issue(issues, "report:" + counter + "_invalid")
    if ready:
        prepared_payload = value.get("prepared_activation_payload")
        if not isinstance(prepared_payload, Mapping):
            _issue(issues, "report:prepared_activation_payload_invalid")
        prepared_sha256 = value.get("prepared_activation_payload_sha256")
        if (
            not isinstance(prepared_sha256, str)
            or _DIGEST.fullmatch(prepared_sha256) is None
            or not isinstance(prepared_payload, Mapping)
            or prepared_sha256 != _sha(prepared_payload)
        ):
            _issue(issues, "report:prepared_activation_payload_sha256_invalid")
        _validate_prepared_activation_payload(
            prepared_payload,
            adapter_report_sha256=value.get("project_adapter_report_sha256"),
            issues=issues,
        )
    declared_sha256 = value.get("report_sha256")
    try:
        expected_sha256 = _sha(
            {key: item for key, item in value.items() if key != "report_sha256"}
        )
    except (TypeError, ValueError):
        expected_sha256 = None
    if (
        not isinstance(declared_sha256, str)
        or _DIGEST.fullmatch(declared_sha256) is None
        or declared_sha256 != expected_sha256
    ):
        _issue(issues, "report:seal_invalid")
    return {"valid": not issues, "issues": sorted(issues)}


def validate_governed_native_controller_report(report: Any) -> dict[str, Any]:
    """Validate whole transport bytes without granting execution authority."""

    from orch_dork_governed_native_reports import validate_controller_report

    return validate_controller_report(report)


def validate_verified_completion_source_capture(report: Any) -> dict[str, Any]:
    """Validate the complete capture transport; confer no closure authority."""
    from orch_dork_governed_native_reports import validate_completion_source_capture

    return validate_completion_source_capture(report)


def build_governed_native_activation_preparation_program(
    *,
    activation_payload: Mapping[str, Any],
    project_adapter_report: Mapping[str, Any],
) -> dict[str, Any]:
    """Construct the exact provider-free activation-preparation envelope."""

    if not isinstance(activation_payload, Mapping):
        raise ValueError("activation_preparation:payload_not_object")
    if not isinstance(project_adapter_report, Mapping):
        raise ValueError("activation_preparation:adapter_report_not_object")
    return {
        "schema": ACTIVATION_PREPARATION_PROGRAM_SCHEMA,
        "activation_payload": deepcopy(dict(activation_payload)),
        "project_adapter_report": deepcopy(dict(project_adapter_report)),
    }


def prepare_governed_native_activation(program: Any) -> dict[str, Any]:
    """Bind one permitting adapter report into an exact healthy activation.

    This seam is provider-free and read-only.  It does not relax controller
    activation or hard pre-spawn admission; it only replaces the advisory
    mutation-permission placeholder with exact pre-implementation adapter
    evidence, refreshes the ground-state seal, and proves that ground healthy.
    """

    issues: list[str] = []
    value = _exact(
        program,
        {"schema", "activation_payload", "project_adapter_report"},
        "preparation",
        issues,
    )
    if value.get("schema") != ACTIVATION_PREPARATION_PROGRAM_SCHEMA:
        _issue(issues, "preparation:schema_invalid")

    payload = _exact(
        value.get("activation_payload"),
        {
            "identity",
            "enrollment_program",
            "project_ground_state",
            "hook_trust_receipt_sha256",
            "task_specs",
        },
        "preparation.activation_payload",
        issues,
    )
    identity = payload.get("identity")
    if not isinstance(identity, Mapping):
        _issue(issues, "preparation.activation_identity_invalid")
        identity = {}
    ticket_id = identity.get("ticket_id")
    admission_sha256 = identity.get("admission_sha256")
    root_thread_id = identity.get("root_thread_id")
    plan_sha256 = identity.get("plan_sha256")
    _identifier(ticket_id, "preparation.identity.ticket_id", issues)
    _digest(admission_sha256, "preparation.identity.admission_sha256", issues)
    _identifier(root_thread_id, "preparation.identity.root_thread_id", issues)
    _digest(plan_sha256, "preparation.identity.plan_sha256", issues)

    adapter_report = value.get("project_adapter_report")
    if not isinstance(adapter_report, Mapping):
        _issue(issues, "preparation.adapter_report:not_object")
        adapter_report = {}
    report_sha256 = adapter_report.get("report_sha256")
    report_core = {
        key: item for key, item in adapter_report.items() if key != "report_sha256"
    }
    if (
        adapter_report.get("schema") != PROJECT_ADAPTER_REPORT_SCHEMA
        or not _digest(
            report_sha256, "preparation.adapter_report.report_sha256", issues
        )
        or report_sha256 != _sha(report_core)
    ):
        _issue(issues, "preparation:adapter_report_invalid")
    if (
        adapter_report.get("status") != "PASS"
        or adapter_report.get("disposition") != "ADAPTER_READY"
        or adapter_report.get("phase") != "pre_implementation"
        or adapter_report.get("adapter_status") != "available"
        or adapter_report.get("implementation_permitted") is not True
        or adapter_report.get("commands_executed_by_plugin") != 0
        or adapter_report.get("authority_boundary_preserved") is not True
        or adapter_report.get("authority_broadened") is not False
        or adapter_report.get("authority_inferred") is not False
        or adapter_report.get("issues") != []
        or adapter_report.get("blockers") != []
    ):
        _issue(issues, "preparation:adapter_not_permitting")
    adapter_definition_sha256 = adapter_report.get("adapter_definition_sha256")
    _digest(
        adapter_definition_sha256,
        "preparation.adapter_report.adapter_definition_sha256",
        issues,
    )
    ticket_binding = adapter_report.get("ticket_admission")
    if not isinstance(ticket_binding, Mapping):
        _issue(issues, "preparation:ticket_binding_invalid")
        ticket_binding = {}
    if (
        ticket_binding.get("status") != "PASS"
        or ticket_binding.get("binding_status") != "BOUND"
        or ticket_binding.get("ticket_id") != ticket_id
        or ticket_binding.get("root_task_id") != root_thread_id
        or ticket_binding.get("admission_sha256") != admission_sha256
        or adapter_report.get("ticket_admission_binding_status") != "BOUND"
        or adapter_report.get("ticket_admission_sha256") != admission_sha256
    ):
        _issue(issues, "preparation:ticket_binding_mismatch")

    state_record = payload.get("project_ground_state")
    if (
        not isinstance(state_record, Mapping)
        or set(state_record) != {"schema", "program", "program_sha256"}
        or state_record.get("schema") != ground_enforcement.HOOK_STATE_SCHEMA
        or state_record.get("program_sha256")
        != ground_enforcement._sha(state_record.get("program"))
    ):
        _issue(issues, "preparation:project_ground_state_invalid")
        ground_program: Mapping[str, Any] = {}
    else:
        ground_program = state_record.get("program", {})
    ground_state = (
        ground_program.get("state", {})
        if isinstance(ground_program, Mapping)
        else {}
    )
    prerequisites = (
        ground_state.get("prerequisites", {})
        if isinstance(ground_state, Mapping)
        else {}
    )
    ticket_ground = prerequisites.get("ticket_admission")
    adapter_ground = prerequisites.get("adapter")
    event = (
        ground_program.get("event")
        if isinstance(ground_program, Mapping)
        else None
    )
    if not isinstance(ticket_ground, Mapping) or not isinstance(
        adapter_ground, Mapping
    ):
        _issue(issues, "preparation:project_ground_prerequisites_invalid")
    elif (
        ticket_ground.get("ticket_id") != ticket_id
        or ticket_ground.get("admission_sha256") != admission_sha256
        or ticket_ground.get("plan_sha256") != plan_sha256
    ):
        _issue(issues, "preparation:project_ground_identity_mismatch")
    if not isinstance(event, Mapping):
        _issue(issues, "preparation:project_ground_event_invalid")

    if issues:
        return _activation_preparation_report(
            issues=issues,
            project_adapter_report_sha256=report_sha256,
        )

    prepared = deepcopy(dict(payload))
    prepared_state_record = prepared["project_ground_state"]
    prepared_ground_program = prepared_state_record["program"]
    prepared_prerequisites = prepared_ground_program["state"]["prerequisites"]
    prepared_prerequisites["ticket_admission"]["implementation_permitted"] = True
    prepared_prerequisites["adapter"].update(
        {
            "status": "PASS",
            "decision": "ALLOW",
            "snapshot_sha256": adapter_definition_sha256,
            "report_sha256": report_sha256,
        }
    )
    prepared_state_record["program_sha256"] = ground_enforcement._sha(
        prepared_ground_program
    )
    hook_input = {
        "session_id": identity.get("root_session_id"),
        "cwd": str(event.get("cwd", "")),
        "hook_event_name": "SessionStart",
        "model": event.get("model"),
        "permission_mode": event.get("permission_mode", "default"),
        "source": event.get("source"),
    }
    try:
        bound = ground_enforcement.program_from_hook_state(
            hook_input, prepared_state_record
        )
        ground_report = ground_enforcement.evaluate_project_ground_enforcement(
            bound
        )
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        sqlite3.Error,
        run_engine.RunKernelError,
    ):
        ground_report = {}
    if (
        ground_report.get("status") != "PASS"
        or ground_report.get("decision") != "HEALTHY"
    ):
        _issue(issues, "preparation:project_ground_not_healthy")
        return _activation_preparation_report(
            issues=issues,
            project_adapter_report_sha256=report_sha256,
            project_ground_report_sha256=ground_report.get("report_sha256"),
        )
    return _activation_preparation_report(
        issues=[],
        project_adapter_report_sha256=report_sha256,
        project_ground_report_sha256=ground_report.get("report_sha256"),
        prepared_activation_payload=prepared,
    )


def build_governed_native_activation_program(
    *,
    controller_id: str,
    prepared_activation_payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Construct the one exact controller envelope for prepared activation."""

    issues: list[str] = []
    _identifier(controller_id, "program.controller_id", issues)
    if not isinstance(prepared_activation_payload, Mapping):
        _issue(issues, "program.payload:not_object")
    if issues:
        raise ValueError("activation_program:" + ";".join(sorted(issues)))
    program = {
        "schema": PROGRAM_SCHEMA,
        "controller_id": controller_id,
        "operation": "activate",
        "expected_cursor": None,
        "payload": deepcopy(dict(prepared_activation_payload)),
    }
    if len(_canonical(program)) > MAX_PROGRAM_BYTES:
        raise ValueError("activation_program:too_large")
    return program


def _checkpoint_action_proposal(controller_id: str, cursor: Any, program: Any, next_action: str) -> dict[str, Any]:
    """Select only the host-evaluated checkpoint continuation or stop."""
    if next_action not in {"continue", "stop"}:raise ValueError("checkpoint:invalid_disposition")
    return {"schema":ACTION_PROPOSAL_SCHEMA,
        "action_id":"checkpoint:" + _sha({"controller_id":controller_id,"cursor":cursor,"program":program}),
        "kind":next_action,"actor_thread_id":program["identity"]["root_task_id"],
        "adapter_sha256":CLOSED_NATIVE_ACTION_ADAPTER_SHA256}


def build_governed_native_stage_program(
    *,
    controller_id: str,
    expected_cursor: Mapping[str, Any],
    stage_program: Mapping[str, Any],
    proposed_action: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Construct one exact controller stage envelope without field translation."""

    issues: list[str] = []
    _identifier(controller_id, "program.controller_id", issues)
    if not _cursor_valid(expected_cursor):
        _issue(issues, "program.expected_cursor_invalid")
    if not isinstance(stage_program, Mapping):
        _issue(issues, "program.stage_program_invalid")
    if proposed_action is not None and not isinstance(proposed_action, Mapping):
        _issue(issues, "program.proposed_action_invalid")
    if issues:
        raise ValueError("stage_program:" + ";".join(sorted(issues)))
    program = {
        "schema": PROGRAM_SCHEMA,
        "controller_id": controller_id,
        "operation": "stage",
        "expected_cursor": deepcopy(dict(expected_cursor)),
        "payload": {
            "stage_program": deepcopy(dict(stage_program)),
            "proposed_action": (
                deepcopy(dict(proposed_action))
                if proposed_action is not None
                else None
            ),
        },
    }
    if len(_canonical(program)) > MAX_PROGRAM_BYTES:
        raise ValueError("stage_program:too_large")
    return program


def _admitting_signature_valid(
    envelope: Any, trust_store: Any, admitted: Mapping[str, Any]
) -> bool:
    """Verify the admitting receipt's Ed25519 signature only, ignoring expiry.

    Comparing labels is not enough. A substituted trust store can copy host_id,
    key_id and generation verbatim from the real one while supplying its own
    public key, and every string comparison then matches by construction. Only
    the signature binds a closure to the key material that actually admitted
    this controller. Persisted admitting envelopes are long expired by design,
    so freshness is deliberately not re-evaluated here.
    """

    if (
        not isinstance(envelope, Mapping)
        or envelope.get("algorithm") != "ed25519"
        or envelope.get("schema") != observer_receipt.ENVELOPE_SCHEMA
        or envelope.get("receipt_kind") != HOOK_TRUST_RECEIPT_KIND
        or envelope.get("host_id") != admitted.get("host_id")
        or envelope.get("key_id") != admitted.get("key_id")
    ):
        return False
    try:
        key = trust_store.keys.get(str(envelope.get("key_id")))
    except AttributeError:
        return False
    if not isinstance(key, Mapping) or "public" not in key:
        return False
    body = dict(envelope)
    encoded = body.pop("signature", None)
    if not isinstance(encoded, str) or len(encoded) > 256:
        return False
    try:
        signature = base64.b64decode(encoded, validate=True)
        signed_body = observer_receipt.evidence.canonical_bytes(body)
    except (TypeError, ValueError, UnicodeError):
        return False
    if len(signature) != 64:
        return False
    try:
        return bool(
            observer_receipt.attestation.ed25519_verify(
                key["public"], signature, signed_body
            )
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _owner_process_absent(value: Any) -> bool:
    """Corroborate that a signed abandonment names a process that is really gone.

    This is defence in depth, never authority: the signature binds the record to
    this controller, and anything ambiguous here fails closed.
    """

    if (
        not isinstance(value, Mapping)
        or set(value) != {"pid", "pgid", "start_ticks"}
        or not all(
            type(value[key]) is int and value[key] > 0
            for key in ("pid", "pgid", "start_ticks")
        )
    ):
        return False
    try:
        with open("/proc/%d/stat" % value["pid"], "rb") as handle:
            raw = handle.read().decode("utf-8", "replace")
    except FileNotFoundError:
        pid_absent = True
    except OSError:
        return False
    else:
        try:
            pid_absent = (
                int(raw[raw.rindex(")") + 2 :].split()[19])
                != value["start_ticks"]
            )
        except (ValueError, IndexError):
            return False
    try:
        os.killpg(value["pgid"], 0)
    except ProcessLookupError:
        group_absent = True
    except OSError:
        group_absent = False
    else:
        group_absent = False
    return bool(pid_absent and group_absent)


def _read_pre_native_failure_artifact(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str,
    label: str,
) -> tuple[Path, dict[str, Any]]:
    candidate = Path(path)
    if (
        not candidate.is_absolute()
        or candidate.is_symlink()
        or _DIGEST.fullmatch(str(expected_sha256)) is None
    ):
        raise ValueError(label + ":reference_invalid")
    try:
        resolved = candidate.resolve(strict=True)
        raw = owned_file.read_owned_bytes(
            resolved,
            max_bytes=MAX_EVENT_BYTES,
            required_mode=0o600,
        )
        value = json.loads(raw.decode("utf-8"))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        raise ValueError(label + ":unavailable") from error
    if (
        not isinstance(value, Mapping)
        or hashlib.sha256(raw).hexdigest() != expected_sha256
        or raw != _canonical(value) + b"\n"
    ):
        raise ValueError(label + ":reference_invalid")
    return resolved, deepcopy(dict(value))


def _pre_native_failure_runtime_report(
    runtime_root: str | os.PathLike[str],
    *,
    expected_package_digest: str,
) -> dict[str, Any]:
    candidate = Path(runtime_root)
    if (
        not candidate.is_absolute()
        or candidate.is_symlink()
        or _DIGEST.fullmatch(str(expected_package_digest)) is None
    ):
        raise ValueError("pre_native_failure:runtime_reference_invalid")
    try:
        root = candidate.resolve(strict=True)
        info = root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or root.is_symlink()
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            or stat.S_IMODE(info.st_mode) & 0o002
        ):
            raise ValueError("unsafe runtime root")
        historical_allowlist = (
            runtime_package.read_declared_runtime_allowlist(root)
        )
        package = runtime_package.validate_runtime_package(
            root,
            root,
            allowlist=historical_allowlist,
        )
        hook_definition_sha256 = owned_file.sha256_owned_file(
            root / "hooks" / "project_ground_hook.py",
            max_bytes=MAX_RUNTIME_FILE_BYTES,
        )
        hook_registration_sha256 = owned_file.sha256_owned_file(
            root / "hooks" / "hooks.json",
            max_bytes=MAX_RUNTIME_FILE_BYTES,
        )
    except (
        OSError,
        TypeError,
        ValueError,
        runtime_package.RuntimePackageError,
    ) as error:
        raise ValueError("pre_native_failure:runtime_unavailable") from error
    if package.get("package_digest") != expected_package_digest:
        raise ValueError("pre_native_failure:runtime_digest_mismatch")
    core = {
        "schema": PRE_NATIVE_FAILURE_RUNTIME_REPORT_SCHEMA,
        "root": str(root),
        "version": package["version"],
        "inventory_hash": package["inventory_hash"],
        "descriptor_hash": package["descriptor_hash"],
        "package_digest": package["package_digest"],
        "hook_definition_sha256": hook_definition_sha256,
        "hook_registration_sha256": hook_registration_sha256,
    }
    return {**core, "report_sha256": _sha(core)}


def _rollout_refusal(reason: str) -> ValueError:
    return ValueError("pre_native_failure:root_rollout:" + reason)


def _root_rollout_turn_parts(
    raw: bytes,
) -> tuple[dict[str, Any], Mapping[str, Any], bool]:
    """Parse one inert root turn and retain its completion and activity facts.

    Both recovery outcomes share exact row, identity and no-tool checks.
    Their separate validators decide whether the completion records a failure
    or an empty completed turn. Startup user/developer context is inert;
    model responses and item events prevent the empty-turn outcome.
    """

    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise _rollout_refusal("encoding") from error
    if not text.endswith("\n"):
        raise _rollout_refusal("trailing_newline")
    rows: list[dict[str, Any]] = []
    for line in text.split("\n")[:-1]:
        try:
            row = json.loads(line)
        except ValueError as error:
            raise _rollout_refusal("row_json") from error
        if (
            not isinstance(row, Mapping)
            or not _ROLLOUT_ROW_REQUIRED_KEYS <= set(row)
            or not set(row) <= _ROLLOUT_ROW_REQUIRED_KEYS | _ROLLOUT_ROW_OPTIONAL_KEYS
            or row.get("type") not in _ROLLOUT_ROW_TYPES
            or not isinstance(row.get("payload"), Mapping)
            or not isinstance(row.get("timestamp"), str)
        ):
            raise _rollout_refusal("row_shape")
        rows.append(dict(row))
    if not rows or rows[0]["type"] != "session_meta":
        raise _rollout_refusal("session_meta_first")
    row_type_counts: dict[str, int] = {}
    event_type_counts: dict[str, int] = {}
    response_item_type_counts: dict[str, int] = {}
    item_type_counts: dict[str, int] = {}
    task_started: list[Mapping[str, Any]] = []
    task_complete: list[Mapping[str, Any]] = []
    turn_contexts: list[Mapping[str, Any]] = []
    empty_turn_activity = False
    for row in rows:
        kind = row["type"]
        payload = row["payload"]
        row_type_counts[kind] = row_type_counts.get(kind, 0) + 1
        if kind == "response_item":
            item_type = payload.get("type")
            if item_type not in _ROLLOUT_INERT_RESPONSE_ITEM_TYPES:
                raise _rollout_refusal("response_item_not_inert")
            if (
                item_type != "message" or payload.get("role") not in {"user", "developer"}
            ):
                empty_turn_activity = True
            response_item_type_counts[item_type] = (
                response_item_type_counts.get(item_type, 0) + 1
            )
        elif kind == "turn_context":
            turn_contexts.append(payload)
        elif kind == "event_msg":
            event_type = payload.get("type")
            if not isinstance(event_type, str) or not event_type:
                raise _rollout_refusal("event_shape")
            if event_type not in {"task_started", "task_complete"}:
                empty_turn_activity = True
            event_type_counts[event_type] = (
                event_type_counts.get(event_type, 0) + 1
            )
            if event_type == "task_started":
                task_started.append(payload)
            elif event_type == "task_complete":
                task_complete.append(payload)
            elif event_type == "turn_aborted":
                raise _rollout_refusal("turn_aborted")
            elif event_type in _ROLLOUT_ITEM_EVENTS:
                item = payload.get("item")
                item_type = item.get("type") if isinstance(item, Mapping) else None
                if item_type not in _ROLLOUT_INERT_ITEM_TYPES:
                    raise _rollout_refusal("item_not_inert")
                item_type_counts[item_type] = item_type_counts.get(item_type, 0) + 1
    if row_type_counts.get("session_meta") != 1:
        raise _rollout_refusal("session_meta_count")
    session = rows[0]["payload"]
    thread_id = session.get("id")
    if not _IDENTIFIER.fullmatch(str(thread_id)):
        raise _rollout_refusal("thread_id")
    if len(task_started) != 1 or len(task_complete) != 1 or len(turn_contexts) != 1:
        raise _rollout_refusal("single_turn_required")
    turn_id = task_started[0].get("turn_id")
    context = turn_contexts[0]
    if (
        not _IDENTIFIER.fullmatch(str(turn_id))
        or task_complete[0].get("turn_id") != turn_id
        or context.get("turn_id") != turn_id
        or not isinstance(context.get("model"), str)
        or not isinstance(context.get("effort"), str)
    ):
        raise _rollout_refusal("turn_identity")
    git = session.get("git")
    core = {
        "schema": ROOT_ROLLOUT_FAILURE_SUMMARY_SCHEMA,
        "thread_id": str(thread_id),
        "originator": (
            session.get("originator")
            if isinstance(session.get("originator"), str) else None
        ),
        "cli_version": (
            session.get("cli_version")
            if isinstance(session.get("cli_version"), str) else None
        ),
        "git_commit_hash": (
            git.get("commit_hash")
            if isinstance(git, Mapping) and isinstance(git.get("commit_hash"), str)
            else None
        ),
        "turn_id": str(turn_id),
        "model": context["model"],
        "effort": context["effort"],
        "row_count": len(rows),
        "row_type_counts": dict(sorted(row_type_counts.items())),
        "event_type_counts": dict(sorted(event_type_counts.items())),
        "response_item_type_counts": dict(sorted(response_item_type_counts.items())),
        "item_type_counts": dict(sorted(item_type_counts.items())),
    }
    return core, task_complete[0], empty_turn_activity


def _root_rollout_failure_summary(raw: bytes) -> dict[str, Any]:
    """Summarize one failed root turn with an explicit nonempty error."""

    core, completion, _activity = _root_rollout_turn_parts(raw)
    error = completion.get("error")
    message = error.get("message") if isinstance(error, Mapping) else None
    if not isinstance(message, str) or not message.strip():
        raise _rollout_refusal("task_complete_without_error")
    core.update(turn_status="failed", error_message=message[:MAX_ROLLOUT_ERROR_MESSAGE_CHARS],
                error_sha256=_sha(error))
    return {**core, "summary_sha256": _sha(core)}


def _root_rollout_empty_control_summary(raw: bytes) -> dict[str, Any]:
    """Summarize completion without any model response or submitted input.

    The owner must additionally corroborate its exact full-history read.
    """

    core, completion, activity = _root_rollout_turn_parts(raw)
    if activity:
        raise _rollout_refusal("item_not_inert")
    if (
        completion.get("error") is not None
        or "last_agent_message" not in completion
        or completion["last_agent_message"] is not None
    ):
        raise _rollout_refusal("event_shape")
    core.update(turn_status="completed", error_message=None, error_sha256=_sha(None))
    return {**core, "summary_sha256": _sha(core)}


def _owner_terminal_rollout_summary(raw: bytes, terminal: Any) -> dict[str, Any]:
    summarizer = (
        _root_rollout_empty_control_summary
        if _empty_owner_control_turn(terminal)
        else _root_rollout_failure_summary
    )
    return summarizer(raw)


def _read_root_rollout(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str,
) -> tuple[Path, bytes]:
    candidate = Path(path)
    if (
        not candidate.is_absolute()
        or candidate.is_symlink()
        or _DIGEST.fullmatch(str(expected_sha256)) is None
    ):
        raise _rollout_refusal("reference_invalid")
    try:
        resolved = candidate.resolve(strict=True)
        info = resolved.lstat()
        raw = owned_file.read_owned_bytes(
            resolved,
            max_bytes=MAX_ROOT_ROLLOUT_BYTES,
            required_mode=0o600,
        )
    except (OSError, ValueError) as error:
        raise _rollout_refusal("unavailable") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or hashlib.sha256(raw).hexdigest() != expected_sha256
    ):
        raise _rollout_refusal("reference_invalid")
    return resolved, raw


def _empty_owner_control_turn(terminal: Any) -> bool:
    return bool(
        isinstance(terminal, Mapping)
        and terminal.get("phase") == "root_action"
        and terminal.get("issue") == "issue170_owner:control_call_count_invalid"
    )


def _owner_terminal_failure_issues(
    terminal: Any,
    *,
    terminal_path: Path | None,
    expected_root_issue: str | None = None,
) -> list[str]:
    """Name every way one owner terminal fails to attest a refused root turn
    with a closed host."""

    issues: list[str] = []
    if (
        not isinstance(terminal, Mapping)
        or set(terminal) != QUALIFICATION_OWNER_TERMINAL_FIELDS
    ):
        return ["pre_native_failure:owner_terminal_shape_invalid"]
    cleanup = terminal.get("host_cleanup")
    publication = terminal.get("partial_publication")
    if expected_root_issue not in {
        None, *(cut.owner_terminal_issue for cut in native_grant_store.OWNER_CLOSED_ACK_CUTS),
    }:
        return ["pre_native_failure:owner_terminal_refusal_invalid"]
    empty_control_turn = expected_root_issue is None and _empty_owner_control_turn(terminal)
    root_action_failure = expected_root_issue is not None or empty_control_turn
    if expected_root_issue is not None:
        root_issue_valid = terminal.get("issue") == expected_root_issue
    elif empty_control_turn:
        root_issue_valid = True
    else:
        root_issue_valid = terminal.get("issue") in QUALIFICATION_OWNER_TURN_FAILURE_ISSUES
    if (
        terminal.get("schema") != QUALIFICATION_OWNER_TERMINAL_SCHEMA
        or terminal.get("status") != "FAIL"
        or terminal.get("disposition") != "QUALIFICATION_OWNER_TERMINAL_FAILURE"
        or terminal.get("phase") != ("root_action" if root_action_failure else "turn_start")
        or not root_issue_valid
        or terminal.get("missing_seam") is not None
        or terminal.get("promotion_receipt_emitted") is not False
        or terminal.get("terminal_order") != ["cleanup_qualification_host"]
        or type(terminal.get("ticket_id")) is not int
        or not isinstance(terminal.get("repair_branch"), str)
        or not _DIGEST.fullmatch(str(terminal.get("runtime_package_digest", "")))
        or not isinstance(terminal.get("generation"), str)
        or not terminal["generation"]
        or not isinstance(publication, Mapping)
        or publication.get("schema")
        != QUALIFICATION_OWNER_PARTIAL_PUBLICATION_SCHEMA
        or publication.get("state") != "ABSENT"
    ):
        _issue(issues, "pre_native_failure:owner_terminal_refusal_invalid")
    if (
        terminal_path is None
        or terminal.get("terminal_evidence_path") != str(terminal_path)
    ):
        _issue(issues, "pre_native_failure:owner_terminal_path_mismatch")
    if (
        not isinstance(cleanup, Mapping)
        or set(cleanup) != QUALIFICATION_HOST_CLEANUP_FIELDS
    ):
        _issue(issues, "pre_native_failure:owner_host_cleanup_shape_invalid")
    elif (
        cleanup.get("schema") != QUALIFICATION_HOST_CLEANUP_SCHEMA
        or cleanup.get("status") != "PASS"
        or cleanup.get("disposition") != "QUALIFICATION_HOST_CLOSED"
        or cleanup.get("issues") != []
        or cleanup.get("host_closed") is not True
        or cleanup.get("process_group_absent") is not True
        or cleanup.get("owner_socket_absent") is not True
        or cleanup.get("descendants_absent") is not True
        or cleanup.get("remaining_descendants") != 0
        or cleanup.get("process_group_members") != 0
        or cleanup.get("native_calls") != 0
        or cleanup.get("task_creations") != 0
        or cleanup.get("model_calls") != 0
        or cleanup.get("provider_free") is not True
    ):
        _issue(issues, "pre_native_failure:owner_host_not_closed")
    return sorted(issues)


def _owner_terminal_rollout_pairing_issues(
    terminal: Mapping[str, Any],
    summary: Mapping[str, Any],
) -> list[str]:
    """Name every way the owner terminal and the rollout fail to describe
    one owner's one root turn.

    The terminal names no task (its last thread read is unobserved on this
    path) and the rollout names no generation, so the pair is joined through
    what both record independently: the owner wrote its source commit into
    the terminal and the app server wrote the workspace's commit and the
    owner's client name into the rollout's session_meta.
    """

    issues: list[str] = []
    if (
        not isinstance(terminal.get("source_commit"), str)
        or terminal.get("source_commit") != summary.get("git_commit_hash")
    ):
        _issue(issues, "pre_native_failure:owner_terminal_rollout_unpaired")
    if summary.get("originator") != QUALIFICATION_OWNER_ORIGINATOR:
        _issue(issues, "pre_native_failure:root_rollout_originator_mismatch")
    if _empty_owner_control_turn(terminal):
        # The rollout's startup context alone cannot distinguish a refused
        # prompt from work. Re-read the owner's exact full-history observation
        # on every validation, including the locked terminalization boundary.
        reference = terminal.get("last_thread_read")
        try:
            if (
                not isinstance(reference, Mapping)
                or set(reference) != {"path", "sha256", "state"}
                or reference.get("state") != "PRESERVED"
            ):
                raise ValueError("invalid retained observation")
            _, read = _read_pre_native_failure_artifact(
                reference["path"], expected_sha256=reference["sha256"],
                label="pre_native_failure:owner_terminal",
            )
            response = read.get("response")
            result = response.get("result") if isinstance(response, Mapping) else None
            thread = result.get("thread") if isinstance(result, Mapping) else None
            turns = thread.get("turns") if isinstance(thread, Mapping) else None
            if (
                set(read) != {"schema", "request_id", "task_id", "response"}
                or read.get("schema") != "orch-dork/issue170-qualification-owner-last-thread-read/v1"
                or read.get("request_id") != "issue170-root-action-read-0"
                or read.get("task_id") != summary.get("thread_id")
                or not isinstance(response, Mapping)
                or set(response) != {"id", "result"}
                or response.get("id") != read.get("request_id")
                or not isinstance(thread, Mapping)
                or thread.get("id") != summary.get("thread_id")
                or thread.get("status") != {"type": "idle"}
                or not isinstance(turns, list) or len(turns) != 1
                or not isinstance(turns[0], Mapping)
                or turns[0].get("id") != summary.get("turn_id")
                or turns[0].get("status") != "completed"
                or "error" not in turns[0] or turns[0]["error"] is not None
                or turns[0].get("items") != []
                or turns[0].get("itemsView") != "full"
                or summary.get("turn_status") != "completed"
            ):
                raise ValueError("retained observation not an empty first turn")
        except (KeyError, TypeError, ValueError):
            _issue(issues, "pre_native_failure:owner_terminal_rollout_unpaired")
    return sorted(issues)


def build_owner_terminal_pre_native_failure_report(
    *,
    owner_terminal_path: str | os.PathLike[str],
    expected_owner_terminal_sha256: str,
    root_rollout_path: str | os.PathLike[str],
    expected_root_rollout_sha256: str,
) -> dict[str, Any]:
    """Assemble the sealed failure report for an owner-refused root turn.

    The report binds the qualification owner's FAIL terminal and the root
    thread rollout by path and digest and carries the facts the controller
    re-derives from both: which turn failed, how the server reported it, how
    the owner refused it, and that the owner's host was closed.  The caller
    persists it as a 0600 canonical artifact and passes it to
    :func:`build_pre_native_failure_terminalization_program`.  A refusal
    names every issue found, joined by ``, ``.
    """

    terminal_path, terminal = _read_pre_native_failure_artifact(
        owner_terminal_path,
        expected_sha256=expected_owner_terminal_sha256,
        label="pre_native_failure:owner_terminal",
    )
    issues = _owner_terminal_failure_issues(
        terminal, terminal_path=terminal_path
    )
    if issues:
        raise ValueError(", ".join(issues))
    rollout_path, rollout_raw = _read_root_rollout(
        root_rollout_path, expected_sha256=expected_root_rollout_sha256
    )
    summary = _owner_terminal_rollout_summary(rollout_raw, terminal)
    issues = _owner_terminal_rollout_pairing_issues(terminal, summary)
    if issues:
        raise ValueError(", ".join(issues))
    core = {
        "schema": OWNER_TERMINAL_PRE_NATIVE_FAILURE_REPORT_SCHEMA,
        "owner_terminal_artifact": {
            "path": str(terminal_path),
            "artifact_sha256": expected_owner_terminal_sha256,
        },
        "owner_terminal": terminal,
        "root_rollout_artifact": {
            "path": str(rollout_path),
            "artifact_sha256": expected_root_rollout_sha256,
            "size_bytes": len(rollout_raw),
        },
        "root_rollout_summary": summary,
        "task_id": summary["thread_id"],
        "turn_id": summary["turn_id"],
        "turn_status": summary["turn_status"],
        "turn_error_message": summary["error_message"],
        "owner_refusal_phase": terminal["phase"],
        "owner_refusal_issue": terminal["issue"],
        "owner_process_group_cleaned": True,
    }
    report = {**core, "report_sha256": _sha(core)}
    if len(_canonical(report)) > MAX_EVENT_BYTES:
        raise ValueError("pre_native_failure:owner_terminal_report_too_large")
    return report


def build_pre_native_failure_terminalization_program(
    *,
    controller_id: str,
    expected_cursor: Mapping[str, Any],
    failure_report_path: str | os.PathLike[str],
    expected_failure_artifact_sha256: str,
    predecessor_authority_path: str | os.PathLike[str],
    expected_authority_artifact_sha256: str,
    historical_runtime_root: str | os.PathLike[str],
    expected_package_digest: str,
) -> dict[str, Any]:
    """Assemble the one sealed, provider-free abandoned-turn transition."""

    if not _IDENTIFIER.fullmatch(str(controller_id)) or not _cursor_valid(
        expected_cursor
    ):
        raise ValueError("pre_native_failure:identity_invalid")
    failure_path, failure_report = _read_pre_native_failure_artifact(
        failure_report_path,
        expected_sha256=expected_failure_artifact_sha256,
        label="pre_native_failure:failure_artifact",
    )
    authority_path, predecessor_authority = _read_pre_native_failure_artifact(
        predecessor_authority_path,
        expected_sha256=expected_authority_artifact_sha256,
        label="pre_native_failure:authority_artifact",
    )
    runtime_report = _pre_native_failure_runtime_report(
        historical_runtime_root,
        expected_package_digest=expected_package_digest,
    )
    evidence_core = {
        "schema": PRE_NATIVE_FAILURE_EVIDENCE_SCHEMA,
        "failure_artifact": {
            "path": str(failure_path),
            "artifact_sha256": expected_failure_artifact_sha256,
        },
        "failure_report": failure_report,
        "predecessor_authority_artifact": {
            "path": str(authority_path),
            "artifact_sha256": expected_authority_artifact_sha256,
        },
        "predecessor_authority": predecessor_authority,
        "historical_runtime_report": runtime_report,
    }
    failure_evidence = {
        **evidence_core,
        "evidence_sha256": _sha(evidence_core),
    }
    program = {
        "schema": PRE_NATIVE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA,
        "controller_id": controller_id,
        "expected_cursor": deepcopy(dict(expected_cursor)),
        "failure_evidence": failure_evidence,
    }
    if len(_canonical(program)) > MAX_PROGRAM_BYTES:
        raise ValueError("pre_native_failure:program_too_large")
    return program


def build_activation_only_failure_terminalization_program(
    *,
    controller_id: str,
    expected_cursor: Mapping[str, Any],
    abandonment_receipt_path: str | os.PathLike[str],
    expected_receipt_artifact_sha256: str,
    hook_trust_verification_report: Mapping[str, Any],
    historical_runtime_root: str | os.PathLike[str],
    expected_package_digest: str,
) -> dict[str, Any]:
    """Assemble the one sealed transition out of an abandoned activation.

    Canonical state cannot distinguish an abandoned activation from a healthy
    one: at sequence one they are identical by construction, and the activation
    identity records no owner process. The distinguishing fact is therefore
    supplied by a host-signed abandonment receipt, whose signature an ordinary
    caller cannot produce and whose payload the controller re-binds to its own
    canonical identity.
    """

    if not _IDENTIFIER.fullmatch(str(controller_id)) or not _cursor_valid(
        expected_cursor
    ):
        raise ValueError("activation_only_failure:identity_invalid")
    receipt_path, receipt_envelope = _read_pre_native_failure_artifact(
        abandonment_receipt_path,
        expected_sha256=expected_receipt_artifact_sha256,
        label="activation_only_failure:abandonment_receipt",
    )
    runtime_report = _pre_native_failure_runtime_report(
        historical_runtime_root,
        expected_package_digest=expected_package_digest,
    )
    evidence_core = {
        "schema": ACTIVATION_ONLY_FAILURE_EVIDENCE_SCHEMA,
        "abandonment_receipt_artifact": {
            "path": str(receipt_path),
            "artifact_sha256": expected_receipt_artifact_sha256,
        },
        "abandonment_receipt": receipt_envelope,
        "hook_trust_verification_report": deepcopy(
            dict(hook_trust_verification_report)
        ),
        "historical_runtime_report": runtime_report,
    }
    failure_evidence = {
        **evidence_core,
        "evidence_sha256": _sha(evidence_core),
    }
    program = {
        "schema": ACTIVATION_ONLY_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA,
        "controller_id": controller_id,
        "expected_cursor": deepcopy(dict(expected_cursor)),
        "failure_evidence": failure_evidence,
    }
    if len(_canonical(program)) > MAX_PROGRAM_BYTES:
        raise ValueError("activation_only_failure:program_too_large")
    return program


def build_partial_native_failure_terminalization_program(
    *,
    controller_id: str,
    expected_cursor: Mapping[str, Any],
    terminal_snapshot_path: str | os.PathLike[str],
    expected_terminal_snapshot_artifact_sha256: str,
    worker_state_path: str | os.PathLike[str],
    expected_worker_state_artifact_sha256: str,
    worker_rollout_path: str | os.PathLike[str],
    expected_worker_rollout_artifact_sha256: str,
    historical_runtime_root: str | os.PathLike[str],
    expected_package_digest: str,
) -> dict[str, Any]:
    """Assemble one sealed recovery for a known partial native batch."""

    if not _IDENTIFIER.fullmatch(str(controller_id)) or not _cursor_valid(
        expected_cursor
    ):
        raise ValueError("partial_native_failure:identity_invalid")
    snapshot_path, snapshot = _read_pre_native_failure_artifact(
        terminal_snapshot_path,
        expected_sha256=expected_terminal_snapshot_artifact_sha256,
        label="partial_native_failure:terminal_snapshot",
    )
    worker_path, worker_state = _read_pre_native_failure_artifact(
        worker_state_path,
        expected_sha256=expected_worker_state_artifact_sha256,
        label="partial_native_failure:worker_state",
    )
    rollout_path = Path(worker_rollout_path)
    try:
        rollout_resolved = rollout_path.resolve(strict=True)
        rollout_info = rollout_resolved.lstat()
        rollout_raw = owned_file.read_owned_bytes(
            rollout_resolved,
            max_bytes=2_097_152,
            required_mode=0o600,
        )
    except (OSError, ValueError) as error:
        raise ValueError(
            "partial_native_failure:worker_rollout:reference_invalid"
        ) from error
    if (
        not rollout_path.is_absolute()
        or rollout_path.is_symlink()
        or not stat.S_ISREG(rollout_info.st_mode)
        or rollout_resolved.parent != snapshot_path.parent
        or worker_path.parent != snapshot_path.parent
        or not _DIGEST.fullmatch(
            str(expected_worker_rollout_artifact_sha256)
        )
        or hashlib.sha256(rollout_raw).hexdigest()
        != expected_worker_rollout_artifact_sha256
    ):
        raise ValueError(
            "partial_native_failure:worker_rollout:reference_invalid"
        )
    runtime_report = _pre_native_failure_runtime_report(
        historical_runtime_root,
        expected_package_digest=expected_package_digest,
    )
    evidence_core = {
        "schema": PARTIAL_NATIVE_FAILURE_EVIDENCE_SCHEMA,
        "terminal_snapshot_artifact": {
            "path": str(snapshot_path),
            "artifact_sha256": expected_terminal_snapshot_artifact_sha256,
        },
        "terminal_snapshot": snapshot,
        "worker_state_artifact": {
            "path": str(worker_path),
            "artifact_sha256": expected_worker_state_artifact_sha256,
        },
        "worker_state": worker_state,
        "worker_rollout_artifact": {
            "path": str(rollout_resolved),
            "artifact_sha256": expected_worker_rollout_artifact_sha256,
            "size_bytes": len(rollout_raw),
        },
        "historical_runtime_report": runtime_report,
    }
    evidence = {
        **evidence_core,
        "evidence_sha256": _sha(evidence_core),
    }
    program = {
        "schema": PARTIAL_NATIVE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA,
        "controller_id": controller_id,
        "expected_cursor": deepcopy(dict(expected_cursor)),
        "failure_evidence": evidence,
    }
    if len(_canonical(program)) > MAX_PROGRAM_BYTES:
        raise ValueError("partial_native_failure:program_too_large")
    return program


def _read_post_spawn_json_artifact(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str,
    label: str,
) -> tuple[Path, dict[str, Any], int]:
    """Read one exact owned recovery artifact without rewriting its bytes."""

    candidate = Path(path)
    if (
        not candidate.is_absolute()
        or candidate.is_symlink()
        or _DIGEST.fullmatch(str(expected_sha256)) is None
    ):
        raise ValueError(label + ":reference_invalid")
    try:
        resolved = candidate.resolve(strict=True)
        raw = owned_file.read_owned_bytes(
            resolved,
            max_bytes=4_194_304,
            required_mode=0o600,
        )
        value = json.loads(raw.decode("utf-8"))
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        raise ValueError(label + ":unavailable") from error
    if (
        not isinstance(value, Mapping)
        or hashlib.sha256(raw).hexdigest() != expected_sha256
    ):
        raise ValueError(label + ":reference_invalid")
    return resolved, deepcopy(dict(value)), len(raw)


class _OwnedRolloutRead(NamedTuple):
    path: Path
    raw: bytes
    rows: tuple[Mapping[str, Any], ...]


class _OwnerClosedAckArtifact(NamedTuple):
    path: Path
    document: Mapping[str, Any] | None


def _read_post_spawn_rollout_rows(path, *, expected_sha256):
    """Own and verify one byte buffer, then parse its JSONL rows once."""

    candidate = Path(path)
    if (not candidate.is_absolute() or candidate.is_symlink()
            or _DIGEST.fullmatch(str(expected_sha256)) is None):
        raise ValueError("post_spawn_failure:rollout_reference_invalid")
    try:
        resolved = candidate.resolve(strict=True)
        raw = owned_file.read_owned_bytes(resolved, max_bytes=4_194_304, required_mode=0o600)
    except (OSError, ValueError) as error:
        raise ValueError("post_spawn_failure:rollout_reference_invalid") from error
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("post_spawn_failure:rollout_reference_invalid")
    rows = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("post_spawn_failure:rollout_json_invalid") from error
        if not isinstance(row, Mapping):
            raise ValueError("post_spawn_failure:rollout_json_invalid")
        rows.append(row)
    return _OwnedRolloutRead(resolved, raw, tuple(rows))


def _post_spawn_rollout_summary_from_rows(read: _OwnedRolloutRead, *, expected_sha256, role, logical_lane_id):
    if (role not in {"root", "worker"}
            or (role == "root") is not (logical_lane_id is None)
            or (logical_lane_id is not None and _IDENTIFIER.fullmatch(logical_lane_id) is None)):
        raise ValueError("post_spawn_failure:rollout_reference_invalid")
    session_meta: Mapping[str, Any] | None = None
    turn_context: Mapping[str, Any] | None = None
    task_complete_count = 0
    terminal_error_present = False
    turn_ids: set[str] = set()
    for row in read.rows:
        payload = row.get("payload")
        if (
            isinstance(payload, Mapping)
            and isinstance(payload.get("turn_id"), str)
            and payload["turn_id"].strip()
        ):
            turn_ids.add(str(payload["turn_id"]))
        if row.get("type") == "session_meta" and isinstance(payload, Mapping):
            if session_meta is not None:
                raise ValueError(
                    "post_spawn_failure:rollout_session_meta_ambiguous"
                )
            session_meta = deepcopy(dict(payload))
        elif (
            row.get("type") == "turn_context"
            and isinstance(payload, Mapping)
            and turn_context is None
        ):
            turn_context = deepcopy(dict(payload))
        elif (
            row.get("type") == "event_msg"
            and isinstance(payload, Mapping)
            and payload.get("type") == "task_complete"
        ):
            task_complete_count += 1
            terminal_error_present = terminal_error_present or isinstance(
                payload.get("error"), Mapping
            )
    if not isinstance(session_meta, Mapping):
        raise ValueError("post_spawn_failure:rollout_session_meta_missing")
    git = (
        session_meta.get("git")
        if isinstance(session_meta.get("git"), Mapping)
        else {}
    )
    source = session_meta.get("source")
    spawn = (
        source.get("subagent", {}).get("thread_spawn")
        if isinstance(source, Mapping)
        and isinstance(source.get("subagent"), Mapping)
        and isinstance(source["subagent"].get("thread_spawn"), Mapping)
        else None
    )
    core = {
        "role": role,
        "logical_lane_id": logical_lane_id,
        "session_id": session_meta.get("id"),
        "parent_thread_id": session_meta.get("parent_thread_id"),
        "spawn_parent_thread_id": (
            spawn.get("parent_thread_id")
            if isinstance(spawn, Mapping)
            else None
        ),
        "candidate_commit": git.get("commit_hash"),
        "model": (
            turn_context.get("model")
            if isinstance(turn_context, Mapping)
            else None
        ),
        "effort": (
            turn_context.get("effort")
            if isinstance(turn_context, Mapping)
            else None
        ),
        "task_complete_count": task_complete_count,
        "terminal_error_present": terminal_error_present,
        "turn_ids": sorted(turn_ids),
        "artifact": {
            "path": str(read.path),
            "artifact_sha256": expected_sha256,
            "size_bytes": len(read.raw),
        },
    }
    return {**core, "summary_sha256": _sha(core)}



def _post_spawn_rollout_summary(
    path: str | os.PathLike[str], *, expected_sha256: str,
    role: str, logical_lane_id: str | None,
) -> tuple[Path, dict[str, Any]]:
    """Bind one root/worker rollout without embedding its potentially large bytes."""

    read = _read_post_spawn_rollout_rows(path, expected_sha256=expected_sha256)
    return read.path, _post_spawn_rollout_summary_from_rows(
        read, expected_sha256=expected_sha256, role=role, logical_lane_id=logical_lane_id,
    )

def build_post_spawn_failure_terminalization_program(
    *,
    controller_id: str,
    expected_cursor: Mapping[str, Any],
    dedicated_run_path: str | os.PathLike[str],
    expected_dedicated_run_artifact_sha256: str,
    attempt_envelope_path: str | os.PathLike[str],
    expected_attempt_envelope_artifact_sha256: str,
    pre_turn_report_path: str | os.PathLike[str],
    expected_pre_turn_artifact_sha256: str,
    root_rollout_path: str | os.PathLike[str],
    expected_root_rollout_artifact_sha256: str,
    worker_rollout_paths: Mapping[str, str | os.PathLike[str]],
    expected_worker_rollout_artifact_sha256: Mapping[str, str],
    historical_runtime_root: str | os.PathLike[str],
    expected_package_digest: str,
) -> dict[str, Any]:
    """Assemble the sealed exact-two-worker Cycle 31 recovery program."""

    if (
        _IDENTIFIER.fullmatch(str(controller_id)) is None
        or not _cursor_valid(expected_cursor)
        or not isinstance(worker_rollout_paths, Mapping)
        or not isinstance(expected_worker_rollout_artifact_sha256, Mapping)
        or set(worker_rollout_paths)
        != set(expected_worker_rollout_artifact_sha256)
        or len(worker_rollout_paths) != 2
        or any(
            _IDENTIFIER.fullmatch(str(lane)) is None
            for lane in worker_rollout_paths
        )
    ):
        raise ValueError("post_spawn_failure:identity_invalid")
    dedicated_path, dedicated, dedicated_size = (
        _read_post_spawn_json_artifact(
            dedicated_run_path,
            expected_sha256=expected_dedicated_run_artifact_sha256,
            label="post_spawn_failure:dedicated_run",
        )
    )
    envelope_path, envelope, envelope_size = (
        _read_post_spawn_json_artifact(
            attempt_envelope_path,
            expected_sha256=expected_attempt_envelope_artifact_sha256,
            label="post_spawn_failure:attempt_envelope",
        )
    )
    pre_turn_path, pre_turn, pre_turn_size = (
        _read_post_spawn_json_artifact(
            pre_turn_report_path,
            expected_sha256=expected_pre_turn_artifact_sha256,
            label="post_spawn_failure:pre_turn",
        )
    )
    roots = {dedicated_path.parent, envelope_path.parent, pre_turn_path.parent}
    root_path, root_rollout = _post_spawn_rollout_summary(
        root_rollout_path,
        expected_sha256=expected_root_rollout_artifact_sha256,
        role="root",
        logical_lane_id=None,
    )
    roots.add(root_path.parent)
    worker_rollouts: list[dict[str, Any]] = []
    for lane_id in sorted(worker_rollout_paths):
        worker_path, summary = _post_spawn_rollout_summary(
            worker_rollout_paths[lane_id],
            expected_sha256=expected_worker_rollout_artifact_sha256[
                lane_id
            ],
            role="worker",
            logical_lane_id=str(lane_id),
        )
        roots.add(worker_path.parent)
        worker_rollouts.append(summary)
    if len(roots) != 1:
        raise ValueError("post_spawn_failure:evidence_root_mismatch")
    runtime_report = _pre_native_failure_runtime_report(
        historical_runtime_root,
        expected_package_digest=expected_package_digest,
    )
    evidence_core = {
        "schema": POST_SPAWN_FAILURE_EVIDENCE_SCHEMA,
        "evidence_root": str(next(iter(roots))),
        "dedicated_run_artifact": {
            "path": str(dedicated_path),
            "artifact_sha256": expected_dedicated_run_artifact_sha256,
            "size_bytes": dedicated_size,
        },
        "dedicated_run": dedicated,
        "attempt_envelope_artifact": {
            "path": str(envelope_path),
            "artifact_sha256": expected_attempt_envelope_artifact_sha256,
            "size_bytes": envelope_size,
        },
        "attempt_envelope": envelope,
        "pre_turn_artifact": {
            "path": str(pre_turn_path),
            "artifact_sha256": expected_pre_turn_artifact_sha256,
            "size_bytes": pre_turn_size,
        },
        "pre_turn_report": pre_turn,
        "root_rollout": root_rollout,
        "worker_rollouts": worker_rollouts,
        "historical_runtime_report": runtime_report,
    }
    evidence = {**evidence_core, "evidence_sha256": _sha(evidence_core)}
    program = {
        "schema": POST_SPAWN_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA,
        "controller_id": controller_id,
        "expected_cursor": deepcopy(dict(expected_cursor)),
        "failure_evidence": evidence,
    }
    if len(_canonical(program)) > MAX_PROGRAM_BYTES:
        raise ValueError("post_spawn_failure:program_too_large")
    return program


def _embedded_json_objects(value: Any, *, depth: int = 0):
    """Yield bounded JSON objects embedded in recorded tool output."""

    if depth > 12:
        return
    if isinstance(value, Mapping):
        yield value
        for nested in value.values():
            yield from _embedded_json_objects(nested, depth=depth + 1)
        return
    if isinstance(value, list):
        for nested in value:
            yield from _embedded_json_objects(nested, depth=depth + 1)
        return
    if not isinstance(value, str) or len(value) > 4_194_304:
        return
    stripped = value.strip()
    candidates = [stripped]
    if "\nOutput:\n" in stripped:
        candidates.append(stripped.rsplit("\nOutput:\n", 1)[1].strip())
    for candidate in candidates:
        if not candidate.startswith(("{", "[")):
            continue
        try:
            decoded = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        yield from _embedded_json_objects(decoded, depth=depth + 1)
        break


def _post_ack_bridge_root_rollout_summary(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str,
) -> tuple[Path, dict[str, Any]]:
    """Bind one interrupted ACK-only root and its exact failed bridge."""

    resolved, base = _post_spawn_rollout_summary(
        path,
        expected_sha256=expected_sha256,
        role="root",
        logical_lane_id=None,
    )
    try:
        raw = owned_file.read_owned_bytes(
            resolved,
            max_bytes=4_194_304,
            required_mode=0o600,
        )
    except (OSError, ValueError) as error:
        raise ValueError(
            "post_ack_bridge_failure:root_rollout_invalid"
        ) from error
    spawn_call_ids: list[str] = []
    spawn_outputs: dict[str, str] = {}
    send_input_calls: dict[str, dict[str, Any]] = {}
    send_input_outputs: dict[str, dict[str, str]] = {}
    stop_denials = 0
    bridge_refusal_call_ids: set[str] = set()
    refusal_reports: dict[str, dict[str, Any]] = {}
    blocked_bridge_call_ids: set[str] = set()
    blocked_bridge_text = (
        "Tool call blocked by PreToolUse hook: "
        "native_controller:exact_action_required. Tool: "
        "mcp__orch_dork__advance_issue94_successor_after_native_action"
    )
    denied_prefix = (
        "Tool call blocked by PreToolUse hook: "
        "native_controller:exact_action_required. Tool: "
    )
    for raw_line in raw.splitlines():
        if not raw_line.strip():
            continue
        try:
            row = json.loads(raw_line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError(
                "post_ack_bridge_failure:root_rollout_json_invalid"
            ) from error
        if not isinstance(row, Mapping):
            raise ValueError(
                "post_ack_bridge_failure:root_rollout_json_invalid"
            )
        payload = row.get("payload")
        if not isinstance(payload, Mapping):
            continue
        payload_type = payload.get("type")
        if row.get("type") == "response_item" and payload_type == "function_call":
            if payload.get("name") == "spawn_agent":
                call_id = payload.get("call_id")
                if not isinstance(call_id, str) or not call_id:
                    raise ValueError(
                        "post_ack_bridge_failure:spawn_call_invalid"
                    )
                spawn_call_ids.append(call_id)
            elif payload.get("name") == "send_input":
                call_id = payload.get("call_id")
                arguments = payload.get("arguments")
                try:
                    tool_input = (
                        json.loads(arguments)
                        if isinstance(arguments, str)
                        else None
                    )
                except json.JSONDecodeError:
                    tool_input = None
                if (
                    not isinstance(call_id, str)
                    or not call_id
                    or call_id in send_input_calls
                    or not isinstance(tool_input, Mapping)
                ):
                    raise ValueError(
                        "post_ack_bridge_failure:send_input_call_invalid"
                    )
                send_input_calls[call_id] = {
                    "call_id": call_id,
                    "namespace": payload.get("namespace"),
                    "tool_input_sha256": _sha(tool_input),
                }
        elif (
            row.get("type") == "response_item"
            and payload_type == "function_call_output"
            and payload.get("call_id") in spawn_call_ids
        ):
            call_id = str(payload["call_id"])
            output = payload.get("output")
            try:
                decoded = json.loads(output) if isinstance(output, str) else output
            except json.JSONDecodeError:
                decoded = None
            worker_id = (
                decoded.get("agent_id")
                if isinstance(decoded, Mapping)
                else None
            )
            if (
                not isinstance(worker_id, str)
                or _IDENTIFIER.fullmatch(worker_id) is None
                or call_id in spawn_outputs
            ):
                raise ValueError(
                    "post_ack_bridge_failure:spawn_output_invalid"
                )
            spawn_outputs[call_id] = worker_id
        elif (
            row.get("type") == "response_item"
            and payload_type == "function_call_output"
            and payload.get("call_id") in send_input_calls
        ):
            call_id = str(payload["call_id"])
            output = payload.get("output")
            hook_tool_name = (
                output.removeprefix(denied_prefix)
                if isinstance(output, str)
                and output.startswith(denied_prefix)
                else None
            )
            if (
                not isinstance(hook_tool_name, str)
                or not hook_tool_name
                or len(hook_tool_name) > 256
                or call_id in send_input_outputs
            ):
                raise ValueError(
                    "post_ack_bridge_failure:send_input_output_invalid"
                )
            send_input_outputs[call_id] = {
                **send_input_calls[call_id],
                "hook_tool_name": hook_tool_name,
            }
        if (
            payload_type == "message"
            and payload.get("role") == "user"
        ):
            stop_denials += _canonical(payload).decode("utf-8").count(
                "native_controller:terminal_state_required"
            )
        if (
            row.get("type") == "response_item"
            and payload_type == "custom_tool_call_output"
        ):
            if blocked_bridge_text in _canonical(payload).decode("utf-8"):
                call_id = payload.get("call_id")
                if (
                    not isinstance(call_id, str)
                    or not call_id
                    or call_id in blocked_bridge_call_ids
                ):
                    raise ValueError(
                        "post_ack_bridge_failure:blocked_bridge_invalid"
                    )
                blocked_bridge_call_ids.add(call_id)
            row_refusals: dict[str, dict[str, Any]] = {}
            for embedded in _embedded_json_objects(payload):
                if (
                    embedded.get("schema")
                    == "orch-dork/qualification-successor-action-advance/v2"
                    and embedded.get("status") == "BLOCKED"
                    and embedded.get("decision") == "REFUSED"
                ):
                    report = deepcopy(dict(embedded))
                    row_refusals[_sha(report)] = report
            if row_refusals:
                call_id = payload.get("call_id")
                if (
                    not isinstance(call_id, str)
                    or not call_id
                    or call_id in bridge_refusal_call_ids
                    or len(row_refusals) != 1
                ):
                    raise ValueError(
                        "post_ack_bridge_failure:bridge_refusal_invalid"
                    )
                bridge_refusal_call_ids.add(call_id)
                refusal_reports.update(row_refusals)
    if (
        len(spawn_call_ids) != 2
        or len(set(spawn_call_ids)) != 2
        or set(spawn_outputs) != set(spawn_call_ids)
        or len(refusal_reports) > 1
        or len(send_input_calls) > 1
        or set(send_input_outputs) != set(send_input_calls)
    ):
        raise ValueError("post_ack_bridge_failure:root_rollout_invalid")
    refusals = list(refusal_reports.values())
    denied_send_input = (
        next(iter(send_input_outputs.values()))
        if send_input_outputs
        else None
    )
    core = {
        **{
            key: deepcopy(value)
            for key, value in base.items()
            if key != "summary_sha256"
        },
        "spawn_call_ids": list(spawn_call_ids),
        "spawn_worker_ids": [spawn_outputs[item] for item in spawn_call_ids],
        "send_input_call_count": len(send_input_calls),
        "denied_send_input": denied_send_input,
        "stop_denial_count": stop_denials,
        "bridge_refusal_invocation_count": len(bridge_refusal_call_ids),
        "bridge_refusal": refusals[0] if refusals else None,
        "bridge_refusals": refusals,
        "blocked_bridge_invocation_count": len(blocked_bridge_call_ids),
    }
    return resolved, {**core, "summary_sha256": _sha(core)}


def _owner_closed_second_continuation_root_rollout_summary(
    path: str | os.PathLike[str], *, expected_sha256: str,
) -> tuple[Path, dict[str, Any]]:
    """Read the generation-67 two-send cut; this grants no recovery authority.

    The ACK-only reader remains separate. Durable hook/action, owner closure,
    capacity and worker receipt binding must precede any terminal mutation.
    """
    resolved, base = _post_spawn_rollout_summary(
        path, expected_sha256=expected_sha256, role="root", logical_lane_id=None,
    )
    raw = owned_file.read_owned_bytes(resolved, max_bytes=4_194_304, required_mode=0o600)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("owner_closed_second_continuation:artifact_changed")
    calls, outputs, contexts, completions, starts = [], {}, [], [], []
    for line in raw.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        payload = row.get("payload")
        if not isinstance(payload, Mapping):
            raise ValueError("owner_closed_second_continuation:root_rollout_invalid")
        kind = payload.get("type")
        if row.get("type") == "response_item":
            if kind == "function_call":
                arguments = json.loads(payload["arguments"])
                if not isinstance(arguments, Mapping):
                    raise ValueError("owner_closed_second_continuation:root_input_invalid")
                calls.append({"name": payload.get("name"), "namespace": payload.get("namespace"),
                              "call_id": payload.get("call_id"), "tool_input_sha256": _sha(arguments)})
            elif kind == "function_call_output":
                call_id = payload.get("call_id")
                if call_id in outputs:
                    raise ValueError("owner_closed_second_continuation:duplicate_output")
                outputs[call_id] = payload.get("output")
            elif kind not in {"message", "reasoning", "compaction"}:
                raise ValueError("owner_closed_second_continuation:extra_root_tool")
        elif row.get("type") == "turn_context":
            contexts.append(payload.get("turn_id"))
        elif row.get("type") == "event_msg" and kind == "task_started":
            starts.append(payload.get("turn_id"))
        elif row.get("type") == "event_msg" and kind == "task_complete":
            if payload.get("error") is not None:
                raise ValueError("owner_closed_second_continuation:root_unfinished")
            completions.append(payload.get("turn_id"))
    expected = [("mcp__orch_dork", "authorize_issue94_successor_first_action"),
                ("multi_agent_v1", "spawn_agent"), ("multi_agent_v1", "spawn_agent"),
                ("multi_agent_v1", "wait_agent"),
                ("mcp__orch_dork", "advance_issue94_successor_after_native_action"),
                ("multi_agent_v1", "send_input"), ("multi_agent_v1", "send_input")]
    ids = [call["call_id"] for call in calls]
    if ([(call["namespace"], call["name"]) for call in calls] != expected
            or any(not isinstance(item, str) or not item for item in ids)
            or len(set(ids)) != 7 or set(outputs) != set(ids)
            or len(contexts) != 6 or len(set(contexts)) != 6
            or contexts != starts or contexts != completions
            or len(base["turn_ids"]) != 6):
        raise ValueError("owner_closed_second_continuation:root_rollout_invalid")
    spawns = [json.loads(outputs[call["call_id"]]) for call in calls[1:3]]
    successful = json.loads(outputs[calls[5]["call_id"]])
    if (any(not isinstance(item, Mapping) or set(item) != {"agent_id", "nickname"}
            or not isinstance(item["agent_id"], str) or not _IDENTIFIER.fullmatch(item["agent_id"])
            for item in spawns) or len({item["agent_id"] for item in spawns}) != 2
            or not isinstance(successful, Mapping) or set(successful) != {"submission_id"}
            or not isinstance(successful["submission_id"], str)
            or not _IDENTIFIER.fullmatch(successful["submission_id"])):
        raise ValueError("owner_closed_second_continuation:root_result_invalid")
    denial = outputs[calls[6]["call_id"]]
    expected_denial = ("Tool call blocked by PreToolUse hook: "
                       "native_controller:exact_action_required. Tool: multi_agent_v1send_input")
    if denial != expected_denial:
        raise ValueError("owner_closed_second_continuation:denial_invalid")
    core = {**{key: value for key, value in base.items() if key != "summary_sha256"},
            "spawn_calls": calls[1:3], "spawn_worker_ids": [item["agent_id"] for item in spawns],
            "completed_send_input": {**calls[5], **successful, "result_sha256": _sha(outputs[calls[5]["call_id"]])},
            "denied_send_input": {**calls[6], "hook_tool_name": "multi_agent_v1send_input"},
            "send_input_call_count": 2}
    return resolved, {**core, "summary_sha256": _sha(core)}


def _post_ack_bridge_worker_rollout_summary(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str,
    logical_lane_id: str,
    observer_id: str,
) -> tuple[Path, dict[str, Any]]:
    """Bind one terminal ACK-only child rollout without retaining prompts."""

    resolved, base = _post_spawn_rollout_summary(
        path,
        expected_sha256=expected_sha256,
        role="worker",
        logical_lane_id=logical_lane_id,
    )
    observation = routing_verify.observe_session_runtime(
        str(resolved),
        session_id=str(base.get("session_id", "")),
        observer_id=observer_id,
    )
    core = {
        **{
            key: deepcopy(value)
            for key, value in base.items()
            if key != "summary_sha256"
        },
        "runtime_observation": observation,
    }
    return resolved, {**core, "summary_sha256": _sha(core)}


def build_post_ack_bridge_failure_terminalization_program(
    *,
    controller_id: str,
    expected_cursor: Mapping[str, Any],
    dedicated_run_path: str | os.PathLike[str],
    expected_dedicated_run_artifact_sha256: str,
    attempt_envelope_path: str | os.PathLike[str],
    expected_attempt_envelope_artifact_sha256: str,
    pre_turn_report_path: str | os.PathLike[str],
    expected_pre_turn_artifact_sha256: str,
    root_rollout_path: str | os.PathLike[str],
    expected_root_rollout_artifact_sha256: str,
    worker_rollout_paths: Mapping[str, str | os.PathLike[str]],
    expected_worker_rollout_artifact_sha256: Mapping[str, str],
    historical_runtime_root: str | os.PathLike[str],
    expected_package_digest: str,
    pretool_denial_path: str | os.PathLike[str] | None = None,
    expected_pretool_denial_artifact_sha256: str | None = None,
) -> dict[str, Any]:
    """Assemble a sealed exact-two-ACK-worker recovery program."""

    if (
        _IDENTIFIER.fullmatch(str(controller_id)) is None
        or not _cursor_valid(expected_cursor)
        or not isinstance(worker_rollout_paths, Mapping)
        or not isinstance(expected_worker_rollout_artifact_sha256, Mapping)
        or set(worker_rollout_paths)
        != set(expected_worker_rollout_artifact_sha256)
        or len(worker_rollout_paths) != 2
        or any(
            _IDENTIFIER.fullmatch(str(lane)) is None
            for lane in worker_rollout_paths
        )
        or (
            (pretool_denial_path is None)
            != (expected_pretool_denial_artifact_sha256 is None)
        )
    ):
        raise ValueError("post_ack_bridge_failure:identity_invalid")
    dedicated_path, dedicated, dedicated_size = (
        _read_post_spawn_json_artifact(
            dedicated_run_path,
            expected_sha256=expected_dedicated_run_artifact_sha256,
            label="post_ack_bridge_failure:dedicated_run",
        )
    )
    envelope_path, envelope, envelope_size = (
        _read_post_spawn_json_artifact(
            attempt_envelope_path,
            expected_sha256=expected_attempt_envelope_artifact_sha256,
            label="post_ack_bridge_failure:attempt_envelope",
        )
    )
    pre_turn_path, pre_turn, pre_turn_size = (
        _read_post_spawn_json_artifact(
            pre_turn_report_path,
            expected_sha256=expected_pre_turn_artifact_sha256,
            label="post_ack_bridge_failure:pre_turn",
        )
    )
    roots = {dedicated_path.parent, envelope_path.parent, pre_turn_path.parent}
    denial_path = None
    denial = None
    denial_size = None
    if pretool_denial_path is not None:
        denial_path, denial, denial_size = _read_post_spawn_json_artifact(
            pretool_denial_path,
            expected_sha256=str(expected_pretool_denial_artifact_sha256),
            label="post_ack_bridge_failure:pretool_denial",
        )
        roots.add(denial_path.parent)
    root_path, root_rollout = _post_ack_bridge_root_rollout_summary(
        root_rollout_path,
        expected_sha256=expected_root_rollout_artifact_sha256,
    )
    roots.add(root_path.parent)
    observer_id = str(dedicated.get("task_id", ""))
    worker_rollouts: list[dict[str, Any]] = []
    for lane_id in sorted(worker_rollout_paths):
        worker_path, summary = _post_ack_bridge_worker_rollout_summary(
            worker_rollout_paths[lane_id],
            expected_sha256=expected_worker_rollout_artifact_sha256[lane_id],
            logical_lane_id=str(lane_id),
            observer_id=observer_id,
        )
        roots.add(worker_path.parent)
        worker_rollouts.append(summary)
    if len(roots) != 1:
        raise ValueError("post_ack_bridge_failure:evidence_root_mismatch")
    runtime_report = _pre_native_failure_runtime_report(
        historical_runtime_root,
        expected_package_digest=expected_package_digest,
    )
    evidence_core = {
        "schema": (
            POST_ACK_BRIDGE_FAILURE_EVIDENCE_SCHEMA_V2
            if denial is not None
            else POST_ACK_BRIDGE_FAILURE_EVIDENCE_SCHEMA
        ),
        "evidence_root": str(next(iter(roots))),
        "dedicated_run_artifact": {
            "path": str(dedicated_path),
            "artifact_sha256": expected_dedicated_run_artifact_sha256,
            "size_bytes": dedicated_size,
        },
        "dedicated_run": dedicated,
        "attempt_envelope_artifact": {
            "path": str(envelope_path),
            "artifact_sha256": expected_attempt_envelope_artifact_sha256,
            "size_bytes": envelope_size,
        },
        "attempt_envelope": envelope,
        "pre_turn_artifact": {
            "path": str(pre_turn_path),
            "artifact_sha256": expected_pre_turn_artifact_sha256,
            "size_bytes": pre_turn_size,
        },
        "pre_turn_report": pre_turn,
        "root_rollout": root_rollout,
        "worker_rollouts": worker_rollouts,
        "historical_runtime_report": runtime_report,
    }
    if denial is not None:
        evidence_core.update(
            {
                "pretool_denial_artifact": {
                    "path": str(denial_path),
                    "artifact_sha256": (
                        expected_pretool_denial_artifact_sha256
                    ),
                    "size_bytes": denial_size,
                },
                "pretool_denial": denial,
            }
        )
    evidence = {**evidence_core, "evidence_sha256": _sha(evidence_core)}
    program = {
        "schema": POST_ACK_BRIDGE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA,
        "controller_id": controller_id,
        "expected_cursor": deepcopy(dict(expected_cursor)),
        "failure_evidence": evidence,
    }
    if len(_canonical(program)) > MAX_PROGRAM_BYTES:
        raise ValueError("post_ack_bridge_failure:program_too_large")
    return program


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(_canonical(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _cursor(rows: list[Mapping[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    row = rows[-1]
    return {
        "run_id": row["run_id"],
        "seq": row["seq"],
        "event_hash": row["event_hash"],
    }


def _cursor_valid(value: Any) -> bool:
    return bool(
        isinstance(value, Mapping)
        and set(value) == {"run_id", "seq", "event_hash"}
        and isinstance(value.get("run_id"), str)
        and type(value.get("seq")) is int
        and value.get("seq", 0) >= 1
        and isinstance(value.get("event_hash"), str)
        and _DIGEST.fullmatch(value["event_hash"]) is not None
    )


def _controller_run_id(controller_id: str) -> str:
    # RunEngine intentionally has a narrow historical ID grammar.
    return "nativecontroller-" + hashlib.sha256(controller_id.encode()).hexdigest()[:24]


_ACTION_EVIDENCE_ROW_FIELDS = frozenset(
    {
        "action",
        "pretool_report_sha256",
        "pretool_durable_record_sha256",
        "posttool_report_sha256",
        "posttool_durable_record_sha256",
        "result_binding",
    }
)


def _reconciled_continue_rows_valid(
    rows: list[Mapping[str, Any]],
    *,
    batch_id: Any,
    batch_lane_ids: list[Any],
    batch_lanes: list[Mapping[str, Any]],
) -> bool:
    """Whether ``rows`` are the owner-reconciled continuations of one batch,
    in wave order from its first lane, each sent to the worker its lane's
    spawn created and each carrying a valid continue result binding."""

    return bool(
        len(rows) <= len(batch_lane_ids) == len(batch_lanes)
        and all(
            isinstance(row, Mapping)
            and set(row) == _ACTION_EVIDENCE_ROW_FIELDS
            and isinstance(row.get("action"), Mapping)
            and row["action"].get("kind") == "continue"
            and row["action"].get("batch_kind") == "continue"
            and row["action"].get("batch_phase") == "primary"
            and row["action"].get("tool_name") == DIRECT_NATIVE_TOOLS["continue"]
            and row["action"].get("batch_id") == batch_id
            and row["action"].get("batch_index") == index
            and row["action"].get("batch_size") == len(batch_lane_ids)
            and row["action"].get("batch_lane_ids") == batch_lane_ids
            and row["action"].get("lane_ids") == [batch_lane_ids[index]]
            and isinstance(row["action"].get("tool_input"), Mapping)
            and row["action"]["tool_input"].get("target")
            == batch_lanes[index].get("agent_id")
            and all(
                _DIGEST.fullmatch(str(row.get(field, ""))) is not None
                for field in (
                    "pretool_report_sha256",
                    "pretool_durable_record_sha256",
                    "posttool_report_sha256",
                    "posttool_durable_record_sha256",
                )
            )
            and native_result.continue_result_binding(
                row.get("result_binding"), [batch_lane_ids[index]]
            )
            is not None
            for index, row in enumerate(rows)
        )
    )


def _event_record(event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    core = {
        "schema": EVENT_SCHEMA,
        "event_type": event_type,
        "payload": deepcopy(dict(payload)),
    }
    if len(_canonical(core)) > MAX_EVENT_BYTES:
        raise ValueError("controller_event:too_large")
    return {**core, "event_sha256": _sha(core)}


def _controller_events(rows: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in rows:
        if row.get("kind") == run_engine.KIND_STARTED:
            facts = json.loads(str(row["payload"]))
            plan = facts.get("plan") if isinstance(facts, Mapping) else None
            origin = plan.get("origin") if isinstance(plan, Mapping) else None
            activation = (
                origin.get("governed_native_activation")
                if isinstance(origin, Mapping)
                else None
            )
            if not isinstance(activation, Mapping):
                raise ValueError("controller_event:activation_missing")
            declared = origin.get("activation_sha256")
            if declared != _sha(activation):
                raise ValueError("controller_event:activation_seal_invalid")
            events.append(_event_record("activated", activation))
            continue
        if row.get("kind") != run_engine.KIND_APPLIED:
            continue
        facts = json.loads(str(row["payload"]))
        raw = facts.get("deliverables", {}).get("controller_event")
        if not isinstance(raw, str):
            raise ValueError("controller_event:missing")
        event = json.loads(raw)
        if not isinstance(event, Mapping) or set(event) != {
            "schema",
            "event_type",
            "payload",
            "event_sha256",
        }:
            raise ValueError("controller_event:invalid")
        if event.get("schema") != EVENT_SCHEMA:
            raise ValueError("controller_event:schema_invalid")
        core = {key: event[key] for key in ("schema", "event_type", "payload")}
        if event.get("event_sha256") != _sha(core):
            raise ValueError("controller_event:seal_invalid")
        events.append(deepcopy(dict(event)))
    return events


def _reduce(events: list[Mapping[str, Any]]) -> dict[str, Any]:
    state: dict[str, Any] = {
        "activation": None,
        "stage_report": None,
        "action": None,
        "action_outcome": None,
        "pending_intent": None,
        "terminal": False,
        "cleanup_required": False,
        "terminal_evidence_sha256": None,
        "seen_action_ids": [],
        "action_evidence": [],
        "last_action_evidence": None,
        "last_batch_result": None,
    }
    for event in events:
        kind = event["event_type"]
        payload = event["payload"]
        if kind == "activated":
            if state["activation"] is not None:
                raise ValueError("controller_state:duplicate_activation")
            state["activation"] = deepcopy(payload)
        elif kind == "stage_intent":
            if state["pending_intent"] is not None:
                raise ValueError("controller_state:overlapping_intent")
            state["pending_intent"] = deepcopy(payload)
        elif kind == "stage_result":
            if state["pending_intent"] is None:
                raise ValueError("controller_state:result_without_intent")
            _retain_checkpoint_sources(state, payload)
            _retain_final_sources(state, payload)
            state["pending_intent"] = None
            state["stage_report"] = deepcopy(payload.get("stage_report"))
            state["action"] = deepcopy(payload.get("action"))
            state["action_outcome"] = None
            state["cleanup_required"] = payload.get("cleanup_required") is True
            if isinstance(state["action"], Mapping):
                action_id = state["action"].get("action_id")
                if action_id in state["seen_action_ids"]:
                    raise ValueError("controller_state:action_id_reused")
                state["seen_action_ids"].append(action_id)
            if payload.get("terminal") is True:
                state["terminal"] = True
            terminal_evidence = payload.get("terminal_evidence_sha256")
            if terminal_evidence is not None:
                state["terminal_evidence_sha256"] = terminal_evidence
        elif kind == "action_observation_intent":
            if state["pending_intent"] is not None:
                raise ValueError("controller_state:overlapping_intent")
            state["pending_intent"] = deepcopy(payload)
        elif kind == "action_observed":
            if state["pending_intent"] is None or state["action"] is None:
                raise ValueError("controller_state:observation_without_action")
            if payload.get("action_id") != state["action"].get("action_id"):
                raise ValueError("controller_state:observation_action_mismatch")
            action_evidence = payload.get(
                "action_evidence", payload.get("hook_evidence")
            )
            if action_evidence is None:
                if payload.get("outcome") != "unknown":
                    raise ValueError("controller_state:action_evidence_missing")
            else:
                hook_shape = {
                        "action",
                        "pretool_report_sha256",
                        "pretool_durable_record_sha256",
                        "posttool_report_sha256",
                        "posttool_durable_record_sha256",
                        "result_binding",
                    }
                owner_shape = {
                    "schema",
                    "action",
                    "owner_observation",
                    "native_receipt",
                    "result_binding",
                }
                if not isinstance(action_evidence, Mapping) or (
                    (
                        set(action_evidence) != hook_shape
                        or action_evidence.get("action") != state["action"]
                    )
                    and (
                        set(action_evidence) != owner_shape
                        or action_evidence.get("schema")
                        != RETAINED_OWNER_ACTION_EVIDENCE_SCHEMA
                        or action_evidence.get("action") != state["action"]
                    )
                ):
                    raise ValueError("controller_state:action_evidence_invalid")
                retained = deepcopy(dict(action_evidence))
                state["action_evidence"].append(retained)
                state["last_action_evidence"] = retained
            state["pending_intent"] = None
            next_action = payload.get("next_action")
            if next_action is not None:
                if not isinstance(next_action, Mapping):
                    raise ValueError("controller_state:next_action_invalid")
                action_id = next_action.get("action_id")
                if action_id in state["seen_action_ids"]:
                    raise ValueError("controller_state:action_id_reused")
                state["seen_action_ids"].append(action_id)
                state["action_outcome"] = None
                state["action"] = deepcopy(dict(next_action))
            else:
                state["action_outcome"] = payload.get(
                    "batch_outcome", payload.get("outcome")
                )
                state["action"] = None
            batch_result = payload.get("batch_result")
            if batch_result is not None:
                if not isinstance(batch_result, Mapping):
                    raise ValueError("controller_state:batch_result_invalid")
                state["last_batch_result"] = deepcopy(dict(batch_result))
            if payload.get("cleanup_required") is True or (
                "cleanup_required" not in payload
                and payload.get("outcome") in {"failed", "cancelled", "timed_out"}
            ):
                state["cleanup_required"] = True
            if payload.get("terminal") is True or (
                "terminal" not in payload and payload.get("outcome") == "unknown"
            ):
                state["terminal"] = True
        else:
            raise ValueError("controller_state:event_type_invalid")
    if state["activation"] is None:
        raise ValueError("controller_state:activation_missing")
    return state


def _retain_checkpoint_sources(state: dict[str, Any], payload: Mapping[str, Any]) -> None:
    """Keep whole checkpoint custody in the existing append-only stage journal.

    Historical events gain no new fields. A later failed stage may have no
    receipt, but cannot erase evidence already accepted by an earlier stage.
    """
    report = payload.get("stage_report")
    receipt = report.get("receipt") if isinstance(report, Mapping) else None
    bindings = receipt.get("bindings") if isinstance(receipt, Mapping) else None
    if "checkpoint_sources" in payload:
        import orch_dork_qualification_progress as progress
        try:
            source = payload["checkpoint_sources"]
            prior = state["stage_report"]["receipt"]
            if ("checkpoint_sources" in state or type(source) is not dict
                    or set(source) != {"coordinator", "workers"}
                    or not isinstance(bindings, Mapping)
                    or bindings.get("worker_checkpoint_profile") != governed_attempt.WORKER_CHECKPOINT_PROFILE
                    or bindings.get("checkpoint_sources_sha256") != _sha(source)
                    or receipt.get("stage") not in {"progress", "stopped"}):
                raise ValueError("invalid checkpoint custody")
            activation = state["activation"]["identity"]
            progress.build_checkpoint_ingress_observation(
                {"root_task_id":activation["root_thread_id"], "root_model":activation["root_model"],
                 "root_effort":activation["root_effort"]}, source["coordinator"], source["workers"])
            program = progress.build_checkpoint_progress_program(prior,
                [source["workers"]["evidence"]["workers"][lane]["progress_report"] for lane in ("spec", "standards")])
            if bindings["progress_prefixes"]["1"]["events"] != program["events"]:
                raise ValueError("checkpoint prefix differs")
            if "checkpoint_accounting_policy" in prior["bindings"]:
                import orch_dork_qualification_budget as accounting
                import orch_dork_efficiency_governor as efficiency_governor
                if _canonical(bindings.get("checkpoint_accounting_policy")) != _canonical(prior["bindings"]["checkpoint_accounting_policy"]):
                    raise ValueError("checkpoint accounting policy changed")
                try:
                    clock = datetime.fromisoformat(state["pending_intent"]["evaluation_time"])
                    budget, observed = accounting.build_checkpoint_admission_budget(prior,source,now=clock)
                except ValueError:
                    if "checkpoint_budget_observation" in bindings or receipt.get("stage") == "progress":
                        raise ValueError("checkpoint accounting clock unobserved")
                else:
                    if (_canonical(observed) != _canonical(bindings.get("checkpoint_budget_observation"))
                            or efficiency_governor.evaluate_budget_program(budget)["receipt_sha256"] != bindings.get("budget_receipt_sha256")):
                        raise ValueError("checkpoint accounting differs from intent")
                    state["checkpoint_budget_observation"] = deepcopy(observed)
                    state["checkpoint_accounting_policy"] = deepcopy(prior["bindings"]["checkpoint_accounting_policy"])
            state["checkpoint_sources"] = deepcopy(source)
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as error:
            raise ValueError("controller_state:checkpoint_custody_invalid") from error
    if isinstance(bindings, Mapping):
        digest = bindings.get("checkpoint_sources_sha256")
        retained = state.get("checkpoint_sources")
        if (digest is not None or retained is not None) and digest != _sha(retained):
            raise ValueError("controller_state:checkpoint_custody_lost")
        for key in ("checkpoint_budget_observation", "checkpoint_accounting_policy"):
            if key in state and _canonical(bindings.get(key)) != _canonical(state[key]):
                raise ValueError("controller_state:checkpoint_accounting_custody_lost")


def _retain_final_sources(state: dict[str, Any], payload: Mapping[str, Any]) -> None:
    """Keep whole final source proof joined to accepted results across replay."""
    report = payload.get("stage_report")
    receipt = report.get("receipt") if isinstance(report, Mapping) else None
    bindings = receipt.get("bindings") if isinstance(receipt, Mapping) else None
    if "final_sources" in payload:
        import orch_dork_native_worker_finals as finals
        try:
            source = payload["final_sources"]
            if ("final_sources" in state or state["stage_report"]["receipt"]["stage"] != "progress"
                    or not isinstance(bindings, Mapping) or receipt["stage"] != "worker_results"
                    or bindings.get("worker_checkpoint_profile") != governed_attempt.WORKER_CHECKPOINT_PROFILE
                    or finals.validate_native_worker_finals(source, state["checkpoint_sources"])["valid"] is not True
                    or source["status"] != "OBSERVED"
                    or _canonical(bindings["worker_results"]) != _canonical([
                        source["evidence"]["workers"][lane]["result_report"] for lane in ("spec", "standards")])):
                raise ValueError("invalid final source custody")
            state["final_sources"] = deepcopy(source)
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as error:
            raise ValueError("controller_state:final_custody_invalid") from error
    if isinstance(bindings, Mapping):
        retained = state.get("final_sources")
        if retained is not None:
            if _canonical(bindings.get("worker_results")) != _canonical([
                    retained["evidence"]["workers"][lane]["result_report"] for lane in ("spec", "standards")]):
                raise ValueError("controller_state:final_custody_lost")
        elif (bindings.get("worker_checkpoint_profile") == governed_attempt.WORKER_CHECKPOINT_PROFILE
                and "worker_results" in bindings):
            raise ValueError("controller_state:final_custody_lost")


def _direct_batch_action(
    *,
    controller_id: str,
    batch_id: str,
    batch_kind: str,
    batch_lane_ids: list[str],
    requests: list[Mapping[str, Any]],
    index: int,
    phase: str,
    actor_thread_id: str,
    adapter_sha256: str,
    predecessor_receipt_sha256: Any,
    failure_outcome: str | None = None,
) -> dict[str, Any]:
    """Materialize one exact direct call from a sealed sequential batch."""

    if (
        batch_kind not in ACTION_KINDS
        or phase not in {"primary", "compensation"}
        or not requests
        or type(index) is not int
        or index < 0
        or index >= len(requests)
        or not batch_lane_ids
        or batch_lane_ids != sorted(set(batch_lane_ids))
        or failure_outcome not in ACTION_OUTCOMES | {None}
        or (phase == "primary" and failure_outcome == "completed")
    ):
        raise ValueError("native_batch:invalid")
    normalized_requests: list[dict[str, Any]] = []
    for request in requests:
        if (
            not isinstance(request, Mapping)
            or set(request) != {"lane_id", "kind", "tool_name", "tool_input"}
            or request.get("kind") not in ACTION_KINDS
            or request.get("tool_name")
            != DIRECT_NATIVE_TOOLS.get(str(request.get("kind")))
            or not isinstance(request.get("tool_input"), Mapping)
            or not isinstance(request.get("lane_id"), str)
            or request.get("lane_id") not in batch_lane_ids
        ):
            raise ValueError("native_batch:request_invalid")
        normalized_requests.append(
            {
                "lane_id": request["lane_id"],
                "kind": request["kind"],
                "tool_name": request["tool_name"],
                "tool_input": deepcopy(dict(request["tool_input"])),
            }
        )
    if len({row["lane_id"] for row in normalized_requests}) != len(
        normalized_requests
    ):
        raise ValueError("native_batch:request_lane_reused")
    request = normalized_requests[index]
    tool_input = deepcopy(request["tool_input"])
    if len(_canonical(tool_input)) > MAX_TOOL_INPUT_BYTES:
        raise ValueError("native_batch:tool_input_too_large")
    action_id = (
        batch_id
        if phase == "primary" and index == 0 and failure_outcome is None
        else "native-"
        + _sha(
            {
                "batch_id": batch_id,
                "phase": phase,
                "index": index,
                "request": request,
                "failure_outcome": failure_outcome,
            }
        )[:32]
    )
    core = {
        "schema": ACTION_SCHEMA,
        "controller_id": controller_id,
        "action_id": action_id,
        "kind": request["kind"],
        "lane_ids": [request["lane_id"]],
        "actor_thread_id": actor_thread_id,
        "tool_name": request["tool_name"],
        "tool_input": tool_input,
        "tool_input_sha256": _sha(tool_input),
        "adapter_sha256": adapter_sha256,
        "predecessor_receipt_sha256": predecessor_receipt_sha256,
        "batch_schema": NATIVE_BATCH_SCHEMA,
        "batch_id": batch_id,
        "batch_kind": batch_kind,
        "batch_phase": phase,
        "batch_index": index,
        "batch_size": len(normalized_requests),
        "batch_lane_ids": list(batch_lane_ids),
        "batch_requests": normalized_requests,
        "batch_requests_sha256": _sha(normalized_requests),
        "batch_failure_outcome": failure_outcome,
    }
    return {**core, "action_sha256": _sha(core)}


def _bounded_review_corpus(
    *,
    source_roots: Mapping[str, Path],
    lane_id: str,
    task_spec: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the no-tool Issue 94 review corpus carried by continuation."""

    source_root = source_roots.get("source")
    if source_root is None:
        raise ValueError("native_continuation:source_root_missing")
    root = Path(source_root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("native_continuation:source_root_invalid")
    root = root.resolve(strict=True)
    raw_scope = task_spec.get("read_scope")
    if not isinstance(raw_scope, list) or any(
        not isinstance(item, str) for item in raw_scope
    ):
        raise ValueError("native_continuation:read_scope_invalid")

    def read_source(relative: str) -> tuple[str, str]:
        candidate = root / relative
        try:
            resolved = candidate.resolve(strict=True)
            metadata = candidate.lstat()
            raw = candidate.read_bytes()
        except OSError as error:
            raise ValueError(
                "native_continuation:source_unavailable"
            ) from error
        if (
            candidate.is_symlink()
            or not resolved.is_relative_to(root)
            or not stat.S_ISREG(metadata.st_mode)
            or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
            or stat.S_IMODE(metadata.st_mode) & 0o002
            or len(raw) > MAX_REVIEW_DOCUMENT_BYTES
        ):
            raise ValueError("native_continuation:source_invalid")
        try:
            return raw.decode("utf-8"), hashlib.sha256(raw).hexdigest()
        except UnicodeError as error:
            raise ValueError(
                "native_continuation:source_not_utf8"
            ) from error

    def between(text: str, start: str, end: str) -> str:
        offset = text.find(start)
        if offset < 0:
            return ""
        limit = text.find(end, offset + len(start))
        return text[offset:] if limit < 0 else text[offset:limit]

    excerpts: list[dict[str, Any]] = []

    def add(relative: str, selector: str, content: str, full_sha: str) -> None:
        normalized = content.strip()
        if not normalized:
            raise ValueError("native_continuation:required_excerpt_missing")
        if len(normalized.encode("utf-8")) > 48_000:
            raise ValueError("native_continuation:excerpt_too_large")
        excerpts.append(
            {
                "path": relative,
                "source_sha256": full_sha,
                "selector": selector,
                "content": normalized,
                "excerpt_sha256": hashlib.sha256(
                    normalized.encode("utf-8")
                ).hexdigest(),
            }
        )

    lane_kind = (
        "spec"
        if lane_id == "spec"
        else "standards"
        if lane_id == "standards"
        else "generic"
    )
    for relative in raw_scope:
        if relative not in {"AGENTS.md", "SPEC.md", "TICKETS.md"}:
            continue
        text, full_sha = read_source(relative)
        if relative == "AGENTS.md" and lane_kind == "standards":
            add(
                relative,
                "qualification-first-promotion-loop",
                between(
                    text,
                    "# Working in this repository",
                    "## Ticket ledger and host ownership",
                ),
                full_sha,
            )
        elif relative == "SPEC.md" and lane_kind == "spec":
            add(
                relative,
                "FR63-controller-contract",
                between(
                    text,
                    "One provider-free `orch-dork/governed-native-controller/v1`",
                    "Activation writes one content-addressed",
                ),
                full_sha,
            )
            add(
                relative,
                "FR63-spawn-and-worker-start",
                between(
                    text,
                    "The action adapter emits one exact direct collaboration-tool input",
                    "The production seam hard-binds",
                ),
                full_sha,
            )
            add(
                relative,
                "FR63-retained-action-evidence",
                between(
                    text,
                    "Each accepted action observation retains the exact action",
                    "Capacity admission and settlement use FR62's canonical",
                ),
                full_sha,
            )
            add(
                relative,
                "acceptance-criterion-51",
                between(
                    text,
                    "51. A provider-free host controller activated before a native task",
                    "52.",
                ),
                full_sha,
            )
        elif relative == "TICKETS.md" and lane_kind in {"spec", "standards"}:
            issue_row = next(
                (
                    line
                    for line in text.splitlines()
                    if line.startswith("| 163 |")
                ),
                "",
            )
            current_cycle = between(
                text,
                "- [ ] Preserve Cycle 31 as replay v17",
                "#### Cycle 1 authority and orchestration evidence",
            )
            if not current_cycle:
                current_cycle = between(
                    text,
                    "- [x] Preserve Cycle 31 as replay v17",
                    "#### Cycle 1 authority and orchestration evidence",
                )
            add(
                relative,
                "issue-163-row-and-current-cycle",
                issue_row + "\n\n" + current_cycle,
                full_sha,
            )

    if lane_kind in {"spec", "standards"} and not excerpts:
        raise ValueError("native_continuation:review_corpus_missing")
    core = {
        "schema": "orch-dork/native-review-corpus/v1",
        "lane_id": lane_id,
        "task_spec_sha256": task_spec.get("task_spec_sha256"),
        "source_root_sha256": hashlib.sha256(
            str(root).encode("utf-8")
        ).hexdigest(),
        "excerpts": excerpts,
    }
    corpus = {**core, "corpus_sha256": _sha(core)}
    if len(_canonical(corpus)) > 72_000:
        raise ValueError("native_continuation:review_corpus_too_large")
    return corpus


# The final continuation's template instruction; the template cites the whole
# sealed corpus as one artifact (see adaptive_contracts.handoff_receipt_template).
_CORPUS_TEMPLATE_INSTRUCTION = (
    "The one artifact_refs entry in handoff_receipt_template is the sealed "
    "review_corpus itself (its corpus_sha256). "
    + adaptive_contracts.HANDOFF_TEMPLATE_INSTRUCTION
    + " Support each source-state claim with its literal evidence in "
    "result_summary. When describing a Markdown checkbox, quote its containing "
    "line with the exact [x] or [ ] marker, and scope that state to that "
    "individual item. Do not infer an item's state from a heading, row, or "
    "neighboring item. "
    # Generation 73 omitted a required empty field. Clarify content versus
    # field presence; the strict receipt validator remains authoritative.
    "Omit claim entries the supplied evidence does not support. The "
    "claims field stays present in your output as the empty list [] (the "
    "template always prefills it as []), never omit the field itself. "
    "Mandatory fields - schema, task_spec_sha256, raw_trace_ref and "
    "the entire artifact_refs array (its single entry is the sealed "
    "review_corpus) - must be copied verbatim from "
    "handoff_receipt_template; do not omit, rename, reorder or invent "
    "values for them. Each checks entry keeps its id, required and "
    "evidence_refs verbatim; only its status is set. "
    "Empty-array fields - claims, conflicts, unknowns and "
    "requested_decisions - must stay present; when empty, render them as "
    "[] rather than null or absent. Keep claims empty as instructed; "
    "for a blocked or failed task, retain the actual unknowns and "
    "requested_decisions required by the preceding contract. "
    "A checked item records its tracking disposition, not proof that every "
    "action named in its label succeeded. Read its following outcome and "
    "limitations before describing what happened. Report successful release, "
    "install, qualification or promotion only from explicit outcome evidence; "
    "an item recording a refusal before those actions does not prove success."
    " Final self-check before yielding: verify your output JSON contains "
    "exactly these eleven top-level keys - schema, disposition, "
    "task_spec_sha256, result_summary, claims, artifact_refs, checks, "
    "conflicts, unknowns, requested_decisions, raw_trace_ref - and that "
    "every empty array stays [] rather than null or absent. If a key is "
    "missing, restore it from handoff_receipt_template before yielding. "
    "Copy raw_trace_ref unchanged, including null when the template "
    "uses null. "
    + " Then yield."
)


class ClosedNativeActionAdapter:
    """Derive one exact native tool input from sealed receipts and TaskSpecs."""

    adapter_sha256 = CLOSED_NATIVE_ACTION_ADAPTER_SHA256

    @staticmethod
    def authorize(
        proposal: Any,
        *,
        next_action: Any,
        receipt: Mapping[str, Any],
        activation: Mapping[str, Any],
        controller_id: str,
        seen_action_ids: list[str],
        source_roots: Mapping[str, Path] | None = None,
    ) -> tuple[dict[str, Any] | None, list[str]]:
        issues: list[str] = []
        value = _exact(
            proposal,
            {
                "schema",
                "action_id",
                "kind",
                "actor_thread_id",
                "adapter_sha256",
            },
            "proposed_action",
            issues,
        )
        if value.get("schema") != ACTION_PROPOSAL_SCHEMA:
            _issue(issues, "proposed_action:schema_invalid")
        _identifier(value.get("action_id"), "proposed_action.action_id", issues)
        if value.get("action_id") in seen_action_ids:
            _issue(issues, "proposed_action:action_id_reused")
        if value.get("kind") not in ACTION_KINDS:
            _issue(issues, "proposed_action:kind_invalid")
        if value.get("kind") != next_action:
            _issue(issues, "proposed_action:not_exact_next_action")
        identity = activation.get("identity", {})
        if value.get("actor_thread_id") != identity.get("root_thread_id"):
            _issue(issues, "proposed_action:root_owner_required")
        if value.get("adapter_sha256") != identity.get("native_adapter_sha256"):
            _issue(issues, "proposed_action:adapter_identity_mismatch")
        if value.get("adapter_sha256") != CLOSED_NATIVE_ACTION_ADAPTER_SHA256:
            _issue(issues, "proposed_action:adapter_unrecognized")
        receipt_core = {
            key: child for key, child in receipt.items() if key != "receipt_sha256"
        } if isinstance(receipt, Mapping) else {}
        if (
            not isinstance(receipt, Mapping)
            or receipt.get("receipt_sha256") != _sha(receipt_core)
            or not isinstance(receipt.get("bindings"), Mapping)
        ):
            _issue(issues, "proposed_action:receipt_invalid")
        bindings = receipt.get("bindings", {}) if isinstance(receipt, Mapping) else {}
        checkpoint_profile = bindings.get("worker_checkpoint_profile")
        if "worker_checkpoint_profile" in bindings and checkpoint_profile != governed_attempt.WORKER_CHECKPOINT_PROFILE:
            _issue(issues, "native_continuation:checkpoint_profile_invalid")
        expected_lanes: list[str] = []
        native_requests: list[dict[str, Any]] = []
        activation_specs = {
            str(row.get("logical_worker_id")): row
            for row in activation.get("task_specs", [])
            if isinstance(row, Mapping)
        }
        if next_action == "spawn":
            raw_lanes = bindings.get("current_wave_logical_lane_ids")
            if (
                not isinstance(raw_lanes, list)
                or any(not isinstance(item, str) for item in raw_lanes)
            ):
                raw_lanes = []
                _issue(issues, "proposed_action:lane_membership_invalid")
            expected_lanes = sorted(raw_lanes)
            all_specs = bindings.get("all_task_specs")
            if not isinstance(all_specs, list):
                all_specs = []
                _issue(issues, "proposed_action:task_specs_invalid")
            normalized_spec_identity = [
                {
                    "logical_worker_id": row.get("logical_worker_id"),
                    "task_spec_sha256": row.get("task_spec_sha256"),
                }
                for row in all_specs
                if isinstance(row, Mapping)
            ]
            normalized_spec_identity.sort(
                key=lambda item: str(item["logical_worker_id"])
            )
            if _sha(normalized_spec_identity) != identity.get("task_specs_sha256"):
                _issue(issues, "proposed_action:task_specs_mismatch")
            routes = {
                str(row.get("logical_worker_id")): row
                for row in all_specs
                if isinstance(row, Mapping)
            }
            if set(expected_lanes) - set(activation_specs):
                _issue(issues, "proposed_action:task_specs_missing")
            for lane_id in expected_lanes:
                route = routes.get(lane_id, {})
                spec = activation_specs.get(lane_id, {}).get("task_spec")
                if (
                    not isinstance(spec, Mapping)
                    or not _identifier(route.get("model"), "proposed_action.model", issues)
                    or not _identifier(route.get("effort"), "proposed_action.effort", issues)
                ):
                    continue
                pre_work_receipt = route_policy.task_spec_pre_work_receipt(
                    logical_lane_id=lane_id,
                    task_spec_sha256=str(route.get("task_spec_sha256")),
                )
                packet = {
                    "schema": "orch-dork/native-task-dispatch/v1",
                    "controller_id": controller_id,
                    "lane_id": lane_id,
                    "task_spec": spec,
                    "pre_work_receipt": pre_work_receipt,
                    "instruction": (
                        "Before tools or substantive work, emit only the exact "
                        "pre_work_receipt JSON object, with no markdown or "
                        "additional fields, then yield this turn. Do not spawn "
                        "workers. Await a controller-owned continuation before "
                        "executing the frozen TaskSpec."
                        " Your entire reply for this turn is this object: "
                        + _canonical(pre_work_receipt).decode("utf-8")
                        + ". Copy it directly. Do not return the enclosing "
                        "dispatch packet or nest this object in another object."
                    ),
                }
                native_requests.append({
                    "lane_id": lane_id,
                    "model": route.get("model"),
                    "reasoning_effort": route.get("effort"),
                    "message": _canonical(packet).decode("utf-8"),
                })
        elif next_action in {"continue", "stop"}:
            raw_bindings = bindings.get("lane_bindings")
            if not isinstance(raw_bindings, list):
                raw_bindings = []
                _issue(issues, "proposed_action:lane_bindings_invalid")
            lane_bindings = [
                row for row in raw_bindings
                if isinstance(row, Mapping)
            ]
            expected_lanes = sorted(str(row.get("logical_worker_id")) for row in lane_bindings)
            for row in sorted(lane_bindings, key=lambda item: str(item.get("logical_worker_id"))):
                lane_id = str(row.get("logical_worker_id"))
                worker_id = row.get("worker_id")
                if not _identifier(worker_id, "proposed_action.worker_id", issues):
                    continue
                request = {"lane_id": lane_id, "worker_id": worker_id}
                if next_action == "continue":
                    task_spec = activation_specs.get(lane_id, {}).get(
                        "task_spec"
                    )
                    if not isinstance(task_spec, Mapping):
                        _issue(issues, "proposed_action:task_specs_missing")
                        continue
                    raw_scope = task_spec.get("read_scope")
                    if (
                        isinstance(raw_scope, list)
                        and any(
                            item in {"AGENTS.md", "SPEC.md", "TICKETS.md"}
                            for item in raw_scope
                        )
                    ):
                        deliverable = task_spec.get("deliverable")
                        result_schema = deliverable.get("schema") if isinstance(deliverable, Mapping) else None
                        if not isinstance(result_schema, str) or not result_schema.strip():
                            _issue(issues, "native_continuation:deliverable_schema_missing")
                            continue
                        try:
                            review_corpus = _bounded_review_corpus(
                                source_roots=source_roots or {},
                                lane_id=lane_id,
                                task_spec=task_spec,
                            )
                        except ValueError as error:
                            _issue(issues, str(error))
                            continue
                        handoff_template = None
                        instruction = (
                            "Complete only the frozen TaskSpec using only "
                            "the sealed review_corpus. Do not call tools "
                            "or spawn. Return one JSON object whose schema "
                            f"is exactly {result_schema}, then yield."
                        )
                        if result_schema == adaptive_contracts.HANDOFF_RECEIPT_SCHEMA:
                            # Generation 49: told only the schema name, the
                            # worker invented a field set.  Hand it the exact
                            # receipt to fill.  The whole sealed corpus is the
                            # one cited artifact (its canonical core bytes hash
                            # to corpus_sha256), so the worker copies a single
                            # reference rather than one per excerpt.
                            corpus_core = {
                                key: value
                                for key, value in review_corpus.items()
                                if key != "corpus_sha256"
                            }
                            try:
                                handoff_template = (
                                    adaptive_contracts.handoff_receipt_template(
                                        dict(task_spec),
                                        [
                                            {
                                                "sha256": review_corpus["corpus_sha256"],
                                                "size_bytes": len(_canonical(corpus_core)),
                                                "media_type": "application/json",
                                            }
                                        ],
                                    )
                                )
                            except adaptive_contracts.ContractValidationError:
                                _issue(issues, "native_continuation:handoff_template_invalid")
                                continue
                            instruction = (
                                "Complete only the frozen TaskSpec using only "
                                "the sealed review_corpus. Do not call tools "
                                "or spawn. " + _CORPUS_TEMPLATE_INSTRUCTION
                            )
                        packet = {
                            "schema": "orch-dork/native-continuation/v1",
                            "controller_id": controller_id,
                            "lane_id": lane_id,
                            "predecessor_receipt_sha256": receipt.get(
                                "receipt_sha256"
                            ),
                            "task_spec_sha256": task_spec.get(
                                "task_spec_sha256"
                            ),
                            "review_corpus": review_corpus,
                            "instruction": instruction,
                        }
                        if handoff_template is not None:
                            packet["handoff_receipt_template"] = handoff_template
                        request["message"] = _canonical(packet).decode(
                            "utf-8"
                        )
                    else:
                        packet = {
                            "schema": "orch-dork/native-continuation/v1",
                            "controller_id": controller_id,
                            "lane_id": lane_id,
                            "predecessor_receipt_sha256": receipt.get(
                                "receipt_sha256"
                            ),
                            "instruction": (
                                "Continue only the frozen TaskSpec and return "
                                "the next required typed packet; do not spawn."
                            ),
                        }
                        request["message"] = _canonical(packet).decode(
                            "utf-8"
                        )
                    if checkpoint_profile == governed_attempt.WORKER_CHECKPOINT_PROFILE:
                        if receipt.get("stage") == "worker_start":
                            # The first continuation asks only for progress;
                            # the receipt template belongs to the final one.
                            packet.pop("handoff_receipt_template", None)
                            packet["checkpoint_submission"] = {
                                "schema": "orch-dork/worker-progress-submission/v1",
                                "task_spec_sha256": task_spec.get("task_spec_sha256"),
                                "sequence": 1, "claims": [], "artifact_refs": [], "checks": [],
                            }
                            packet["instruction"] = (
                                "Begin the frozen TaskSpec using the supplied evidence. "
                                "Do not call tools or spawn. Fill only claims, artifact_refs "
                                "and checks in checkpoint_submission with your actual progress. "
                                "Preserve its schema, task_spec_sha256 and sequence; add no fields. "
                                "Do not supply usage or a source pointer. Return only that JSON "
                                "object, then yield. Await another controller-owned continuation "
                                "before returning the final handoff."
                            )
                        elif receipt.get("stage") == "progress":
                            packet["task_spec_sha256"] = task_spec["task_spec_sha256"]
                            evidence_scope = ("only the sealed review_corpus" if "review_corpus" in packet
                                              else "the supplied evidence")
                            packet["instruction"] = (
                                f"Complete only the frozen TaskSpec using {evidence_scope}. "
                                "Do not call tools or spawn. "
                                + (
                                    _CORPUS_TEMPLATE_INSTRUCTION
                                    if "handoff_receipt_template" in packet
                                    else "Return one JSON object whose schema "
                                    "is exactly orch-dork/handoff-receipt/v1, then yield."
                                )
                            )
                        else:
                            _issue(issues, "native_continuation:checkpoint_stage_invalid")
                        request["message"] = _canonical(packet).decode("utf-8")
                native_requests.append(request)
        if not expected_lanes or len(expected_lanes) != len(set(expected_lanes)):
            _issue(issues, "proposed_action:lane_membership_invalid")
        if len(native_requests) != len(expected_lanes):
            _issue(issues, "proposed_action:native_request_derivation_failed")
        if issues:
            return None, sorted(issues)

        direct_requests: list[dict[str, Any]] = []
        for request in native_requests:
            lane_id = str(request["lane_id"])
            if next_action == "spawn":
                tool_input = {
                    "fork_context": False,
                    "message": request["message"],
                    "model": request["model"],
                    "reasoning_effort": request["reasoning_effort"],
                }
            elif next_action == "continue":
                tool_input = {
                    "target": request["worker_id"],
                    "message": request["message"],
                }
            else:
                tool_input = {"target": request["worker_id"]}
            direct_requests.append(
                {
                    "lane_id": lane_id,
                    "kind": next_action,
                    "tool_name": DIRECT_NATIVE_TOOLS[next_action],
                    "tool_input": tool_input,
                }
            )
        try:
            action = _direct_batch_action(
                controller_id=controller_id,
                batch_id=str(value["action_id"]),
                batch_kind=str(value["kind"]),
                batch_lane_ids=list(expected_lanes),
                requests=direct_requests,
                index=0,
                phase="primary",
                actor_thread_id=str(value["actor_thread_id"]),
                adapter_sha256=str(value["adapter_sha256"]),
                predecessor_receipt_sha256=receipt.get("receipt_sha256"),
            )
        except (KeyError, TypeError, ValueError):
            return None, ["proposed_action:direct_batch_derivation_failed"]
        return action, []


class GovernedNativeController:
    """One durable provider-free transition seam for governed native work."""

    def __init__(
        self,
        *,
        store: Any = None,
        artifacts: Any = None,
        plugin_data: str | os.PathLike[str],
        hook_definition_path: str | os.PathLike[str],
        source_roots: Mapping[str, str | Path] | None = None,
        now: datetime | Callable[[], datetime] | None = None,
        observer_state_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        provided_plugin_data = Path(plugin_data)
        if not provided_plugin_data.is_absolute() or provided_plugin_data.is_symlink():
            raise ValueError("plugin_data:absolute_non_symlink_required")
        self.plugin_data = provided_plugin_data.resolve()
        self.plugin_data.mkdir(parents=True, exist_ok=True, mode=0o700)
        plugin_data_stat = self.plugin_data.stat()
        if (
            not self.plugin_data.is_dir()
            or (hasattr(os, "getuid") and plugin_data_stat.st_uid != os.getuid())
            or plugin_data_stat.st_mode & 0o022
        ):
            raise ValueError("plugin_data:unsafe_owner_or_mode")
        state_root = self.plugin_data / "governed-native"
        state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        state_root_stat = state_root.stat()
        if (
            state_root.is_symlink()
            or (hasattr(os, "getuid") and state_root_stat.st_uid != os.getuid())
            or state_root_stat.st_mode & 0o022
        ):
            raise ValueError("plugin_data:unsafe_state_root")
        canonical_store_path = native_grant_store.canonical_database_path(
            self.plugin_data
        )
        if store is None:
            store = run_store.SQLiteRunStore(canonical_store_path, max_payload_bytes=MAX_STORE_PAYLOAD_BYTES)
        supplied_path = getattr(store, "_path", None)
        if (
            not getattr(store, "durable", False)
            or supplied_path is None
            or Path(supplied_path).resolve() != canonical_store_path
        ):
            raise ValueError("controller_store:canonical_plugin_data_store_required")
        if (type(getattr(store, "max_payload_bytes", None)) is not int
                or store.max_payload_bytes < MAX_STORE_PAYLOAD_BYTES):
            raise ValueError("controller_store:payload_limit_insufficient")
        self.store = store
        self.grants = native_grant_store.NativeGrantStore(canonical_store_path)
        self.hook_definition_path = Path(hook_definition_path).resolve()
        self.plugin_manifest_path = (
            self.hook_definition_path.parent.parent
            / ".codex-plugin"
            / "plugin.json"
        )
        plugin_root = self.plugin_manifest_path.parent.parent
        normalized_source_roots = dict(source_roots or {})
        supplied_plugin_root = normalized_source_roots.get("plugin")
        if supplied_plugin_root is not None:
            supplied_path = Path(supplied_plugin_root)
            if (
                not supplied_path.is_absolute()
                or supplied_path.is_symlink()
                or supplied_path.resolve() != plugin_root
            ):
                raise ValueError("source_roots:plugin_root_mismatch")
        normalized_source_roots["plugin"] = plugin_root
        if artifacts is None:
            artifacts = artifact_ledger.FilesystemArtifactLedger(
                self.plugin_data / "governed-native" / "artifacts"
            )
        if (
            not getattr(artifacts, "durable", False)
            or Path(getattr(artifacts, "_root", "")).resolve()
            != (state_root / "artifacts").resolve()
        ):
            raise ValueError("controller_artifacts:canonical_plugin_data_ledger_required")
        self.now = now if now is not None else (lambda: datetime.now(timezone.utc))
        configured_trust_path = os.environ.get(
            observer_receipt.TRUST_STORE_ENV
        )
        self._observer_state_dir = (
            Path(observer_state_dir)
            if observer_state_dir is not None
            else (
                Path(configured_trust_path).parent
                if configured_trust_path
                else observer_authority.default_state_dir()
            )
        )
        try:
            capacity_trust_store = (
                observer_receipt.ObserverTrustStore.from_host_file(
                    self._observer_state_dir
                    / observer_authority.TRUST_STORE_FILENAME
                )
            )
        except (observer_receipt.ObserverReceiptError, OSError, ValueError):
            capacity_trust_store = None
        # This tower is the controller's run engine and shared-capacity
        # authority only; it never prepares or advances a plan, so it is not
        # given the observed root (a plan-preparing tower must be).
        self.tower = control_tower.ControlTower(
            store=store,
            artifacts=artifacts,
            cleanup_observer_trust_store=capacity_trust_store,
            cleanup_observer_replay_guard=observer_receipt.SQLiteReplayGuard(
                state_root / "cleanup-replay.sqlite3"
            ),
            cleanup_observer_evaluation_time=self.now,
        )
        self.engine = self.tower.engine
        self.capacity_authority = self.tower
        self.source_roots = normalized_source_roots
        self._attempt_observer = SignedAttemptObservationAdapter(
            self.plugin_data, self.now
        )
        self._hook_trust_replay_guard = observer_receipt.SQLiteReplayGuard(
            state_root / "hook-trust-replay.sqlite3"
        )
        # Resolve and pin observer trust once. Host-launched processes may name
        # their fixed authority before construction; ordinary local callers use
        # the owner's canonical state directory without ambient setup.
        self._lock_path = self.plugin_data / "governed-native-controller.lock"

    @contextmanager
    def _locked(self):
        descriptor = os.open(
            self._lock_path,
            os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self.store.init()
            self.grants.initialize()
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _rows(self, run_id: str) -> list[Mapping[str, Any]]:
        if not self.store.exists(run_id):
            return []
        return list(self.engine.events(run_id, 0))

    def _append(self, run_id: str, event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        rows = self._rows(run_id)
        current = _cursor(rows)
        if current is None:
            raise ValueError("controller_stream:missing")
        event = _event_record(event_type, payload)
        self.engine.apply(
            run_id,
            "controller",
            roles=("controller",),
            status="SUCCESS",
            deliverables={
                "controller_event": _canonical(event).decode("utf-8")
            },
            evidence={"controller_event": event["event_sha256"]},
            expected_seq=current["seq"],
            expected_prev_hash=current["event_hash"],
        )
        return _cursor(self._rows(run_id))

    def _state(self, run_id: str, *, recover_provisional: bool = True) -> tuple[dict[str, Any], list[Mapping[str, Any]]]:
        rows = self._rows(run_id)
        events = _controller_events(rows)
        state = _reduce(events)
        action = state.get("action")
        grant = (
            self.grants.read_action(str(action.get("action_sha256")))
            if isinstance(action, Mapping)
            else None
        )
        if (
            recover_provisional
            and isinstance(action, Mapping)
            and isinstance(grant, Mapping)
            and grant.get("state") == "PROVISIONAL"
        ):
            cursor = _cursor(rows)
            if cursor is None:
                raise ValueError("grant:controller_tip_missing")
            recovered = self.grants.finalize_action(action, cursor)
            if recovered.get("status") not in {"FINALIZED", "IDEMPOTENT"}:
                raise ValueError("grant:recovery_failed")
            grant = self.grants.read_action(str(action.get("action_sha256")))
        state["grant_state"] = (
            grant.get("state")
            if isinstance(grant, Mapping)
            else "OUTCOME_UNKNOWN"
            if state.get("action_outcome") == "unknown"
            else None
        )
        state["grant"] = grant
        return state, rows

    def _evaluation_time(self) -> datetime:
        value = self.now() if callable(self.now) else self.now
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("controller_clock:trusted_utc_required")
        return value.astimezone(timezone.utc)

    def _hook_binding(
        self,
        *,
        controller_id: str,
        cursor: Mapping[str, Any],
        state: Mapping[str, Any],
        ground_state_sha256: str,
    ) -> dict[str, Any]:
        activation = state["activation"]
        identity = activation["identity"]
        action = state.get("action")
        hook_action = None
        if isinstance(action, Mapping) and state.get("grant_state") in {
            "AUTHORIZED",
            "DISPATCHED",
            "POST_OBSERVED",
        }:
            hook_action = {
                "action_id": action["action_id"],
                "action_sha256": action["action_sha256"],
                "kind": action["kind"],
                "actor_thread_id": action["actor_thread_id"],
                "lane_ids": list(action["lane_ids"]),
                "tool_name": action["tool_name"],
                "tool_input_sha256": action["tool_input_sha256"],
            }
        status = (
            "TERMINAL"
            if state.get("terminal")
            else "BLOCKED"
            if state.get("pending_intent") is not None
            or (
                isinstance(action, Mapping)
                and state.get("grant_state")
                not in {"AUTHORIZED", "DISPATCHED", "POST_OBSERVED"}
            )
            else "ACTIVE"
            if hook_action is not None
            else "WAITING"
        )
        core = {
            "schema": HOOK_BINDING_SCHEMA,
            "controller_id": controller_id,
            "controller_run_id": cursor["run_id"],
            "controller_seq": cursor["seq"],
            "controller_event_hash": cursor["event_hash"],
            "root_thread_id": identity["root_thread_id"],
            "root_session_id": identity["root_session_id"],
            "root_model": identity["root_model"],
            "hook_definition_sha256": identity["hook_definition_sha256"],
            "hook_registration_sha256": identity[
                "hook_registration_sha256"
            ],
            "store_identity_sha256": self.grants.store_identity_sha256,
            "ground_state_sha256": ground_state_sha256,
            "status": status,
            "action": hook_action,
        }
        return {**core, "binding_sha256": _sha(core)}

    def _installed_plugin_version(self) -> str | None:
        try:
            manifest = owned_file.read_owned_json(
                self.plugin_manifest_path,
                max_bytes=MAX_RUNTIME_FILE_BYTES,
            )
        except (OSError, UnicodeError, ValueError):
            return None
        if not isinstance(manifest, Mapping):
            return None
        version = manifest.get("version")
        return version if isinstance(version, str) and version else None

    def _hook_runtime_matches(self, identity: Any) -> bool:
        if not isinstance(identity, Mapping):
            return False
        try:
            definition_sha256 = owned_file.sha256_owned_file(
                self.hook_definition_path,
                max_bytes=MAX_RUNTIME_FILE_BYTES,
            )
            registration_sha256 = owned_file.sha256_owned_file(
                self.hook_definition_path.parent / "hooks.json",
                max_bytes=MAX_RUNTIME_FILE_BYTES,
            )
        except (OSError, ValueError):
            return False
        installed_plugin_version = self._installed_plugin_version()
        return bool(
            definition_sha256 == identity.get("hook_definition_sha256")
            and registration_sha256
            == identity.get("hook_registration_sha256")
            and installed_plugin_version
            == identity.get("installed_plugin_version")
        )

    def _sync_hook(
        self,
        *,
        controller_id: str,
        cursor: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> str:
        if not self.grants.owner_matches(controller_id, str(cursor.get("run_id"))):
            raise ValueError("hook_state:controller_owner_mismatch")
        if not self._hook_runtime_matches(
            state.get("activation", {}).get("identity")
        ):
            raise ValueError("hook_state:hook_runtime_mismatch")
        if self.grants.current_tip(str(cursor.get("run_id"))) != dict(cursor):
            raise ValueError("hook_state:controller_tip_mismatch")
        record = deepcopy(state["activation"]["project_ground_state"])
        terminal_report = state.get("stage_report")
        program = record.get("program")
        if not isinstance(program, Mapping):
            raise ValueError("hook_state:program_missing")
        program = deepcopy(dict(program))
        if (
            state.get("terminal")
            and isinstance(terminal_report, Mapping)
            and terminal_report.get("status") == "PASS"
            and terminal_report.get("disposition") == "TERMINALLY_QUALIFIED"
        ):
            program["completion"] = {
                "final_verification_valid": True,
                "final_verification_sha256": state.get(
                    "terminal_evidence_sha256"
                ) or _sha(terminal_report),
                "independent_observation": "BOUND",
                "governed_controller_status": "PASS",
            }
        else:
            program["completion"] = {
                "final_verification_valid": False,
                "final_verification_sha256": None,
                "independent_observation": "UNBOUND",
                "governed_controller_status": "PENDING",
            }
        record["program"] = program
        record["program_sha256"] = ground_enforcement._sha(program)
        ground_state_sha256 = _sha(record)
        record["native_controller"] = self._hook_binding(
            controller_id=controller_id,
            cursor=cursor,
            state=state,
            ground_state_sha256=ground_state_sha256,
        )
        current_path = self.plugin_data / "project-ground" / "current.json"
        projected = self.grants.hook_projection()
        desired_binding = record["native_controller"]
        try:
            current = owned_file.read_owned_json(
                current_path, max_bytes=MAX_RUNTIME_FILE_BYTES
            )
        except FileNotFoundError:
            current = None
        if current is not None:
            if not isinstance(current, Mapping):
                raise ValueError("hook_state:projection_file_invalid")
            native = current.get("native_controller") if isinstance(current, Mapping) else None
            if native is not None:
                current_ground = {
                    key: child
                    for key, child in current.items()
                    if key != "native_controller"
                }
                native_projection = {
                    "controller_id": native.get("controller_id"),
                    "controller_run_id": native.get("controller_run_id"),
                    "controller_seq": native.get("controller_seq"),
                    "controller_event_hash": native.get("controller_event_hash"),
                    "binding_sha256": native.get("binding_sha256"),
                } if isinstance(native, Mapping) else {}
                native_sealed = bool(
                    isinstance(native, Mapping)
                    and native.get("binding_sha256")
                    == _sha(
                        {
                            key: child
                            for key, child in native.items()
                            if key != "binding_sha256"
                        }
                    )
                )
                if not native_sealed or not (
                    native == desired_binding or native_projection == projected
                ) or native.get("ground_state_sha256") != _sha(current_ground):
                    raise ValueError("hook_state:cas_conflict")
            else:
                if projected is not None:
                    raise ValueError("hook_state:native_binding_missing")
                if current.get("program_sha256") != record.get("program_sha256"):
                    raise ValueError("hook_state:base_state_mismatch")
        elif projected is not None:
            raise ValueError("hook_state:projection_file_missing")
        _atomic_json(current_path, record)
        if not self.grants.record_hook_projection(
            desired_binding, expected_previous=projected
        ):
            raise ValueError("hook_state:projection_cas_failed")
        return _sha(record)

    @staticmethod
    def _base_report(
        *,
        controller_id: Any,
        status: str,
        decision: str,
        issues: list[str],
        cursor: Mapping[str, Any] | None = None,
        state: Mapping[str, Any] | None = None,
        hook_state_sha256: str | None = None,
        review_observation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        stage_report = state.get("stage_report") if isinstance(state, Mapping) else None
        stored_action = state.get("action") if isinstance(state, Mapping) else None
        action = (
            stored_action
            if isinstance(stored_action, Mapping)
            and state.get("grant_state") == "AUTHORIZED"
            else None
        )
        controller_state = {
            "terminal": bool(state.get("terminal")) if isinstance(state, Mapping) else False,
            "pending_intent": bool(state.get("pending_intent")) if isinstance(state, Mapping) else False,
            "action_outcome": state.get("action_outcome") if isinstance(state, Mapping) else None,
            "action_authorized": isinstance(action, Mapping),
            "grant_state": state.get("grant_state") if isinstance(state, Mapping) else None,
            "cleanup_required": bool(state.get("cleanup_required")) if isinstance(state, Mapping) else False,
        }
        report = {
            "schema": REPORT_SCHEMA,
            "policy_version": CONTROLLER_POLICY_VERSION,
            "status": status,
            "decision": decision,
            "controller_id": controller_id,
            "issues": sorted(set(issues)),
            "cursor": deepcopy(dict(cursor)) if isinstance(cursor, Mapping) else None,
            "stage_report": deepcopy(stage_report),
            "next_stage_action": (
                stage_report.get("next_action")
                if isinstance(stage_report, Mapping)
                else None
            ),
            "action": deepcopy(action),
            "controller_state": controller_state,
            "hook_state_sha256": hook_state_sha256,
            "provider_free": True,
            "hosted_calls": 0,
            "model_calls": 0,
            "native_calls": 0,
            "task_creations": 0,
            "worker_creations": 0,
            "credential_reads": 0,
            "authority_grants_minted": 0,
            "native_action_authorizations": 1 if isinstance(action, Mapping) else 0,
        }
        if review_observation is not None:
            report.update(schema=REVIEW_WAIT_REPORT_SCHEMA, review_observation=deepcopy(dict(review_observation)))
        return {**report, "report_sha256": _sha(report)}

    def _validate_program(self, program: Any) -> tuple[Mapping[str, Any], list[str]]:
        issues: list[str] = []
        value = _exact(
            program,
            {"schema", "controller_id", "operation", "expected_cursor", "payload"},
            "program",
            issues,
        )
        try:
            if len(_canonical(program)) > MAX_PROGRAM_BYTES:
                _issue(issues, "program:too_large")
        except (TypeError, ValueError):
            _issue(issues, "program:not_json")
        if value.get("schema") != PROGRAM_SCHEMA:
            _issue(issues, "program:schema_invalid")
        _identifier(value.get("controller_id"), "program.controller_id", issues)
        if value.get("operation") not in OPERATIONS:
            _issue(issues, "program:operation_invalid")
        if not isinstance(value.get("payload"), Mapping):
            _issue(issues, "program.payload:not_object")
        return value, sorted(issues)

    def _validate_hook_trust(
        self,
        receipt_sha256: Any,
        *,
        controller_id: str,
        identity: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        issues: list[str] = []
        if not _digest(receipt_sha256, "activation.hook_trust_receipt", issues):
            return None, issues
        path = (
            self.plugin_data
            / "governed-native"
            / "hook-trust"
            / (str(receipt_sha256) + ".json")
        )
        try:
            raw = owned_file.read_owned_bytes(
                path, max_bytes=MAX_DURABLE_FILE_BYTES
            )
            if hashlib.sha256(raw).hexdigest() != receipt_sha256:
                raise ValueError("trust receipt digest mismatch")
            envelope = json.loads(raw.decode("utf-8"))
        except FileNotFoundError:
            return None, ["activation:hook_trust_receipt_missing"]
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return None, ["activation:hook_trust_receipt_invalid"]
        evaluation_time = (
            self.now() if callable(self.now) else self.now
        )
        expected = {
            "schema": HOOK_TRUST_PAYLOAD_SCHEMA,
            "status": "PASS",
            "controller_id": controller_id,
            "project_id": identity.get("project_id"),
            "root_session_id": identity.get("root_session_id"),
            "hook_definition_sha256": identity.get("hook_definition_sha256"),
            "hook_registration_sha256": identity.get("hook_registration_sha256"),
        }
        report = observer_receipt.verify_signed_receipt(
            envelope,
            expected_kind=HOOK_TRUST_RECEIPT_KIND,
            expected_payload=expected,
            evaluation_time=evaluation_time,
            replay_guard=self._hook_trust_replay_guard,
        )
        payload = report.get("payload") if isinstance(report.get("payload"), Mapping) else {}
        if (
            report.get("status") != "PASS"
            or set(payload)
            != set(expected)
            | {
                "mode",
                "invocation_id",
                "hook_inventory_report_sha256",
            }
            or payload.get("mode") not in HOOK_TRUST_MODES
            or not _IDENTIFIER.fullmatch(str(payload.get("invocation_id", "")))
            or _DIGEST.fullmatch(
                str(payload.get("hook_inventory_report_sha256", ""))
            )
            is None
        ):
            return None, ["activation:hook_trust_unavailable"]
        return {
            "mode": payload["mode"],
            "invocation_id": payload["invocation_id"],
            "hook_inventory_report_sha256": payload[
                "hook_inventory_report_sha256"
            ],
            "signed_receipt_sha256": report.get("signed_receipt_sha256"),
            "verification_report_sha256": report.get("report_sha256"),
        }, []

    def _validate_activation(
        self, payload: Any, *, controller_id: str
    ) -> tuple[dict[str, Any] | None, list[str]]:
        issues: list[str] = []
        value = _exact(
            payload,
            {
                "identity",
                "enrollment_program",
                "project_ground_state",
                "hook_trust_receipt_sha256",
                "task_specs",
            },
            "activation",
            issues,
        )
        identity = _exact(
            value.get("identity"),
            {
                "project_id",
                "enrollment_generation",
                "installed_plugin_version",
                "ticket_id",
                "admission_sha256",
                "authority_scope_sha256",
                "root_thread_id",
                "root_session_id",
                "run_id",
                "attempt_id",
                "root_model",
                "root_effort",
                "source_version",
                "task_loaded_version",
                "fresh_task",
                "plan_sha256",
                "task_specs_sha256",
                "hook_definition_sha256",
                "hook_registration_sha256",
                "native_adapter_sha256",
            },
            "activation.identity",
            issues,
        )
        for field in (
            "project_id",
            "installed_plugin_version",
            "ticket_id",
            "root_thread_id",
            "root_session_id",
            "run_id",
            "attempt_id",
            "root_model",
            "root_effort",
            "source_version",
            "task_loaded_version",
        ):
            _identifier(identity.get(field), "activation.identity." + field, issues)
        if type(identity.get("enrollment_generation")) is not int or identity.get(
            "enrollment_generation", 0
        ) < 1:
            _issue(issues, "activation.identity.enrollment_generation:invalid")
        for field in (
            "admission_sha256",
            "authority_scope_sha256",
            "plan_sha256",
            "task_specs_sha256",
            "hook_definition_sha256",
            "hook_registration_sha256",
            "native_adapter_sha256",
        ):
            _digest(identity.get(field), "activation.identity." + field, issues)

        if identity.get("fresh_task") is not True:
            _issue(issues, "activation.identity.fresh_task_required")
        if not (
            identity.get("source_version")
            == identity.get("installed_plugin_version")
            == identity.get("task_loaded_version")
        ):
            _issue(issues, "activation:plugin_generation_identity_mismatch")

        try:
            task_specs = normalized_task_specs(value.get("task_specs"))
        except ValueError:
            task_specs = []
            _issue(issues, "activation:task_specs_invalid")
        if _sha([
            {
                "logical_worker_id": row["logical_worker_id"],
                "task_spec_sha256": row["task_spec_sha256"],
            }
            for row in task_specs
        ]) != identity.get("task_specs_sha256"):
            _issue(issues, "activation:task_specs_identity_mismatch")

        try:
            observed_hook_sha = owned_file.sha256_owned_file(
                self.hook_definition_path,
                max_bytes=MAX_RUNTIME_FILE_BYTES,
            )
        except (OSError, ValueError):
            observed_hook_sha = None
            _issue(issues, "activation:hook_definition_unavailable")
        if (
            observed_hook_sha != identity.get("hook_definition_sha256")
        ):
            _issue(issues, "activation:hook_definition_mismatch")
        try:
            observed_registration_sha = owned_file.sha256_owned_file(
                self.hook_definition_path.parent / "hooks.json",
                max_bytes=MAX_RUNTIME_FILE_BYTES,
            )
        except (OSError, ValueError):
            observed_registration_sha = None
            _issue(issues, "activation:hook_registration_unavailable")
        if observed_registration_sha != identity.get("hook_registration_sha256"):
            _issue(issues, "activation:hook_registration_mismatch")
        trust, trust_issues = self._validate_hook_trust(
            value.get("hook_trust_receipt_sha256"),
            controller_id=controller_id,
            identity=identity,
        )
        issues.extend(trust_issues)
        if identity.get("native_adapter_sha256") != CLOSED_NATIVE_ACTION_ADAPTER_SHA256:
            _issue(issues, "activation:native_adapter_mismatch")

        installed_plugin_version = self._installed_plugin_version()
        if installed_plugin_version is None:
            _issue(issues, "activation:plugin_manifest_unavailable")
        if installed_plugin_version != identity.get("installed_plugin_version"):
            _issue(issues, "activation:plugin_generation_mismatch")

        try:
            enrollment = project_ground.evaluate_project_enrollment(
                value.get("enrollment_program")
            )
        except Exception:
            enrollment = {}
            _issue(issues, "activation:enrollment_evaluation_failed")
        if enrollment.get("status") != "PASS" or enrollment.get("decision") != "ACTIVE":
            _issue(issues, "activation:enrollment_not_active")
        if (
            enrollment.get("project_id") != identity.get("project_id")
            or enrollment.get("binding_generation")
            != identity.get("enrollment_generation")
        ):
            _issue(issues, "activation:enrollment_identity_mismatch")

        roots = dict(self.source_roots)
        root_custody = None
        try:
            observation = enrollment.get("observation", {})
            enrolled_root = Path(observation["canonical_root"])
            roots.setdefault("source", enrolled_root)
            root_custody = owned_file.source_root_custody(roots)
            source = root_custody["source"]
            if source != {"path": str(enrolled_root), "device": observation["device"],
                          "inode": observation["inode"]}:
                raise ValueError("source_roots:mismatch")
        except (KeyError, OSError, TypeError, ValueError):
            _issue(issues, "activation:source_roots_mismatch")

        state_record = value.get("project_ground_state")
        if (
            not isinstance(state_record, Mapping)
            or set(state_record) != {"schema", "program", "program_sha256"}
            or state_record.get("schema") != ground_enforcement.HOOK_STATE_SCHEMA
            or state_record.get("program_sha256")
            != ground_enforcement._sha(state_record.get("program"))
        ):
            _issue(issues, "activation:project_ground_state_invalid")
            ground_program = {}
        else:
            ground_program = state_record.get("program", {})
        ground_state = ground_program.get("state", {}) if isinstance(ground_program, Mapping) else {}
        prereq = ground_state.get("prerequisites", {}) if isinstance(ground_state, Mapping) else {}
        if (
            prereq.get("enrollment", {}).get("project_id") != identity.get("project_id")
            or prereq.get("enrollment", {}).get("generation")
            != identity.get("enrollment_generation")
            or prereq.get("ticket_admission", {}).get("ticket_id")
            != identity.get("ticket_id")
            or prereq.get("ticket_admission", {}).get("admission_sha256")
            != identity.get("admission_sha256")
            or prereq.get("ticket_admission", {}).get("plan_sha256")
            != identity.get("plan_sha256")
            or prereq.get("lease", {}).get("owner_thread_id")
            != identity.get("root_thread_id")
            or prereq.get("lease", {}).get("current_thread_id")
            != identity.get("root_thread_id")
            or prereq.get("authority", {}).get("scope_sha256")
            != identity.get("authority_scope_sha256")
        ):
            _issue(issues, "activation:project_ground_identity_mismatch")
        if ground_state.get("hook", {}).get("observed_sha256") != observed_hook_sha:
            _issue(issues, "activation:project_ground_hook_mismatch")
        completion = (
            ground_program.get("completion")
            if isinstance(ground_program, Mapping)
            else None
        )
        if completion != {
            "final_verification_valid": False,
            "final_verification_sha256": None,
            "independent_observation": "UNBOUND",
            "governed_controller_status": "PENDING",
        }:
            _issue(issues, "activation:completion_must_be_pending")
        tool_policy = (
            ground_program.get("tool_policy")
            if isinstance(ground_program, Mapping)
            and isinstance(ground_program.get("tool_policy"), Mapping)
            else {}
        )
        read_only_tools = tool_policy.get("read_only_tools")
        if (
            not isinstance(read_only_tools, list)
            or len(read_only_tools) != len(set(read_only_tools))
            or not set(read_only_tools).issubset(CLOSED_READ_ONLY_TOOLS)
        ):
            _issue(issues, "activation:read_only_tool_policy_unrecognized")

        if not issues:
            hook_input = {
                "session_id": identity["root_session_id"],
                "cwd": str(
                    ground_program.get("event", {}).get("cwd", "")
                ),
                "hook_event_name": "SessionStart",
                "model": ground_program.get("event", {}).get("model"),
                "permission_mode": ground_program.get("event", {}).get(
                    "permission_mode", "default"
                ),
                "source": ground_program.get("event", {}).get("source"),
            }
            try:
                bound = ground_enforcement.program_from_hook_state(
                    hook_input, state_record
                )
                ground_report = ground_enforcement.evaluate_project_ground_enforcement(
                    bound
                )
            except (
                KeyError,
                OSError,
                TypeError,
                ValueError,
                sqlite3.Error,
                run_engine.RunKernelError,
            ):
                ground_report = {}
            if ground_report.get("decision") != "HEALTHY":
                _issue(issues, "activation:project_ground_not_healthy")
        if issues:
            return None, sorted(issues)
        self.source_roots = roots
        return {
            "identity": deepcopy(dict(identity)),
            "source_roots": root_custody,
            "enrollment_report": {
                "report_sha256": enrollment.get("report_sha256"),
                "record_sha256": enrollment.get("record_sha256"),
                "manifest_sha256": enrollment.get("manifest_sha256"),
            },
            "project_ground_state": deepcopy(dict(state_record)),
            "hook_trust": deepcopy(dict(trust or {})),
            "task_specs": task_specs,
        }, []

    def _activate(self, value: Mapping[str, Any]) -> dict[str, Any]:
        controller_id = value.get("controller_id")
        if value.get("expected_cursor") is not None:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="ACTIVATION_REFUSED",
                issues=["activation:expected_cursor_must_be_null"],
            )
        activation, issues = self._validate_activation(
            value.get("payload"), controller_id=str(controller_id)
        )
        if issues:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="ACTIVATION_REFUSED",
                issues=issues,
            )
        run_id = _controller_run_id(controller_id)
        activation_sha256 = _sha(activation)
        existing_state: Mapping[str, Any] | None = None
        existing_rows: list[Mapping[str, Any]] | None = None
        if self.store.exists(run_id):
            existing_state, existing_rows = self._state(run_id)
            if existing_state.get("activation") != activation:
                return self._base_report(
                    controller_id=controller_id,
                    status="BLOCKED",
                    decision="ACTIVATION_REFUSED",
                    issues=["activation:existing_identity_mismatch"],
                    cursor=_cursor(existing_rows),
                    state=existing_state,
                )
        ownership = self.grants.register_owner(
            controller_id=str(controller_id),
            controller_run_id=run_id,
            activation_sha256=activation_sha256,
        )
        if ownership.get("status") == "CONFLICT" and self._owner_releasable(
            ownership.get("owner"), successor_activation=activation
        ):
            retirement = self._terminal_retirement_evidence(
                ownership.get("owner")
            )
            retired = (
                self.grants.terminalize_partial_native_failure_spawn(
                    expected_owner=ownership["owner"],
                    terminal_binding=retirement["binding"],
                    capacity_tip=retirement["capacity_tip"],
                    capacity_authority=retirement["capacity_authority"],
                )
                if isinstance(retirement, Mapping)
                else {"status": "REFUSED"}
            )
            if retired.get("status") == "NOT_APPLICABLE":
                prior_state, _ = self._state(ownership["owner"]["controller_run_id"])
                receipt = prior_state.get("stage_report", {}).get("receipt", {})
                if (
                    isinstance(receipt, Mapping)
                    and native_grant_store.owner_closed_ack_cut_for_failure(receipt.get("failure_cut")) is not None
                ):
                    retired = self.grants.terminalize_owner_closed_action(
                        expected_owner=ownership["owner"],
                        terminal_binding=retirement["binding"],
                        capacity_tip=retirement["capacity_tip"],
                        capacity_authority=retirement["capacity_authority"],
                    )
                else:
                    retired = self.grants.stale_terminal_unclaimed_spawn(
                        expected_owner=ownership["owner"],
                        terminal_binding=retirement["binding"],
                        capacity_tip=retirement["capacity_tip"],
                    )
            if retired.get("status") in {
                "STALED",
                "TERMINALIZED",
                "NOT_REQUIRED",
            }:
                ownership = self.grants.rotate_owner(
                    expected_owner=ownership["owner"],
                    controller_id=str(controller_id),
                    controller_run_id=run_id,
                    activation_sha256=activation_sha256,
                )
        if ownership.get("status") not in {"CREATED", "MATCH", "ROTATED"}:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="ACTIVATION_REFUSED",
                issues=["activation:active_controller_conflict"],
            )
        run_marker = self.grants.controller_run_marker(run_id)
        if not isinstance(run_marker, Mapping):
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="ACTIVATION_REFUSED",
                issues=["activation:run_witness_unavailable"],
            )
        if existing_state is not None and existing_rows is not None:
            cursor = _cursor(existing_rows)
            hook_sha = self._sync_hook(
                controller_id=str(controller_id),
                cursor=cursor,
                state=existing_state,
            )
            return self._base_report(
                controller_id=controller_id,
                status="PASS",
                decision="ACTIVATION_RECOVERED_READ_ONLY",
                issues=[],
                cursor=cursor,
                state=existing_state,
                hook_state_sha256=hook_sha,
            )
        plan = run_engine.make_plan(
            run_id=run_id,
            name="governed native controller",
            expected_roles=("controller",),
            deliverable=True,
            actors=(
                run_engine.actor(
                    actor_key="controller",
                    kind="integrator",
                    model="provider-free-controller",
                    intent="governance:native-exact-action",
                ),
            ),
            origin={
                "controller_id": controller_id,
                "activation_identity_sha256": _sha(activation["identity"]),
                "activation_sha256": activation_sha256,
                "governed_native_activation": activation,
                "policy_version": CONTROLLER_POLICY_VERSION,
                "store_identity_sha256": self.grants.store_identity_sha256,
                "controller_run_marker_sha256": run_marker[
                    "marker_sha256"
                ],
                "previous_controller_run_id": run_marker[
                    "previous_controller_run_id"
                ],
                "previous_controller_run_marker_sha256": run_marker[
                    "previous_marker_sha256"
                ],
            },
        )
        self.engine.start(plan)
        state, rows = self._state(run_id)
        cursor = _cursor(rows)
        hook_sha = self._sync_hook(
            controller_id=controller_id, cursor=cursor, state=state
        )
        return self._base_report(
            controller_id=controller_id,
            status="PASS",
            decision="ACTIVATED_READ_ONLY",
            issues=[],
            cursor=cursor,
            state=state,
            hook_state_sha256=hook_sha,
        )

    def _terminal_run_closed(self, binding: Mapping[str, Any]) -> bool:
        prior_run_id = binding.get("controller_run_id")
        if not isinstance(prior_run_id, str) or not self.store.exists(prior_run_id):
            return False
        try:
            state, rows = self._state(prior_run_id)
            cursor = _cursor(rows)
            authority = self.tower.read_shared_capacity_authority()
            active = (
                authority.get("state", {}).get("active_lane_ids")
                if isinstance(authority, Mapping)
                and authority.get("status") == "VERIFIED"
                else None
            )
        except ValueError:
            return False
        return bool(
            state.get("terminal")
            and isinstance(state.get("stage_report"), Mapping)
            and state.get("pending_intent") is None
            and state.get("action") is None
            and not state.get("cleanup_required")
            and active == []
            and isinstance(cursor, Mapping)
            and binding.get("controller_seq") == cursor.get("seq")
            and binding.get("controller_event_hash") == cursor.get("event_hash")
        )

    def _owner_releasable(
        self, owner: Any, *, successor_activation: Mapping[str, Any]
    ) -> bool:
        if not isinstance(owner, Mapping):
            return False
        prior_run_id = owner.get("controller_run_id")
        if not isinstance(prior_run_id, str) or not self.store.exists(prior_run_id):
            return False
        try:
            prior_state, _prior_rows = self._state(prior_run_id)
            prior_identity = prior_state.get("activation", {}).get("identity", {})
            successor_identity = successor_activation.get("identity", {})
            current = owned_file.read_owned_json(
                self.plugin_data / "project-ground" / "current.json",
                max_bytes=MAX_RUNTIME_FILE_BYTES,
            )
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
        except (OSError, json.JSONDecodeError, ValueError):
            return False
        return bool(
            isinstance(binding, Mapping)
            and self._terminal_run_closed(binding)
            and binding.get("controller_id") == owner.get("controller_id")
            and binding.get("controller_run_id") == prior_run_id
            and binding.get("status") == "TERMINAL"
            and binding.get("action") is None
            and binding.get("binding_sha256") == _sha(binding_core)
            and all(
                prior_identity.get(field) != successor_identity.get(field)
                for field in ("attempt_id", "run_id", "admission_sha256")
            )
        )

    def _terminal_retirement_evidence(self, owner: Any) -> dict[str, Any] | None:
        if not isinstance(owner, Mapping):
            return None
        try:
            first = owned_file.read_owned_json(
                self.plugin_data / "project-ground" / "current.json",
                max_bytes=MAX_RUNTIME_FILE_BYTES,
            )
            first_binding = (
                first.get("native_controller")
                if isinstance(first, Mapping)
                else None
            )
            first_authority = self.tower.read_shared_capacity_authority()
            first_tip = self.grants.verified_tip(
                str(first_authority.get("store_id"))
            )
            second = owned_file.read_owned_json(
                self.plugin_data / "project-ground" / "current.json",
                max_bytes=MAX_RUNTIME_FILE_BYTES,
            )
            second_binding = (
                second.get("native_controller")
                if isinstance(second, Mapping)
                else None
            )
            second_authority = self.tower.read_shared_capacity_authority()
            second_tip = self.grants.verified_tip(
                str(second_authority.get("store_id"))
            )
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return None
        first_state = (
            first_authority.get("state")
            if isinstance(first_authority, Mapping)
            and isinstance(first_authority.get("state"), Mapping)
            else {}
        )
        second_state = (
            second_authority.get("state")
            if isinstance(second_authority, Mapping)
            and isinstance(second_authority.get("state"), Mapping)
            else {}
        )
        if not (
            isinstance(first_binding, Mapping)
            and first_binding == second_binding
            and first_binding.get("controller_id") == owner.get("controller_id")
            and first_binding.get("controller_run_id")
            == owner.get("controller_run_id")
            and first_binding.get("status") == "TERMINAL"
            and first_binding.get("action") is None
            and first_authority.get("status") == "VERIFIED"
            and first_authority.get("continuity_verified") is True
            and second_authority.get("status") == "VERIFIED"
            and second_authority.get("continuity_verified") is True
            and first_authority.get("store_id")
            == second_authority.get("store_id")
            and first_authority.get("state_sha256")
            == second_authority.get("state_sha256")
            and first_state.get("active_lane_ids") == []
            and second_state.get("active_lane_ids") == []
            and isinstance(first_tip, Mapping)
            and first_tip == second_tip
        ):
            return None
        return {
            "binding": deepcopy(dict(first_binding)),
            "capacity_tip": deepcopy(dict(first_tip)),
            "capacity_authority": deepcopy(dict(first_authority)),
        }

    @staticmethod
    def _expected_cursor_issue(
        expected: Any, current: Mapping[str, Any] | None
    ) -> str | None:
        if not _cursor_valid(expected):
            return "controller:expected_cursor_invalid"
        if dict(expected) != dict(current or {}):
            return "controller:stale_cursor"
        return None

    @staticmethod
    def _stage_continuity_issues(
        stage_program: Any, state: Mapping[str, Any]
    ) -> list[str]:
        issues: list[str] = []
        value = _exact(
            stage_program,
            {"schema", "operation", "identity", "predecessor_receipt", "payload"},
            "stage.program",
            issues,
        )
        checkpoint_pre_spawn = (
            value.get("schema") == governed_attempt.CHECKPOINT_PROGRAM_SCHEMA
            and value.get("operation") == "pre_spawn"
        )
        if value.get("schema") != governed_attempt.PROGRAM_SCHEMA and not checkpoint_pre_spawn:
            _issue(issues, "stage:schema_invalid")
        identity = value.get("identity") if isinstance(value.get("identity"), Mapping) else {}
        activation = state.get("activation", {})
        bound = activation.get("identity", {}) if isinstance(activation, Mapping) else {}
        expected_identity = {
            "run_id": bound.get("run_id"),
            "attempt_id": bound.get("attempt_id"),
            "root_task_id": bound.get("root_thread_id"),
            "root_model": bound.get("root_model"),
            "root_effort": bound.get("root_effort"),
            "source_version": bound.get("source_version"),
            "installed_version": bound.get("installed_plugin_version"),
            "task_loaded_version": bound.get("task_loaded_version"),
            "fresh_task": bound.get("fresh_task"),
        }
        if identity != expected_identity:
            _issue(issues, "stage:identity_mismatch")
        operation = value.get("operation")
        prior_report = state.get("stage_report")
        prior_receipt = (
            prior_report.get("receipt")
            if isinstance(prior_report, Mapping)
            and isinstance(prior_report.get("receipt"), Mapping)
            else None
        )
        submitted = value.get("predecessor_receipt")
        if prior_receipt is None:
            if operation != "pre_spawn" or submitted is not None:
                _issue(issues, "stage:first_transition_must_be_pre_spawn")
        elif submitted != prior_receipt:
            _issue(issues, "stage:predecessor_not_controller_tip")

        payload = value.get("payload") if isinstance(value.get("payload"), Mapping) else {}
        if operation == "pre_spawn":
            ticket = payload.get("ticket_admission") if isinstance(payload.get("ticket_admission"), Mapping) else {}
            plan = payload.get("logical_plan") if isinstance(payload.get("logical_plan"), Mapping) else {}
            project = plan.get("project") if isinstance(plan.get("project"), Mapping) else {}
            hard_admission = payload.get("hard_admission")
            candidate_plan = (
                hard_admission.get("candidate_plan")
                if isinstance(hard_admission, Mapping)
                else None
            )
            semantic = (
                candidate_plan.get("semantic_decision")
                if isinstance(candidate_plan, Mapping)
                else {}
            )
            wave = payload.get("wave_preflight") if isinstance(payload.get("wave_preflight"), Mapping) else {}
            try:
                specs_sha = task_specs_identity_sha256(wave.get("task_specs"))
            except ValueError:
                specs_sha = None
            if (
                ticket.get("ticket_id") != bound.get("ticket_id")
                or ticket.get("admission_sha256") != bound.get("admission_sha256")
                or ticket.get("root_task_id") != bound.get("root_thread_id")
            ):
                _issue(issues, "stage:ticket_admission_mismatch")
            if (
                _sha(plan) != bound.get("plan_sha256")
                or project.get("project_id") != bound.get("project_id")
                or project.get("binding_generation") != bound.get("enrollment_generation")
                or specs_sha != bound.get("task_specs_sha256")
            ):
                _issue(issues, "stage:plan_or_taskspec_mismatch")
            if not isinstance(semantic, Mapping) or semantic.get(
                "authority_scope_sha256"
            ) != bound.get("authority_scope_sha256"):
                _issue(issues, "stage:authority_scope_mismatch")
        elif isinstance(submitted, Mapping):
            bindings = submitted.get("bindings") if isinstance(submitted.get("bindings"), Mapping) else {}
            if (
                submitted.get("run_id") != bound.get("run_id")
                or submitted.get("attempt_id") != bound.get("attempt_id")
                or submitted.get("root_task_id") != bound.get("root_thread_id")
                or submitted.get("plan_sha256") != bound.get("plan_sha256")
                or bindings.get("ticket_id") != bound.get("ticket_id")
                or bindings.get("ticket_admission_sha256") != bound.get("admission_sha256")
                or bindings.get("project_id") != bound.get("project_id")
                or bindings.get("binding_generation") != bound.get("enrollment_generation")
            ):
                _issue(issues, "stage:predecessor_identity_mismatch")
        if operation == "worker_start":
            evidence = state.get("last_batch_result")
            expected_result = (
                native_result.spawn_result_binding(
                    evidence.get("result_binding"),
                    evidence.get("lane_ids"),
                )
                if isinstance(evidence, Mapping)
                and evidence.get("kind") == "spawn"
                else None
            )
            creations = payload.get("creations")
            observed_lanes: list[dict[str, str]] | None = None
            if isinstance(creations, list):
                candidates: list[dict[str, str]] = []
                for creation in creations:
                    if not isinstance(creation, Mapping):
                        candidates = []
                        break
                    lane_id = creation.get("logical_worker_id")
                    agent_id = creation.get("worker_id")
                    if not isinstance(lane_id, str) or not isinstance(agent_id, str):
                        candidates = []
                        break
                    candidates.append({"lane_id": lane_id, "agent_id": agent_id})
                candidates.sort(key=lambda row: row["lane_id"])
                observed_lanes = candidates
            if (
                expected_result is None
                or observed_lanes != expected_result["lanes"]
            ):
                _issue(issues, "stage:spawn_result_worker_mismatch")
        if operation in {"worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification", "cleanup"}:
            batch = state.get("last_batch_result")
            expected_lanes = ["spec", "standards"]
            if (not isinstance(batch, Mapping) or batch.get("kind") != "continue"
                    or batch.get("lane_ids") != expected_lanes
                    or native_result.continue_result_binding(batch.get("result_binding"), expected_lanes) is None):
                _issue(issues, "stage:result_collection_before_complete_batch")
            try:
                # This pure constructor rejects malformed/replaced observations
                # before any stage intent can change the durable predecessor.
                if operation == "worker_results":
                    constructed = governed_attempt.build_worker_results_program(
                        expected_identity, state.get("stage_report"), payload.get("worker_results"))
                elif operation == "result_aggregation":
                    constructed = governed_attempt.build_result_aggregation_program(expected_identity, state.get("stage_report"))
                elif operation == "review_submission":
                    constructed = governed_attempt.build_review_submission_program(
                        expected_identity, state.get("stage_report"), payload.get("review_submission"), payload.get("review_context"))
                    if (payload["review_context"]["owner_hook_inventory_report"]["report_sha256"]
                            != activation["hook_trust"]["hook_inventory_report_sha256"]):
                        _issue(issues, "stage:review_owner_inventory_mismatch")
                else:
                    constructor = (governed_attempt.build_verified_cleanup_program if operation == "cleanup"
                                   else governed_attempt.build_terminal_verification_program if operation == "terminal_verification"
                                   else governed_attempt.build_semantic_review_program)
                    constructed = constructor(expected_identity, state.get("stage_report"))
                    context = state["stage_report"]["receipt"]["bindings"]["review_context"]
                    if context["owner_hook_inventory_report"]["report_sha256"] != activation["hook_trust"]["hook_inventory_report_sha256"]:
                        _issue(issues, "stage:review_owner_inventory_mismatch")
                if _canonical(constructed) != _canonical(stage_program):
                    _issue(issues, "stage:" + operation + "_program_mismatch")
            except (KeyError, TypeError, ValueError, OverflowError):
                _issue(issues, "stage:" + operation + "_program_invalid")
        return sorted(issues)

    def _collect_worker_checkpoints(self, state: Mapping[str, Any], native_request_meta: Any) -> tuple[str, dict[str, Any] | None]:
        """Collect owned checkpoint bytes without creating a stage or grant.

        The current native wrapper name comes from its held source record,
        selected by the host MCP call ID. It need not be the logical MCP tool
        name. Stage admission independently reobserves the returned bundle.
        """
        from lifecycle_conformance.host_adapter import mcp_call_context
        import orch_dork_coordinator_usage as coordinator
        import orch_dork_local_task_runtime as local
        import orch_dork_native_attempt_observer as native
        import orch_dork_qualification_progress as progress
        import orch_dork_qualification_results as results
        try:
            context = mcp_call_context(native_request_meta)
            activation = state["activation"]
            identity = activation["identity"]
            receipt = state["stage_report"]["receipt"]
            if (receipt["stage"] != "worker_start" or receipt["next_action"] != "continue"
                    or receipt["bindings"].get("worker_checkpoint_profile") != governed_attempt.WORKER_CHECKPOINT_PROFILE
                    or "checkpoint_sources" in state or state["action_outcome"] != "completed"
                    or state["action"] is not None or state["pending_intent"] is not None
                    or state["cleanup_required"] or state["terminal"] or not self._retained_hook_evidence_valid(state)
                    or context["task_id"] != identity["root_thread_id"]
                    or context["model"] != identity["root_model"] or context["effort"] != identity["root_effort"]):
                raise ValueError("not awaiting owned checkpoints")
            joins = results.join_bindings(receipt["bindings"], identity["root_thread_id"])
            tasks = {r["logical_worker_id"]:r["task_spec"] for r in activation["task_specs"]}
            if len(activation["task_specs"]) != 2 or set(tasks) != {"spec", "standards"}:
                raise ValueError("different frozen tasks")
            batch = state["last_batch_result"]
            normalized = native_result.continue_result_binding(batch["result_binding"], ["spec", "standards"])
            if batch["kind"] != "continue" or batch["lane_ids"] != ["spec", "standards"] or normalized is None:
                raise ValueError("incomplete checkpoint batch")
            turns = {r["lane_id"]:r["submission"]["submission_id"] for r in normalized["submissions"]}
            continued = [r for r in state["action_evidence"] if r["action"]["kind"] == "continue"]
            if len(continued) != 2:
                raise ValueError("different checkpoint continuation count")
            lanes = {}
            for row in continued:
                action = row["action"]
                if (action["batch_id"] != batch["batch_id"] or action["batch_phase"] != "primary"
                        or len(action["lane_ids"]) != 1 or action["lane_ids"][0] in lanes):
                    raise ValueError("different checkpoint action")
                lane = action["lane_ids"][0]
                target = next(r for r in joins if r["binding"]["logical_worker_id"] == lane)
                observed = native_result.continue_result_binding(row["result_binding"], [lane])
                if (observed is None or observed["submissions"][0]["submission"]["submission_id"] != turns[lane]
                        or action["tool_input"]["target"] != target["binding"]["worker_id"]
                        or tasks[lane]["task_spec_sha256"] != target["task_spec_sha256"]):
                    raise ValueError("checkpoint identity differs")
                root_turn_id = self._action_evidence_turn_id(row, identity)
                if root_turn_id is None:
                    raise ValueError("checkpoint custody differs")
                lanes[lane] = {"task_spec_sha256":target["task_spec_sha256"],
                    **{key:target["binding"][key] for key in ("model", "effort")},
                    "root_turn_id":root_turn_id}
        except (KeyError, TypeError, ValueError, StopIteration, OverflowError, RecursionError) as error:
            raise ValueError("checkpoint_sources:controller_binding_invalid") from error
        try:
            hook = local.OwnerHookInventoryArtifact.from_report(local.observe_qualification_host_hooks(
                socket_path=os.environ.get(local.OWNER_SOCKET_ENV, ""), cwd=self.source_roots["source"]))
            if hook.report_sha256 != activation["hook_trust"]["hook_inventory_report_sha256"]:
                raise ValueError("different frozen owner")
            selection = {"owner":{"root_task_id":identity["root_thread_id"],
                "worker_ids":{r["binding"]["logical_worker_id"]:r["binding"]["worker_id"] for r in joins},
                "owner_identity_sha256":hook.owner_identity_sha256,
                "app_server_argv_sha256":hook.app_server_argv_sha256,
                "hook_inventory_report_sha256":hook.report_sha256},
                "root_turn_id":context["turn_id"], "worker_turn_ids":turns}
            inventory = local.observe_worker_checkpoint_sources(selection)
            if (local.validate_worker_checkpoint_sources(inventory)["valid"] is not True
                    or _canonical(inventory["expectation"]) != _canonical(selection)):
                raise ValueError("invalid checkpoint inventory")
            if inventory["status"] != "OBSERVED":
                return inventory["status"], None
            private = os.environ.get("CODEX_HOME")
            if not private and os.environ.get("HOME"):private = str(Path(os.environ["HOME"]) / ".codex")
            if not private or not Path(private).is_absolute():raise ValueError("private root unavailable")
            scan = native._scan(inventory["observation"]["sources"]["root"], Path(private), pending_call_id=context["tool_call_id"])
            descriptor = {key:scan["active"]["prefix"]["pending_call"][key] for key in ("call_id", "name", "namespace")}
            root = coordinator.observe_coordinator_usage({"sources":selection, "model":identity["root_model"],
                "effort":identity["root_effort"], "pending_call":descriptor})
            workers = native.observe_native_worker_checkpoints({"sources":selection, "lanes":lanes}, tasks)
            if (coordinator.validate_coordinator_usage(root)["valid"] is not True
                    or native.validate_native_worker_checkpoint_observation(workers)["valid"] is not True):
                raise ValueError("invalid checkpoint source observation")
            if "REFUSED" in (root["status"], workers["status"]):return "REFUSED", None
            if "PENDING" in (root["status"], workers["status"]):return "PENDING", None
            held = {**{key:scan[key] for key in ("path", "file_sha256", "prefix_bytes", "custody")},
                    "metadata_source_ref":{key:scan["metadata"][key] for key in ("line", "sha256")}}
            if (_canonical(root["evidence"]["source_inventory"]) != _canonical(inventory)
                    or _canonical(root["evidence"]["source"]) != _canonical(held)):
                raise ValueError("current call source changed")
            progress.build_checkpoint_ingress_observation(
                {"root_task_id":identity["root_thread_id"], "root_model":identity["root_model"],
                 "root_effort":identity["root_effort"]}, root, workers)
            progress.build_checkpoint_progress_program(receipt,
                [workers["evidence"]["workers"][lane]["progress_report"] for lane in ("spec", "standards")])
            return "OBSERVED", {"coordinator":root, "workers":workers}
        except (KeyError, TypeError, ValueError, OSError, OverflowError, RecursionError) as error:
            raise ValueError("checkpoint_sources:source_unavailable") from error

    def _reobserve_worker_checkpoints(self, state: Mapping[str, Any], sources: Any) -> str:
        """Join retained action identities, then independently reread owned bytes.

        Called only after retained hook custody has validated, before stage
        intent. Pending and refusal do not advance the controller or a grant.
        The v2 pre-spawn profile remains disabled at the native schema gate
        until its budget and reservation constructor is complete.
        """
        import orch_dork_coordinator_usage as coordinator
        import orch_dork_native_attempt_observer as native_observer
        import orch_dork_qualification_progress as progress
        import orch_dork_qualification_results as results
        try:
            if type(sources) is not dict or set(sources) != {"coordinator", "workers"}:
                raise ValueError("invalid source bundle")
            activation = state["activation"]
            identity = activation["identity"]
            prior = state["stage_report"]["receipt"]
            if (prior["stage"] != "worker_start" or state["action_outcome"] != "completed"
                    or state["action"] is not None or state["pending_intent"] is not None
                    or state["cleanup_required"] or state["terminal"]):
                raise ValueError("not awaiting first checkpoint")
            progress.build_checkpoint_ingress_observation(
                {"root_task_id":identity["root_thread_id"], "root_model":identity["root_model"],
                 "root_effort":identity["root_effort"]}, sources["coordinator"], sources["workers"])
            progress.build_checkpoint_progress_program(prior,
                [sources["workers"]["evidence"]["workers"][lane]["progress_report"] for lane in ("spec", "standards")])
            inventory = sources["coordinator"]["evidence"]["source_inventory"]
            selection = deepcopy(inventory["expectation"])
            if selection["owner"]["hook_inventory_report_sha256"] != activation["hook_trust"]["hook_inventory_report_sha256"]:
                raise ValueError("different frozen owner")
            joins = results.join_bindings(prior["bindings"], identity["root_thread_id"])
            tasks = {row["logical_worker_id"]:row["task_spec"] for row in activation["task_specs"]}
            if set(tasks) != {"spec", "standards"}:
                raise ValueError("different frozen tasks")
            selection["owner"]["root_task_id"] = identity["root_thread_id"]
            selection["owner"]["worker_ids"] = {row["binding"]["logical_worker_id"]:row["binding"]["worker_id"] for row in joins}
            batch = state["last_batch_result"]
            normalized = native_result.continue_result_binding(batch["result_binding"], ["spec", "standards"])
            if batch["kind"] != "continue" or batch["lane_ids"] != ["spec", "standards"] or normalized is None:
                raise ValueError("incomplete checkpoint batch")
            selection["worker_turn_ids"] = {row["lane_id"]:row["submission"]["submission_id"] for row in normalized["submissions"]}
            continued = [row for row in state["action_evidence"] if row["action"]["kind"] == "continue"]
            if len(continued) != 2:
                raise ValueError("repeated checkpoint continuation")
            lanes = {}
            for row in continued:
                action = row["action"]
                lane_ids = action["lane_ids"]
                if (action["batch_id"] != batch["batch_id"] or action["batch_phase"] != "primary"
                        or len(lane_ids) != 1 or lane_ids[0] in lanes):
                    raise ValueError("different checkpoint action")
                lane = lane_ids[0]
                target = next(join for join in joins if join["binding"]["logical_worker_id"] == lane)
                observed = native_result.continue_result_binding(row["result_binding"], [lane])
                if (observed is None or observed["submissions"][0]["submission"]["submission_id"] != selection["worker_turn_ids"][lane]
                        or action["tool_input"]["target"] != target["binding"]["worker_id"]
                        or tasks[lane]["task_spec_sha256"] != target["task_spec_sha256"]):
                    raise ValueError("checkpoint identity differs")
                root_turn_id = self._action_evidence_turn_id(row, identity)
                if root_turn_id is None:
                    raise ValueError("checkpoint action custody differs")
                lanes[lane] = {"task_spec_sha256":target["task_spec_sha256"],
                    **{key:target["binding"][key] for key in ("model", "effort")},
                    "root_turn_id":root_turn_id}
            root_expected = {"sources":selection, "model":identity["root_model"], "effort":identity["root_effort"],
                             "pending_call":sources["coordinator"]["expectation"]["pending_call"]}
            worker_expected = {"sources":selection, "lanes":lanes}
            if (root_expected != sources["coordinator"]["expectation"]
                    or worker_expected != sources["workers"]["expectation"]):
                raise ValueError("source selection differs from retained actions")
            root = coordinator.observe_coordinator_usage(root_expected)
            workers = native_observer.observe_native_worker_checkpoints(worker_expected, tasks)
            if (coordinator.validate_coordinator_usage(root)["valid"] is not True
                    or native_observer.validate_native_worker_checkpoint_observation(workers)["valid"] is not True):
                raise ValueError("invalid current observation")
            if "REFUSED" in (root["status"], workers["status"]):
                return "REFUSED"
            if "PENDING" in (root["status"], workers["status"]):
                return "PENDING"
            if sources != {"coordinator":root, "workers":workers}:
                raise ValueError("owned evidence changed")
            return "OBSERVED"
        except (KeyError, TypeError, ValueError, StopIteration, OverflowError, RecursionError):
            return "REFUSED"

    def _observe_worker_finals(self, state: Mapping[str, Any], native_request_meta: Any) -> dict[str, Any]:
        """Read finals selected by journal actions and host-only MCP context.

        This helper does not advance the state or grant authority. Its caller
        must own the controller; the stage path also holds the controller lock.
        Missing context/custody refuses before owner reads. The v2 activation
        gate remains closed until budget and lifecycle integration is complete.
        """
        from lifecycle_conformance.host_adapter import mcp_call_context
        import orch_dork_native_worker_finals as finals
        import orch_dork_qualification_results as results
        try:
            context = mcp_call_context(native_request_meta)
            activation = state["activation"]
            identity = activation["identity"]
            receipt = state["stage_report"]["receipt"]
            bindings = receipt["bindings"]
            sources = state["checkpoint_sources"]
            if (receipt["stage"] != "progress" or receipt["next_action"] != "continue"
                    or bindings.get("worker_checkpoint_profile") != governed_attempt.WORKER_CHECKPOINT_PROFILE
                    or bindings.get("checkpoint_sources_sha256") != _sha(sources)
                    or state["action_outcome"] != "completed" or state["action"] is not None
                    or state["pending_intent"] is not None or state["cleanup_required"] or state["terminal"]
                    or "final_sources" in state or not self._retained_hook_evidence_valid(state)
                    or context["task_id"] != identity["root_thread_id"]
                    or context["model"] != identity["root_model"] or context["effort"] != identity["root_effort"]):
                raise ValueError("not awaiting owned final results")
            old = sources["workers"]["expectation"]
            selection = deepcopy(old["sources"])
            selection["root_turn_id"] = context["turn_id"]
            if selection["owner"]["hook_inventory_report_sha256"] != activation["hook_trust"]["hook_inventory_report_sha256"]:
                raise ValueError("different frozen owner")
            joins = results.join_bindings(bindings, identity["root_thread_id"])
            selection["owner"]["root_task_id"] = identity["root_thread_id"]
            selection["owner"]["worker_ids"] = {r["binding"]["logical_worker_id"]:r["binding"]["worker_id"] for r in joins}
            tasks = {r["logical_worker_id"]:r["task_spec"] for r in activation["task_specs"]}
            if len(activation["task_specs"]) != 2 or set(tasks) != {"spec", "standards"}:
                raise ValueError("different frozen tasks")
            batch = state["last_batch_result"]
            normalized = native_result.continue_result_binding(batch["result_binding"], ["spec", "standards"])
            if batch["kind"] != "continue" or batch["lane_ids"] != ["spec", "standards"] or normalized is None:
                raise ValueError("incomplete final batch")
            selection["worker_turn_ids"] = {r["lane_id"]:r["submission"]["submission_id"] for r in normalized["submissions"]}
            continued = [r for r in state["action_evidence"] if r["action"]["kind"] == "continue"]
            if len(continued) != 4:
                raise ValueError("different continuation count")
            checkpoint_batch = continued[0]["action"]["batch_id"]
            if checkpoint_batch == batch["batch_id"]:
                raise ValueError("reused continuation batch")
            lanes = {}
            for index, row in enumerate(continued):
                lane = ("spec", "standards")[index % 2]
                action = row["action"]
                target = next(r for r in joins if r["binding"]["logical_worker_id"] == lane)
                expected_turn = (old["sources"] if index < 2 else selection)["worker_turn_ids"][lane]
                observed = native_result.continue_result_binding(row["result_binding"], [lane])
                if (action["lane_ids"] != [lane] or action["batch_phase"] != "primary"
                        or action["batch_id"] != (checkpoint_batch if index < 2 else batch["batch_id"])
                        or action["tool_input"]["target"] != target["binding"]["worker_id"]
                        or observed is None or observed["submissions"][0]["submission"]["submission_id"] != expected_turn
                        or tasks[lane]["task_spec_sha256"] != target["task_spec_sha256"]
                        or _canonical(tasks[lane]) != _canonical(sources["workers"]["evidence"]["workers"][lane]["progress_report"]["task_spec"])):
                    raise ValueError("continuation identity differs")
                root_turn_id = self._action_evidence_turn_id(row, identity)
                if root_turn_id is None:
                    raise ValueError("continuation custody differs")
                lane_expected = {"task_spec_sha256":target["task_spec_sha256"],
                    **{key:target["binding"][key] for key in ("model", "effort")},
                    "root_turn_id":root_turn_id}
                if index < 2:
                    if _canonical(lane_expected) != _canonical(old["lanes"][lane]):
                        raise ValueError("checkpoint action changed")
                else:
                    if expected_turn == old["sources"]["worker_turn_ids"][lane]:
                        raise ValueError("reused worker turn")
                    lanes[lane] = lane_expected
            expected = finals.build_native_worker_finals_expectation(selection, lanes, sources)
        except (KeyError, TypeError, ValueError, StopIteration, OverflowError, RecursionError) as error:
            raise ValueError("final_sources:controller_binding_invalid") from error
        report = finals.observe_native_worker_finals(expected, sources)
        if finals.validate_native_worker_finals(report, sources)["valid"] is not True:
            raise ValueError("final_sources:observation_invalid")
        return report

    def observe_verified_completion_sources(self, *, env=None) -> dict[str, Any]:
        """Bind idle-owner source bytes to the two retained completed closes.

        This host read requires a waiting canonical owner before reading state;
        it cannot recover a provisional grant or advance a stage. Monotonic
        journal/authority snapshots bracket all reads. Physical process cleanup,
        signed release and final qualification remain separate obligations.
        """
        from orch_dork_governed_native_reports import completion_source_report, completion_waiting_authority
        import orch_dork_local_task_runtime as local
        import orch_dork_native_attempt_observer as source_reader
        import orch_dork_qualification_verification as verification

        try:
            before = self.grants.canonical_authority()
            completion_waiting_authority(before)
            run_id = before["owner"]["controller_run_id"]
            state, rows = self._state(run_id, recover_provisional=False)
            identity = state["activation"]["identity"]
            projected = before["identity"]
            if (before["owner"]["activation_sha256"] != _sha(state["activation"])
                    or any(_canonical(projected[key]) != _canonical(identity[key]) for key in (
                        "root_thread_id", "root_session_id", "root_model", "hook_definition_sha256", "hook_registration_sha256"))
                    or _canonical(before["tip"]) != _canonical(_cursor(rows))
                    or state["action"] is not None or state["pending_intent"] is not None
                    or state["terminal"] is not False or state["cleanup_required"] is not False
                    or state["action_outcome"] != "completed" or state["grant_state"] is not None
                    or state["stage_report"]["receipt"]["bindings"]["review_context"]["owner_hook_inventory_report"]["report_sha256"]
                        != state["activation"]["hook_trust"]["hook_inventory_report_sha256"]
                    or not self._hook_runtime_matches(identity) or not self._retained_hook_evidence_valid(state)):
                raise ValueError("completion_sources:controller_binding_invalid")
            controller_report = self._base_report(controller_id=before["owner"]["controller_id"],
                status="PASS", decision="WAITING_FOR_STAGE", issues=[], cursor=_cursor(rows), state=state)
            stopped = [row for row in state["action_evidence"] if row["action"]["kind"] == "stop"]
            # Validate the whole closed batch before any source/owner I/O.
            from orch_dork_governed_native_reports import completion_closed_batch
            completion_closed_batch(controller_report, before, stopped, state["last_batch_result"])
            checkpoint = state.get("checkpoint_sources")
            observation = verification.observe_verified_native_source_capture(
                state["stage_report"], checkpoint_sources=checkpoint, env=env)
            closes = []
            if observation["status"] == "OBSERVED":
                environment = os.environ if env is None else env
                private = environment.get("CODEX_HOME") or str(Path(environment["HOME"]) / ".codex")
                evidence = observation["evidence"]
                scan = source_reader._scan(evidence["owner_before"]["observation"]["sources"]["root"], Path(private))
                role = evidence["roles"]["root"]
                if any(_canonical(scan[key]) != _canonical(role[key]) for key in ("path", "file_sha256", "prefix_bytes", "custody")):
                    raise ValueError("completion_sources:root_source_changed")
                pairs = {pair["call"]["record"]["payload"]["call_id"]: pair
                    for turn in scan["turns"] if turn["window"]["turn_id"] in evidence["root_turn_ids"]
                    for pair in turn["native_pairs"] if pair["call"]["record"]["payload"]["name"] == "close_agent"}
                if len(pairs) != 2:
                    raise ValueError("completion_sources:close_count_invalid")
                for row in stopped:
                    lane = row["action"]["lane_ids"][0]
                    post, issues = self._validate_hook_action_report(row["posttool_report_sha256"], row["action"])
                    if issues or post is None:
                        raise ValueError("completion_sources:hook_changed")
                    closes.append({"lane_id": lane, "posttool": deepcopy(post),
                        "source_pair": deepcopy(pairs[evidence["worker_events"][lane][-1]["call_id"]])})
                latest = local.observe_completed_attempt_sources(evidence["owner_before"]["expectation"], env=env)
                if _canonical(latest) != _canonical(evidence["owner_after"]):
                    raise ValueError("completion_sources:owner_changed")
            latest_state, latest_rows = self._state(run_id, recover_provisional=False)
            after = self.grants.canonical_authority()
            if (_canonical(latest_state) != _canonical(state) or _canonical(_cursor(latest_rows)) != _canonical(before["tip"])
                    or not self._hook_runtime_matches(identity) or not self._retained_hook_evidence_valid(latest_state)):
                raise ValueError("completion_sources:controller_changed")
            report = completion_source_report(before, after, controller_report, stopped,
                state["last_batch_result"], checkpoint, observation, closes)
            if validate_verified_completion_source_capture(report)["valid"] is not True:
                raise ValueError("completion_sources:binding_invalid")
            return report
        except (KeyError, TypeError, ValueError, OSError, RecursionError, OverflowError) as error:
            raise ValueError("completion_sources:binding_invalid") from error

    def _stage(self, value: Mapping[str, Any], run_id: str, *, native_request_meta: Any = None) -> dict[str, Any]:
        controller_id = value["controller_id"]
        state, rows = self._state(run_id)
        current = _cursor(rows)
        cursor_issue = self._expected_cursor_issue(value.get("expected_cursor"), current)
        if cursor_issue is not None:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="STAGE_REFUSED",
                issues=[cursor_issue],
                cursor=current,
                state=state,
            )
        if state.get("terminal"):
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="STAGE_REFUSED",
                issues=["controller:terminal"],
                cursor=current,
                state=state,
            )
        if state.get("pending_intent") is not None:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="OUTCOME_UNKNOWN",
                issues=["controller:pending_intent_outcome_unknown"],
                cursor=current,
                state=state,
            )
        if state.get("action") is not None:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="STAGE_REFUSED",
                issues=["controller:active_action_unobserved"],
                cursor=current,
                state=state,
            )
        if not self._retained_hook_evidence_valid(state):
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="STAGE_REFUSED",
                issues=["stage:retained_hook_evidence_invalid"],
                cursor=current,
                state=state,
            )
        cleanup_only = bool(state.get("cleanup_required"))
        if (
            state.get("action_outcome") not in {None, "completed"}
            and not cleanup_only
        ):
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="STAGE_REFUSED",
                issues=["controller:prior_action_not_completed"],
                cursor=current,
                state=state,
            )
        payload_issues: list[str] = []
        payload = _exact(
            value.get("payload"),
            {"stage_program", "proposed_action"},
            "stage",
            payload_issues,
        )
        stage_program = payload.get("stage_program")
        if not isinstance(stage_program, Mapping):
            _issue(payload_issues, "stage:program_invalid")
            stage_program = {}
        activation_identity = state["activation"]["identity"]
        payload_issues.extend(self._stage_continuity_issues(stage_program, state))
        if stage_program.get("operation") in {"worker_results", "result_aggregation", "review_submission", "semantic_review", "terminal_verification", "failure_closure", "final_qualification", "owner_disposition"} and payload.get("proposed_action") is not None:
            _issue(payload_issues, "stage:unexpected_proposed_action")
        if stage_program.get("operation") == "review_submission":
            stage_payload = stage_program.get("payload")
            review_context = stage_payload.get("review_context") if isinstance(stage_payload, Mapping) else None
            if not isinstance(review_context, Mapping) or review_context.get("controller_id") != controller_id:
                _issue(payload_issues, "stage:review_controller_mismatch")
        if stage_program.get("operation") in {"semantic_review", "terminal_verification", "cleanup", "failure_closure", "final_qualification", "owner_disposition"}:
            try:
                if state["stage_report"]["receipt"]["bindings"]["review_context"]["controller_id"] != controller_id:
                    _issue(payload_issues, "stage:review_controller_mismatch")
            except (KeyError, TypeError):
                _issue(payload_issues, "stage:review_context_invalid")
        if cleanup_only and stage_program.get("operation") != "capacity_settlement":
            _issue(payload_issues, "stage:cleanup_settlement_only")
        if payload_issues:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="STAGE_REFUSED",
                issues=payload_issues,
                cursor=current,
                state=state,
            )

        checkpoint_sources = None
        owned_checkpoint_budget = False
        if (stage_program.get("operation") == "progress"
                and state.get("stage_report", {}).get("receipt", {}).get("stage") == "worker_start"
                and state["stage_report"]["receipt"]["bindings"].get("worker_checkpoint_profile") == governed_attempt.WORKER_CHECKPOINT_PROFILE):
            checkpoint_sources = stage_program["payload"].get("checkpoint_sources")
            try:
                from lifecycle_conformance.host_adapter import mcp_call_context
                context = mcp_call_context(native_request_meta)
                expected = checkpoint_sources["coordinator"]["expectation"]
                if (context["task_id"] != activation_identity["root_thread_id"]
                        or context["model"] != activation_identity["root_model"]
                        or context["effort"] != activation_identity["root_effort"]
                        or context["turn_id"] != expected["sources"]["root_turn_id"]
                        or context["tool_call_id"] != expected["pending_call"]["call_id"]):
                    raise ValueError("different native checkpoint call")
            except (KeyError, TypeError, ValueError):
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=["stage:checkpoint_call_mismatch"], cursor=current, state=state)
            observed = self._reobserve_worker_checkpoints(state, checkpoint_sources)
            if observed != "OBSERVED":
                return self._base_report(controller_id=controller_id,
                    status="PASS" if observed == "PENDING" else "BLOCKED",
                    decision="CHECKPOINT_OBSERVATION_PENDING" if observed == "PENDING" else "STAGE_REFUSED",
                    issues=[] if observed == "PENDING" else ["stage:checkpoint_sources_unobserved"], cursor=current, state=state)
            try:
                import orch_dork_qualification_progress as progress
                expected = progress.build_checkpoint_stage_program(stage_program["identity"], state["stage_report"], checkpoint_sources)
                if _canonical(expected) != _canonical(stage_program):
                    raise ValueError("different checkpoint consumption")
                if "checkpoint_accounting_policy" in state["stage_report"]["receipt"]["bindings"]:
                    if payload.get("proposed_action") is not None:
                        raise ValueError("checkpoint disposition must be host-derived")
                    owned_checkpoint_budget = True
            except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=["stage:checkpoint_budget_unobserved"], cursor=current, state=state)

        final_sources = None
        if (stage_program.get("operation") == "worker_results"
                and state.get("stage_report", {}).get("receipt", {}).get("bindings", {}).get("worker_checkpoint_profile")
                    == governed_attempt.WORKER_CHECKPOINT_PROFILE):
            try:
                final_sources = self._observe_worker_finals(state, native_request_meta)
                if final_sources["status"] != "OBSERVED":
                    raise ValueError("stage:final_sources_" + final_sources["status"].lower())
                observed_results = [final_sources["evidence"]["workers"][lane]["result_report"] for lane in ("spec", "standards")]
                if _canonical(stage_program["payload"]["worker_results"]) != _canonical(observed_results):
                    raise ValueError("stage:final_results_changed")
            except ValueError as error:
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=[str(error)], cursor=current, state=state)

        prepared_report = None
        stage_evaluation_time = self._evaluation_time()
        if stage_program.get("operation") == "semantic_review":
            # Reading an unmaterialized call is not a lifecycle transition.
            # Observe once before any intent; only a disposition that advances
            # review or establishes an evidence barrier is durably committed.
            prepared_report = governed_attempt.evaluate_governed_attempt(
                stage_program, source_roots=self.source_roots, now=stage_evaluation_time,
                observer=self._attempt_observer, capacity_authority=self.capacity_authority)
            if (not isinstance(prepared_report, Mapping) or prepared_report.get("status") != "PASS"
                    or governed_attempt.validate_post_batch_report(prepared_report).get("valid") is not True):
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=["stage:semantic_observation_invalid"], cursor=current, state=state)
            reviewed = prepared_report["receipt"]["bindings"]
            if reviewed["review_outcome"] == "pending":
                return self._base_report(controller_id=controller_id, status="PASS", decision="REVIEW_OBSERVATION_PENDING",
                    issues=[], cursor=current, state=state, review_observation=reviewed["review_observation"])

        if stage_program.get("operation") == "failure_closure":
            import orch_dork_completion_settlement as completion
            import orch_dork_qualification_closure as failure
            from orch_dork_qualification_final_metadata import observe_native_final_metadata

            failure_payload = stage_program.get("payload")
            if isinstance(failure_payload, Mapping) and failure_payload.get("failure_profile") == "completion_budget_exhausted":
                failure_observer = lambda source, pre: observe_native_final_metadata(self, source, pre)
            else:
                failure_observer = lambda source: completion.observe_current_completion_settlement(self, source)
            prepared_report = governed_attempt.evaluate_governed_attempt(stage_program, now=stage_evaluation_time,
                observer=failure_observer)
            if failure.validate_failure_closure_report(prepared_report)["valid"] is not True:
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=prepared_report.get("issues") or ["stage:failure_closure_unverified"], cursor=current, state=state)
            # Reserve bounded event overhead plus the separately retained checkpoint.
            retained_bytes = len(_canonical(state.get("checkpoint_sources")))
            if len(_canonical(prepared_report)) + retained_bytes + 4096 > MAX_EVENT_BYTES:
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=["stage:failure_closure_evidence_too_large"], cursor=current, state=state)
            try:
                stage_evaluation_time = failure._commit_time(self, prepared_report, not_before=stage_evaluation_time)
            except Exception:
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=["stage:failure_closure_commit_unverified"], cursor=current, state=state)

        if stage_program.get("operation") == "final_qualification":
            import orch_dork_qualification_final as final
            from orch_dork_qualification_final_metadata import observe_native_final_metadata

            prepared_report = governed_attempt.evaluate_governed_attempt(stage_program,
                observer=lambda source, pre: observe_native_final_metadata(self, source, pre))
            if final.validate_final_qualification_report(prepared_report)["valid"] is not True:
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=prepared_report.get("issues") or ["stage:final_qualification_unverified"], cursor=current, state=state)
            retained_bytes = len(_canonical(state.get("checkpoint_sources")))
            if len(_canonical(prepared_report)) + retained_bytes + 4096 > MAX_EVENT_BYTES:
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=["stage:final_qualification_evidence_too_large"], cursor=current, state=state)
            try:
                stage_evaluation_time = final._commit_time(self, prepared_report)
            except Exception as error:
                issue = str(error) if type(error) is ValueError and str(error).startswith("final_qualification:") else "stage:final_qualification_commit_unverified"
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=[issue], cursor=current, state=state)

        if stage_program.get("operation") == "owner_disposition":
            import orch_dork_qualification_owner as owner_readiness

            prepared_report = governed_attempt.evaluate_governed_attempt(stage_program,
                observer=lambda receipt: owner_readiness.observe_owner_disposition_readiness(self, receipt))
            if owner_readiness.validate_owner_disposition_report(prepared_report)["valid"] is not True:
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=prepared_report.get("issues") or ["stage:owner_readiness_unverified"], cursor=current, state=state)
            retained_bytes = len(_canonical(state.get("checkpoint_sources")))
            if len(_canonical(prepared_report)) + retained_bytes + 4096 > MAX_EVENT_BYTES:
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=["stage:owner_readiness_evidence_too_large"], cursor=current, state=state)
            try:
                stage_evaluation_time = owner_readiness._commit_time(self, prepared_report)
            except Exception:
                return self._base_report(controller_id=controller_id, status="BLOCKED", decision="STAGE_REFUSED",
                    issues=["stage:owner_readiness_commit_unverified"], cursor=current, state=state)

        intent = {
            "operation": stage_program.get("operation"),
            "stage_program_sha256": _sha(stage_program),
            "evaluation_time": stage_evaluation_time.isoformat(),
            "proposed_action_sha256": (
                _sha(payload.get("proposed_action"))
                if payload.get("proposed_action") is not None
                else None
            ),
        }
        intent_cursor = self._append(run_id, "stage_intent", intent)
        try:
            evaluation_time = datetime.fromisoformat(intent["evaluation_time"])
            report = prepared_report if prepared_report is not None else governed_attempt.evaluate_governed_attempt(
                stage_program, source_roots=self.source_roots, now=evaluation_time,
                observer=self._attempt_observer, capacity_authority=self.capacity_authority)
            report = deepcopy(dict(report)) if isinstance(report, Mapping) else {}
        except Exception as error:
            report = {
                "status": "BLOCKED",
                "disposition": "CONTROLLER_EVALUATOR_FAILED",
                "issues": ["stage:evaluator_exception:" + type(error).__name__],
                "receipt": None,
                "next_action": "stop",
            }
        next_action = report.get("next_action")
        receipt = report.get("receipt") if isinstance(report.get("receipt"), Mapping) else {}
        action = None
        action_issues: list[str] = []
        proposed_action = payload.get("proposed_action")
        if owned_checkpoint_budget and next_action in {"continue", "stop"}:
            proposed_action = _checkpoint_action_proposal(controller_id,current,stage_program,next_action)
        stop_required = bool(
            report.get("status") == "BLOCKED"
            and report.get("disposition") == "STOP_REQUIRED"
            and next_action == "stop"
            and isinstance(receipt, Mapping)
            and receipt.get("stage") == "stopped"
            and receipt.get("status") == "STOP_REQUIRED"
            and receipt.get("next_action") == "stop"
        )
        if (
            (report.get("status") == "PASS" or stop_required)
            and next_action in ACTION_KINDS
        ):
            try:
                action, action_issues = ClosedNativeActionAdapter.authorize(
                    proposed_action,
                    next_action=next_action,
                    receipt=receipt,
                    activation=state["activation"],
                    controller_id=controller_id,
                    seen_action_ids=state.get("seen_action_ids", []),
                    source_roots=self.source_roots,
                )
            except Exception as error:
                action_issues = [
                    "stage:action_derivation_failed:" + type(error).__name__
                ]
        elif proposed_action is not None:
            action_issues.append("stage:unexpected_proposed_action")
        plan_sha = receipt.get("plan_sha256")
        if plan_sha is not None and plan_sha != activation_identity.get("plan_sha256"):
            action_issues.append("stage:plan_identity_mismatch")
        result_status = report.get("status")
        terminal_evidence_sha256 = (
            _sha(report)
            if report.get("status") == "PASS"
            and report.get("disposition") == "TERMINALLY_QUALIFIED"
            else None
        )
        authority = self.tower.read_shared_capacity_authority()
        capacity_guard: Mapping[str, Any] | None = None
        authority_state = (
            authority.get("state")
            if isinstance(authority, Mapping)
            and authority.get("status") == "VERIFIED"
            and isinstance(authority.get("state"), Mapping)
            else {}
        )
        active_lanes = authority_state.get("active_lane_ids")
        if isinstance(action, Mapping) and action.get("kind") == "spawn":
            try:
                first_capacity_guard = self.grants.verified_tip(
                    str(authority.get("store_id"))
                )
                confirmed_authority = self.tower.read_shared_capacity_authority()
                confirmed_capacity_guard = self.grants.verified_tip(
                    str(confirmed_authority.get("store_id"))
                )
            except Exception:
                first_capacity_guard = None
                confirmed_authority = {}
                confirmed_capacity_guard = None
            if (
                first_capacity_guard is None
                or first_capacity_guard != confirmed_capacity_guard
                or authority.get("store_id")
                != confirmed_authority.get("store_id")
                or authority.get("state_sha256")
                != confirmed_authority.get("state_sha256")
            ):
                action = None
                action_issues.append("stage:spawn_capacity_authority_raced")
            else:
                authority = confirmed_authority
                capacity_guard = confirmed_capacity_guard
                authority_state = (
                    authority.get("state")
                    if isinstance(authority.get("state"), Mapping)
                    else {}
                )
                active_lanes = authority_state.get("active_lane_ids")
            bindings = (
                receipt.get("bindings")
                if isinstance(receipt.get("bindings"), Mapping)
                else {}
            )
            expected_physical_lanes = sorted(
                str(activation_identity.get("run_id")) + ":" + lane_id
                for lane_id in (
                    action.get("batch_lane_ids", action.get("lane_ids", []))
                    if isinstance(action, Mapping)
                    else []
                )
            )
            if isinstance(action, Mapping) and (
                bindings.get("capacity_authority_lane_ids")
                != expected_physical_lanes
                or bindings.get("capacity_authority_store_id")
                != authority.get("store_id")
                or bindings.get("capacity_authority_state_sha256")
                != authority.get("state_sha256")
                or not isinstance(active_lanes, list)
                or not set(expected_physical_lanes).issubset(active_lanes)
            ):
                action = None
                action_issues.append("stage:spawn_capacity_authority_mismatch")
        active_capacity = isinstance(active_lanes, list) and bool(active_lanes)
        failed_stage = bool(action_issues or (result_status != "PASS" and action is None))
        cleanup_required = bool(failed_stage and (active_capacity or cleanup_only))
        terminal = bool(
            report.get("disposition") == "TERMINALLY_QUALIFIED"
            or (stage_program.get("operation") == "owner_disposition"
                and report.get("disposition") == "CONTROLLER_QUIESCENT"
                and report.get("status") == "PASS")
            or cleanup_only
            or (failed_stage and not cleanup_required)
        )
        result_payload = {
            "intent_cursor": intent_cursor,
            "stage_report": report,
            "action": action,
            "capacity_guard": (
                deepcopy(dict(capacity_guard))
                if isinstance(action, Mapping)
                and action.get("kind") == "spawn"
                and isinstance(capacity_guard, Mapping)
                else None
            ),
            "terminal": terminal,
            "cleanup_required": cleanup_required,
            "terminal_evidence_sha256": terminal_evidence_sha256,
            "issues": sorted(set(action_issues)),
        }
        if (checkpoint_sources is not None
                and receipt.get("bindings", {}).get("checkpoint_sources_sha256") == _sha(checkpoint_sources)):
            result_payload["checkpoint_sources"] = deepcopy(checkpoint_sources)
        if (final_sources is not None and receipt.get("stage") == "worker_results"
                and _canonical(receipt.get("bindings", {}).get("worker_results")) == _canonical(observed_results)):
            result_payload["final_sources"] = deepcopy(final_sources)
        if isinstance(action, Mapping):
            prepared = self.grants.prepare_action(
                action,
                intent_cursor,
                capacity_guard=(
                    capacity_guard if action.get("kind") == "spawn" else None
                ),
            )
            if prepared.get("status") not in {"PREPARED", "IDEMPOTENT"}:
                raise ValueError("grant:preparation_failed")
        result_cursor = self._append(run_id, "stage_result", result_payload)
        if isinstance(action, Mapping):
            finalized = self.grants.finalize_action(action, result_cursor)
            if finalized.get("status") not in {"FINALIZED", "IDEMPOTENT"}:
                raise ValueError("grant:finalization_failed")
        state, _rows = self._state(run_id)
        hook_sha = self._sync_hook(
            controller_id=controller_id,
            cursor=result_cursor,
            state=state,
        )
        if action_issues:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="STAGE_REFUSED",
                issues=action_issues,
                cursor=result_cursor,
                state=state,
                hook_state_sha256=hook_sha,
            )
        if result_status != "PASS" and action is None:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="STAGE_BLOCKED",
                issues=list(report.get("issues", [])),
                cursor=result_cursor,
                state=state,
                hook_state_sha256=hook_sha,
            )
        return self._base_report(
            controller_id=controller_id,
            status="PASS",
            decision="ACTION_AUTHORIZED" if action is not None else "STAGE_ADVANCED",
            issues=[],
            cursor=result_cursor,
            state=state,
            hook_state_sha256=hook_sha,
        )

    def _read_hook_event(
        self, report_sha256: str, identity: Mapping[str, Any]
    ) -> tuple[Mapping[str, Any] | None, str | None]:
        if _DIGEST.fullmatch(report_sha256) is None:
            return None, "invalid"
        session_key = hashlib.sha256(
            str(identity.get("root_session_id")).encode("utf-8")
        ).hexdigest()
        path = (
            self.plugin_data
            / "project-ground"
            / "events"
            / session_key
            / (report_sha256 + ".json")
        )
        try:
            durable = owned_file.read_owned_json(
                path, max_bytes=MAX_DURABLE_FILE_BYTES
            )
        except FileNotFoundError:
            return None, "missing"
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return None, "unavailable"
        if not isinstance(durable, Mapping):
            return None, "invalid"
        return durable, None

    def _validate_hook_action_report(
        self,
        report_sha256: str,
        action: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any] | None, list[str]]:
        controller_run_id = _controller_run_id(str(action.get("controller_id")))
        controller_state = _reduce(_controller_events(self._rows(controller_run_id)))
        activation = controller_state.get("activation", {})
        identity = (
            activation.get("identity")
            if isinstance(activation, Mapping)
            and isinstance(activation.get("identity"), Mapping)
            else {}
        )
        durable, read_issue = self._read_hook_event(report_sha256, identity)
        if read_issue is not None:
            return None, ["observation:hook_report_" + read_issue]
        durable_core = {
            key: child
            for key, child in durable.items()
            if key != "durable_record_sha256"
        }
        native = durable.get("native_controller")
        durable_identity = durable.get("identity")
        grant = self.grants.read_action(str(action.get("action_sha256")))
        pretool_report_sha256 = (
            grant.get("pretool_report_sha256")
            if isinstance(grant, Mapping)
            else None
        )
        pretool = None
        if isinstance(pretool_report_sha256, str):
            pretool, _pretool_read_issue = self._read_hook_event(
                pretool_report_sha256, identity
            )
        pretool_core = (
            {
                key: child
                for key, child in pretool.items()
                if key != "durable_record_sha256"
            }
            if isinstance(pretool, Mapping)
            else {}
        )
        pretool_native = (
            pretool.get("native_controller")
            if isinstance(pretool, Mapping)
            and isinstance(pretool.get("native_controller"), Mapping)
            else {}
        )
        pretool_identity = (
            pretool.get("identity")
            if isinstance(pretool, Mapping)
            and isinstance(pretool.get("identity"), Mapping)
            else {}
        )
        ground_program = (
            activation.get("project_ground_state", {}).get("program", {})
            if isinstance(activation, Mapping)
            and isinstance(activation.get("project_ground_state"), Mapping)
            else {}
        )
        ground_state = (
            ground_program.get("state", {})
            if isinstance(ground_program, Mapping)
            and isinstance(ground_program.get("state"), Mapping)
            else {}
        )
        prerequisites = (
            ground_state.get("prerequisites", {})
            if isinstance(ground_state.get("prerequisites"), Mapping)
            else {}
        )
        enrollment = prerequisites.get("enrollment", {})
        ticket = prerequisites.get("ticket_admission", {})
        lease = prerequisites.get("lease", {})
        authority = prerequisites.get("authority", {})
        expected_durable_identity = {
            "project_id": enrollment.get("project_id"),
            "generation": enrollment.get("generation"),
            "ticket_id": ticket.get("ticket_id"),
            "admission_sha256": ticket.get("admission_sha256"),
            "plan_sha256": ticket.get("plan_sha256"),
            "lease_version": lease.get("version"),
            "lease_owner_thread_id": lease.get("owner_thread_id"),
            "current_thread_id": lease.get("current_thread_id"),
            "session_id": identity.get("root_session_id"),
            "authority_scope_sha256": authority.get("scope_sha256"),
            "workspace_baseline_sha256": prerequisites.get("workspace", {}).get(
                "baseline_sha256"
            ),
            "writable_scope_sha256": authority.get("writable_scope_sha256"),
            "adapter_snapshot_sha256": prerequisites.get("adapter", {}).get(
                "snapshot_sha256"
            ),
            "active_controller_sha256": prerequisites.get(
                "active_controller", {}
            ).get("report_sha256"),
            "capsule_sha256": prerequisites.get("capsule", {}).get(
                "capsule_sha256"
            ),
            "execution_readiness_sha256": prerequisites.get(
                "execution_readiness", {}
            ).get("report_sha256"),
        }
        identity_bindings_match = bool(
            isinstance(durable_identity, Mapping)
            and set(durable_identity) == DURABLE_HOOK_IDENTITY_FIELDS
            and all(
                durable_identity.get(field) == expected
                for field, expected in expected_durable_identity.items()
            )
            and _IDENTIFIER.fullmatch(str(durable_identity.get("turn_id", "")))
            is not None
        )
        result_binding = (
            native_result.normalize_native_result(
                native.get("result_binding"),
                action_kind=action.get("kind"),
                expected_lane_ids=action.get("lane_ids"),
                outcome=native.get("outcome"),
            )
            if isinstance(native, Mapping)
            else None
        )
        result_binding_valid = bool(
            (
                isinstance(native, Mapping)
                and native.get("outcome") == "completed"
                and result_binding is not None
                and result_binding == native.get("result_binding")
            )
            or (
                isinstance(native, Mapping)
                and native.get("outcome") != "completed"
                and native.get("result_binding") is None
            )
        )
        if (
            set(durable) != DURABLE_HOOK_EVENT_FIELDS
            or durable.get("schema") != DURABLE_HOOK_EVENT_SCHEMA
            or durable.get("report_schema") != ground_enforcement.REPORT_SCHEMA
            or durable.get("durable_record_sha256")
            != ground_enforcement._sha(durable_core)
            or durable.get("report_sha256") != report_sha256
            or durable.get("hook_event_name") != "PostToolUse"
            or durable.get("status") != "PASS"
            or durable.get("decision") != "OBSERVED"
            or durable.get("tool_input_sha256") != action.get("tool_input_sha256")
            or not identity_bindings_match
            or not isinstance(grant, Mapping)
            or not isinstance(native, Mapping)
            or set(native) != DURABLE_POSTTOOL_NATIVE_FIELDS
            or native.get("present") is not True
            or native.get("controller_id") != action.get("controller_id")
            or native.get("controller_seq") != grant.get("controller_seq")
            or native.get("status") != "ACTIVE"
            or native.get("action_id") != action.get("action_id")
            or native.get("matched") is not True
            or native.get("grant_state") != "POST_OBSERVED"
            or not isinstance(native.get("tool_use_id"), str)
            or native.get("pretool_report_sha256")
            != pretool_report_sha256
            or not isinstance(native.get("outcome"), str)
            or not _DIGEST.fullmatch(str(native.get("result_sha256", "")))
            or not result_binding_valid
            or grant.get("state") != "POST_OBSERVED"
            or grant.get("posttool_report_sha256") != report_sha256
            or grant.get("tool_use_id") != native.get("tool_use_id")
            or grant.get("outcome") != native.get("outcome")
            or grant.get("result_sha256") != native.get("result_sha256")
            or grant.get("result_binding_sha256")
            != _sha(native.get("result_binding"))
            or not isinstance(pretool, Mapping)
            or set(pretool) != DURABLE_HOOK_EVENT_FIELDS
            or pretool.get("schema") != DURABLE_HOOK_EVENT_SCHEMA
            or pretool.get("report_schema") != ground_enforcement.REPORT_SCHEMA
            or pretool.get("report_sha256") != pretool_report_sha256
            or pretool.get("durable_record_sha256")
            != ground_enforcement._sha(pretool_core)
            or pretool.get("hook_event_name") != "PreToolUse"
            or pretool.get("status") != "PASS"
            or pretool.get("decision") != "ALLOW"
            or pretool.get("mutating") is not True
            or pretool.get("tool_input_sha256")
            != action.get("tool_input_sha256")
            or set(pretool_identity) != DURABLE_HOOK_IDENTITY_FIELDS
            or any(
                pretool_identity.get(field) != durable_identity.get(field)
                for field in DURABLE_HOOK_IDENTITY_FIELDS - {"turn_id"}
            )
            or _IDENTIFIER.fullmatch(str(pretool_identity.get("turn_id", "")))
            is None
            or set(pretool_native) != DURABLE_PRETOOL_NATIVE_FIELDS
            or pretool_native.get("present") is not True
            or pretool_native.get("controller_id") != action.get("controller_id")
            or pretool_native.get("controller_seq") != grant.get("controller_seq")
            or pretool_native.get("status") != "ACTIVE"
            or pretool_native.get("action_id") != action.get("action_id")
            or pretool_native.get("matched") is not True
            or pretool_native.get("grant_state") != "DISPATCHED"
            or pretool_native.get("tool_use_id") != native.get("tool_use_id")
            or pretool_native.get("pretool_event_sha256")
            != grant.get("pretool_event_sha256")
        ):
            return None, ["observation:hook_report_mismatch"]
        return durable, []

    @staticmethod
    def _retained_owner_evidence_valid(
        evidence: Any, identity: Mapping[str, Any]
    ) -> bool:
        if (
            not isinstance(evidence, Mapping)
            or set(evidence)
            != {
                "schema",
                "action",
                "owner_observation",
                "native_receipt",
                "result_binding",
            }
            or evidence.get("schema")
            != RETAINED_OWNER_ACTION_EVIDENCE_SCHEMA
            or not isinstance(evidence.get("action"), Mapping)
            or not isinstance(evidence.get("owner_observation"), Mapping)
            or not isinstance(evidence.get("native_receipt"), Mapping)
        ):
            return False
        action = evidence["action"]
        observation = evidence["owner_observation"]
        receipt = evidence["native_receipt"]
        observation_core = {
            key: value
            for key, value in observation.items()
            if key != "report_sha256"
        }
        normalized = native_result.normalize_native_result(
            evidence.get("result_binding"),
            action_kind=action.get("kind"),
            expected_lane_ids=action.get("lane_ids"),
            outcome=receipt.get("outcome"),
        )
        return bool(
            set(observation)
            == {
                "schema",
                "status",
                "task_id",
                "session_id",
                "turn_id",
                "thread_read_sha256",
                "tool_call_id",
                "native_receipt_sha256",
                "report_sha256",
            }
            and observation.get("schema")
            == RETAINED_OWNER_OBSERVATION_SCHEMA
            and observation.get("status") == "OBSERVED"
            and observation.get("task_id") == identity.get("root_thread_id")
            and observation.get("session_id")
            == identity.get("root_session_id")
            and _IDENTIFIER.fullmatch(str(observation.get("turn_id", "")))
            is not None
            and _DIGEST.fullmatch(
                str(observation.get("thread_read_sha256", ""))
            )
            is not None
            and _IDENTIFIER.fullmatch(
                str(observation.get("tool_call_id", ""))
            )
            is not None
            and observation.get("native_receipt_sha256") == _sha(receipt)
            and observation.get("report_sha256") == _sha(observation_core)
            and set(receipt)
            == {
                "schema",
                "action_id",
                "outcome",
                "tool_name",
                "tool_input_sha256",
                "tool_use_id",
                "result_sha256",
                "result_binding",
                "source_pointer",
            }
            and receipt.get("schema") == NATIVE_ACTION_RECEIPT_SCHEMA
            and receipt.get("action_id") == action.get("action_id")
            and receipt.get("tool_name") == action.get("tool_name")
            and receipt.get("tool_input_sha256")
            == action.get("tool_input_sha256")
            and receipt.get("tool_use_id")
            == observation.get("tool_call_id")
            and receipt.get("result_sha256")
            == _sha(evidence.get("result_binding"))
            and receipt.get("result_binding")
            == evidence.get("result_binding")
            and normalized == evidence.get("result_binding")
        )

    def _action_evidence_turn_id(
        self, evidence: Mapping[str, Any], identity: Mapping[str, Any]
    ) -> str | None:
        if self._retained_owner_evidence_valid(evidence, identity):
            return str(evidence["owner_observation"]["turn_id"])
        post, issue = self._read_hook_event(
            evidence.get("posttool_report_sha256"), identity
        )
        if (
            issue is not None
            or not isinstance(post, Mapping)
            or post.get("durable_record_sha256")
            != evidence.get("posttool_durable_record_sha256")
        ):
            return None
        turn_id = post.get("identity", {}).get("turn_id")
        return str(turn_id) if _IDENTIFIER.fullmatch(str(turn_id or "")) else None

    def _retained_hook_evidence_valid(self, state: Mapping[str, Any]) -> bool:
        """Validate retained action evidence from hooks or the owner stream."""

        identity = state.get("activation", {}).get("identity", {})
        evidence_rows = state.get("action_evidence")
        if not isinstance(identity, Mapping) or not isinstance(evidence_rows, list):
            return False
        for evidence in evidence_rows:
            if self._retained_owner_evidence_valid(evidence, identity):
                continue
            if (
                not isinstance(evidence, Mapping)
                or set(evidence)
                != {
                    "action",
                    "pretool_report_sha256",
                    "pretool_durable_record_sha256",
                    "posttool_report_sha256",
                    "posttool_durable_record_sha256",
                    "result_binding",
                }
                or not isinstance(evidence.get("action"), Mapping)
            ):
                return False
            action = evidence["action"]
            post_sha256 = evidence.get("posttool_report_sha256")
            pre_sha256 = evidence.get("pretool_report_sha256")
            if not isinstance(post_sha256, str) or not isinstance(pre_sha256, str):
                return False
            post, post_issues = self._validate_hook_action_report(post_sha256, action)
            pre, pre_issue = self._read_hook_event(pre_sha256, identity)
            if (
                post_issues
                or not isinstance(post, Mapping)
                or pre_issue is not None
                or not isinstance(pre, Mapping)
                or pre.get("durable_record_sha256")
                != evidence.get("pretool_durable_record_sha256")
                or post.get("durable_record_sha256")
                != evidence.get("posttool_durable_record_sha256")
                or post.get("native_controller", {}).get("result_binding")
                != evidence.get("result_binding")
            ):
                return False
        return True

    @staticmethod
    def _batch_fields(action: Any) -> Mapping[str, Any] | None:
        if not isinstance(action, Mapping):
            return None
        requests = action.get("batch_requests")
        lanes = action.get("batch_lane_ids")
        index = action.get("batch_index")
        if (
            action.get("batch_schema") != NATIVE_BATCH_SCHEMA
            or action.get("batch_kind") not in ACTION_KINDS
            or action.get("batch_phase") not in {"primary", "compensation"}
            or not isinstance(action.get("batch_id"), str)
            or not isinstance(requests, list)
            or not requests
            or action.get("batch_requests_sha256") != _sha(requests)
            or type(index) is not int
            or index < 0
            or action.get("batch_size") != len(requests)
            or index >= len(requests)
            or not isinstance(lanes, list)
            or lanes != sorted(set(lanes))
            or not lanes
        ):
            return None
        request = requests[index]
        if (
            not isinstance(request, Mapping)
            or set(request) != {"lane_id", "kind", "tool_name", "tool_input"}
            or action.get("kind") != request.get("kind")
            or action.get("tool_name") != request.get("tool_name")
            or action.get("tool_input") != request.get("tool_input")
            or action.get("lane_ids") != [request.get("lane_id")]
            or request.get("lane_id") not in lanes
        ):
            return None
        return action

    @staticmethod
    def _aggregate_batch_result(
        evidence_rows: list[Mapping[str, Any]], action: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        batch = GovernedNativeController._batch_fields(action)
        if batch is None:
            return None
        expected_size = int(batch["batch_size"])
        by_index: dict[int, Mapping[str, Any]] = {}
        for evidence in evidence_rows:
            evidence_action = (
                evidence.get("action") if isinstance(evidence, Mapping) else None
            )
            if (
                not isinstance(evidence_action, Mapping)
                or evidence_action.get("batch_id") != batch.get("batch_id")
                or evidence_action.get("batch_phase") != "primary"
                or evidence_action.get("batch_requests_sha256")
                != batch.get("batch_requests_sha256")
            ):
                continue
            evidence_index = evidence_action.get("batch_index")
            if type(evidence_index) is not int or evidence_index in by_index:
                return None
            normalized = native_result.normalize_native_result(
                evidence.get("result_binding"),
                action_kind=evidence_action.get("kind"),
                expected_lane_ids=evidence_action.get("lane_ids"),
                outcome="completed",
            )
            if normalized is None:
                return None
            by_index[evidence_index] = normalized
        if sorted(by_index) != list(range(expected_size)):
            return None
        kind = batch["batch_kind"]
        if kind == "spawn":
            result_binding: dict[str, Any] = {
                "schema": native_result.NATIVE_SPAWN_RESULT_SCHEMA,
                "lanes": [
                    row
                    for index in range(expected_size)
                    for row in by_index[index]["lanes"]
                ],
            }
        elif kind == "continue":
            result_binding = {
                "schema": native_result.NATIVE_CONTINUE_RESULT_SCHEMA,
                "submissions": [
                    row
                    for index in range(expected_size)
                    for row in by_index[index]["submissions"]
                ],
            }
        else:
            result_binding = {
                "schema": native_result.NATIVE_STOP_RESULT_SCHEMA,
                "closed": [
                    row
                    for index in range(expected_size)
                    for row in by_index[index]["closed"]
                ],
            }
        normalized_batch = native_result.normalize_native_result(
            result_binding,
            action_kind=kind,
            expected_lane_ids=batch["batch_lane_ids"],
            outcome="completed",
        )
        if normalized_batch != result_binding:
            return None
        return {
            "schema": NATIVE_BATCH_SCHEMA,
            "batch_id": batch["batch_id"],
            "kind": kind,
            "lane_ids": list(batch["batch_lane_ids"]),
            "result_binding": result_binding,
        }

    @staticmethod
    def _successful_spawn_compensation_requests(
        evidence_rows: list[Mapping[str, Any]], action: Mapping[str, Any]
    ) -> list[dict[str, Any]]:
        created: dict[str, str] = {}
        for evidence in evidence_rows:
            evidence_action = (
                evidence.get("action") if isinstance(evidence, Mapping) else None
            )
            binding = (
                evidence.get("result_binding")
                if isinstance(evidence, Mapping)
                else None
            )
            if (
                not isinstance(evidence_action, Mapping)
                or evidence_action.get("batch_id") != action.get("batch_id")
                or evidence_action.get("batch_phase") != "primary"
                or evidence_action.get("kind") != "spawn"
                or not isinstance(binding, Mapping)
            ):
                continue
            normalized = native_result.spawn_result_binding(
                binding, evidence_action.get("lane_ids")
            )
            if normalized is None:
                continue
            row = normalized["lanes"][0]
            created[row["lane_id"]] = row["agent_id"]
        return [
            {
                "lane_id": lane_id,
                "kind": "stop",
                "tool_name": DIRECT_NATIVE_TOOLS["stop"],
                "tool_input": {"target": created[lane_id]},
            }
            for lane_id in sorted(created)
        ]

    def _next_batch_transition(
        self,
        *,
        action: Mapping[str, Any],
        outcome: str,
        evidence_rows: list[Mapping[str, Any]],
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str, bool]:
        """Derive the next direct call or the settled aggregate batch result."""

        batch = self._batch_fields(action)
        if batch is None:
            raise ValueError("native_batch:active_action_invalid")
        phase = str(batch["batch_phase"])
        failure_outcome = batch.get("batch_failure_outcome")
        if failure_outcome not in ACTION_OUTCOMES | {None}:
            raise ValueError("native_batch:failure_outcome_invalid")
        if outcome != "completed" and failure_outcome is None:
            failure_outcome = outcome

        # A failed or uncertain close leaves an explicit cleanup obligation.
        # Do not prepare another close grant and rely on a later report consumer
        # to reject it. Successful compensation still retains the spawn failure.
        if outcome != "completed" and (phase == "compensation" or batch["batch_kind"] == "stop"):
            # The original failure and this close remain separate journal facts;
            # either unknown effect must also remain visible in the batch result.
            unresolved_outcome = (
                "unknown" if "unknown" in (failure_outcome, outcome)
                else str(failure_outcome)
            )
            return None, None, unresolved_outcome, True

        requests = list(batch["batch_requests"])
        next_index = int(batch["batch_index"]) + 1
        next_requests = requests
        next_phase = phase
        should_continue = False
        if phase == "compensation":
            should_continue = next_index < len(requests)
        elif batch["batch_kind"] == "stop":
            should_continue = next_index < len(requests)
        elif failure_outcome is None:
            should_continue = next_index < len(requests)
        elif batch["batch_kind"] == "spawn":
            next_requests = self._successful_spawn_compensation_requests(
                evidence_rows, action
            )
            next_phase = "compensation"
            next_index = 0
            should_continue = bool(next_requests)

        if should_continue:
            next_action = _direct_batch_action(
                controller_id=str(action["controller_id"]),
                batch_id=str(batch["batch_id"]),
                batch_kind=str(batch["batch_kind"]),
                batch_lane_ids=list(batch["batch_lane_ids"]),
                requests=next_requests,
                index=next_index,
                phase=next_phase,
                actor_thread_id=str(action["actor_thread_id"]),
                adapter_sha256=str(action["adapter_sha256"]),
                predecessor_receipt_sha256=action.get(
                    "predecessor_receipt_sha256"
                ),
                failure_outcome=(
                    str(failure_outcome)
                    if failure_outcome is not None
                    else None
                ),
            )
            return next_action, None, "pending", False

        if failure_outcome is not None:
            return None, None, str(failure_outcome), True
        batch_result = self._aggregate_batch_result(evidence_rows, action)
        if batch_result is None:
            raise ValueError("native_batch:aggregate_result_invalid")
        return None, batch_result, "completed", False

    def _fresh_spawn_capacity_guard(
        self, action: Mapping[str, Any], state: Mapping[str, Any]
    ) -> Mapping[str, Any] | None:
        try:
            first = self.tower.read_shared_capacity_authority()
            first_guard = self.grants.verified_tip(str(first.get("store_id")))
            second = self.tower.read_shared_capacity_authority()
            second_guard = self.grants.verified_tip(str(second.get("store_id")))
        except Exception:
            return None
        authority_state = (
            second.get("state") if isinstance(second.get("state"), Mapping) else {}
        )
        active_lanes = authority_state.get("active_lane_ids")
        identity = state.get("activation", {}).get("identity", {})
        expected = sorted(
            str(identity.get("run_id")) + ":" + str(lane_id)
            for lane_id in action.get("batch_lane_ids", [])
        )
        receipt = (
            state.get("stage_report", {}).get("receipt", {})
            if isinstance(state.get("stage_report"), Mapping)
            else {}
        )
        bindings = (
            receipt.get("bindings")
            if isinstance(receipt, Mapping)
            and isinstance(receipt.get("bindings"), Mapping)
            else {}
        )
        if (
            first_guard is None
            or first_guard != second_guard
            or first.get("store_id") != second.get("store_id")
            or first.get("state_sha256") != second.get("state_sha256")
            or bindings.get("capacity_authority_lane_ids") != expected
            or bindings.get("capacity_authority_store_id") != second.get("store_id")
            or bindings.get("capacity_authority_state_sha256")
            != second.get("state_sha256")
            or not isinstance(active_lanes, list)
            or not set(expected).issubset(active_lanes)
        ):
            return None
        return second_guard

    def _observe(self, value: Mapping[str, Any], run_id: str) -> dict[str, Any]:
        controller_id = value["controller_id"]
        state, rows = self._state(run_id)
        current = _cursor(rows)
        cursor_issue = self._expected_cursor_issue(value.get("expected_cursor"), current)
        if cursor_issue is not None:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="OBSERVATION_REFUSED",
                issues=[cursor_issue],
                cursor=current,
                state=state,
            )
        if state.get("pending_intent") is not None:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="OUTCOME_UNKNOWN",
                issues=["controller:pending_intent_outcome_unknown"],
                cursor=current,
                state=state,
            )
        if state.get("terminal"):
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="OBSERVATION_REFUSED",
                issues=["controller:terminal"],
                cursor=current,
                state=state,
            )
        action = state.get("action")
        issues: list[str] = []
        raw_payload = value.get("payload")
        retained_owner_path = bool(
            isinstance(raw_payload, Mapping)
            and "retained_owner_observation" in raw_payload
        )
        payload = _exact(
            raw_payload,
            {
                "schema",
                "action_id",
                "tool_name",
                "tool_input_sha256",
                "tool_use_id",
                "outcome",
                "native_receipt",
                *(
                    {"retained_owner_observation"}
                    if retained_owner_path
                    else {"hook_report_sha256"}
                ),
            },
            "observation",
            issues,
        )
        if payload.get("schema") != ACTION_OBSERVATION_SCHEMA:
            _issue(issues, "observation:schema_invalid")
        if not isinstance(action, Mapping):
            _issue(issues, "observation:no_active_action")
        else:
            for field in ("action_id", "tool_name", "tool_input_sha256"):
                if payload.get(field) != action.get(field):
                    _issue(issues, "observation:" + field + "_mismatch")
        if payload.get("outcome") not in ACTION_OUTCOMES:
            _issue(issues, "observation:outcome_invalid")
        _identifier(payload.get("tool_use_id"), "observation.tool_use_id", issues)

        receipt = _exact(
            payload.get("native_receipt"),
            {
                "schema",
                "action_id",
                "outcome",
                "tool_name",
                "tool_input_sha256",
                "tool_use_id",
                "result_sha256",
                "result_binding",
                "source_pointer",
            },
            "observation.native_receipt",
            issues,
        )
        if receipt.get("schema") != NATIVE_ACTION_RECEIPT_SCHEMA:
            _issue(issues, "observation:native_receipt_schema_invalid")
        for field in (
            "action_id",
            "outcome",
            "tool_name",
            "tool_input_sha256",
            "tool_use_id",
        ):
            if receipt.get(field) != payload.get(field):
                _issue(issues, "observation:native_receipt_" + field + "_mismatch")
        _digest(
            receipt.get("result_sha256"),
            "observation.native_receipt.result_sha256",
            issues,
        )
        if not isinstance(receipt.get("source_pointer"), str) or not receipt.get(
            "source_pointer"
        ):
            _issue(issues, "observation:native_receipt_source_invalid")

        normalized_result = None
        if isinstance(action, Mapping):
            normalized_result = native_result.normalize_native_result(
                receipt.get("result_binding"),
                action_kind=action.get("kind"),
                expected_lane_ids=action.get("lane_ids"),
                outcome=payload.get("outcome"),
            )
            if (
                payload.get("outcome") == "completed"
                and (
                    normalized_result is None
                    or normalized_result != receipt.get("result_binding")
                )
            ) or (
                payload.get("outcome") != "completed"
                and receipt.get("result_binding") is not None
            ):
                _issue(issues, "observation:native_receipt_result_binding_invalid")

        hook_report_sha256 = (
            None if retained_owner_path else payload.get("hook_report_sha256")
        )
        hook_durable: Mapping[str, Any] | None = None
        owner_evidence: dict[str, Any] | None = None
        if retained_owner_path:
            owner_observation = payload.get("retained_owner_observation")
            owner_evidence = {
                "schema": RETAINED_OWNER_ACTION_EVIDENCE_SCHEMA,
                "action": (
                    deepcopy(dict(action))
                    if isinstance(action, Mapping)
                    else None
                ),
                "owner_observation": deepcopy(owner_observation),
                "native_receipt": deepcopy(dict(receipt)),
                "result_binding": deepcopy(receipt.get("result_binding")),
            }
            identity = state.get("activation", {}).get("identity", {})
            if (
                not isinstance(identity, Mapping)
                or not self._retained_owner_evidence_valid(
                    owner_evidence, identity
                )
                or receipt.get("result_sha256")
                != _sha(receipt.get("result_binding"))
            ):
                _issue(issues, "observation:retained_owner_invalid")
        elif hook_report_sha256 is None:
            _issue(issues, "observation:hook_report_required")
        else:
            _digest(
                hook_report_sha256,
                "observation.hook_report_sha256",
                issues,
            )
            if isinstance(action, Mapping) and not issues:
                hook_durable, hook_issues = self._validate_hook_action_report(
                    hook_report_sha256,
                    action,
                )
                issues.extend(hook_issues)
        if isinstance(hook_durable, Mapping):
            native = hook_durable.get("native_controller", {})
            if (
                native.get("outcome") != payload.get("outcome")
                or native.get("result_sha256") != receipt.get("result_sha256")
                or native.get("tool_use_id") != payload.get("tool_use_id")
                or native.get("result_binding") != receipt.get("result_binding")
            ):
                _issue(issues, "observation:hook_result_mismatch")
        elif not retained_owner_path:
            _issue(issues, "observation:result_unobserved")
        if issues:
            if isinstance(action, Mapping):
                intent_cursor = self._append(
                    run_id,
                    "action_observation_intent",
                    {
                        "action_id": action.get("action_id"),
                        "observation_sha256": _sha(payload),
                    },
                )
                observed_cursor = self._append(
                    run_id,
                    "action_observed",
                    {
                        "intent_cursor": intent_cursor,
                        "action_id": action.get("action_id"),
                        "outcome": "unknown",
                        "native_receipt_sha256": None,
                        "hook_report_sha256": hook_report_sha256,
                        "tool_use_id": payload.get("tool_use_id"),
                        "action_evidence": None,
                        "cleanup_required": True,
                        "terminal": True,
                    },
                )
                state, _rows = self._state(run_id)
                hook_sha = self._sync_hook(
                    controller_id=controller_id,
                    cursor=observed_cursor,
                    state=state,
                )
                return self._base_report(
                    controller_id=controller_id,
                    status="BLOCKED",
                    decision="ACTION_EVIDENCE_CONTRADICTORY",
                    issues=issues,
                    cursor=observed_cursor,
                    state=state,
                    hook_state_sha256=hook_sha,
                )
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="OBSERVATION_REFUSED",
                issues=issues,
                cursor=current,
                state=state,
            )
        if retained_owner_path:
            binding = {
                "controller_id": controller_id,
                "controller_run_id": current["run_id"],
                "controller_seq": current["seq"],
                "controller_event_hash": current["event_hash"],
                "action": action,
            }
            recorded = self.grants.record_retained_owner_observation(
                binding,
                tool_use_id=str(payload["tool_use_id"]),
                outcome=str(payload["outcome"]),
                result_sha256=str(receipt["result_sha256"]),
                result_binding=receipt.get("result_binding"),
                observation_sha256=str(
                    payload["retained_owner_observation"]["report_sha256"]
                ),
            )
            if recorded.get("status") not in {
                "RECORDED",
                "IDEMPOTENT",
                "RECONCILED",
            }:
                return self._base_report(
                    controller_id=controller_id,
                    status="BLOCKED",
                    decision="OBSERVATION_REFUSED",
                    issues=[
                        str(
                            recorded.get("reason")
                            or "observation:owner_grant_unavailable"
                        )
                    ],
                    cursor=current,
                    state=state,
                )
            if recorded.get("status") == "RECONCILED":
                # The hook and retained-owner rails observed the same call.
                # Keep the hook evidence in the controller journal because the
                # grant row already seals those durable records; the owner
                # payload remains bound by the observation-intent digest.
                grant = self.grants.read_action(
                    str(action.get("action_sha256"))
                )
                pretool_report_sha256 = (
                    grant.get("pretool_report_sha256")
                    if isinstance(grant, Mapping)
                    else None
                )
                posttool_report_sha256 = (
                    grant.get("posttool_report_sha256")
                    if isinstance(grant, Mapping)
                    else None
                )
                pretool, pretool_issue = (
                    self._read_hook_event(
                        pretool_report_sha256,
                        state["activation"]["identity"],
                    )
                    if isinstance(pretool_report_sha256, str)
                    else (None, "missing")
                )
                posttool, posttool_issues = (
                    self._validate_hook_action_report(
                        posttool_report_sha256,
                        action,
                    )
                    if isinstance(posttool_report_sha256, str)
                    else (None, ["missing"])
                )
                if (
                    not isinstance(pretool, Mapping)
                    or pretool_issue is not None
                    or not isinstance(posttool, Mapping)
                    or posttool_issues
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="OBSERVATION_REFUSED",
                        issues=["observation:reconciled_hook_unavailable"],
                        cursor=current,
                        state=state,
                    )
                sealed_binding = posttool.get("native_controller", {}).get(
                    "result_binding"
                )
                owner_binding = receipt.get("result_binding")
                # A non-completed outcome seals no result on either rail; the
                # projection witness rule compares completed results only.
                projection_compatible = (
                    native_result.retained_owner_projection_compatible(
                        sealed_binding,
                        owner_binding,
                        action_kind=action.get("kind"),
                        expected_lane_ids=action.get("lane_ids"),
                        tool_use_id=payload.get("tool_use_id"),
                    )
                    if payload.get("outcome") == "completed"
                    else sealed_binding is None and owner_binding is None
                )
                if not projection_compatible:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="OBSERVATION_REFUSED",
                        issues=[
                            "observation:reconciled_projection_incompatible"
                        ],
                        cursor=current,
                        state=state,
                    )
                # The wire result the hook sealed is the evidence later stages
                # reopen (a continuation's submission id is the worker turn
                # the checkpoint sources must match); the owner's projection
                # stays bound through the observation-intent digest only.
                action_evidence = {
                    "action": deepcopy(dict(action)),
                    "pretool_report_sha256": pretool_report_sha256,
                    "pretool_durable_record_sha256": pretool[
                        "durable_record_sha256"
                    ],
                    "posttool_report_sha256": posttool_report_sha256,
                    "posttool_durable_record_sha256": posttool[
                        "durable_record_sha256"
                    ],
                    "result_binding": deepcopy(sealed_binding),
                }
            else:
                action_evidence = owner_evidence
        else:
            grant = self.grants.read_action(str(action.get("action_sha256")))
            pretool_report_sha256 = (
                grant.get("pretool_report_sha256")
                if isinstance(grant, Mapping)
                else None
            )
            pretool, pretool_issue = (
                self._read_hook_event(
                    pretool_report_sha256, state["activation"]["identity"]
                )
                if isinstance(pretool_report_sha256, str)
                else (None, "missing")
            )
            if (
                not isinstance(pretool, Mapping)
                or pretool_issue is not None
                or not isinstance(hook_durable, Mapping)
            ):
                return self._base_report(
                    controller_id=controller_id,
                    status="BLOCKED",
                    decision="OBSERVATION_REFUSED",
                    issues=["observation:durable_evidence_unavailable"],
                    cursor=current,
                    state=state,
                )
            native = hook_durable["native_controller"]
            action_evidence = {
                "action": deepcopy(dict(action)),
                "pretool_report_sha256": pretool_report_sha256,
                "pretool_durable_record_sha256": pretool[
                    "durable_record_sha256"
                ],
                "posttool_report_sha256": hook_report_sha256,
                "posttool_durable_record_sha256": hook_durable[
                    "durable_record_sha256"
                ],
                "result_binding": deepcopy(native.get("result_binding")),
            }
        evidence_rows = [
            *[
                deepcopy(dict(row))
                for row in state.get("action_evidence", [])
                if isinstance(row, Mapping)
            ],
            action_evidence,
        ]
        transition_issues: list[str] = []
        try:
            next_action, batch_result, batch_outcome, cleanup_required = (
                self._next_batch_transition(
                    action=action,
                    outcome=str(payload["outcome"]),
                    evidence_rows=evidence_rows,
                )
            )
        except (KeyError, TypeError, ValueError):
            next_action = None
            batch_result = None
            batch_outcome = "unknown"
            cleanup_required = True
            transition_issues.append("observation:native_batch_transition_invalid")
        next_capacity_guard: Mapping[str, Any] | None = None
        if isinstance(next_action, Mapping) and next_action.get("kind") == "spawn":
            next_capacity_guard = self._fresh_spawn_capacity_guard(
                next_action, state
            )
            if next_capacity_guard is None:
                next_action = None
                batch_result = None
                batch_outcome = "unknown"
                cleanup_required = True
                transition_issues.append(
                    "observation:spawn_capacity_authority_stale"
                )
        # Unresolved cleanup requires independent resolution, even when its
        # failure is known. A signed settlement alone cannot resume this owner.
        terminal = batch_outcome == "unknown" or (
            action.get("kind") == "stop" and payload["outcome"] != "completed"
        )
        intent_cursor = self._append(
            run_id,
            "action_observation_intent",
            {
                "action_id": payload["action_id"],
                "observation_sha256": _sha(payload),
            },
        )
        if isinstance(next_action, Mapping):
            prepared = self.grants.prepare_action(
                next_action,
                intent_cursor,
                capacity_guard=(
                    next_capacity_guard
                    if next_action.get("kind") == "spawn"
                    else None
                ),
            )
            if prepared.get("status") not in {"PREPARED", "IDEMPOTENT"}:
                raise ValueError("grant:batch_preparation_failed")
        observed_cursor = self._append(
            run_id,
            "action_observed",
            {
                "intent_cursor": intent_cursor,
                "action_id": payload["action_id"],
                "outcome": payload["outcome"],
                "native_receipt_sha256": _sha(payload["native_receipt"]),
                "hook_report_sha256": hook_report_sha256,
                "tool_use_id": payload["tool_use_id"],
                "action_evidence": action_evidence,
                "next_action": deepcopy(dict(next_action))
                if isinstance(next_action, Mapping)
                else None,
                "next_capacity_guard": deepcopy(dict(next_capacity_guard))
                if isinstance(next_capacity_guard, Mapping)
                else None,
                "batch_result": deepcopy(dict(batch_result))
                if isinstance(batch_result, Mapping)
                else None,
                "batch_outcome": batch_outcome,
                "cleanup_required": cleanup_required,
                "terminal": terminal,
            },
        )
        if isinstance(next_action, Mapping):
            finalized = self.grants.finalize_action(next_action, observed_cursor)
            if finalized.get("status") not in {"FINALIZED", "IDEMPOTENT"}:
                raise ValueError("grant:batch_finalization_failed")
        state, _rows = self._state(run_id)
        hook_sha = self._sync_hook(
            controller_id=controller_id,
            cursor=observed_cursor,
            state=state,
        )
        return self._base_report(
            controller_id=controller_id,
            status=(
                "PASS"
                if isinstance(next_action, Mapping)
                or batch_outcome == "completed"
                else "BLOCKED"
            ),
            decision=(
                "ACTION_AUTHORIZED"
                if isinstance(next_action, Mapping)
                else "ACTION_OBSERVED"
                if batch_outcome == "completed"
                else "ACTION_EVIDENCE_CONTRADICTORY"
                if transition_issues
                else "ACTION_TERMINAL_FAILURE"
            ),
            issues=(
                transition_issues
                if transition_issues
                else []
                if isinstance(next_action, Mapping)
                or batch_outcome == "completed"
                else ["native_action:" + batch_outcome]
            ),
            cursor=observed_cursor,
            state=state,
            hook_state_sha256=hook_sha,
        )

    def _inspect(self, value: Mapping[str, Any], run_id: str) -> dict[str, Any]:
        controller_id = value["controller_id"]
        if set(value.get("payload", {})):
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="INSPECTION_REFUSED",
                issues=["inspect:payload_must_be_empty"],
            )
        state, rows = self._state(run_id)
        current = _cursor(rows)
        if value.get("expected_cursor") is not None:
            cursor_issue = self._expected_cursor_issue(
                value.get("expected_cursor"), current
            )
            if cursor_issue is not None:
                return self._base_report(
                    controller_id=controller_id,
                    status="BLOCKED",
                    decision="INSPECTION_REFUSED",
                    issues=[cursor_issue],
                    cursor=current,
                    state=state,
                )
        hook_sha = self._sync_hook(
            controller_id=controller_id,
            cursor=current,
            state=state,
        )
        decision = (
            "OUTCOME_UNKNOWN"
            if state.get("pending_intent") is not None
            or (
                state.get("action") is not None
                and state.get("grant_state")
                in {
                    "DISPATCHED",
                    "PROVISIONAL",
                    "MISSING",
                    "STALE",
                    "OUTCOME_UNKNOWN",
                    None,
                }
            )
            else "TERMINAL"
            if state.get("terminal")
            else "CLEANUP_REQUIRED"
            if state.get("cleanup_required")
            else "ACTION_RESULT_READY"
            if state.get("action") is not None
            and state.get("grant_state") == "POST_OBSERVED"
            else "ACTION_PENDING"
            if state.get("action") is not None
            and state.get("grant_state") == "AUTHORIZED"
            else "WAITING_FOR_STAGE"
        )
        return self._base_report(
            controller_id=controller_id,
            status="BLOCKED" if decision in {"OUTCOME_UNKNOWN", "CLEANUP_REQUIRED"} else "PASS",
            decision=decision,
            issues=(
                ["controller:pending_intent_outcome_unknown"]
                if decision == "OUTCOME_UNKNOWN"
                else ["controller:identity_bound_cleanup_required"]
                if decision == "CLEANUP_REQUIRED"
                else []
            ),
            cursor=current,
            state=state,
            hook_state_sha256=hook_sha,
        )

    def _activation_only_failure_evidence_issues(
        self,
        evidence: Any,
        *,
        controller_id: str,
        authority: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> list[str]:
        issues: list[str] = []
        fields = {
            "schema",
            "abandonment_receipt_artifact",
            "abandonment_receipt",
            "hook_trust_verification_report",
            "historical_runtime_report",
            "evidence_sha256",
        }
        if not isinstance(evidence, Mapping) or set(evidence) != fields:
            return ["activation_only_failure:evidence_shape_invalid"]
        evidence_core = {
            key: deepcopy(value)
            for key, value in evidence.items()
            if key != "evidence_sha256"
        }
        if (
            evidence.get("schema") != ACTIVATION_ONLY_FAILURE_EVIDENCE_SCHEMA
            or evidence.get("evidence_sha256") != _sha(evidence_core)
        ):
            return ["activation_only_failure:evidence_seal_invalid"]
        artifact = evidence.get("abandonment_receipt_artifact")
        if not isinstance(artifact, Mapping) or set(artifact) != {
            "path",
            "artifact_sha256",
        }:
            return [
                "activation_only_failure:abandonment_receipt:reference_invalid"
            ]
        try:
            _resolved, persisted = _read_pre_native_failure_artifact(
                str(artifact.get("path", "")),
                expected_sha256=str(artifact.get("artifact_sha256", "")),
                label="activation_only_failure:abandonment_receipt",
            )
        except ValueError:
            return [
                "activation_only_failure:abandonment_receipt:reference_invalid"
            ]
        envelope = evidence.get("abandonment_receipt")
        if persisted != envelope:
            _issue(
                issues, "activation_only_failure:abandonment_receipt_mismatch"
            )
        owner = (
            authority.get("owner")
            if isinstance(authority, Mapping)
            and isinstance(authority.get("owner"), Mapping)
            else {}
        )
        activation = (
            state.get("activation") if isinstance(state, Mapping) else None
        )
        identity = (
            activation.get("identity")
            if isinstance(activation, Mapping)
            and isinstance(activation.get("identity"), Mapping)
            else {}
        )
        runtime = evidence.get("historical_runtime_report")
        runtime_core = (
            {
                key: deepcopy(value)
                for key, value in runtime.items()
                if key != "report_sha256"
            }
            if isinstance(runtime, Mapping)
            else {}
        )
        if (
            not isinstance(runtime, Mapping)
            or runtime.get("schema")
            != PRE_NATIVE_FAILURE_RUNTIME_REPORT_SCHEMA
            or runtime.get("report_sha256") != _sha(runtime_core)
        ):
            _issue(issues, "activation_only_failure:runtime_report_invalid")
        else:
            try:
                observed_runtime = _pre_native_failure_runtime_report(
                    str(runtime["root"]),
                    expected_package_digest=str(runtime["package_digest"]),
                )
            except ValueError:
                observed_runtime = None
            controller_runtime_root = self.plugin_manifest_path.parent.parent
            if (
                observed_runtime != runtime
                or Path(str(runtime.get("root", ""))).resolve()
                != controller_runtime_root
            ):
                _issue(
                    issues, "activation_only_failure:runtime_report_mismatch"
                )
            if any(
                (
                    runtime.get("version")
                    != identity.get("installed_plugin_version"),
                    runtime.get("hook_definition_sha256")
                    != identity.get("hook_definition_sha256"),
                    runtime.get("hook_registration_sha256")
                    != identity.get("hook_registration_sha256"),
                )
            ):
                _issue(
                    issues, "activation_only_failure:runtime_identity_mismatch"
                )

        # The signature, not the file, is the authority. Every binding field is
        # re-derived from canonical state, so a receipt signed for a different
        # controller, run, activation or task cannot be replayed onto this one.
        expected = {
            "schema": ACTIVATION_ABANDONMENT_PAYLOAD_SCHEMA,
            "status": "ABANDONED",
            "controller_id": controller_id,
            "controller_run_id": owner.get("controller_run_id"),
            "activation_sha256": owner.get("activation_sha256"),
            "store_identity_sha256": owner.get("store_identity_sha256"),
            "root_thread_id": identity.get("root_thread_id"),
            "root_session_id": identity.get("root_session_id"),
        }
        # The activation already sealed which signing authority admitted this
        # controller. Re-deriving it from canonical state means a rotated or
        # substituted trust root cannot close a controller it never admitted.
        sealed_trust = (
            activation.get("hook_trust")
            if isinstance(activation, Mapping)
            and isinstance(activation.get("hook_trust"), Mapping)
            else {}
        )
        admitted = evidence.get("hook_trust_verification_report")
        admitted_core = (
            {
                key: deepcopy(value)
                for key, value in admitted.items()
                if key != "report_sha256"
            }
            if isinstance(admitted, Mapping)
            else {}
        )
        if (
            not isinstance(admitted, Mapping)
            or observer_receipt.evidence.seal(admitted_core, "report_sha256")
            != admitted
            or admitted.get("status") != "PASS"
            or admitted.get("report_sha256")
            != sealed_trust.get("verification_report_sha256")
            or admitted.get("signed_receipt_sha256")
            != sealed_trust.get("signed_receipt_sha256")
        ):
            _issue(
                issues, "activation_only_failure:admitting_authority_unbound"
            )
            return sorted(issues)
        try:
            trust_store = observer_receipt.ObserverTrustStore.from_host_file(
                self._observer_state_dir
                / observer_authority.TRUST_STORE_FILENAME
            )
        except (observer_receipt.ObserverReceiptError, OSError, ValueError):
            _issue(issues, "activation_only_failure:trust_root_unavailable")
            return sorted(issues)
        # Prove cryptographically that the loaded store holds the key that
        # admitted this controller. Labels are copyable; a signature is not.
        #
        # If the observer key has been rotated away, the historical signature
        # can no longer be verified and closure fails closed here. An in-band
        # succession record was tried and withdrawn: every form of it proved to
        # be a transferable credential, because the retiring key can only
        # endorse labels and key material an attacker who can write the pinned
        # store may also author. Rotate only after open controllers are closed
        # or qualified; recovering an already-rotated host is a break-glass
        # change, not a runtime path.
        try:
            admitting_raw = owned_file.read_owned_bytes(
                self.plugin_data
                / "governed-native"
                / "hook-trust"
                / (str(sealed_trust.get("signed_receipt_sha256")) + ".json"),
                max_bytes=MAX_DURABLE_FILE_BYTES,
            )
            admitting_envelope = json.loads(admitting_raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            admitting_raw, admitting_envelope = b"", None
        if (
            hashlib.sha256(admitting_raw).hexdigest()
            != sealed_trust.get("signed_receipt_sha256")
            or not _admitting_signature_valid(
                admitting_envelope, trust_store, admitted
            )
        ):
            _issue(
                issues, "activation_only_failure:trust_root_not_admitting"
            )
            return sorted(issues)
        verification = observer_receipt.verify_signed_receipt(
            envelope,
            expected_kind=ACTIVATION_ABANDONMENT_RECEIPT_KIND,
            expected_payload=expected,
            evaluation_time=self._evaluation_time(),
            trust_store=trust_store,
            replay_guard=self._hook_trust_replay_guard,
        )
        attested = (
            verification.get("payload")
            if isinstance(verification.get("payload"), Mapping)
            else {}
        )
        if verification.get("status") != "PASS":
            _issue(
                issues,
                "activation_only_failure:abandonment_receipt_unverified:"
                + str(verification.get("reason")),
            )
            return sorted(issues)
        if (
            verification.get("host_id") != admitted.get("host_id")
            or verification.get("key_id") != admitted.get("key_id")
            or verification.get("trust_generation")
            != admitted.get("trust_generation")
        ):
            _issue(
                issues, "activation_only_failure:signing_authority_changed"
            )
            return sorted(issues)
        if set(attested) != set(expected) | {
            "abandoned_turn_id",
            "owner_process",
        }:
            _issue(
                issues,
                "activation_only_failure:abandonment_receipt_unverified:"
                + str(verification.get("reason")),
            )
            return sorted(issues)
        if not _IDENTIFIER.fullmatch(str(attested.get("abandoned_turn_id"))):
            _issue(
                issues,
                "activation_only_failure:failure_report_identity_mismatch",
            )
        if not _owner_process_absent(attested.get("owner_process")):
            _issue(issues, "activation_only_failure:owner_process_still_live")
        return sorted(issues)

    def _pre_native_failure_evidence_issues(
        self,
        evidence: Any,
        *,
        controller_id: str,
        authority: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> list[str]:
        issues: list[str] = []
        fields = {
            "schema",
            "failure_artifact",
            "failure_report",
            "predecessor_authority_artifact",
            "predecessor_authority",
            "historical_runtime_report",
            "evidence_sha256",
        }
        if not isinstance(evidence, Mapping) or set(evidence) != fields:
            return ["pre_native_failure:evidence_shape_invalid"]
        evidence_core = {
            key: deepcopy(value)
            for key, value in evidence.items()
            if key != "evidence_sha256"
        }
        if (
            evidence.get("schema") != PRE_NATIVE_FAILURE_EVIDENCE_SCHEMA
            or evidence.get("evidence_sha256") != _sha(evidence_core)
        ):
            return ["pre_native_failure:evidence_seal_invalid"]

        def reference(value: Any, label: str) -> tuple[Path | None, dict[str, Any] | None]:
            if (
                not isinstance(value, Mapping)
                or set(value) != {"path", "artifact_sha256"}
            ):
                _issue(issues, label + ":reference_invalid")
                return None, None
            try:
                return _read_pre_native_failure_artifact(
                    str(value.get("path", "")),
                    expected_sha256=str(value.get("artifact_sha256", "")),
                    label=label,
                )
            except ValueError:
                _issue(issues, label + ":reference_invalid")
                return None, None

        failure_path, persisted_failure = reference(
            evidence.get("failure_artifact"),
            "pre_native_failure:failure_artifact",
        )
        _authority_path, persisted_authority = reference(
            evidence.get("predecessor_authority_artifact"),
            "pre_native_failure:authority_artifact",
        )
        failure = evidence.get("failure_report")
        expected_authority = evidence.get("predecessor_authority")
        runtime = evidence.get("historical_runtime_report")
        if persisted_failure != failure:
            _issue(issues, "pre_native_failure:failure_artifact_mismatch")
        if persisted_authority != expected_authority:
            _issue(issues, "pre_native_failure:authority_artifact_mismatch")
        if expected_authority != authority:
            _issue(issues, "pre_native_failure:authority_snapshot_changed")

        runtime_fields = {
            "schema",
            "root",
            "version",
            "inventory_hash",
            "descriptor_hash",
            "package_digest",
            "hook_definition_sha256",
            "hook_registration_sha256",
            "report_sha256",
        }
        runtime_core = (
            {
                key: deepcopy(value)
                for key, value in runtime.items()
                if key != "report_sha256"
            }
            if isinstance(runtime, Mapping)
            else {}
        )
        if (
            not isinstance(runtime, Mapping)
            or set(runtime) != runtime_fields
            or runtime.get("schema")
            != PRE_NATIVE_FAILURE_RUNTIME_REPORT_SCHEMA
            or runtime.get("report_sha256") != _sha(runtime_core)
        ):
            _issue(issues, "pre_native_failure:runtime_report_invalid")
        else:
            try:
                observed_runtime = _pre_native_failure_runtime_report(
                    str(runtime["root"]),
                    expected_package_digest=str(runtime["package_digest"]),
                )
            except ValueError:
                observed_runtime = None
            controller_runtime_root = self.plugin_manifest_path.parent.parent
            if (
                observed_runtime != runtime
                or Path(str(runtime.get("root", ""))).resolve()
                != controller_runtime_root
            ):
                _issue(issues, "pre_native_failure:runtime_report_mismatch")

        activation = state.get("activation")
        identity = (
            activation.get("identity")
            if isinstance(activation, Mapping)
            and isinstance(activation.get("identity"), Mapping)
            else {}
        )
        if isinstance(runtime, Mapping) and any(
            (
                runtime.get("version")
                != identity.get("installed_plugin_version"),
                runtime.get("hook_definition_sha256")
                != identity.get("hook_definition_sha256"),
                runtime.get("hook_registration_sha256")
                != identity.get("hook_registration_sha256"),
            )
        ):
            _issue(issues, "pre_native_failure:runtime_identity_mismatch")

        if (
            isinstance(failure, Mapping)
            and failure.get("schema")
            == OWNER_TERMINAL_PRE_NATIVE_FAILURE_REPORT_SCHEMA
        ):
            issues.extend(
                self._owner_terminal_pre_native_failure_issues(
                    failure,
                    identity=identity,
                    runtime=runtime,
                    failure_path=failure_path,
                )
            )
            return sorted(set(issues))
        if (
            not isinstance(failure, Mapping)
            or set(failure) != _PRE_NATIVE_FAILURE_PACKET_FIELDS
        ):
            _issue(issues, "pre_native_failure:failure_report_shape_invalid")
            return sorted(issues)
        packet_schema = failure.get("schema")
        boundary = failure.get("pre_turn_boundary")
        notifications = failure.get("notification_counts")
        hook_runs = failure.get("hook_runs")
        runtime_hooks = (
            str(runtime.get("root")) + "/hooks/hooks.json"
            if isinstance(runtime, Mapping)
            else None
        )

        def runtime_hook_source_matches(value: Any) -> bool:
            if not isinstance(value, str):
                return False
            source = Path(value)
            version = (
                runtime.get("version")
                if isinstance(runtime, Mapping)
                else None
            )
            return bool(
                source.is_absolute()
                and not source.is_symlink()
                and (
                    value == runtime_hooks
                    or (
                        source.name == "hooks.json"
                        and source.parent.name == "hooks"
                        and source.parent.parent.name == version
                    )
                )
            )
        session_start_observed = bool(
            isinstance(hook_runs, list)
            and any(
                isinstance(row, Mapping)
                and row.get("eventName") == "sessionStart"
                and row.get("status") == "completed"
                and row.get("source") == "plugin"
                and runtime_hook_source_matches(row.get("sourcePath"))
                for row in hook_runs
            )
        )
        terminal_stop_observed = bool(
            isinstance(hook_runs, list)
            and any(
                isinstance(row, Mapping)
                and row.get("eventName") == "stop"
                and row.get("status") == "blocked"
                and row.get("source") == "plugin"
                and runtime_hook_source_matches(row.get("sourcePath"))
                and isinstance(row.get("entries"), list)
                and any(
                    isinstance(entry, Mapping)
                    and entry.get("kind") == "feedback"
                    and entry.get("text")
                    == "native_controller:terminal_state_required"
                    for entry in row["entries"]
                )
                for row in hook_runs
            )
        )
        expected_boundary = {
            "live_boundary_crossed": (
                boundary.get("live_boundary_crossed")
                if isinstance(boundary, Mapping)
                else None
            ),
            "native_action_authorized": False,
            "next_owner_action": "turn/start",
            "required_hook_event": "SessionStart",
            "turn_started": False,
            "worker_created": False,
        }
        if (
            not isinstance(packet_schema, str)
            or re.fullmatch(
                r"issue163/cycle[1-9][0-9]*-dedicated-app-server-run/v2",
                packet_schema,
            )
            is None
            or failure.get("status") != "COMPLETED"
            or failure.get("issues") != []
            or failure.get("existing_server_restarted") is not False
            or failure.get("owner_socket_injected") is not True
            or failure.get("owned_process_group_cleaned") is not True
            or failure.get("server_output_exhausted") is not False
            or failure.get("server_returncode") != 0
            or failure.get("pre_turn_successor_prepared") is not True
            or failure.get("pre_turn_decision") != "READY_FOR_SESSION_START"
            or failure.get("pre_turn_controller_id") != controller_id
            or failure.get("task_id") != identity.get("root_thread_id")
            or not _IDENTIFIER.fullmatch(str(failure.get("turn_id", "")))
            or failure.get("turn_started_after_pre_turn") is not True
            or failure.get("turn_status") != "interrupted"
            or failure.get("last_message_present") is not True
            or failure.get("pre_turn_hooks_enabled") is not True
            or type(failure.get("pre_turn_hook_count")) is not int
            or failure.get("pre_turn_hook_count", 0) < 1
            or not _DIGEST.fullmatch(
                str(failure.get("expected_app_server_argv_sha256", ""))
            )
            or not _DIGEST.fullmatch(
                str(failure.get("host_preparation_report_sha256", ""))
            )
            or not _DIGEST.fullmatch(
                str(failure.get("pre_turn_hook_inventory_report_sha256", ""))
            )
            or not _DIGEST.fullmatch(
                str(failure.get("pre_turn_report_sha256", ""))
            )
            or not isinstance(
                expected_boundary["live_boundary_crossed"], bool
            )
            or boundary != expected_boundary
            or not isinstance(notifications, Mapping)
            or notifications.get("turn/started") != 1
            or notifications.get("turn/completed") != 1
            or not session_start_observed
            or not terminal_stop_observed
            or failure_path is None
        ):
            _issue(issues, "pre_native_failure:failure_report_invalid")
        else:
            evidence_root = Path(str(failure.get("pre_turn_evidence_root", "")))
            pre_turn_path = Path(str(failure.get("pre_turn_report_path", "")))
            if (
                not evidence_root.is_absolute()
                or evidence_root.is_symlink()
                or not pre_turn_path.is_absolute()
                or pre_turn_path.is_symlink()
                or pre_turn_path.parent != evidence_root
            ):
                _issue(issues, "pre_native_failure:pre_turn_reference_invalid")
            else:
                pre_turn_raw = b""
                try:
                    pre_turn_raw = owned_file.read_owned_bytes(
                        pre_turn_path.resolve(strict=True),
                        max_bytes=MAX_EVENT_BYTES,
                        required_mode=0o600,
                    )
                    pre_turn_report = json.loads(
                        pre_turn_raw.decode("utf-8")
                    )
                except (
                    OSError,
                    UnicodeError,
                    json.JSONDecodeError,
                    ValueError,
                ):
                    pre_turn_report = None
                pre_turn_core = (
                    {
                        key: deepcopy(value)
                        for key, value in pre_turn_report.items()
                        if key != "report_sha256"
                    }
                    if isinstance(pre_turn_report, Mapping)
                    else {}
                )
                pre_turn_controller = (
                    pre_turn_report.get("controller")
                    if isinstance(pre_turn_report, Mapping)
                    and isinstance(
                        pre_turn_report.get("controller"), Mapping
                    )
                    else None
                )
                if (
                    not isinstance(pre_turn_report, Mapping)
                    or pre_turn_raw
                    != _canonical(pre_turn_report) + b"\n"
                    or pre_turn_report.get("report_sha256")
                    != failure.get("pre_turn_report_sha256")
                    or pre_turn_report.get("report_sha256")
                    != _sha(pre_turn_core)
                    or pre_turn_report.get("schema")
                    not in {
                        "orch-dork/qualification-successor-pre-turn/v3",
                        "orch-dork/qualification-successor-pre-turn/v4",
                        "orch-dork/qualification-successor-pre-turn/v5",
                    }
                    or pre_turn_report.get("status") != "PASS"
                    or pre_turn_report.get("decision")
                    != "READY_FOR_SESSION_START"
                    or not isinstance(
                        pre_turn_report.get("provider_free"), bool
                    )
                    or boundary.get("live_boundary_crossed")
                    is pre_turn_report.get("provider_free")
                    or not isinstance(pre_turn_controller, Mapping)
                    or pre_turn_controller.get("controller_id")
                    != controller_id
                    or pre_turn_controller.get("root_thread_id")
                    != identity.get("root_thread_id")
                    or pre_turn_report.get("boundary") != boundary
                ):
                    _issue(
                        issues,
                        "pre_native_failure:pre_turn_report_invalid",
                    )
        return sorted(issues)

    def _owner_terminal_pre_native_failure_issues(
        self,
        failure: Mapping[str, Any],
        *,
        identity: Mapping[str, Any],
        runtime: Any,
        failure_path: Path | None,
    ) -> list[str]:
        """Re-derive an owner-terminal failure report from its two sources.

        The report is accepted only when the owner terminal it embeds is the
        artifact at the path the terminal itself names, the terminal attests
        a refused root turn with a closed host for this controller's
        generation, the root rollout it names re-summarizes to the same
        failed single turn of this controller's root thread, and the two
        sources pair as one owner's one turn (same source commit, the
        owner's originator).
        """

        issues: list[str] = []
        if set(failure) != _OWNER_TERMINAL_FAILURE_REPORT_FIELDS:
            return ["pre_native_failure:owner_terminal_report_shape_invalid"]
        if failure_path is None:
            return ["pre_native_failure:owner_terminal_report_path_unbound"]
        core = {
            key: deepcopy(value)
            for key, value in failure.items()
            if key != "report_sha256"
        }
        if failure.get("report_sha256") != _sha(core):
            return ["pre_native_failure:owner_terminal_report_seal_invalid"]
        terminal_ref = failure.get("owner_terminal_artifact")
        rollout_ref = failure.get("root_rollout_artifact")
        terminal_path: Path | None = None
        persisted_terminal: dict[str, Any] | None = None
        if (
            not isinstance(terminal_ref, Mapping)
            or set(terminal_ref) != {"path", "artifact_sha256"}
        ):
            _issue(issues, "pre_native_failure:owner_terminal:reference_invalid")
        else:
            try:
                terminal_path, persisted_terminal = (
                    _read_pre_native_failure_artifact(
                        str(terminal_ref.get("path", "")),
                        expected_sha256=str(
                            terminal_ref.get("artifact_sha256", "")
                        ),
                        label="pre_native_failure:owner_terminal",
                    )
                )
            except ValueError:
                _issue(
                    issues, "pre_native_failure:owner_terminal:reference_invalid"
                )
        terminal = failure.get("owner_terminal")
        if persisted_terminal is not None and persisted_terminal != terminal:
            _issue(issues, "pre_native_failure:owner_terminal_artifact_mismatch")
        issues.extend(
            _owner_terminal_failure_issues(terminal, terminal_path=terminal_path)
        )
        runtime_digest = (
            runtime.get("package_digest") if isinstance(runtime, Mapping)
            else None
        )
        # The terminal's ticket is the release ticket whose branch carries the
        # generation; the activation identity's ticket_id is the governed
        # review admission ("issue-94").  Only generation and runtime digest
        # bind the two.
        if isinstance(terminal, Mapping) and (
            terminal.get("generation") != identity.get("installed_plugin_version")
            or terminal.get("runtime_package_digest") != runtime_digest
        ):
            _issue(issues, "pre_native_failure:owner_terminal_generation_mismatch")

        summary: dict[str, Any] | None = None
        if (
            not isinstance(rollout_ref, Mapping)
            or set(rollout_ref) != {"path", "artifact_sha256", "size_bytes"}
        ):
            _issue(issues, "pre_native_failure:root_rollout:reference_invalid")
        else:
            try:
                rollout_path, rollout_raw = _read_root_rollout(
                    str(rollout_ref.get("path", "")),
                    expected_sha256=str(rollout_ref.get("artifact_sha256", "")),
                )
                if (
                    str(rollout_path) != rollout_ref.get("path")
                    or len(rollout_raw) != rollout_ref.get("size_bytes")
                ):
                    raise _rollout_refusal("reference_invalid")
                summary = _owner_terminal_rollout_summary(rollout_raw, terminal)
            except ValueError as error:
                _issue(issues, str(error))
        if summary is not None and summary != failure.get("root_rollout_summary"):
            _issue(issues, "pre_native_failure:root_rollout_summary_mismatch")
        if summary is not None and (
            summary["thread_id"] != identity.get("root_thread_id")
            or summary["model"] != identity.get("root_model")
            or summary["effort"] != identity.get("root_effort")
        ):
            _issue(issues, "pre_native_failure:root_rollout_identity_mismatch")
        if summary is not None and isinstance(terminal, Mapping):
            issues.extend(
                _owner_terminal_rollout_pairing_issues(terminal, summary)
            )
        if summary is not None and isinstance(terminal, Mapping) and (
            failure.get("task_id") != summary["thread_id"]
            or failure.get("turn_id") != summary["turn_id"]
            or failure.get("turn_status") != summary["turn_status"]
            or failure.get("turn_status") != ("completed" if _empty_owner_control_turn(terminal) else "failed")
            or failure.get("turn_error_message") != summary["error_message"]
            or failure.get("owner_refusal_phase") != terminal.get("phase")
            or failure.get("owner_refusal_issue") != terminal.get("issue")
            or failure.get("owner_process_group_cleaned") is not True
        ):
            _issue(issues, "pre_native_failure:owner_terminal_report_invalid")
        return sorted(set(issues))

    def _partial_native_failure_evidence_issues(
        self,
        evidence: Any,
        *,
        controller_id: str,
        authority: Mapping[str, Any],
        state: Mapping[str, Any],
        capacity: Mapping[str, Any],
    ) -> list[str]:
        """Validate the exact persisted partial-batch failure corpus."""

        issues: list[str] = []
        fields = {
            "schema",
            "terminal_snapshot_artifact",
            "terminal_snapshot",
            "worker_state_artifact",
            "worker_state",
            "worker_rollout_artifact",
            "historical_runtime_report",
            "evidence_sha256",
        }
        if not isinstance(evidence, Mapping) or set(evidence) != fields:
            return ["partial_native_failure:evidence_shape_invalid"]
        evidence_core = {
            key: deepcopy(value)
            for key, value in evidence.items()
            if key != "evidence_sha256"
        }
        if (
            evidence.get("schema") != PARTIAL_NATIVE_FAILURE_EVIDENCE_SCHEMA
            or evidence.get("evidence_sha256") != _sha(evidence_core)
        ):
            return ["partial_native_failure:evidence_seal_invalid"]

        def json_reference(
            value: Any, expected: Any, label: str
        ) -> tuple[Path | None, dict[str, Any] | None]:
            if (
                not isinstance(value, Mapping)
                or set(value) != {"path", "artifact_sha256"}
            ):
                _issue(issues, label + ":reference_invalid")
                return None, None
            try:
                path, report = _read_pre_native_failure_artifact(
                    str(value.get("path", "")),
                    expected_sha256=str(value.get("artifact_sha256", "")),
                    label=label,
                )
            except ValueError:
                _issue(issues, label + ":reference_invalid")
                return None, None
            if report != expected:
                _issue(issues, label + ":artifact_mismatch")
            return path, report

        snapshot = evidence.get("terminal_snapshot")
        worker = evidence.get("worker_state")
        snapshot_path, persisted_snapshot = json_reference(
            evidence.get("terminal_snapshot_artifact"),
            snapshot,
            "partial_native_failure:terminal_snapshot",
        )
        worker_path, persisted_worker = json_reference(
            evidence.get("worker_state_artifact"),
            worker,
            "partial_native_failure:worker_state",
        )
        rollout_reference = evidence.get("worker_rollout_artifact")
        rollout_path: Path | None = None
        rollout_raw = b""
        if (
            not isinstance(rollout_reference, Mapping)
            or set(rollout_reference)
            != {"path", "artifact_sha256", "size_bytes"}
            or not _DIGEST.fullmatch(
                str(rollout_reference.get("artifact_sha256", ""))
            )
            or type(rollout_reference.get("size_bytes")) is not int
            or rollout_reference.get("size_bytes", 0) < 1
        ):
            _issue(
                issues,
                "partial_native_failure:worker_rollout:reference_invalid",
            )
        else:
            candidate = Path(str(rollout_reference.get("path", "")))
            try:
                rollout_path = candidate.resolve(strict=True)
                rollout_raw = owned_file.read_owned_bytes(
                    rollout_path,
                    max_bytes=2_097_152,
                    required_mode=0o600,
                )
            except (OSError, ValueError):
                rollout_path = None
            if (
                rollout_path is None
                or not candidate.is_absolute()
                or candidate.is_symlink()
                or snapshot_path is None
                or rollout_path.parent != snapshot_path.parent
                or hashlib.sha256(rollout_raw).hexdigest()
                != rollout_reference.get("artifact_sha256")
                or len(rollout_raw) != rollout_reference.get("size_bytes")
            ):
                _issue(
                    issues,
                    "partial_native_failure:worker_rollout:reference_invalid",
                )

        runtime_value = evidence.get("historical_runtime_report")
        runtime = runtime_value if isinstance(runtime_value, Mapping) else {}
        runtime_core = (
            {
                key: deepcopy(value)
                for key, value in runtime.items()
                if key != "report_sha256"
            }
        )
        if (
            not isinstance(runtime_value, Mapping)
            or runtime.get("schema")
            != PRE_NATIVE_FAILURE_RUNTIME_REPORT_SCHEMA
            or runtime.get("report_sha256") != _sha(runtime_core)
        ):
            _issue(issues, "partial_native_failure:runtime_report_invalid")
        else:
            try:
                observed_runtime = _pre_native_failure_runtime_report(
                    str(runtime.get("root", "")),
                    expected_package_digest=str(
                        runtime.get("package_digest", "")
                    ),
                )
            except ValueError:
                observed_runtime = None
            if (
                observed_runtime != runtime
                or Path(str(runtime.get("root", ""))).resolve()
                != self.plugin_manifest_path.parent.parent
            ):
                _issue(
                    issues,
                    "partial_native_failure:runtime_report_mismatch",
                )

        snapshot_core = (
            {
                key: deepcopy(value)
                for key, value in snapshot.items()
                if key != "report_sha256"
            }
            if isinstance(snapshot, Mapping)
            else {}
        )
        snapshot_fields = {
            "schema",
            "generation",
            "candidate_commit",
            "task_id",
            "turn_id",
            "controller_id",
            "controller_cursor",
            "controller_authority",
            "controller_state",
            "capacity_authority",
            "project_ground_current",
            "durable_posttool_event",
            "failure_codes",
            "artifacts",
            "report_sha256",
        }
        activation = state.get("activation")
        identity = (
            activation.get("identity")
            if isinstance(activation, Mapping)
            and isinstance(activation.get("identity"), Mapping)
            else {}
        )
        action = state.get("action")
        grant = state.get("grant")
        durable = (
            snapshot.get("durable_posttool_event")
            if isinstance(snapshot, Mapping)
            else None
        )
        durable_native = (
            durable.get("native_controller")
            if isinstance(durable, Mapping)
            and isinstance(durable.get("native_controller"), Mapping)
            else None
        )
        if (
            not isinstance(snapshot, Mapping)
            or set(snapshot) != snapshot_fields
            or re.fullmatch(
                r"orch-dork/issue163-cycle[1-9][0-9]*-terminal-snapshot/v2",
                str(snapshot.get("schema", "")),
            )
            is None
            or snapshot.get("report_sha256") != _sha(snapshot_core)
            or persisted_snapshot != snapshot
            or snapshot.get("controller_id") != controller_id
            or snapshot.get("controller_cursor") != authority.get("tip")
            or snapshot.get("controller_authority") != authority
            or snapshot.get("controller_state") != state
            or snapshot.get("capacity_authority") != capacity
            or snapshot.get("task_id") != identity.get("root_thread_id")
            or snapshot.get("turn_id")
            != (
                durable.get("identity", {}).get("turn_id")
                if isinstance(durable, Mapping)
                else None
            )
            or snapshot.get("generation")
            != identity.get("installed_plugin_version")
            or not re.fullmatch(
                r"[0-9a-f]{40}",
                str(snapshot.get("candidate_commit", "")),
            )
            or snapshot.get("failure_codes")
            != [
                "native_controller:canonical_status_mismatch",
                "native_controller:exact_action_required",
            ]
            or not isinstance(action, Mapping)
            or not isinstance(grant, Mapping)
            or not isinstance(durable, Mapping)
            or durable.get("schema")
            != "orch-dork/project-ground-durable-event/v1"
            or durable.get("status") != "BLOCKED"
            or durable.get("decision") != "OBSERVED"
            or durable.get("hook_event_name") != "PostToolUse"
            or durable.get("durable_record_sha256")
            != _sha(
                {
                    key: deepcopy(value)
                    for key, value in durable.items()
                    if key != "durable_record_sha256"
                }
            )
            or not isinstance(durable_native, Mapping)
            or durable_native.get("grant_state") != "OUTCOME_UNKNOWN"
            or durable_native.get("outcome") != "unknown"
            or durable_native.get("result_binding") is not None
            or durable_native.get("action_id") != action.get("action_id")
            or durable_native.get("tool_use_id") != grant.get("tool_use_id")
            or durable.get("tool_input_sha256")
            != action.get("tool_input_sha256")
            or durable.get("report_sha256")
            not in {
                path.stem
                for path in [
                    self.plugin_data
                    / "project-ground/events"
                    / hashlib.sha256(
                        str(identity.get("root_session_id", "")).encode(
                            "utf-8"
                        )
                    ).hexdigest()
                    / (str(durable.get("report_sha256")) + ".json")
                ]
                if path.is_file()
            }
        ):
            _issue(issues, "partial_native_failure:snapshot_invalid")
        else:
            event_path = (
                self.plugin_data
                / "project-ground/events"
                / hashlib.sha256(
                    str(identity["root_session_id"]).encode("utf-8")
                ).hexdigest()
                / (str(durable["report_sha256"]) + ".json")
            )
            try:
                persisted_durable = owned_file.read_owned_json(
                    event_path,
                    max_bytes=MAX_EVENT_BYTES,
                    required_mode=0o600,
                )
                current_ground = owned_file.read_owned_json(
                    self.plugin_data / "project-ground/current.json",
                    max_bytes=MAX_RUNTIME_FILE_BYTES,
                )
            except (OSError, ValueError, json.JSONDecodeError):
                persisted_durable = None
                current_ground = None
            if (
                persisted_durable != durable
                or current_ground != snapshot.get("project_ground_current")
            ):
                _issue(
                    issues,
                    "partial_native_failure:durable_state_mismatch",
                )

        worker_core = (
            {
                key: deepcopy(value)
                for key, value in worker.items()
                if key != "report_sha256"
            }
            if isinstance(worker, Mapping)
            else {}
        )
        worker_thread = (
            worker.get("thread")
            if isinstance(worker, Mapping)
            and isinstance(worker.get("thread"), Mapping)
            else None
        )
        spawn_edge = (
            worker.get("spawn_edge")
            if isinstance(worker, Mapping)
            and isinstance(worker.get("spawn_edge"), Mapping)
            else None
        )
        source = None
        try:
            source = (
                json.loads(str(worker_thread.get("source")))
                if isinstance(worker_thread, Mapping)
                else None
            )
        except json.JSONDecodeError:
            source = None
        spawn_source = (
            source.get("subagent", {}).get("thread_spawn")
            if isinstance(source, Mapping)
            and isinstance(source.get("subagent"), Mapping)
            and isinstance(source["subagent"].get("thread_spawn"), Mapping)
            else None
        )
        worker_id = (
            worker_thread.get("id")
            if isinstance(worker_thread, Mapping)
            else None
        )
        nickname = (
            spawn_source.get("agent_nickname")
            if isinstance(spawn_source, Mapping)
            else None
        )
        expected_wire_result = json.dumps(
            {"agent_id": worker_id, "nickname": nickname},
            sort_keys=True,
            separators=(",", ":"),
        )
        if (
            not isinstance(worker, Mapping)
            or worker.get("schema")
            != "orch-dork/issue163-cycle29-worker-state/v1"
            or worker.get("report_sha256") != _sha(worker_core)
            or persisted_worker != worker
            or worker.get("process_match_count") != 0
            or worker.get("terminal_receipt_observed") is not True
            or worker.get("terminal_disposition") != "BLOCKED"
            or worker.get("close_api_status")
            != "unreachable_after_owner_process_cleanup"
            or not isinstance(worker_thread, Mapping)
            or not isinstance(spawn_edge, Mapping)
            or not isinstance(spawn_source, Mapping)
            or worker_thread.get("git_sha")
            != snapshot.get("candidate_commit")
            or worker_thread.get("model") != "qwen-local/qwen-smart"
            or worker_thread.get("reasoning_effort") != "xhigh"
            or spawn_edge.get("child_thread_id") != worker_id
            or spawn_edge.get("parent_thread_id")
            != identity.get("root_thread_id")
            or spawn_source.get("parent_thread_id")
            != identity.get("root_thread_id")
            or not _IDENTIFIER.fullmatch(str(worker_id or ""))
            or not isinstance(nickname, str)
            or not nickname.strip()
            or rollout_reference.get("artifact_sha256")
            != worker.get("rollout_sha256")
            or rollout_reference.get("size_bytes")
            != worker.get("rollout_size_bytes")
            or str(worker_id).encode("utf-8") not in rollout_raw
            or b"TERMINAL_STATE_RECORDED" not in rollout_raw
            or durable_native is None
            or durable_native.get("result_sha256")
            != _sha(expected_wire_result)
        ):
            _issue(issues, "partial_native_failure:worker_evidence_invalid")

        artifacts = (
            snapshot.get("artifacts")
            if isinstance(snapshot, Mapping)
            and isinstance(snapshot.get("artifacts"), Mapping)
            else None
        )
        if snapshot_path is not None and isinstance(artifacts, Mapping):
            for name, reference in artifacts.items():
                candidate = snapshot_path.parent / str(name)
                try:
                    payload = owned_file.read_owned_bytes(
                        candidate,
                        max_bytes=2_097_152,
                        required_mode=0o600,
                    )
                except (OSError, ValueError):
                    payload = b""
                if (
                    not isinstance(reference, Mapping)
                    or set(reference) != {"sha256", "size_bytes"}
                    or hashlib.sha256(payload).hexdigest()
                    != reference.get("sha256")
                    or len(payload) != reference.get("size_bytes")
                ):
                    _issue(
                        issues,
                        "partial_native_failure:root_artifact_invalid",
                    )
                    break
            runner_names = [
                name
                for name in artifacts
                if str(name).endswith("dedicated-app-server-result.json")
            ]
            runner = None
            if len(runner_names) == 1:
                try:
                    runner = owned_file.read_owned_json(
                        snapshot_path.parent / str(runner_names[0]),
                        max_bytes=MAX_EVENT_BYTES,
                        required_mode=0o600,
                    )
                except (OSError, ValueError, json.JSONDecodeError):
                    runner = None
            hook_runs = (
                runner.get("hook_runs")
                if isinstance(runner, Mapping)
                and isinstance(runner.get("hook_runs"), list)
                else []
            )
            saw_second_denial = any(
                isinstance(row, Mapping)
                and row.get("eventName") == "preToolUse"
                and row.get("status") == "blocked"
                and any(
                    isinstance(entry, Mapping)
                    and entry.get("kind") == "feedback"
                    and entry.get("text")
                    == (
                        "native_controller:canonical_status_mismatch; "
                        "native_controller:exact_action_required"
                    )
                    for entry in row.get("entries", [])
                )
                for row in hook_runs
            )
            if (
                not isinstance(runner, Mapping)
                or runner.get("status") != "COMPLETED"
                or runner.get("task_id") != identity.get("root_thread_id")
                or runner.get("turn_id") != snapshot.get("turn_id")
                or runner.get("pre_turn_controller_id") != controller_id
                or runner.get("turn_status") != "interrupted"
                or runner.get("owned_process_group_cleaned") is not True
                or runner.get("server_output_exhausted") is not False
                or runner.get("existing_server_restarted") is not False
                or not saw_second_denial
            ):
                _issue(issues, "partial_native_failure:runner_invalid")
        else:
            _issue(issues, "partial_native_failure:root_artifact_invalid")
        return sorted(issues)

    def _post_spawn_failure_evidence_issues(
        self,
        evidence: Any,
        *,
        controller_id: str,
        authority: Mapping[str, Any],
        state: Mapping[str, Any],
        capacity: Mapping[str, Any],
        spawn_lanes: list[dict[str, str]],
    ) -> list[str]:
        """Validate the exact persisted two-worker post-spawn failure."""

        issues: list[str] = []
        fields = {
            "schema",
            "evidence_root",
            "dedicated_run_artifact",
            "dedicated_run",
            "attempt_envelope_artifact",
            "attempt_envelope",
            "pre_turn_artifact",
            "pre_turn_report",
            "root_rollout",
            "worker_rollouts",
            "historical_runtime_report",
            "evidence_sha256",
        }
        if not isinstance(evidence, Mapping) or set(evidence) != fields:
            return ["post_spawn_failure:evidence_shape_invalid"]
        evidence_core = {
            key: deepcopy(value)
            for key, value in evidence.items()
            if key != "evidence_sha256"
        }
        if (
            evidence.get("schema") != POST_SPAWN_FAILURE_EVIDENCE_SCHEMA
            or evidence.get("evidence_sha256") != _sha(evidence_core)
        ):
            return ["post_spawn_failure:evidence_seal_invalid"]

        evidence_root = Path(str(evidence.get("evidence_root", "")))
        try:
            resolved_evidence_root = evidence_root.resolve(strict=True)
            root_info = resolved_evidence_root.lstat()
        except OSError:
            resolved_evidence_root = Path("/")
            root_info = None
        if (
            not evidence_root.is_absolute()
            or evidence_root.is_symlink()
            or root_info is None
            or not stat.S_ISDIR(root_info.st_mode)
            or (hasattr(os, "getuid") and root_info.st_uid != os.getuid())
            or stat.S_IMODE(root_info.st_mode) & 0o022
        ):
            _issue(issues, "post_spawn_failure:evidence_root_invalid")

        def reread_json(
            reference: Any, expected: Any, label: str
        ) -> dict[str, Any] | None:
            if (
                not isinstance(reference, Mapping)
                or set(reference)
                != {"path", "artifact_sha256", "size_bytes"}
                or type(reference.get("size_bytes")) is not int
                or reference.get("size_bytes", 0) < 1
            ):
                _issue(issues, label + ":reference_invalid")
                return None
            try:
                path, observed, size = _read_post_spawn_json_artifact(
                    str(reference.get("path", "")),
                    expected_sha256=str(
                        reference.get("artifact_sha256", "")
                    ),
                    label=label,
                )
            except ValueError:
                _issue(issues, label + ":reference_invalid")
                return None
            if (
                path.parent != resolved_evidence_root
                or size != reference.get("size_bytes")
                or observed != expected
            ):
                _issue(issues, label + ":artifact_mismatch")
                return None
            return observed

        dedicated = evidence.get("dedicated_run")
        envelope = evidence.get("attempt_envelope")
        pre_turn = evidence.get("pre_turn_report")
        reread_json(
            evidence.get("dedicated_run_artifact"),
            dedicated,
            "post_spawn_failure:dedicated_run",
        )
        reread_json(
            evidence.get("attempt_envelope_artifact"),
            envelope,
            "post_spawn_failure:attempt_envelope",
        )
        reread_json(
            evidence.get("pre_turn_artifact"),
            pre_turn,
            "post_spawn_failure:pre_turn",
        )

        runtime = evidence.get("historical_runtime_report")
        runtime_core = (
            {
                key: deepcopy(value)
                for key, value in runtime.items()
                if key != "report_sha256"
            }
            if isinstance(runtime, Mapping)
            else {}
        )
        if (
            not isinstance(runtime, Mapping)
            or runtime.get("schema")
            != PRE_NATIVE_FAILURE_RUNTIME_REPORT_SCHEMA
            or runtime.get("report_sha256") != _sha(runtime_core)
        ):
            _issue(issues, "post_spawn_failure:runtime_report_invalid")
        else:
            try:
                observed_runtime = _pre_native_failure_runtime_report(
                    str(runtime.get("root", "")),
                    expected_package_digest=str(
                        runtime.get("package_digest", "")
                    ),
                )
            except ValueError:
                observed_runtime = None
            if (
                observed_runtime != runtime
                or Path(str(runtime.get("root", ""))).resolve()
                != self.plugin_manifest_path.parent.parent
            ):
                _issue(
                    issues,
                    "post_spawn_failure:runtime_report_mismatch",
                )

        activation_payload = state.get("activation")
        identity = (
            activation_payload.get("identity")
            if isinstance(activation_payload, Mapping)
            and isinstance(activation_payload.get("identity"), Mapping)
            else {}
        )
        target = (
            envelope.get("target")
            if isinstance(envelope, Mapping)
            and isinstance(envelope.get("target"), Mapping)
            else {}
        )
        envelope_authority = (
            envelope.get("authority")
            if isinstance(envelope, Mapping)
            and isinstance(envelope.get("authority"), Mapping)
            else {}
        )
        limits = (
            envelope.get("limits")
            if isinstance(envelope, Mapping)
            and isinstance(envelope.get("limits"), Mapping)
            else {}
        )
        if (
            not isinstance(envelope, Mapping)
            or envelope.get("schema")
            != "issue163/cycle31-owner-bound-attempt/v1"
            or envelope_authority.get("status") != "AUTHORIZED"
            or envelope_authority.get("continuing_authority_after_failure")
            is not False
            or envelope_authority.get("ordinary_root_native_attempts") != 0
            or limits.get("fallbacks") != 0
            or limits.get("replacements") != 0
            or limits.get("retries") != 0
            or limits.get("owner_bound_attempts") != 1
            or limits.get("root_tasks") != 1
            or limits.get("root_turns") != 1
            or limits.get("worker_lanes") != 2
            or target.get("generation")
            != identity.get("installed_plugin_version")
            or target.get("runtime_package_digest")
            != runtime.get("package_digest")
            or not re.fullmatch(
                r"[0-9a-f]{40}",
                str(target.get("candidate_commit", "")),
            )
            or Path(str(target.get("installed_root", ""))).resolve()
            != Path(str(runtime.get("root", ""))).resolve()
        ):
            _issue(issues, "post_spawn_failure:attempt_envelope_invalid")

        boundary = (
            dedicated.get("pre_turn_boundary")
            if isinstance(dedicated, Mapping)
            else None
        )
        if (
            not isinstance(dedicated, Mapping)
            or dedicated.get("schema")
            != "issue163/cycle31-dedicated-app-server-run/v2"
            or dedicated.get("status") != "FAILED"
            or dedicated.get("issues") != []
            or dedicated.get("server_returncode") != -9
            or dedicated.get("server_output_exhausted") is not False
            or dedicated.get("existing_server_restarted") is not False
            or dedicated.get("owned_process_group_cleaned") is not True
            or dedicated.get("owner_socket_injected") is not True
            or dedicated.get("pre_turn_successor_prepared") is not True
            or dedicated.get("pre_turn_hooks_enabled") is not True
            or dedicated.get("pre_turn_hook_count") != 5
            or dedicated.get("pre_turn_controller_id") != controller_id
            or dedicated.get("pre_turn_decision")
            != "READY_FOR_SESSION_START"
            or dedicated.get("task_id") != identity.get("root_thread_id")
            or not _IDENTIFIER.fullmatch(str(dedicated.get("turn_id", "")))
            or dedicated.get("turn_started_after_pre_turn") is not True
            or dedicated.get("turn_status") is not None
            or boundary
            != {
                "live_boundary_crossed": True,
                "native_action_authorized": False,
                "next_owner_action": "turn/start",
                "required_hook_event": "SessionStart",
                "turn_started": False,
                "worker_created": False,
            }
        ):
            _issue(issues, "post_spawn_failure:dedicated_run_invalid")

        pre_turn_core = (
            {
                key: deepcopy(value)
                for key, value in pre_turn.items()
                if key != "report_sha256"
            }
            if isinstance(pre_turn, Mapping)
            else {}
        )
        pre_turn_controller = (
            pre_turn.get("controller")
            if isinstance(pre_turn, Mapping)
            and isinstance(pre_turn.get("controller"), Mapping)
            else {}
        )
        preactivation = (
            pre_turn.get("preactivation_report")
            if isinstance(pre_turn, Mapping)
            and isinstance(pre_turn.get("preactivation_report"), Mapping)
            else {}
        )
        if (
            not isinstance(pre_turn, Mapping)
            or pre_turn.get("schema")
            != "orch-dork/qualification-successor-pre-turn/v5"
            or pre_turn.get("status") != "PASS"
            or pre_turn.get("decision") != "READY_FOR_SESSION_START"
            or pre_turn.get("report_sha256") != _sha(pre_turn_core)
            or pre_turn.get("report_sha256")
            != dedicated.get("pre_turn_report_sha256")
            or pre_turn_controller.get("controller_id") != controller_id
            or pre_turn_controller.get("root_thread_id")
            != identity.get("root_thread_id")
            or pre_turn_controller.get("root_session_id")
            != identity.get("root_session_id")
            or pre_turn_controller.get("root_model")
            != identity.get("root_model")
            or pre_turn.get("boundary") != boundary
            or preactivation.get("source_root")
            != str(self.source_roots.get("source", ""))
        ):
            _issue(issues, "post_spawn_failure:pre_turn_invalid")

        expected_workers = {
            row["lane_id"]: row["agent_id"] for row in spawn_lanes
        }

        def reread_rollout(summary: Any) -> dict[str, Any] | None:
            if not isinstance(summary, Mapping):
                _issue(issues, "post_spawn_failure:rollout_invalid")
                return None
            artifact = summary.get("artifact")
            if (
                set(summary)
                != {
                    "role",
                    "logical_lane_id",
                    "session_id",
                    "parent_thread_id",
                    "spawn_parent_thread_id",
                    "candidate_commit",
                    "model",
                    "effort",
                    "task_complete_count",
                    "terminal_error_present",
                    "turn_ids",
                    "artifact",
                    "summary_sha256",
                }
                or not isinstance(artifact, Mapping)
                or set(artifact)
                != {"path", "artifact_sha256", "size_bytes"}
            ):
                _issue(issues, "post_spawn_failure:rollout_invalid")
                return None
            try:
                path, observed = _post_spawn_rollout_summary(
                    str(artifact.get("path", "")),
                    expected_sha256=str(
                        artifact.get("artifact_sha256", "")
                    ),
                    role=str(summary.get("role", "")),
                    logical_lane_id=summary.get("logical_lane_id"),
                )
            except ValueError:
                _issue(issues, "post_spawn_failure:rollout_invalid")
                return None
            if (
                path.parent != resolved_evidence_root
                or observed != summary
                or artifact.get("size_bytes") != path.stat().st_size
            ):
                _issue(issues, "post_spawn_failure:rollout_mismatch")
                return None
            return observed

        root_rollout = reread_rollout(evidence.get("root_rollout"))
        worker_rollouts = evidence.get("worker_rollouts")
        observed_workers: dict[str, Mapping[str, Any]] = {}
        if isinstance(worker_rollouts, list):
            for summary in worker_rollouts:
                observed = reread_rollout(summary)
                if isinstance(observed, Mapping):
                    lane_id = observed.get("logical_lane_id")
                    if isinstance(lane_id, str) and lane_id not in observed_workers:
                        observed_workers[lane_id] = observed
                    else:
                        _issue(
                            issues,
                            "post_spawn_failure:worker_rollout_ambiguous",
                        )
        else:
            _issue(issues, "post_spawn_failure:worker_rollouts_invalid")

        candidate_commit = target.get("candidate_commit")
        if (
            not isinstance(root_rollout, Mapping)
            or root_rollout.get("role") != "root"
            or root_rollout.get("logical_lane_id") is not None
            or root_rollout.get("session_id")
            != identity.get("root_session_id")
            or root_rollout.get("parent_thread_id") is not None
            or root_rollout.get("candidate_commit") != candidate_commit
            or dedicated.get("turn_id") not in root_rollout.get("turn_ids", [])
            or root_rollout.get("task_complete_count") != 0
        ):
            _issue(issues, "post_spawn_failure:root_rollout_invalid")
        if set(observed_workers) != set(expected_workers):
            _issue(issues, "post_spawn_failure:worker_rollouts_invalid")
        else:
            expected_terminal_shapes = {
                spawn_lanes[0]["lane_id"]: {
                    "task_complete_count": 0,
                    "terminal_error_present": False,
                },
                spawn_lanes[1]["lane_id"]: {
                    "task_complete_count": 1,
                    "terminal_error_present": True,
                },
            }
            for lane_id, worker_id in expected_workers.items():
                observed = observed_workers[lane_id]
                terminal_shape = expected_terminal_shapes.get(lane_id)
                if (
                    observed.get("role") != "worker"
                    or observed.get("session_id") != worker_id
                    or observed.get("parent_thread_id")
                    != identity.get("root_thread_id")
                    or observed.get("spawn_parent_thread_id")
                    != identity.get("root_thread_id")
                    or observed.get("candidate_commit") != candidate_commit
                    or observed.get("model") != "qwen-local/qwen-smart"
                    or observed.get("effort") != "xhigh"
                    or not isinstance(terminal_shape, Mapping)
                    or observed.get("task_complete_count")
                    != terminal_shape["task_complete_count"]
                    or observed.get("terminal_error_present")
                    is not terminal_shape["terminal_error_present"]
                    or not isinstance(observed.get("turn_ids"), list)
                    or len(observed["turn_ids"]) != 1
                ):
                    _issue(
                        issues,
                        "post_spawn_failure:worker_rollout_invalid",
                    )
                    break

        expected_capacity_lanes = sorted(
            str(identity.get("run_id")) + ":" + row["lane_id"]
            for row in spawn_lanes
        )
        active = (
            capacity.get("state", {}).get("active_lane_ids")
            if isinstance(capacity, Mapping)
            and isinstance(capacity.get("state"), Mapping)
            else None
        )
        if active != expected_capacity_lanes:
            _issue(issues, "post_spawn_failure:capacity_binding_mismatch")
        return sorted(issues)

    def _post_ack_bridge_failure_evidence_issues(
        self,
        evidence: Any,
        *,
        controller_id: str,
        state: Mapping[str, Any],
        capacity: Mapping[str, Any],
        spawn_lanes: list[dict[str, str]],
    ) -> list[str]:
        """Validate one closed-profile ACK-only bridge failure."""

        issues: list[str] = []
        fields = {
            "schema",
            "evidence_root",
            "dedicated_run_artifact",
            "dedicated_run",
            "attempt_envelope_artifact",
            "attempt_envelope",
            "pre_turn_artifact",
            "pre_turn_report",
            "root_rollout",
            "worker_rollouts",
            "historical_runtime_report",
            "evidence_sha256",
        }
        evidence_schema = (
            evidence.get("schema") if isinstance(evidence, Mapping) else None
        )
        if evidence_schema == POST_ACK_BRIDGE_FAILURE_EVIDENCE_SCHEMA_V2:
            fields.update(
                {"pretool_denial_artifact", "pretool_denial"}
            )
        if not isinstance(evidence, Mapping) or set(evidence) != fields:
            return ["post_ack_bridge_failure:evidence_shape_invalid"]
        core = {
            key: deepcopy(value)
            for key, value in evidence.items()
            if key != "evidence_sha256"
        }
        if (
            evidence_schema
            not in {
                POST_ACK_BRIDGE_FAILURE_EVIDENCE_SCHEMA,
                POST_ACK_BRIDGE_FAILURE_EVIDENCE_SCHEMA_V2,
            }
            or evidence.get("evidence_sha256") != _sha(core)
        ):
            return ["post_ack_bridge_failure:evidence_seal_invalid"]

        evidence_root = Path(str(evidence.get("evidence_root", "")))
        try:
            resolved_root = evidence_root.resolve(strict=True)
            root_info = resolved_root.lstat()
        except OSError:
            resolved_root = Path("/")
            root_info = None
        if (
            not evidence_root.is_absolute()
            or evidence_root.is_symlink()
            or root_info is None
            or not stat.S_ISDIR(root_info.st_mode)
            or (hasattr(os, "getuid") and root_info.st_uid != os.getuid())
            or stat.S_IMODE(root_info.st_mode) & 0o022
        ):
            _issue(issues, "post_ack_bridge_failure:evidence_root_invalid")

        def reread_json(
            reference: Any, expected: Any, label: str
        ) -> dict[str, Any] | None:
            if (
                not isinstance(reference, Mapping)
                or set(reference)
                != {"path", "artifact_sha256", "size_bytes"}
                or type(reference.get("size_bytes")) is not int
                or reference.get("size_bytes", 0) < 1
            ):
                _issue(issues, label + ":reference_invalid")
                return None
            try:
                path, observed, size = _read_post_spawn_json_artifact(
                    str(reference.get("path", "")),
                    expected_sha256=str(reference.get("artifact_sha256", "")),
                    label=label,
                )
            except ValueError:
                _issue(issues, label + ":reference_invalid")
                return None
            if (
                path.parent != resolved_root
                or size != reference.get("size_bytes")
                or observed != expected
            ):
                _issue(issues, label + ":artifact_mismatch")
                return None
            return observed

        dedicated = evidence.get("dedicated_run")
        envelope = evidence.get("attempt_envelope")
        pre_turn = evidence.get("pre_turn_report")
        validated_dedicated = reread_json(
            evidence.get("dedicated_run_artifact"),
            dedicated,
            "post_ack_bridge_failure:dedicated_run",
        )
        validated_envelope = reread_json(
            evidence.get("attempt_envelope_artifact"),
            envelope,
            "post_ack_bridge_failure:attempt_envelope",
        )
        reread_json(
            evidence.get("pre_turn_artifact"),
            pre_turn,
            "post_ack_bridge_failure:pre_turn",
        )
        pretool_denial = evidence.get("pretool_denial")
        validated_pretool_denial = (
            reread_json(
                evidence.get("pretool_denial_artifact"),
                pretool_denial,
                "post_ack_bridge_failure:pretool_denial",
            )
            if evidence_schema == POST_ACK_BRIDGE_FAILURE_EVIDENCE_SCHEMA_V2
            else None
        )
        profile = (
            _POST_ACK_BRIDGE_FAILURE_PROFILES.get(
                (
                    str(validated_envelope.get("schema", "")),
                    str(validated_dedicated.get("schema", "")),
                )
            )
            if isinstance(validated_envelope, Mapping)
            and isinstance(validated_dedicated, Mapping)
            else None
        )
        if (
            profile is not None
            and (
                profile.get("state_shape")
                == "pending_continuation_denied"
            )
            != (
                evidence_schema
                == POST_ACK_BRIDGE_FAILURE_EVIDENCE_SCHEMA_V2
            )
        ):
            _issue(issues, "post_ack_bridge_failure:evidence_profile_invalid")

        runtime = evidence.get("historical_runtime_report")
        runtime_core = (
            {
                key: deepcopy(value)
                for key, value in runtime.items()
                if key != "report_sha256"
            }
            if isinstance(runtime, Mapping)
            else {}
        )
        if (
            not isinstance(runtime, Mapping)
            or runtime.get("schema")
            != PRE_NATIVE_FAILURE_RUNTIME_REPORT_SCHEMA
            or runtime.get("report_sha256") != _sha(runtime_core)
        ):
            _issue(issues, "post_ack_bridge_failure:runtime_report_invalid")
        else:
            try:
                observed_runtime = _pre_native_failure_runtime_report(
                    str(runtime.get("root", "")),
                    expected_package_digest=str(
                        runtime.get("package_digest", "")
                    ),
                )
            except ValueError:
                observed_runtime = None
            if (
                observed_runtime != runtime
                or Path(str(runtime.get("root", ""))).resolve()
                != self.plugin_manifest_path.parent.parent
            ):
                _issue(
                    issues,
                    "post_ack_bridge_failure:runtime_report_mismatch",
                )

        activation_payload = state.get("activation")
        identity = (
            activation_payload.get("identity")
            if isinstance(activation_payload, Mapping)
            and isinstance(activation_payload.get("identity"), Mapping)
            else {}
        )
        target = (
            envelope.get("target")
            if isinstance(envelope, Mapping)
            and isinstance(envelope.get("target"), Mapping)
            else {}
        )
        envelope_authority = (
            envelope.get("authority")
            if isinstance(envelope, Mapping)
            and isinstance(envelope.get("authority"), Mapping)
            else {}
        )
        limits = (
            envelope.get("limits")
            if isinstance(envelope, Mapping)
            and isinstance(envelope.get("limits"), Mapping)
            else {}
        )
        if (
            not isinstance(envelope, Mapping)
            or profile is None
            or envelope_authority.get("status") != "AUTHORIZED"
            or envelope_authority.get("continuing_authority_after_failure")
            is not False
            or envelope_authority.get("ordinary_root_native_attempts") != 0
            or limits.get("fallbacks") != 0
            or limits.get("replacements") != 0
            or limits.get("retries") != 0
            or limits.get("owner_bound_attempts") != 1
            or limits.get("root_tasks") != 1
            or limits.get("root_turns") != 1
            or limits.get("worker_lanes") != 2
            or target.get("generation")
            != identity.get("installed_plugin_version")
            or target.get("runtime_package_digest")
            != runtime.get("package_digest")
            or not re.fullmatch(
                r"[0-9a-f]{40}", str(target.get("candidate_commit", ""))
            )
            or Path(str(target.get("installed_root", ""))).resolve()
            != Path(str(runtime.get("root", ""))).resolve()
        ):
            _issue(issues, "post_ack_bridge_failure:attempt_envelope_invalid")

        boundary = (
            dedicated.get("pre_turn_boundary")
            if isinstance(dedicated, Mapping)
            else None
        )
        dedicated_hash_fields = (
            "expected_app_server_argv_sha256",
            "host_preparation_report_sha256",
            "pre_turn_hook_inventory_report_sha256",
        )
        if (
            not isinstance(dedicated, Mapping)
            or profile is None
            or dedicated.get("status") != "FAILED"
            or dedicated.get("issues")
            != ["RuntimeError:app_server_proxy_closed"]
            or dedicated.get("server_returncode") != -9
            or dedicated.get("server_output_exhausted") is not False
            or dedicated.get("existing_server_restarted") is not False
            or dedicated.get("owned_process_group_cleaned") is not True
            or dedicated.get("owner_socket_injected") is not True
            or dedicated.get("pre_turn_successor_prepared") is not True
            or dedicated.get("pre_turn_hooks_enabled") is not True
            or dedicated.get("pre_turn_hook_count") != 5
            or any(
                _DIGEST.fullmatch(str(dedicated.get(field, ""))) is None
                for field in dedicated_hash_fields
            )
            or dedicated.get("pre_turn_controller_id") != controller_id
            or dedicated.get("pre_turn_decision")
            != "READY_FOR_SESSION_START"
            or dedicated.get("task_id") != identity.get("root_thread_id")
            or not _IDENTIFIER.fullmatch(str(dedicated.get("turn_id", "")))
            or dedicated.get("turn_started_after_pre_turn") is not True
            or dedicated.get("turn_status") is not None
            or boundary
            != {
                "live_boundary_crossed": True,
                "native_action_authorized": False,
                "next_owner_action": "turn/start",
                "required_hook_event": "SessionStart",
                "turn_started": False,
                "worker_created": False,
            }
        ):
            _issue(issues, "post_ack_bridge_failure:dedicated_run_invalid")
        else:
            try:
                referenced_pre_turn, referenced_value, _size = (
                    _read_post_spawn_json_artifact(
                        str(dedicated.get("pre_turn_report_path", "")),
                        expected_sha256=str(
                            evidence.get("pre_turn_artifact", {}).get(
                                "artifact_sha256", ""
                            )
                        ),
                        label="post_ack_bridge_failure:dedicated_pre_turn",
                    )
                )
            except ValueError:
                referenced_pre_turn = None
                referenced_value = None
            if (
                referenced_value != pre_turn
                or referenced_pre_turn is None
                or referenced_pre_turn.parent
                != Path(str(dedicated.get("pre_turn_evidence_root", ""))).resolve()
            ):
                _issue(
                    issues,
                    "post_ack_bridge_failure:dedicated_pre_turn_invalid",
                )

        pre_turn_core = (
            {
                key: deepcopy(value)
                for key, value in pre_turn.items()
                if key != "report_sha256"
            }
            if isinstance(pre_turn, Mapping)
            else {}
        )
        pre_turn_controller = (
            pre_turn.get("controller")
            if isinstance(pre_turn, Mapping)
            and isinstance(pre_turn.get("controller"), Mapping)
            else {}
        )
        preactivation = (
            pre_turn.get("preactivation_report")
            if isinstance(pre_turn, Mapping)
            and isinstance(pre_turn.get("preactivation_report"), Mapping)
            else {}
        )
        if (
            not isinstance(pre_turn, Mapping)
            or pre_turn.get("schema")
            != "orch-dork/qualification-successor-pre-turn/v5"
            or pre_turn.get("status") != "PASS"
            or pre_turn.get("decision") != "READY_FOR_SESSION_START"
            or pre_turn.get("report_sha256") != _sha(pre_turn_core)
            or pre_turn.get("report_sha256")
            != dedicated.get("pre_turn_report_sha256")
            or pre_turn_controller.get("controller_id") != controller_id
            or pre_turn_controller.get("root_thread_id")
            != identity.get("root_thread_id")
            or pre_turn_controller.get("root_session_id")
            != identity.get("root_session_id")
            or pre_turn_controller.get("root_model")
            != identity.get("root_model")
            or pre_turn.get("boundary") != boundary
            or preactivation.get("source_root")
            != str(self.source_roots.get("source", ""))
        ):
            _issue(issues, "post_ack_bridge_failure:pre_turn_invalid")

        def reread_root(summary: Any) -> dict[str, Any] | None:
            if not isinstance(summary, Mapping):
                _issue(issues, "post_ack_bridge_failure:root_rollout_invalid")
                return None
            artifact = summary.get("artifact")
            if not isinstance(artifact, Mapping):
                _issue(issues, "post_ack_bridge_failure:root_rollout_invalid")
                return None
            try:
                path, observed = _post_ack_bridge_root_rollout_summary(
                    str(artifact.get("path", "")),
                    expected_sha256=str(artifact.get("artifact_sha256", "")),
                )
            except ValueError:
                _issue(issues, "post_ack_bridge_failure:root_rollout_invalid")
                return None
            if (
                path.parent != resolved_root
                or observed != summary
                or artifact.get("size_bytes") != path.stat().st_size
            ):
                _issue(issues, "post_ack_bridge_failure:root_rollout_mismatch")
                return None
            return observed

        def reread_worker(summary: Any) -> dict[str, Any] | None:
            if not isinstance(summary, Mapping):
                _issue(issues, "post_ack_bridge_failure:worker_rollout_invalid")
                return None
            artifact = summary.get("artifact")
            lane_id = summary.get("logical_lane_id")
            if not isinstance(artifact, Mapping) or not isinstance(lane_id, str):
                _issue(issues, "post_ack_bridge_failure:worker_rollout_invalid")
                return None
            try:
                path, observed = _post_ack_bridge_worker_rollout_summary(
                    str(artifact.get("path", "")),
                    expected_sha256=str(artifact.get("artifact_sha256", "")),
                    logical_lane_id=lane_id,
                    observer_id=str(identity.get("root_thread_id", "")),
                )
            except ValueError:
                _issue(issues, "post_ack_bridge_failure:worker_rollout_invalid")
                return None
            if (
                path.parent != resolved_root
                or observed != summary
                or artifact.get("size_bytes") != path.stat().st_size
            ):
                _issue(issues, "post_ack_bridge_failure:worker_rollout_mismatch")
                return None
            return observed

        root_rollout = reread_root(evidence.get("root_rollout"))
        worker_values = evidence.get("worker_rollouts")
        observed_workers: dict[str, Mapping[str, Any]] = {}
        if isinstance(worker_values, list):
            for summary in worker_values:
                observed = reread_worker(summary)
                lane_id = (
                    observed.get("logical_lane_id")
                    if isinstance(observed, Mapping)
                    else None
                )
                if isinstance(lane_id, str) and lane_id not in observed_workers:
                    observed_workers[lane_id] = observed
                elif observed is not None:
                    _issue(
                        issues,
                        "post_ack_bridge_failure:worker_rollout_ambiguous",
                    )
        else:
            _issue(issues, "post_ack_bridge_failure:worker_rollouts_invalid")

        expected_workers = {
            row["lane_id"]: row["agent_id"] for row in spawn_lanes
        }
        candidate_commit = target.get("candidate_commit")
        action = state.get("action")
        grant = state.get("grant")
        refusal = (
            root_rollout.get("bridge_refusal")
            if isinstance(root_rollout, Mapping)
            and isinstance(root_rollout.get("bridge_refusal"), Mapping)
            else None
        )
        refusal_core = {
            key: deepcopy(value)
            for key, value in (refusal or {}).items()
            if key != "report_sha256"
        }
        denied_send_input = (
            root_rollout.get("denied_send_input")
            if isinstance(root_rollout, Mapping)
            and isinstance(root_rollout.get("denied_send_input"), Mapping)
            else None
        )
        root_invalid = bool(
            not isinstance(root_rollout, Mapping)
            or root_rollout.get("role") != "root"
            or root_rollout.get("logical_lane_id") is not None
            or root_rollout.get("session_id")
            != identity.get("root_session_id")
            or root_rollout.get("parent_thread_id") is not None
            or root_rollout.get("candidate_commit") != candidate_commit
            or root_rollout.get("model") != identity.get("root_model")
            or root_rollout.get("effort") != identity.get("root_effort")
            or dedicated.get("turn_id") not in root_rollout.get("turn_ids", [])
            or root_rollout.get("task_complete_count") != 0
            or root_rollout.get("terminal_error_present") is not False
            or root_rollout.get("spawn_worker_ids")
            != [row["agent_id"] for row in spawn_lanes]
            or root_rollout.get("send_input_call_count")
            != (profile or {}).get("send_input_call_count")
            or root_rollout.get("stop_denial_count")
            != (profile or {}).get("stop_denial_count")
            or root_rollout.get("bridge_refusal_invocation_count")
            != (profile or {}).get("bridge_refusal_invocation_count")
            or root_rollout.get("blocked_bridge_invocation_count")
            != (profile or {}).get("blocked_bridge_invocation_count")
        )
        refusal_fields = {
            "schema",
            "status",
            "decision",
            "issues",
            "provider_free",
            "model_calls",
            "hosted_calls",
            "native_actions",
            "task_creations",
            "worker_creations",
            "authority_grants_minted",
            "report_sha256",
        }
        if (profile or {}).get("bridge_refusal_code") is not None:
            root_invalid = bool(
                root_invalid
                or not isinstance(refusal, Mapping)
                or root_rollout.get("bridge_refusals") != [refusal]
                or set(refusal) != refusal_fields
                or refusal.get("schema")
                != "orch-dork/qualification-successor-action-advance/v2"
                or refusal.get("status") != "BLOCKED"
                or refusal.get("decision") != "REFUSED"
                or refusal.get("issues")
                != [(profile or {}).get("bridge_refusal_code")]
                or refusal.get("provider_free") is not True
                or any(
                    refusal.get(field) != 0
                    for field in (
                        "model_calls",
                        "hosted_calls",
                        "native_actions",
                        "task_creations",
                        "worker_creations",
                        "authority_grants_minted",
                    )
                )
                or refusal.get("report_sha256") != _sha(refusal_core)
                or denied_send_input is not None
            )
        else:
            root_invalid = bool(
                root_invalid
                or refusal is not None
                or root_rollout.get("bridge_refusals") != []
                or not isinstance(denied_send_input, Mapping)
                or set(denied_send_input)
                != {
                    "call_id",
                    "namespace",
                    "tool_input_sha256",
                    "hook_tool_name",
                }
                or denied_send_input.get("namespace") != "multi_agent_v1"
                or denied_send_input.get("hook_tool_name")
                != (profile or {}).get("denied_hook_tool_name")
                or not isinstance(action, Mapping)
                or action.get("kind") != "continue"
                or denied_send_input.get("tool_input_sha256")
                != action.get("tool_input_sha256")
            )
        if root_invalid:
            _issue(issues, "post_ack_bridge_failure:root_rollout_invalid")

        if (profile or {}).get("state_shape") == "pending_continuation_denied":
            durable = validated_pretool_denial
            durable_core = (
                {
                    key: deepcopy(value)
                    for key, value in durable.items()
                    if key != "durable_record_sha256"
                }
                if isinstance(durable, Mapping)
                else {}
            )
            durable_identity = (
                durable.get("identity")
                if isinstance(durable, Mapping)
                and isinstance(durable.get("identity"), Mapping)
                else {}
            )
            durable_native = (
                durable.get("native_controller")
                if isinstance(durable, Mapping)
                and isinstance(durable.get("native_controller"), Mapping)
                else {}
            )
            ground_program = (
                activation_payload.get("project_ground_state", {}).get(
                    "program", {}
                )
                if isinstance(activation_payload, Mapping)
                and isinstance(
                    activation_payload.get("project_ground_state"), Mapping
                )
                else {}
            )
            ground_state = (
                ground_program.get("state", {})
                if isinstance(ground_program, Mapping)
                and isinstance(ground_program.get("state"), Mapping)
                else {}
            )
            prerequisites = (
                ground_state.get("prerequisites", {})
                if isinstance(ground_state, Mapping)
                and isinstance(ground_state.get("prerequisites"), Mapping)
                else {}
            )
            enrollment = prerequisites.get("enrollment", {})
            ticket = prerequisites.get("ticket_admission", {})
            lease = prerequisites.get("lease", {})
            ground_authority = prerequisites.get("authority", {})
            expected_durable_identity = {
                "project_id": enrollment.get("project_id"),
                "generation": enrollment.get("generation"),
                "ticket_id": ticket.get("ticket_id"),
                "admission_sha256": ticket.get("admission_sha256"),
                "plan_sha256": ticket.get("plan_sha256"),
                "lease_version": lease.get("version"),
                "lease_owner_thread_id": lease.get("owner_thread_id"),
                "current_thread_id": lease.get("current_thread_id"),
                "session_id": identity.get("root_session_id"),
                "authority_scope_sha256": ground_authority.get(
                    "scope_sha256"
                ),
                "workspace_baseline_sha256": prerequisites.get(
                    "workspace", {}
                ).get("baseline_sha256"),
                "writable_scope_sha256": ground_authority.get(
                    "writable_scope_sha256"
                ),
                "adapter_snapshot_sha256": prerequisites.get(
                    "adapter", {}
                ).get("snapshot_sha256"),
                "active_controller_sha256": prerequisites.get(
                    "active_controller", {}
                ).get("report_sha256"),
                "capsule_sha256": prerequisites.get("capsule", {}).get(
                    "capsule_sha256"
                ),
                "execution_readiness_sha256": prerequisites.get(
                    "execution_readiness", {}
                ).get("report_sha256"),
            }
            denial_invalid = bool(
                not isinstance(durable, Mapping)
                or set(durable) != DURABLE_HOOK_EVENT_FIELDS
                or durable.get("schema") != DURABLE_HOOK_EVENT_SCHEMA
                or durable.get("report_schema")
                != ground_enforcement.REPORT_SCHEMA
                or durable.get("durable_record_sha256") != _sha(durable_core)
                or _DIGEST.fullmatch(str(durable.get("report_sha256", "")))
                is None
                or durable.get("hook_event_name") != "PreToolUse"
                or durable.get("status") != "BLOCKED"
                or durable.get("decision") != "DENY"
                or durable.get("coverage_class") != "local_function"
                or durable.get("mutating") is not True
                or durable.get("completion_invalidated") is not False
                or durable.get("reason_codes")
                != ["native_controller:exact_action_required"]
                or _DIGEST.fullmatch(str(durable.get("state_sha256", "")))
                is None
                or not isinstance(action, Mapping)
                or not isinstance(grant, Mapping)
                or durable.get("tool_input_sha256")
                != action.get("tool_input_sha256")
                or set(durable_identity) != DURABLE_HOOK_IDENTITY_FIELDS
                or any(
                    durable_identity.get(field) != expected
                    for field, expected in expected_durable_identity.items()
                )
                or durable_identity.get("turn_id") != dedicated.get("turn_id")
                or set(durable_native)
                != {
                    "present",
                    "controller_id",
                    "controller_seq",
                    "status",
                    "action_id",
                    "matched",
                    "grant_state",
                }
                or durable_native.get("present") is not True
                or durable_native.get("controller_id") != controller_id
                or durable_native.get("controller_seq")
                != grant.get("controller_seq")
                or durable_native.get("status") != "ACTIVE"
                or durable_native.get("action_id") != action.get("action_id")
                or durable_native.get("matched") is not False
                or durable_native.get("grant_state") is not None
            )
            durable_report_sha256 = (
                durable.get("report_sha256")
                if isinstance(durable, Mapping)
                else ""
            )
            event_path = (
                self.plugin_data
                / "project-ground"
                / "events"
                / hashlib.sha256(
                    str(identity.get("root_session_id", "")).encode("utf-8")
                ).hexdigest()
                / (str(durable_report_sha256) + ".json")
            )
            try:
                persisted_durable = owned_file.read_owned_json(
                    event_path,
                    max_bytes=MAX_DURABLE_FILE_BYTES,
                    required_mode=0o600,
                )
            except (OSError, ValueError, json.JSONDecodeError):
                persisted_durable = None
            if persisted_durable != durable:
                denial_invalid = True
            if denial_invalid:
                _issue(
                    issues,
                    "post_ack_bridge_failure:pretool_denial_invalid",
                )

        stage_report_value = state.get("stage_report")
        stage_receipt = (
            stage_report_value.get("receipt")
            if isinstance(stage_report_value, Mapping)
            and isinstance(stage_report_value.get("receipt"), Mapping)
            else {}
        )
        stage_bindings = (
            stage_receipt.get("bindings")
            if isinstance(stage_receipt.get("bindings"), Mapping)
            else {}
        )
        task_specs = stage_bindings.get("task_specs")
        specs = {
            str(row.get("logical_worker_id")): row
            for row in task_specs or []
            if isinstance(row, Mapping)
        }
        if set(observed_workers) != set(expected_workers) or set(specs) != set(
            expected_workers
        ):
            _issue(issues, "post_ack_bridge_failure:worker_rollouts_invalid")
        else:
            for lane_id, worker_id in expected_workers.items():
                observed = observed_workers[lane_id]
                observation = observed.get("runtime_observation")
                validation = routing_verify.validate_session_runtime_observation(
                    observation
                )
                route = (
                    observation.get("route")
                    if isinstance(observation, Mapping)
                    and isinstance(observation.get("route"), Mapping)
                    else {}
                )
                usage = (
                    observation.get("usage")
                    if isinstance(observation, Mapping)
                    and isinstance(observation.get("usage"), Mapping)
                    else {}
                )
                expected_receipt = route_policy.task_spec_pre_work_receipt(
                    logical_lane_id=lane_id,
                    task_spec_sha256=str(specs[lane_id].get("task_spec_sha256")),
                )
                if (
                    observed.get("role") != "worker"
                    or observed.get("session_id") != worker_id
                    or observed.get("parent_thread_id")
                    != identity.get("root_thread_id")
                    or observed.get("spawn_parent_thread_id")
                    != identity.get("root_thread_id")
                    or observed.get("candidate_commit") != candidate_commit
                    or observed.get("model") != specs[lane_id].get("model")
                    or observed.get("effort") != specs[lane_id].get("effort")
                    or observed.get("task_complete_count") != 1
                    or observed.get("terminal_error_present") is not False
                    or not isinstance(observed.get("turn_ids"), list)
                    or len(observed["turn_ids"]) != 1
                    or validation.get("valid") is not True
                    or route.get("session_id") != worker_id
                    or route.get("model") != specs[lane_id].get("model")
                    or route.get("effort") != specs[lane_id].get("effort")
                    or route.get("context_policy") != "none"
                    or route.get("inherited_history") is not False
                    or observation.get("terminal_schema")
                    != route_policy.TASK_SPEC_PRE_WORK_RECEIPT_SCHEMA
                    or observation.get("terminal_json_sha256")
                    != _sha(expected_receipt)
                    or usage.get("status") != "observed"
                    or usage.get("tool_calls") != 0
                ):
                    _issue(
                        issues,
                        "post_ack_bridge_failure:worker_rollout_invalid",
                    )
                    break

        expected_capacity_lanes = sorted(
            str(identity.get("run_id")) + ":" + row["lane_id"]
            for row in spawn_lanes
        )
        active = (
            capacity.get("state", {}).get("active_lane_ids")
            if isinstance(capacity, Mapping)
            and isinstance(capacity.get("state"), Mapping)
            else None
        )
        if active != expected_capacity_lanes:
            _issue(
                issues,
                "post_ack_bridge_failure:capacity_binding_mismatch",
            )
        return sorted(issues)

    def terminalize_pre_native_failure(self, program: Any) -> dict[str, Any]:
        """Close one proven abandoned turn before any native action existed."""

        top_fields = {
            "schema",
            "controller_id",
            "expected_cursor",
            "failure_evidence",
        }
        if not isinstance(program, Mapping) or set(program) != top_fields:
            return self._base_report(
                controller_id=(
                    program.get("controller_id")
                    if isinstance(program, Mapping)
                    else None
                ),
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=["pre_native_failure:program_shape_invalid"],
            )
        value = deepcopy(dict(program))
        controller_id = value.get("controller_id")
        if (
            value.get("schema")
            != PRE_NATIVE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA
            or not _IDENTIFIER.fullmatch(str(controller_id))
            or not _cursor_valid(value.get("expected_cursor"))
            or len(_canonical(value)) > MAX_PROGRAM_BYTES
        ):
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=["pre_native_failure:program_invalid"],
            )

        state: Mapping[str, Any] | None = None
        current: Mapping[str, Any] | None = None
        try:
            with self._locked():
                run_id = _controller_run_id(str(controller_id))
                if (
                    not self.grants.owner_matches(str(controller_id), run_id)
                    or not self.store.exists(run_id)
                    or not self.grants.custody_valid()
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["pre_native_failure:controller_not_active"],
                    )
                state, rows = self._state(run_id)
                current = _cursor(rows)
                cursor_issue = self._expected_cursor_issue(
                    value.get("expected_cursor"), current
                )
                if cursor_issue is not None:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[cursor_issue],
                        cursor=current,
                        state=state,
                    )
                activation = state.get("activation")
                identity = (
                    activation.get("identity")
                    if isinstance(activation, Mapping)
                    and isinstance(activation.get("identity"), Mapping)
                    else None
                )
                if not self._hook_runtime_matches(identity):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["pre_native_failure:historical_runtime_not_active"],
                        cursor=current,
                        state=state,
                    )
                stage_report = state.get("stage_report")
                pristine_waiting = bool(
                    isinstance(stage_report, Mapping)
                    and stage_report.get("operation") == "pre_spawn"
                    and stage_report.get("status") == "PASS"
                    and stage_report.get("disposition")
                    == "SHARED_CAPACITY_ADMISSION_REQUIRED"
                    and stage_report.get("issues") == []
                    and stage_report.get("next_action")
                    == "capacity_admission"
                    and state.get("terminal") is False
                    and state.get("pending_intent") is None
                    and state.get("action") is None
                    and state.get("action_outcome") is None
                    and state.get("cleanup_required") is False
                    and state.get("grant") is None
                    and state.get("grant_state") is None
                    and state.get("seen_action_ids") == []
                    and state.get("action_evidence") == []
                    and state.get("last_action_evidence") is None
                    and state.get("last_batch_result") is None
                )
                if not pristine_waiting:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "pre_native_failure:pristine_waiting_state_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                capacity = self.tower.read_shared_capacity_authority()
                capacity_state = (
                    capacity.get("state")
                    if isinstance(capacity, Mapping)
                    and isinstance(capacity.get("state"), Mapping)
                    else None
                )
                if (
                    not isinstance(capacity, Mapping)
                    or capacity.get("status") != "VERIFIED"
                    or capacity.get("continuity_verified") is not True
                    or capacity.get("reason_codes") != []
                    or not isinstance(capacity_state, Mapping)
                    or capacity.get("state_sha256")
                    != capacity_state.get("state_sha256")
                    or capacity_state.get("active_lane_ids") != []
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["pre_native_failure:zero_capacity_required"],
                        cursor=current,
                        state=state,
                    )
                authority = self.grants.canonical_authority()
                lifecycle = (
                    authority.get("lifecycle")
                    if isinstance(authority, Mapping)
                    and isinstance(authority.get("lifecycle"), Mapping)
                    else None
                )
                if (
                    authority.get("status") != "VERIFIED"
                    or authority.get("tip") != current
                    or not isinstance(lifecycle, Mapping)
                    or lifecycle
                    != {
                        "terminal": False,
                        "terminal_qualified": False,
                        "terminal_evidence_sha256": None,
                        "pending_intent": False,
                        "cleanup_required": False,
                        "action_sha256": None,
                        "grant_state": None,
                        "tool_use_id": None,
                        "expected_binding_status": "WAITING",
                    }
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["pre_native_failure:waiting_authority_required"],
                        cursor=current,
                        state=state,
                    )
                evidence_issues = self._pre_native_failure_evidence_issues(
                    value.get("failure_evidence"),
                    controller_id=str(controller_id),
                    authority=authority,
                    state=state,
                )
                if evidence_issues:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=evidence_issues,
                        cursor=current,
                        state=state,
                    )

                evidence = value["failure_evidence"]
                failure = evidence["failure_report"]
                runtime = evidence["historical_runtime_report"]
                evaluation_time = self._evaluation_time().isoformat()
                intent = {
                    "operation": "pre_native_failure_terminalization",
                    "failure_evidence_sha256": evidence["evidence_sha256"],
                    "evaluation_time": evaluation_time,
                    "proposed_action_sha256": None,
                }
                intent_cursor = self._append(run_id, "stage_intent", intent)
                closed_stage = {
                    "schema": PRE_NATIVE_FAILURE_STAGE_REPORT_SCHEMA,
                    "operation": "pre_native_failure_terminalization",
                    "status": "PASS",
                    "disposition": "PRE_NATIVE_FAILURE_TERMINALIZED",
                    "issues": [],
                    "receipt": {
                        "failure_evidence_sha256": evidence[
                            "evidence_sha256"
                        ],
                        "failure_artifact_sha256": evidence[
                            "failure_artifact"
                        ]["artifact_sha256"],
                        "predecessor_authority_artifact_sha256": evidence[
                            "predecessor_authority_artifact"
                        ]["artifact_sha256"],
                        "historical_runtime_report_sha256": runtime[
                            "report_sha256"
                        ],
                        "historical_package_digest": runtime[
                            "package_digest"
                        ],
                        "abandoned_turn_id": failure["turn_id"],
                        "abandoned_turn_status": failure["turn_status"],
                        "capacity_authority_state_sha256": capacity[
                            "state_sha256"
                        ],
                        "owner_process_group_cleaned": True,
                    },
                    "next_action": "terminal",
                }
                terminal_evidence_sha256 = _sha(closed_stage)
                result_cursor = self._append(
                    run_id,
                    "stage_result",
                    {
                        "intent_cursor": intent_cursor,
                        "stage_report": closed_stage,
                        "action": None,
                        "capacity_guard": None,
                        "terminal": True,
                        "cleanup_required": False,
                        "terminal_evidence_sha256": terminal_evidence_sha256,
                        "issues": [],
                    },
                )
                state, _rows = self._state(run_id)
                hook_sha = self._sync_hook(
                    controller_id=str(controller_id),
                    cursor=result_cursor,
                    state=state,
                )
                if (
                    not self.grants.custody_valid()
                    or not self._hook_runtime_matches(identity)
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["pre_native_failure:post_commit_custody_invalid"],
                        cursor=result_cursor,
                        state=state,
                        hook_state_sha256=hook_sha,
                    )
                return self._base_report(
                    controller_id=controller_id,
                    status="PASS",
                    decision="PRE_NATIVE_FAILURE_TERMINALIZED",
                    issues=[],
                    cursor=result_cursor,
                    state=state,
                    hook_state_sha256=hook_sha,
                )
        except Exception as error:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="CONTROLLER_REFUSED",
                issues=["pre_native_failure:" + type(error).__name__],
                cursor=current,
                state=state,
            )

    def terminalize_activation_only_failure(self, program: Any) -> dict[str, Any]:
        """Close one abandoned activation that never reached a pre-spawn stage."""

        top_fields = {
            "schema",
            "controller_id",
            "expected_cursor",
            "failure_evidence",
        }
        if not isinstance(program, Mapping) or set(program) != top_fields:
            return self._base_report(
                controller_id=(
                    program.get("controller_id")
                    if isinstance(program, Mapping)
                    else None
                ),
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=["activation_only_failure:program_shape_invalid"],
            )
        value = deepcopy(dict(program))
        controller_id = value.get("controller_id")
        if (
            value.get("schema")
            != ACTIVATION_ONLY_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA
            or not _IDENTIFIER.fullmatch(str(controller_id))
            or not _cursor_valid(value.get("expected_cursor"))
            or len(_canonical(value)) > MAX_PROGRAM_BYTES
        ):
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=["activation_only_failure:program_invalid"],
            )

        state: Mapping[str, Any] | None = None
        current: Mapping[str, Any] | None = None
        try:
            with self._locked():
                run_id = _controller_run_id(str(controller_id))
                if (
                    not self.grants.owner_matches(str(controller_id), run_id)
                    or not self.store.exists(run_id)
                    or not self.grants.custody_valid()
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["activation_only_failure:controller_not_active"],
                    )
                state, rows = self._state(run_id)
                current = _cursor(rows)
                cursor_issue = self._expected_cursor_issue(
                    value.get("expected_cursor"), current
                )
                if cursor_issue is not None:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[cursor_issue],
                        cursor=current,
                        state=state,
                    )
                activation = state.get("activation")
                identity = (
                    activation.get("identity")
                    if isinstance(activation, Mapping)
                    and isinstance(activation.get("identity"), Mapping)
                    else None
                )
                if not self._hook_runtime_matches(identity):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "activation_only_failure:historical_runtime_not_active"
                        ],
                        cursor=current,
                        state=state,
                    )
                pristine_activation = bool(
                    state.get("stage_report") is None
                    and current.get("seq") == 1
                    and len(_controller_events(rows)) == 1
                    and state.get("terminal") is False
                    and state.get("pending_intent") is None
                    and state.get("action") is None
                    and state.get("action_outcome") is None
                    and state.get("cleanup_required") is False
                    and state.get("grant") is None
                    and state.get("grant_state") is None
                    and state.get("seen_action_ids") == []
                    and state.get("action_evidence") == []
                    and state.get("last_action_evidence") is None
                    and state.get("last_batch_result") is None
                )
                if not pristine_activation:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "activation_only_failure:pristine_activation_state_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                inventory = self.grants.read_grant_inventory()
                if (
                    not isinstance(inventory, Mapping)
                    or inventory.get("status") != "VERIFIED"
                    or inventory.get("unsettled_grant_count") != 0
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["activation_only_failure:settled_grants_required"],
                        cursor=current,
                        state=state,
                    )
                capacity = self.tower.read_shared_capacity_authority()
                capacity_state = (
                    capacity.get("state")
                    if isinstance(capacity, Mapping)
                    and isinstance(capacity.get("state"), Mapping)
                    else None
                )
                if (
                    not isinstance(capacity, Mapping)
                    or capacity.get("status") != "VERIFIED"
                    or capacity.get("continuity_verified") is not True
                    or capacity.get("reason_codes") != []
                    or not isinstance(capacity_state, Mapping)
                    or capacity.get("state_sha256")
                    != capacity_state.get("state_sha256")
                    or capacity_state.get("active_lane_ids") != []
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["activation_only_failure:zero_capacity_required"],
                        cursor=current,
                        state=state,
                    )
                authority = self.grants.canonical_authority()
                lifecycle = (
                    authority.get("lifecycle")
                    if isinstance(authority, Mapping)
                    and isinstance(authority.get("lifecycle"), Mapping)
                    else None
                )
                if (
                    authority.get("status") != "VERIFIED"
                    or authority.get("tip") != current
                    or not isinstance(lifecycle, Mapping)
                    or lifecycle
                    != {
                        "terminal": False,
                        "terminal_qualified": False,
                        "terminal_evidence_sha256": None,
                        "pending_intent": False,
                        "cleanup_required": False,
                        "action_sha256": None,
                        "grant_state": None,
                        "tool_use_id": None,
                        "expected_binding_status": "WAITING",
                    }
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "activation_only_failure:waiting_authority_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                evidence_issues = self._activation_only_failure_evidence_issues(
                    value.get("failure_evidence"),
                    controller_id=str(controller_id),
                    authority=authority,
                    state=state,
                )
                if evidence_issues:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=evidence_issues,
                        cursor=current,
                        state=state,
                    )

                evidence = value["failure_evidence"]
                envelope = evidence["abandonment_receipt"]
                attested = envelope["payload"]
                runtime = evidence["historical_runtime_report"]
                evaluation_time = self._evaluation_time().isoformat()
                intent = {
                    "operation": "activation_only_failure_terminalization",
                    "failure_evidence_sha256": evidence["evidence_sha256"],
                    "evaluation_time": evaluation_time,
                    "proposed_action_sha256": None,
                }
                intent_cursor = self._append(run_id, "stage_intent", intent)
                closed_stage = {
                    "schema": ACTIVATION_ONLY_FAILURE_STAGE_REPORT_SCHEMA,
                    "operation": "activation_only_failure_terminalization",
                    "status": "PASS",
                    "disposition": "ACTIVATION_ONLY_FAILURE_TERMINALIZED",
                    "issues": [],
                    "receipt": {
                        "failure_evidence_sha256": evidence["evidence_sha256"],
                        "abandonment_receipt_artifact_sha256": evidence[
                            "abandonment_receipt_artifact"
                        ]["artifact_sha256"],
                        "abandonment_receipt_sha256": _sha(envelope),
                        "abandonment_signing_key_id": envelope["key_id"],
                        "abandonment_signing_host_id": envelope["host_id"],
                        "admitting_authority_report_sha256": evidence[
                            "hook_trust_verification_report"
                        ]["report_sha256"],
                        "historical_runtime_report_sha256": runtime[
                            "report_sha256"
                        ],
                        "historical_package_digest": runtime["package_digest"],
                        "abandoned_task_id": attested["root_thread_id"],
                        "abandoned_turn_id": attested["abandoned_turn_id"],
                        "abandoned_owner_process": deepcopy(
                            attested["owner_process"]
                        ),
                        "capacity_authority_state_sha256": capacity[
                            "state_sha256"
                        ],
                    },
                    "next_action": "terminal",
                }
                terminal_evidence_sha256 = _sha(closed_stage)
                result_cursor = self._append(
                    run_id,
                    "stage_result",
                    {
                        "intent_cursor": intent_cursor,
                        "stage_report": closed_stage,
                        "action": None,
                        "capacity_guard": None,
                        "terminal": True,
                        "cleanup_required": False,
                        "terminal_evidence_sha256": terminal_evidence_sha256,
                        "issues": [],
                    },
                )
                state, _rows = self._state(run_id)
                hook_sha = self._sync_hook(
                    controller_id=str(controller_id),
                    cursor=result_cursor,
                    state=state,
                )
                if (
                    not self.grants.custody_valid()
                    or not self._hook_runtime_matches(identity)
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "activation_only_failure:post_commit_custody_invalid"
                        ],
                        cursor=result_cursor,
                        state=state,
                        hook_state_sha256=hook_sha,
                    )
                return self._base_report(
                    controller_id=controller_id,
                    status="PASS",
                    decision="ACTIVATION_ONLY_FAILURE_TERMINALIZED",
                    issues=[],
                    cursor=result_cursor,
                    state=state,
                    hook_state_sha256=hook_sha,
                )
        except Exception as error:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="CONTROLLER_REFUSED",
                issues=["activation_only_failure:" + type(error).__name__],
                cursor=current,
                state=state,
            )

    def terminalize_partial_native_failure(self, program: Any) -> dict[str, Any]:
        """Close one proven interrupted batch with one dead created worker."""

        top_fields = {
            "schema",
            "controller_id",
            "expected_cursor",
            "failure_evidence",
        }
        if not isinstance(program, Mapping) or set(program) != top_fields:
            return self._base_report(
                controller_id=(
                    program.get("controller_id")
                    if isinstance(program, Mapping)
                    else None
                ),
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=["partial_native_failure:program_shape_invalid"],
            )
        value = deepcopy(dict(program))
        controller_id = value.get("controller_id")
        if (
            value.get("schema")
            != PARTIAL_NATIVE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA
            or not _IDENTIFIER.fullmatch(str(controller_id))
            or not _cursor_valid(value.get("expected_cursor"))
            or len(_canonical(value)) > MAX_PROGRAM_BYTES
        ):
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=["partial_native_failure:program_invalid"],
            )

        state: Mapping[str, Any] | None = None
        current: Mapping[str, Any] | None = None
        try:
            with self._locked():
                run_id = _controller_run_id(str(controller_id))
                if (
                    not self.grants.owner_matches(str(controller_id), run_id)
                    or not self.store.exists(run_id)
                    or not self.grants.custody_valid()
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["partial_native_failure:controller_not_active"],
                    )
                state, rows = self._state(run_id)
                current = _cursor(rows)
                cursor_issue = self._expected_cursor_issue(
                    value.get("expected_cursor"), current
                )
                if cursor_issue is not None:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[cursor_issue],
                        cursor=current,
                        state=state,
                    )
                activation = state.get("activation")
                identity = (
                    activation.get("identity")
                    if isinstance(activation, Mapping)
                    and isinstance(activation.get("identity"), Mapping)
                    else None
                )
                if not self._hook_runtime_matches(identity):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "partial_native_failure:historical_runtime_not_active"
                        ],
                        cursor=current,
                        state=state,
                    )
                action = state.get("action")
                grant = state.get("grant")
                stage_report = state.get("stage_report")
                batch_lane_ids = (
                    action.get("batch_lane_ids")
                    if isinstance(action, Mapping)
                    and isinstance(action.get("batch_lane_ids"), list)
                    else []
                )
                expected_lanes = [
                    str(identity.get("run_id")) + ":" + str(lane)
                    for lane in batch_lane_ids
                ]
                exact_partial = bool(
                    isinstance(identity, Mapping)
                    and isinstance(stage_report, Mapping)
                    and stage_report.get("operation") == "capacity_admission"
                    and stage_report.get("status") == "PASS"
                    and stage_report.get("disposition") == "SPAWN_AUTHORIZED"
                    and stage_report.get("issues") == []
                    and isinstance(action, Mapping)
                    and action.get("kind") == "spawn"
                    and action.get("batch_kind") == "spawn"
                    and action.get("batch_phase") == "primary"
                    and action.get("batch_index") == 0
                    and action.get("batch_size") == 2
                    and len(batch_lane_ids) == 2
                    and all(_IDENTIFIER.fullmatch(str(lane)) for lane in batch_lane_ids)
                    and action.get("lane_ids") == [batch_lane_ids[0]]
                    and isinstance(grant, Mapping)
                    and grant.get("state") == "OUTCOME_UNKNOWN"
                    and grant.get("action_sha256")
                    == action.get("action_sha256")
                    and isinstance(grant.get("tool_use_id"), str)
                    and bool(grant.get("tool_use_id", "").strip())
                    and _DIGEST.fullmatch(
                        str(grant.get("pretool_event_sha256", ""))
                    )
                    is not None
                    and _DIGEST.fullmatch(
                        str(grant.get("pretool_report_sha256", ""))
                    )
                    is not None
                    and state.get("grant_state") == "OUTCOME_UNKNOWN"
                    and state.get("terminal") is False
                    and state.get("pending_intent") is None
                    and state.get("action_outcome") is None
                    and state.get("cleanup_required") is False
                    and state.get("seen_action_ids") == [action.get("action_id")]
                    and state.get("action_evidence") == []
                    and state.get("last_action_evidence") is None
                    and state.get("last_batch_result") is None
                )
                if not exact_partial:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "partial_native_failure:exact_partial_state_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                authority = self.grants.canonical_authority()
                lifecycle = (
                    authority.get("lifecycle")
                    if isinstance(authority, Mapping)
                    and isinstance(authority.get("lifecycle"), Mapping)
                    else None
                )
                if (
                    authority.get("status") != "VERIFIED"
                    or authority.get("tip") != current
                    or not isinstance(lifecycle, Mapping)
                    or lifecycle.get("expected_binding_status") != "BLOCKED"
                    or lifecycle.get("terminal") is not False
                    or lifecycle.get("pending_intent") is not False
                    or lifecycle.get("cleanup_required") is not False
                    or lifecycle.get("action_sha256")
                    != action.get("action_sha256")
                    or lifecycle.get("grant_state") != "OUTCOME_UNKNOWN"
                    or lifecycle.get("tool_use_id") != grant.get("tool_use_id")
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "partial_native_failure:blocked_authority_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                capacity = self.tower.read_shared_capacity_authority()
                active = (
                    capacity.get("state", {}).get("active_lane_ids")
                    if isinstance(capacity, Mapping)
                    and isinstance(capacity.get("state"), Mapping)
                    else None
                )
                if (
                    capacity.get("status") != "VERIFIED"
                    or capacity.get("continuity_verified") is not True
                    or capacity.get("reason_codes") != []
                    or active != expected_lanes
                    or capacity.get("state_sha256")
                    != capacity.get("state", {}).get("state_sha256")
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "partial_native_failure:exact_capacity_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                evidence_issues = self._partial_native_failure_evidence_issues(
                    value.get("failure_evidence"),
                    controller_id=str(controller_id),
                    authority=authority,
                    state=state,
                    capacity=capacity,
                )
                if evidence_issues:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=evidence_issues,
                        cursor=current,
                        state=state,
                    )
                evidence = value["failure_evidence"]
                snapshot = evidence["terminal_snapshot"]
                worker = evidence["worker_state"]
                worker_id = worker["thread"]["id"]
                evaluation_time = self._evaluation_time().isoformat()
                intent = {
                    "operation": "partial_native_failure_terminalization",
                    "failure_evidence_sha256": evidence["evidence_sha256"],
                    "evaluation_time": evaluation_time,
                    "proposed_action_sha256": None,
                }
                intent_cursor = self._append(run_id, "stage_intent", intent)
                closed_stage = {
                    "schema": PARTIAL_NATIVE_FAILURE_STAGE_REPORT_SCHEMA,
                    "operation": "partial_native_failure_terminalization",
                    "status": "PASS",
                    "disposition": "PARTIAL_NATIVE_FAILURE_TERMINALIZED",
                    "issues": [],
                    "receipt": {
                        "failure_evidence_sha256": evidence[
                            "evidence_sha256"
                        ],
                        "terminal_snapshot_report_sha256": snapshot[
                            "report_sha256"
                        ],
                        "historical_runtime_report_sha256": evidence[
                            "historical_runtime_report"
                        ]["report_sha256"],
                        "historical_package_digest": evidence[
                            "historical_runtime_report"
                        ]["package_digest"],
                        "abandoned_turn_id": snapshot["turn_id"],
                        "created_worker_id": worker_id,
                        "created_logical_lane_id": batch_lane_ids[0],
                        "unmaterialized_logical_lane_ids": [
                            batch_lane_ids[1]
                        ],
                        "worker_terminal_disposition": "BLOCKED",
                        "worker_process_match_count": 0,
                        "owner_process_group_cleaned": True,
                        "capacity_authority_state_sha256": capacity[
                            "state_sha256"
                        ],
                    },
                    "next_action": "terminal_capacity_settlement",
                }
                terminal_evidence_sha256 = _sha(closed_stage)
                result_cursor = self._append(
                    run_id,
                    "stage_result",
                    {
                        "intent_cursor": intent_cursor,
                        "stage_report": closed_stage,
                        "action": None,
                        "capacity_guard": None,
                        "terminal": True,
                        "cleanup_required": False,
                        "terminal_evidence_sha256": terminal_evidence_sha256,
                        "issues": [],
                    },
                )
                state, _rows = self._state(run_id)
                hook_sha = self._sync_hook(
                    controller_id=str(controller_id),
                    cursor=result_cursor,
                    state=state,
                )
                if (
                    not self.grants.custody_valid()
                    or not self._hook_runtime_matches(identity)
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "partial_native_failure:post_commit_custody_invalid"
                        ],
                        cursor=result_cursor,
                        state=state,
                        hook_state_sha256=hook_sha,
                    )
                return self._base_report(
                    controller_id=controller_id,
                    status="PASS",
                    decision="PARTIAL_NATIVE_FAILURE_TERMINALIZED",
                    issues=[],
                    cursor=result_cursor,
                    state=state,
                    hook_state_sha256=hook_sha,
                )
        except Exception as error:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="CONTROLLER_REFUSED",
                issues=["partial_native_failure:" + type(error).__name__],
                cursor=current,
                state=state,
            )

    def terminalize_post_spawn_failure(self, program: Any) -> dict[str, Any]:
        """Close the exact Cycle 31 two-worker post-spawn deadlock."""

        top_fields = {
            "schema",
            "controller_id",
            "expected_cursor",
            "failure_evidence",
        }
        if not isinstance(program, Mapping) or set(program) != top_fields:
            return self._base_report(
                controller_id=(
                    program.get("controller_id")
                    if isinstance(program, Mapping)
                    else None
                ),
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=["post_spawn_failure:program_shape_invalid"],
            )
        value = deepcopy(dict(program))
        controller_id = value.get("controller_id")
        if (
            value.get("schema")
            != POST_SPAWN_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA
            or _IDENTIFIER.fullmatch(str(controller_id)) is None
            or not _cursor_valid(value.get("expected_cursor"))
            or len(_canonical(value)) > MAX_PROGRAM_BYTES
        ):
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=["post_spawn_failure:program_invalid"],
            )

        state: Mapping[str, Any] | None = None
        current: Mapping[str, Any] | None = None
        try:
            with self._locked():
                run_id = _controller_run_id(str(controller_id))
                if (
                    not self.grants.owner_matches(str(controller_id), run_id)
                    or not self.store.exists(run_id)
                    or not self.grants.custody_valid()
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["post_spawn_failure:controller_not_active"],
                    )
                state, rows = self._state(run_id)
                current = _cursor(rows)
                cursor_issue = self._expected_cursor_issue(
                    value.get("expected_cursor"), current
                )
                if cursor_issue is not None:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[cursor_issue],
                        cursor=current,
                        state=state,
                    )
                activation_payload = state.get("activation")
                identity = (
                    activation_payload.get("identity")
                    if isinstance(activation_payload, Mapping)
                    and isinstance(
                        activation_payload.get("identity"), Mapping
                    )
                    else None
                )
                if not self._hook_runtime_matches(identity):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "post_spawn_failure:historical_runtime_not_active"
                        ],
                        cursor=current,
                        state=state,
                    )
                batch = state.get("last_batch_result")
                spawn_binding = (
                    native_result.spawn_result_binding(
                        batch.get("result_binding"), batch.get("lane_ids")
                    )
                    if isinstance(batch, Mapping)
                    and batch.get("kind") == "spawn"
                    else None
                )
                spawn_lanes = (
                    deepcopy(list(spawn_binding["lanes"]))
                    if isinstance(spawn_binding, Mapping)
                    and isinstance(spawn_binding.get("lanes"), list)
                    else []
                )
                stage_report = state.get("stage_report")
                action_evidence = state.get("action_evidence")
                evidence_actions = (
                    [
                        row.get("action")
                        for row in action_evidence
                        if isinstance(row, Mapping)
                    ]
                    if isinstance(action_evidence, list)
                    else []
                )
                exact_actions = bool(
                    len(spawn_lanes) == 2
                    and [row.get("lane_id") for row in spawn_lanes]
                    == sorted(row.get("lane_id") for row in spawn_lanes)
                    and len(action_evidence or []) == 2
                    and len(evidence_actions) == 2
                    and all(isinstance(action, Mapping) for action in evidence_actions)
                    and [action.get("batch_index") for action in evidence_actions]
                    == [0, 1]
                    and all(
                        action.get("kind") == "spawn"
                        and action.get("batch_kind") == "spawn"
                        and action.get("batch_phase") == "primary"
                        and action.get("batch_size") == 2
                        and action.get("batch_lane_ids")
                        == [row["lane_id"] for row in spawn_lanes]
                        and action.get("lane_ids")
                        == [spawn_lanes[index]["lane_id"]]
                        and action.get("tool_name")
                        == DIRECT_NATIVE_TOOLS["spawn"]
                        and action.get("action_id")
                        == state.get("seen_action_ids", [None, None])[index]
                        for index, action in enumerate(evidence_actions)
                    )
                    and all(
                        isinstance(action_evidence[index].get("result_binding"), Mapping)
                        and native_result.spawn_result_binding(
                            action_evidence[index]["result_binding"],
                            [spawn_lanes[index]["lane_id"]],
                        )
                        == {
                            "schema": "orch-dork/native-spawn-result/v1",
                            "lanes": [spawn_lanes[index]],
                        }
                        for index in range(2)
                    )
                )
                exact_state = bool(
                    isinstance(identity, Mapping)
                    and isinstance(stage_report, Mapping)
                    and stage_report.get("schema")
                    == governed_attempt.REPORT_SCHEMA
                    and stage_report.get("operation") == "spawn_outcome"
                    and stage_report.get("status") == "BLOCKED"
                    and stage_report.get("disposition") == "PROGRAM_REFUSED"
                    and stage_report.get("issues")
                    == ["program:operation_invalid"]
                    and stage_report.get("receipt") is None
                    and stage_report.get("next_action") == "stop"
                    and state.get("terminal") is False
                    and state.get("pending_intent") is None
                    and state.get("cleanup_required") is True
                    and state.get("action") is None
                    and state.get("action_outcome") is None
                    and state.get("grant") is None
                    and state.get("grant_state") is None
                    and state.get("last_action_evidence")
                    == action_evidence[-1]
                    and exact_actions
                    and self._retained_hook_evidence_valid(state)
                )
                if not exact_state:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "post_spawn_failure:exact_deadlock_state_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                authority = self.grants.canonical_authority()
                lifecycle = (
                    authority.get("lifecycle")
                    if isinstance(authority, Mapping)
                    and isinstance(authority.get("lifecycle"), Mapping)
                    else None
                )
                if (
                    authority.get("status") != "VERIFIED"
                    or authority.get("tip") != current
                    or not isinstance(lifecycle, Mapping)
                    or lifecycle.get("expected_binding_status") != "WAITING"
                    or lifecycle.get("terminal") is not False
                    or lifecycle.get("pending_intent") is not False
                    or lifecycle.get("cleanup_required") is not True
                    or lifecycle.get("action_sha256") is not None
                    or lifecycle.get("grant_state") is not None
                    or lifecycle.get("tool_use_id") is not None
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "post_spawn_failure:blocked_authority_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                capacity = self.tower.read_shared_capacity_authority()
                expected_capacity_lanes = sorted(
                    str(identity.get("run_id")) + ":" + row["lane_id"]
                    for row in spawn_lanes
                )
                active = (
                    capacity.get("state", {}).get("active_lane_ids")
                    if isinstance(capacity, Mapping)
                    and isinstance(capacity.get("state"), Mapping)
                    else None
                )
                if (
                    capacity.get("status") != "VERIFIED"
                    or capacity.get("continuity_verified") is not True
                    or capacity.get("reason_codes") != []
                    or active != expected_capacity_lanes
                    or capacity.get("state_sha256")
                    != capacity.get("state", {}).get("state_sha256")
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["post_spawn_failure:exact_capacity_required"],
                        cursor=current,
                        state=state,
                    )
                evidence_issues = self._post_spawn_failure_evidence_issues(
                    value.get("failure_evidence"),
                    controller_id=str(controller_id),
                    authority=authority,
                    state=state,
                    capacity=capacity,
                    spawn_lanes=spawn_lanes,
                )
                if evidence_issues:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=evidence_issues,
                        cursor=current,
                        state=state,
                    )

                evidence = value["failure_evidence"]
                dedicated = evidence["dedicated_run"]
                worker_rollouts = {
                    row["logical_lane_id"]: row
                    for row in evidence["worker_rollouts"]
                }
                evaluation_time = self._evaluation_time().isoformat()
                intent = {
                    "operation": "post_spawn_failure_terminalization",
                    "failure_evidence_sha256": evidence["evidence_sha256"],
                    "evaluation_time": evaluation_time,
                    "proposed_action_sha256": None,
                }
                intent_cursor = self._append(run_id, "stage_intent", intent)
                created_workers = [
                    {
                        "logical_lane_id": row["lane_id"],
                        "worker_id": row["agent_id"],
                        "rollout_artifact_sha256": worker_rollouts[
                            row["lane_id"]
                        ]["artifact"]["artifact_sha256"],
                        "terminal_task_complete_count": worker_rollouts[
                            row["lane_id"]
                        ]["task_complete_count"],
                    }
                    for row in spawn_lanes
                ]
                closed_stage = {
                    "schema": POST_SPAWN_FAILURE_STAGE_REPORT_SCHEMA,
                    "operation": "post_spawn_failure_terminalization",
                    "status": "PASS",
                    "disposition": "POST_SPAWN_FAILURE_TERMINALIZED",
                    "issues": [],
                    "receipt": {
                        "failure_evidence_sha256": evidence[
                            "evidence_sha256"
                        ],
                        "historical_runtime_report_sha256": evidence[
                            "historical_runtime_report"
                        ]["report_sha256"],
                        "historical_package_digest": evidence[
                            "historical_runtime_report"
                        ]["package_digest"],
                        "attempt_envelope_artifact_sha256": evidence[
                            "attempt_envelope_artifact"
                        ]["artifact_sha256"],
                        "dedicated_run_artifact_sha256": evidence[
                            "dedicated_run_artifact"
                        ]["artifact_sha256"],
                        "pre_turn_artifact_sha256": evidence[
                            "pre_turn_artifact"
                        ]["artifact_sha256"],
                        "root_rollout_artifact_sha256": evidence[
                            "root_rollout"
                        ]["artifact"]["artifact_sha256"],
                        "abandoned_task_id": dedicated["task_id"],
                        "abandoned_turn_id": dedicated["turn_id"],
                        "created_workers": created_workers,
                        "owner_process_group_cleaned": True,
                        "capacity_authority_state_sha256": capacity[
                            "state_sha256"
                        ],
                    },
                    "next_action": "terminal_capacity_settlement",
                }
                terminal_evidence_sha256 = _sha(closed_stage)
                result_cursor = self._append(
                    run_id,
                    "stage_result",
                    {
                        "intent_cursor": intent_cursor,
                        "stage_report": closed_stage,
                        "action": None,
                        "capacity_guard": None,
                        "terminal": True,
                        "cleanup_required": False,
                        "terminal_evidence_sha256": terminal_evidence_sha256,
                        "issues": [],
                    },
                )
                state, _rows = self._state(run_id)
                hook_sha = self._sync_hook(
                    controller_id=str(controller_id),
                    cursor=result_cursor,
                    state=state,
                )
                if (
                    not self.grants.custody_valid()
                    or not self._hook_runtime_matches(identity)
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "post_spawn_failure:post_commit_custody_invalid"
                        ],
                        cursor=result_cursor,
                        state=state,
                        hook_state_sha256=hook_sha,
                    )
                return self._base_report(
                    controller_id=controller_id,
                    status="PASS",
                    decision="POST_SPAWN_FAILURE_TERMINALIZED",
                    issues=[],
                    cursor=result_cursor,
                    state=state,
                    hook_state_sha256=hook_sha,
                )
        except Exception as error:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="CONTROLLER_REFUSED",
                issues=["post_spawn_failure:" + type(error).__name__],
                cursor=current,
                state=state,
            )

    def terminalize_post_ack_bridge_failure(
        self, program: Any
    ) -> dict[str, Any]:
        """Close one exact profiled two-worker ACK bridge failure."""

        top_fields = {
            "schema",
            "controller_id",
            "expected_cursor",
            "failure_evidence",
        }
        if not isinstance(program, Mapping) or set(program) != top_fields:
            return self._base_report(
                controller_id=(
                    program.get("controller_id")
                    if isinstance(program, Mapping)
                    else None
                ),
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=["post_ack_bridge_failure:program_shape_invalid"],
            )
        value = deepcopy(dict(program))
        controller_id = value.get("controller_id")
        if (
            value.get("schema")
            != POST_ACK_BRIDGE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA
        ) or (
            _IDENTIFIER.fullmatch(str(controller_id)) is None
            or not _cursor_valid(value.get("expected_cursor"))
            or len(_canonical(value)) > MAX_PROGRAM_BYTES
        ):
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=["post_ack_bridge_failure:program_invalid"],
            )

        state: Mapping[str, Any] | None = None
        current: Mapping[str, Any] | None = None
        try:
            with self._locked():
                run_id = _controller_run_id(str(controller_id))
                if (
                    not self.grants.owner_matches(str(controller_id), run_id)
                    or not self.store.exists(run_id)
                    or not self.grants.custody_valid()
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "post_ack_bridge_failure:controller_not_active"
                        ],
                    )
                state, rows = self._state(run_id)
                current = _cursor(rows)
                cursor_issue = self._expected_cursor_issue(
                    value.get("expected_cursor"), current
                )
                if cursor_issue is not None:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[cursor_issue],
                        cursor=current,
                        state=state,
                    )
                activation_payload = state.get("activation")
                identity = (
                    activation_payload.get("identity")
                    if isinstance(activation_payload, Mapping)
                    and isinstance(activation_payload.get("identity"), Mapping)
                    else None
                )
                if not self._hook_runtime_matches(identity):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "post_ack_bridge_failure:"
                            "historical_runtime_not_active"
                        ],
                        cursor=current,
                        state=state,
                    )
                batch = state.get("last_batch_result")
                spawn_binding = (
                    native_result.spawn_result_binding(
                        batch.get("result_binding"), batch.get("lane_ids")
                    )
                    if isinstance(batch, Mapping)
                    and batch.get("kind") == "spawn"
                    else None
                )
                spawn_lanes = (
                    deepcopy(list(spawn_binding["lanes"]))
                    if isinstance(spawn_binding, Mapping)
                    and isinstance(spawn_binding.get("lanes"), list)
                    else []
                )
                stage_report = state.get("stage_report")
                evidence_value = value.get("failure_evidence")
                embedded_envelope = (
                    evidence_value.get("attempt_envelope")
                    if isinstance(evidence_value, Mapping)
                    and isinstance(
                        evidence_value.get("attempt_envelope"), Mapping
                    )
                    else {}
                )
                embedded_dedicated = (
                    evidence_value.get("dedicated_run")
                    if isinstance(evidence_value, Mapping)
                    and isinstance(evidence_value.get("dedicated_run"), Mapping)
                    else {}
                )
                profile = _POST_ACK_BRIDGE_FAILURE_PROFILES.get(
                    (
                        str(embedded_envelope.get("schema", "")),
                        str(embedded_dedicated.get("schema", "")),
                    )
                )
                action_evidence = state.get("action_evidence")
                evidence_actions = (
                    [
                        row.get("action")
                        for row in action_evidence
                        if isinstance(row, Mapping)
                    ]
                    if isinstance(action_evidence, list)
                    else []
                )
                exact_actions = bool(
                    len(spawn_lanes) == 2
                    and [row.get("lane_id") for row in spawn_lanes]
                    == sorted(row.get("lane_id") for row in spawn_lanes)
                    and len(action_evidence or []) == 2
                    and len(evidence_actions) == 2
                    and all(
                        isinstance(action, Mapping)
                        for action in evidence_actions
                    )
                    and [
                        action.get("batch_index")
                        for action in evidence_actions
                    ]
                    == [0, 1]
                    and all(
                        action.get("kind") == "spawn"
                        and action.get("batch_kind") == "spawn"
                        and action.get("batch_phase") == "primary"
                        and action.get("batch_size") == 2
                        and action.get("batch_lane_ids")
                        == [row["lane_id"] for row in spawn_lanes]
                        and action.get("lane_ids")
                        == [spawn_lanes[index]["lane_id"]]
                        and action.get("tool_name")
                        == DIRECT_NATIVE_TOOLS["spawn"]
                        and action.get("action_id")
                        == state.get("seen_action_ids", [None, None])[index]
                        for index, action in enumerate(evidence_actions)
                    )
                    and all(
                        isinstance(
                            action_evidence[index].get("result_binding"),
                            Mapping,
                        )
                        and native_result.spawn_result_binding(
                            action_evidence[index]["result_binding"],
                            [spawn_lanes[index]["lane_id"]],
                        )
                        == {
                            "schema": "orch-dork/native-spawn-result/v1",
                            "lanes": [spawn_lanes[index]],
                        }
                        for index in range(2)
                    )
                )
                exact_state = bool(
                    isinstance(identity, Mapping)
                    and isinstance(stage_report, Mapping)
                    and stage_report.get("schema")
                    == governed_attempt.REPORT_SCHEMA
                    and stage_report.get("operation") == "capacity_admission"
                    and stage_report.get("status") == "PASS"
                    and stage_report.get("disposition") == "SPAWN_AUTHORIZED"
                    and stage_report.get("issues") == []
                    and stage_report.get("next_action") == "spawn"
                    and isinstance(stage_report.get("receipt"), Mapping)
                    and state.get("terminal") is False
                    and state.get("pending_intent") is None
                    and state.get("cleanup_required") is False
                    and state.get("action") is None
                    and state.get("action_outcome") == "completed"
                    and state.get("grant") is None
                    and state.get("grant_state") is None
                    and state.get("last_action_evidence")
                    == action_evidence[-1]
                    and exact_actions
                    and self._retained_hook_evidence_valid(state)
                )
                waiting_state = exact_state
                action = state.get("action")
                grant = state.get("grant")
                pending_continuation_state = bool(
                    profile is not None
                    and profile.get("state_shape")
                    == "pending_continuation_denied"
                    and isinstance(identity, Mapping)
                    and isinstance(stage_report, Mapping)
                    and stage_report.get("schema")
                    == governed_attempt.REPORT_SCHEMA
                    and stage_report.get("operation") == "worker_start"
                    and stage_report.get("status") == "PASS"
                    and stage_report.get("disposition") == "WORK_AUTHORIZED"
                    and stage_report.get("issues") == []
                    and stage_report.get("next_action") == "continue"
                    and isinstance(stage_report.get("receipt"), Mapping)
                    and state.get("terminal") is False
                    and state.get("pending_intent") is None
                    and state.get("cleanup_required") is False
                    and state.get("action_outcome") is None
                    and isinstance(action, Mapping)
                    and action.get("kind") == "continue"
                    and action.get("batch_kind") == "continue"
                    and action.get("batch_phase") == "primary"
                    and action.get("batch_index") == 0
                    and action.get("batch_size") == 2
                    and action.get("batch_lane_ids")
                    == [row["lane_id"] for row in spawn_lanes]
                    and action.get("lane_ids") == [spawn_lanes[0]["lane_id"]]
                    and action.get("tool_name")
                    == DIRECT_NATIVE_TOOLS["continue"]
                    and state.get("seen_action_ids", [])[-1:]
                    == [action.get("action_id")]
                    and isinstance(grant, Mapping)
                    and grant.get("state") == "AUTHORIZED"
                    and grant.get("action_sha256")
                    == action.get("action_sha256")
                    and grant.get("action_kind") == "continue"
                    and grant.get("tool_name") == action.get("tool_name")
                    and grant.get("tool_input_sha256")
                    == action.get("tool_input_sha256")
                    and all(
                        grant.get(field) is None
                        for field in (
                            "pretool_event_sha256",
                            "pretool_report_sha256",
                            "tool_use_id",
                            "outcome",
                            "result_sha256",
                            "result_binding_sha256",
                            "posttool_report_sha256",
                        )
                    )
                    and state.get("last_action_evidence")
                    == action_evidence[-1]
                    and exact_actions
                    and self._retained_hook_evidence_valid(state)
                )
                exact_state = waiting_state or pending_continuation_state
                if not exact_state:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "post_ack_bridge_failure:exact_state_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                authority = self.grants.canonical_authority()
                lifecycle = (
                    authority.get("lifecycle")
                    if isinstance(authority, Mapping)
                    and isinstance(authority.get("lifecycle"), Mapping)
                    else None
                )
                exact_authority = False
                if authority.get("status") == "VERIFIED":
                    exact_authority = bool(
                        authority.get("tip") == current
                        and isinstance(lifecycle, Mapping)
                        and lifecycle.get("terminal") is False
                        and lifecycle.get("pending_intent") is False
                        and lifecycle.get("cleanup_required") is False
                        and lifecycle.get("tool_use_id") is None
                        and (
                            (
                                waiting_state
                                and lifecycle.get("expected_binding_status")
                                == "WAITING"
                                and lifecycle.get("action_sha256") is None
                                and lifecycle.get("grant_state") is None
                            )
                            or (
                                pending_continuation_state
                                and lifecycle.get("expected_binding_status")
                                == "ACTIVE"
                                and lifecycle.get("action_sha256")
                                == action.get("action_sha256")
                                and lifecycle.get("grant_state")
                                == "AUTHORIZED"
                            )
                        )
                    )
                if not exact_authority:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "post_ack_bridge_failure:exact_authority_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                capacity = self.tower.read_shared_capacity_authority()
                expected_capacity_lanes = sorted(
                    str(identity.get("run_id")) + ":" + row["lane_id"]
                    for row in spawn_lanes
                )
                active = (
                    capacity.get("state", {}).get("active_lane_ids")
                    if isinstance(capacity, Mapping)
                    and isinstance(capacity.get("state"), Mapping)
                    else None
                )
                if (
                    capacity.get("status") != "VERIFIED"
                    or capacity.get("continuity_verified") is not True
                    or capacity.get("reason_codes") != []
                    or active != expected_capacity_lanes
                    or capacity.get("state_sha256")
                    != capacity.get("state", {}).get("state_sha256")
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "post_ack_bridge_failure:exact_capacity_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                evidence_issues = (
                    self._post_ack_bridge_failure_evidence_issues(
                        value.get("failure_evidence"),
                        controller_id=str(controller_id),
                        state=state,
                        capacity=capacity,
                        spawn_lanes=spawn_lanes,
                    )
                )
                if evidence_issues:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=evidence_issues,
                        cursor=current,
                        state=state,
                    )

                evidence = value["failure_evidence"]
                dedicated = evidence["dedicated_run"]
                worker_rollouts = {
                    row["logical_lane_id"]: row
                    for row in evidence["worker_rollouts"]
                }
                evaluation_time = self._evaluation_time().isoformat()
                intent = {
                    "operation": "post_ack_bridge_failure_terminalization",
                    "failure_evidence_sha256": evidence["evidence_sha256"],
                    "evaluation_time": evaluation_time,
                    "proposed_action_sha256": None,
                }
                intent_cursor = self._append(run_id, "stage_intent", intent)
                created_workers = [
                    {
                        "logical_lane_id": row["lane_id"],
                        "worker_id": row["agent_id"],
                        "rollout_artifact_sha256": worker_rollouts[
                            row["lane_id"]
                        ]["artifact"]["artifact_sha256"],
                        "terminal_task_complete_count": worker_rollouts[
                            row["lane_id"]
                        ]["task_complete_count"],
                        "pre_work_receipt_sha256": worker_rollouts[
                            row["lane_id"]
                        ]["runtime_observation"]["terminal_json_sha256"],
                    }
                    for row in spawn_lanes
                ]
                terminal_receipt = {
                    "failure_evidence_sha256": evidence[
                        "evidence_sha256"
                    ],
                    "historical_runtime_report_sha256": evidence[
                        "historical_runtime_report"
                    ]["report_sha256"],
                    "historical_package_digest": evidence[
                        "historical_runtime_report"
                    ]["package_digest"],
                    "attempt_envelope_artifact_sha256": evidence[
                        "attempt_envelope_artifact"
                    ]["artifact_sha256"],
                    "dedicated_run_artifact_sha256": evidence[
                        "dedicated_run_artifact"
                    ]["artifact_sha256"],
                    "pre_turn_artifact_sha256": evidence[
                        "pre_turn_artifact"
                    ]["artifact_sha256"],
                    "root_rollout_artifact_sha256": evidence[
                        "root_rollout"
                    ]["artifact"]["artifact_sha256"],
                    "abandoned_task_id": dedicated["task_id"],
                    "abandoned_turn_id": dedicated["turn_id"],
                    "created_workers": created_workers,
                    "owner_process_group_cleaned": True,
                    "capacity_authority_state_sha256": capacity[
                        "state_sha256"
                    ],
                }
                if pending_continuation_state:
                    terminal_receipt.update(
                        {
                            "pretool_denial_artifact_sha256": evidence[
                                "pretool_denial_artifact"
                            ]["artifact_sha256"],
                            "pretool_denial_report_sha256": evidence[
                                "pretool_denial"
                            ]["report_sha256"],
                            "pretool_denial_durable_record_sha256": evidence[
                                "pretool_denial"
                            ]["durable_record_sha256"],
                            "abandoned_action_id": action["action_id"],
                            "abandoned_action_sha256": action[
                                "action_sha256"
                            ],
                            "denied_hook_tool_name": evidence[
                                "root_rollout"
                            ]["denied_send_input"]["hook_tool_name"],
                        }
                    )
                else:
                    terminal_receipt["bridge_refusal_report_sha256"] = (
                        evidence["root_rollout"]["bridge_refusal"][
                            "report_sha256"
                        ]
                    )
                closed_stage = {
                    "schema": POST_ACK_BRIDGE_FAILURE_STAGE_REPORT_SCHEMA,
                    "operation": "post_ack_bridge_failure_terminalization",
                    "status": "PASS",
                    "disposition": "POST_ACK_BRIDGE_FAILURE_TERMINALIZED",
                    "issues": [],
                    "receipt": terminal_receipt,
                    "next_action": "terminal_capacity_settlement",
                }
                terminal_evidence_sha256 = _sha(closed_stage)
                result_cursor = self._append(
                    run_id,
                    "stage_result",
                    {
                        "intent_cursor": intent_cursor,
                        "stage_report": closed_stage,
                        "action": None,
                        "capacity_guard": None,
                        "terminal": True,
                        "cleanup_required": False,
                        "terminal_evidence_sha256": terminal_evidence_sha256,
                        "issues": [],
                    },
                )
                state, _rows = self._state(run_id)
                hook_sha = self._sync_hook(
                    controller_id=str(controller_id),
                    cursor=result_cursor,
                    state=state,
                )
                if (
                    not self.grants.custody_valid()
                    or not self._hook_runtime_matches(identity)
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "post_ack_bridge_failure:post_commit_custody_invalid"
                        ],
                        cursor=result_cursor,
                        state=state,
                        hook_state_sha256=hook_sha,
                    )
                return self._base_report(
                    controller_id=controller_id,
                    status="PASS",
                    decision="POST_ACK_BRIDGE_FAILURE_TERMINALIZED",
                    issues=[],
                    cursor=result_cursor,
                    state=state,
                    hook_state_sha256=hook_sha,
                )
        except Exception as error:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="CONTROLLER_REFUSED",
                issues=[
                    "post_ack_bridge_failure:" + type(error).__name__
                ],
                cursor=current,
                state=state,
            )

    def advance(self, program: Any, *, native_request_meta: Any = None) -> dict[str, Any]:
        """Advance one exact transition or inspect the durable state.

        This method performs no native, provider, model, hosted, credential, or
        task-creation call.  A returned action is an authorization packet only.
        """

        value, issues = self._validate_program(program)
        if issues:
            return self._base_report(
                controller_id=value.get("controller_id"),
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=issues,
            )
        with self._locked():
            try:
                def custody_refusal() -> dict[str, Any]:
                    return self._base_report(
                        controller_id=value["controller_id"],
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["controller:authority_custody_invalid"],
                    )

                def runtime_refusal() -> dict[str, Any]:
                    return self._base_report(
                        controller_id=value["controller_id"],
                        status="BLOCKED",
                        decision="CONTROLLER_NOT_ACTIVE",
                        issues=["controller:hook_runtime_mismatch"],
                    )

                if value["operation"] == "activate":
                    result = self._activate(value)
                    if (
                        result.get("status") == "PASS"
                        and not self.grants.custody_valid()
                    ):
                        return custody_refusal()
                    if result.get("status") == "PASS":
                        run_id = _controller_run_id(value["controller_id"])
                        owner_activation = self.grants.verified_owner_activation(
                            value["controller_id"], run_id
                        )
                        identity = (
                            owner_activation.get("identity")
                            if isinstance(owner_activation, Mapping)
                            else None
                        )
                        if not self._hook_runtime_matches(identity):
                            return runtime_refusal()
                    return result
                run_id = _controller_run_id(value["controller_id"])
                if not self.grants.owner_matches(value["controller_id"], run_id):
                    return self._base_report(
                        controller_id=value["controller_id"],
                        status="BLOCKED",
                        decision="CONTROLLER_NOT_ACTIVE",
                        issues=["controller:owner_mismatch"],
                    )
                if not self.store.exists(run_id):
                    return self._base_report(
                        controller_id=value["controller_id"],
                        status="BLOCKED",
                        decision="CONTROLLER_NOT_ACTIVE",
                        issues=["controller:not_found"],
                    )
                owner_activation = self.grants.verified_owner_activation(
                    value["controller_id"], run_id
                )
                identity = (
                    owner_activation.get("identity")
                    if isinstance(owner_activation, Mapping)
                    else None
                )
                if not self._hook_runtime_matches(identity):
                    return self._base_report(
                        controller_id=value["controller_id"],
                        status="BLOCKED",
                        decision="CONTROLLER_NOT_ACTIVE",
                        issues=["controller:hook_runtime_mismatch"],
                    )
                try:
                    self.source_roots = owned_file.activated_source_roots(
                        self.source_roots,
                        owner_activation.get("source_roots") if isinstance(owner_activation, Mapping) else None,
                    )
                except (OSError, TypeError, ValueError):
                    return self._base_report(
                        controller_id=value["controller_id"], status="BLOCKED",
                        decision="CONTROLLER_REFUSED", issues=["controller:source_roots_mismatch"],
                    )
                if value["operation"] == "stage":
                    result = self._stage(value, run_id, native_request_meta=native_request_meta)
                elif value["operation"] == "observe":
                    result = self._observe(value, run_id)
                else:
                    result = self._inspect(value, run_id)
                if (
                    result.get("status") == "PASS"
                    and not self.grants.custody_valid()
                ):
                    return custody_refusal()
                if (
                    result.get("status") == "PASS"
                    and not self._hook_runtime_matches(identity)
                ):
                    return runtime_refusal()
                return result
            except Exception as error:
                return self._base_report(
                    controller_id=value["controller_id"],
                    status="BLOCKED",
                    decision="CONTROLLER_REFUSED",
                    issues=["controller:" + type(error).__name__],
                )

    def _observed_spawn_stall_evidence_issues(
        self,
        evidence: Any,
        *,
        controller_id: str,
        authority: Mapping[str, Any],
        state: Mapping[str, Any],
        capacity: Mapping[str, Any],
    ) -> list[str]:
        """Validate the exact corpus an observed spawn batch stall leaves.

        Proportionate on purpose: it demands the artifacts this failure really
        produces and no others.  It accepts the first spawn's durable PostTool
        record before controller advancement, that same record after
        advancement authorized the next lane but before its tool dispatch, or
        the last spawn's durable record after advancement drained the batch
        with no next action (generation 47: every worker died before its first
        hook event, so the controller kept awaiting acknowledgements).  Once
        the owner has reconciled continuations, the snapshot still seals the
        last spawn's record (generation 49 after every continuation, generation
        86 with a later continuation bound).
        """

        issues: list[str] = []
        fields = {
            "schema",
            "terminal_snapshot_artifact",
            "terminal_snapshot",
            "worker_rollout_artifact",
            "historical_runtime_report",
            "evidence_sha256",
        }
        if not isinstance(evidence, Mapping) or set(evidence) != fields:
            return ["observed_spawn_stall:evidence_shape_invalid"]
        evidence_core = {
            key: deepcopy(value)
            for key, value in evidence.items()
            if key != "evidence_sha256"
        }
        if (
            evidence.get("schema") != OBSERVED_SPAWN_STALL_EVIDENCE_SCHEMA
            or evidence.get("evidence_sha256") != _sha(evidence_core)
        ):
            return ["observed_spawn_stall:evidence_seal_invalid"]

        snapshot = evidence.get("terminal_snapshot")
        reference = evidence.get("terminal_snapshot_artifact")
        snapshot_path: Path | None = None
        persisted_snapshot: dict[str, Any] | None = None
        if not isinstance(reference, Mapping) or set(reference) != {
            "path",
            "artifact_sha256",
        }:
            _issue(
                issues,
                "observed_spawn_stall:terminal_snapshot:reference_invalid",
            )
        else:
            try:
                (
                    snapshot_path,
                    persisted_snapshot,
                ) = _read_pre_native_failure_artifact(
                    str(reference.get("path", "")),
                    expected_sha256=str(reference.get("artifact_sha256", "")),
                    label="observed_spawn_stall:terminal_snapshot",
                )
            except ValueError:
                _issue(
                    issues,
                    "observed_spawn_stall:terminal_snapshot:reference_invalid",
                )

        activation = state.get("activation")
        identity = (
            activation.get("identity")
            if isinstance(activation, Mapping)
            and isinstance(activation.get("identity"), Mapping)
            else {}
        )
        action = state.get("action")
        grant = state.get("grant")
        prior_evidence = state.get("last_action_evidence")
        stage_report = state.get("stage_report")
        rows = state.get("action_evidence")
        last_action = (
            prior_evidence.get("action")
            if isinstance(prior_evidence, Mapping)
            and isinstance(prior_evidence.get("action"), Mapping)
            else None
        )
        reconciled_continuations = bool(
            isinstance(stage_report, Mapping)
            and isinstance(last_action, Mapping)
            and last_action.get("kind") == "continue"
            and type(last_action.get("batch_size")) is int
            and last_action["batch_size"] > 0
            and isinstance(rows, list)
        )
        worker_results_bound = bool(
            reconciled_continuations
            and action is None
            and stage_report.get("operation") == "worker_results"
            and len(rows) == 2 * last_action["batch_size"]
        )
        later_continuation_bound = bool(
            reconciled_continuations
            and isinstance(action, Mapping)
            and action.get("kind") == "continue"
            and stage_report.get("operation") == "worker_start"
            and type(action.get("batch_index")) is int
            and action["batch_index"] >= 1
            and len(rows) == last_action["batch_size"] + action["batch_index"]
        )
        if worker_results_bound or later_continuation_bound:
            # Generation 49's worker-results cut and generation 86's later
            # continuation: the snapshot seals the last spawn's durable record,
            # so the link is checked against that row rather than the
            # continuation rows that followed it.
            prior_evidence = rows[last_action["batch_size"] - 1]
        prior_action = (
            prior_evidence.get("action")
            if isinstance(prior_evidence, Mapping)
            and isinstance(prior_evidence.get("action"), Mapping)
            else None
        )
        observed_action = prior_action or action
        pending_action_bound = isinstance(action, Mapping) and isinstance(
            grant, Mapping
        )
        batch_complete_bound = bool(
            action is None
            and grant is None
            and isinstance(prior_action, Mapping)
            and type(prior_action.get("batch_size")) is int
            and prior_action.get("batch_index")
            == prior_action.get("batch_size", 0) - 1
        )
        snapshot_core = (
            {
                key: deepcopy(value)
                for key, value in snapshot.items()
                if key != "report_sha256"
            }
            if isinstance(snapshot, Mapping)
            else {}
        )
        snapshot_fields = {
            "schema",
            "generation",
            "candidate_commit",
            "task_id",
            "turn_id",
            "controller_id",
            "controller_cursor",
            "controller_authority",
            "controller_state",
            "capacity_authority",
            "project_ground_current",
            "durable_posttool_event",
            "worker_process_match_count",
            "owner_process_match_count",
            "report_sha256",
        }
        durable = (
            snapshot.get("durable_posttool_event")
            if isinstance(snapshot, Mapping)
            else None
        )
        durable_native = (
            durable.get("native_controller")
            if isinstance(durable, Mapping)
            and isinstance(durable.get("native_controller"), Mapping)
            else None
        )
        result_binding = (
            durable_native.get("result_binding")
            if isinstance(durable_native, Mapping)
            and isinstance(durable_native.get("result_binding"), Mapping)
            else None
        )
        lanes = (
            result_binding.get("lanes")
            if isinstance(result_binding, Mapping)
            and isinstance(result_binding.get("lanes"), list)
            else None
        )
        lane_row = (
            lanes[0]
            if isinstance(lanes, list)
            and len(lanes) == 1
            and isinstance(lanes[0], Mapping)
            else None
        )
        worker_id = (
            lane_row.get("agent_id") if isinstance(lane_row, Mapping) else None
        )
        if (
            isinstance(prior_action, Mapping)
            and isinstance(prior_evidence, Mapping)
            and isinstance(durable, Mapping)
            and isinstance(durable_native, Mapping)
        ):
            observed_action_link_valid = bool(
                durable.get("report_sha256")
                == prior_evidence.get("posttool_report_sha256")
                and durable.get("durable_record_sha256")
                == prior_evidence.get("posttool_durable_record_sha256")
                and durable_native.get("pretool_report_sha256")
                == prior_evidence.get("pretool_report_sha256")
                and result_binding == prior_evidence.get("result_binding")
                and durable_native.get("action_id")
                == prior_action.get("action_id")
                and durable.get("tool_input_sha256")
                == prior_action.get("tool_input_sha256")
                and _DIGEST.fullmatch(
                    str(durable_native.get("result_sha256", ""))
                )
                is not None
            )
        elif isinstance(durable, Mapping) and isinstance(
            durable_native, Mapping
        ):
            observed_action_link_valid = bool(
                isinstance(action, Mapping)
                and isinstance(grant, Mapping)
                and durable_native.get("action_id")
                == action.get("action_id")
                and durable_native.get("tool_use_id")
                == grant.get("tool_use_id")
                and durable_native.get("result_sha256")
                == grant.get("result_sha256")
                and durable.get("tool_input_sha256")
                == action.get("tool_input_sha256")
            )
        else:
            observed_action_link_valid = False
        if (
            not isinstance(snapshot, Mapping)
            or set(snapshot) != snapshot_fields
            or snapshot.get("schema")
            != OBSERVED_SPAWN_STALL_TERMINAL_SNAPSHOT_SCHEMA
            or snapshot.get("report_sha256") != _sha(snapshot_core)
            or persisted_snapshot != snapshot
            or snapshot.get("controller_id") != controller_id
            or snapshot.get("controller_cursor") != authority.get("tip")
            or snapshot.get("controller_authority") != authority
            or snapshot.get("controller_state") != state
            or snapshot.get("capacity_authority") != capacity
            or snapshot.get("task_id") != identity.get("root_thread_id")
            or snapshot.get("generation")
            != identity.get("installed_plugin_version")
            or not re.fullmatch(
                r"[0-9a-f]{40}",
                str(snapshot.get("candidate_commit", "")),
            )
            or snapshot.get("turn_id")
            != (
                durable.get("identity", {}).get("turn_id")
                if isinstance(durable, Mapping)
                else None
            )
            or type(snapshot.get("worker_process_match_count")) is not int
            or snapshot.get("worker_process_match_count") != 0
            or type(snapshot.get("owner_process_match_count")) is not int
            or snapshot.get("owner_process_match_count") != 0
            or not isinstance(identity.get("root_session_id"), str)
            or not str(identity.get("root_session_id", "")).strip()
            or not (pending_action_bound or batch_complete_bound)
            or not isinstance(durable, Mapping)
            or _DIGEST.fullmatch(str(durable.get("report_sha256", ""))) is None
            or durable.get("schema")
            != "orch-dork/project-ground-durable-event/v1"
            or durable.get("status") != "PASS"
            or durable.get("decision") != "OBSERVED"
            or durable.get("hook_event_name") != "PostToolUse"
            or durable.get("durable_record_sha256")
            != _sha(
                {
                    key: deepcopy(value)
                    for key, value in durable.items()
                    if key != "durable_record_sha256"
                }
            )
            or not isinstance(durable_native, Mapping)
            or durable_native.get("grant_state") != "POST_OBSERVED"
            or durable_native.get("outcome") != "completed"
            or not isinstance(result_binding, Mapping)
            or result_binding.get("schema")
            != "orch-dork/native-spawn-result/v1"
            or lane_row is None
            or not isinstance(observed_action, Mapping)
            or lane_row.get("lane_id")
            != (observed_action.get("lane_ids") or [None])[0]
            or not _IDENTIFIER.fullmatch(str(worker_id or ""))
            or not observed_action_link_valid
        ):
            _issue(issues, "observed_spawn_stall:snapshot_invalid")
        else:
            event_path = (
                self.plugin_data
                / "project-ground/events"
                / hashlib.sha256(
                    str(identity["root_session_id"]).encode("utf-8")
                ).hexdigest()
                / (str(durable["report_sha256"]) + ".json")
            )
            try:
                persisted_durable = owned_file.read_owned_json(
                    event_path,
                    max_bytes=MAX_EVENT_BYTES,
                    required_mode=0o600,
                )
                current_ground = owned_file.read_owned_json(
                    self.plugin_data / "project-ground/current.json",
                    max_bytes=MAX_RUNTIME_FILE_BYTES,
                )
            except (OSError, ValueError, json.JSONDecodeError):
                persisted_durable = None
                current_ground = None
            if (
                persisted_durable != durable
                or current_ground != snapshot.get("project_ground_current")
            ):
                _issue(
                    issues, "observed_spawn_stall:durable_state_mismatch"
                )

        rollout_reference = evidence.get("worker_rollout_artifact")
        rollout_raw = b""
        if (
            not isinstance(rollout_reference, Mapping)
            or set(rollout_reference)
            != {"path", "artifact_sha256", "size_bytes"}
            or not _DIGEST.fullmatch(
                str(rollout_reference.get("artifact_sha256", ""))
            )
            or type(rollout_reference.get("size_bytes")) is not int
            or rollout_reference.get("size_bytes", 0) < 1
        ):
            _issue(
                issues, "observed_spawn_stall:worker_rollout:reference_invalid"
            )
        else:
            candidate = Path(str(rollout_reference.get("path", "")))
            rollout_path: Path | None = None
            try:
                rollout_path = candidate.resolve(strict=True)
                rollout_raw = owned_file.read_owned_bytes(
                    rollout_path,
                    max_bytes=2_097_152,
                    required_mode=0o600,
                )
            except (OSError, ValueError):
                rollout_path = None
            if (
                rollout_path is None
                or not candidate.is_absolute()
                or candidate.is_symlink()
                or snapshot_path is None
                or rollout_path.parent != snapshot_path.parent
                or hashlib.sha256(rollout_raw).hexdigest()
                != rollout_reference.get("artifact_sha256")
                or len(rollout_raw) != rollout_reference.get("size_bytes")
                or str(worker_id or "").encode("utf-8") not in rollout_raw
                or b"TERMINAL_STATE_RECORDED" in rollout_raw
            ):
                _issue(
                    issues,
                    "observed_spawn_stall:worker_rollout:reference_invalid",
                )

        runtime_value = evidence.get("historical_runtime_report")
        runtime = runtime_value if isinstance(runtime_value, Mapping) else {}
        runtime_core = {
            key: deepcopy(value)
            for key, value in runtime.items()
            if key != "report_sha256"
        }
        if (
            not isinstance(runtime_value, Mapping)
            or runtime.get("schema")
            != PRE_NATIVE_FAILURE_RUNTIME_REPORT_SCHEMA
            or runtime.get("report_sha256") != _sha(runtime_core)
        ):
            _issue(issues, "observed_spawn_stall:runtime_report_invalid")
        else:
            try:
                observed_runtime = _pre_native_failure_runtime_report(
                    str(runtime.get("root", "")),
                    expected_package_digest=str(
                        runtime.get("package_digest", "")
                    ),
                )
            except ValueError:
                observed_runtime = None
            if (
                observed_runtime != runtime
                or Path(str(runtime.get("root", ""))).resolve()
                != self.plugin_manifest_path.parent.parent
            ):
                _issue(issues, "observed_spawn_stall:runtime_report_mismatch")
        return sorted(issues)

    def _post_observed_continuation_sealed(
        self, grant: Mapping[str, Any], action: Mapping[str, Any]
    ) -> bool:
        """Whether the bound continuation's durable PostTool record seals the
        completed wire result its grant claims, for exactly these lanes."""

        posttool, issues = self._validate_hook_action_report(
            str(grant.get("posttool_report_sha256")), action
        )
        native = (
            posttool.get("native_controller")
            if isinstance(posttool, Mapping)
            else None
        )
        if issues or not isinstance(native, Mapping):
            return False
        binding = native.get("result_binding")
        return bool(
            native.get("grant_state") == "POST_OBSERVED"
            and native.get("outcome") == "completed"
            and native.get("action_id") == action.get("action_id")
            and native.get("tool_use_id") == grant.get("tool_use_id")
            and native.get("result_sha256") == grant.get("result_sha256")
            and isinstance(binding, Mapping)
            and native_result.normalize_native_result(
                binding,
                action_kind=action.get("kind"),
                expected_lane_ids=action.get("lane_ids"),
                outcome="completed",
            )
            == binding
            and _sha(binding) == grant.get("result_binding_sha256")
        )

    def terminalize_owner_closed_ack_stall(self, program: Any) -> dict[str, Any]:
        """Close an exact unused continuation after the dedicated owner closed.

        V1 requires two ACK-only workers and a denied first continuation. V2
        additionally proves the completed first continuation and its zero-tool
        handoff before accepting the denied second action. V3 proves a truncated
        control result after both ACKs, before any continuation. None resumes work.
        """

        controller_id = program.get("controller_id") if isinstance(program, Mapping) else None
        current = None
        state = None
        hook_sha = None
        try:
            if not isinstance(program, Mapping) or set(program) != {
                "schema", "controller_id", "expected_cursor", "artifacts",
                "historical_runtime_root", "historical_package_digest",
            } or native_grant_store.owner_closed_ack_cut_for_program(program.get("schema")) is None:
                raise ValueError("owner_closed_ack_stall:program_invalid")
            if not _IDENTIFIER.fullmatch(str(controller_id)) or not _cursor_valid(program["expected_cursor"]):
                raise ValueError("owner_closed_ack_stall:program_invalid")
            with self._locked():
                run_id = _controller_run_id(controller_id)
                if not self.grants.owner_matches(controller_id, run_id) or not self.grants.custody_valid():
                    raise ValueError("owner_closed_ack_stall:controller_not_active")
                state, rows = self._state(run_id, recover_provisional=False)
                current = _cursor(rows)
                cursor_issue = self._expected_cursor_issue(program["expected_cursor"], current)
                if cursor_issue:
                    raise ValueError(cursor_issue)
                identity = state["activation"]["identity"]
                if not self._hook_runtime_matches(identity):
                    raise ValueError("owner_closed_ack_stall:historical_runtime_not_active")
                authority = self.grants.canonical_authority()
                capacity = self.tower.read_shared_capacity_authority()
                receipt = _owner_closed_ack_stall_receipt(
                    self, program, state=state, authority=authority, capacity=capacity,
                )
                closed_stage = {
                    "schema": OBSERVED_SPAWN_STALL_STAGE_REPORT_SCHEMA,
                    "operation": "observed_spawn_stall_terminalization",
                    "status": "PASS",
                    "disposition": "OBSERVED_SPAWN_STALL_TERMINALIZED",
                    "issues": [], "receipt": receipt,
                    "next_action": "terminal_capacity_settlement",
                }
                intent_cursor = self._append(run_id, "stage_intent", {
                    "operation": "observed_spawn_stall_terminalization",
                    "failure_evidence_sha256": receipt["failure_evidence_sha256"],
                    "evaluation_time": self._evaluation_time().isoformat(),
                    "proposed_action_sha256": None,
                })
                result_cursor = self._append(run_id, "stage_result", {
                    "intent_cursor": intent_cursor, "stage_report": closed_stage,
                    "action": None, "capacity_guard": None, "terminal": True,
                    "cleanup_required": False,
                    "terminal_evidence_sha256": _sha(closed_stage), "issues": [],
                })
                current = result_cursor
                state, _ = self._state(run_id, recover_provisional=False)
                hook_sha = self._sync_hook(controller_id=controller_id, cursor=result_cursor, state=state)
                if not self.grants.custody_valid() or not self._hook_runtime_matches(identity):
                    raise ValueError("owner_closed_ack_stall:post_commit_custody_invalid")
                return self._base_report(
                    controller_id=controller_id, status="PASS",
                    decision="OBSERVED_SPAWN_STALL_TERMINALIZED", issues=[],
                    cursor=result_cursor, state=state, hook_state_sha256=hook_sha,
                )
        except (OSError, KeyError, TypeError, ValueError) as error:
            return self._base_report(
                controller_id=controller_id, status="BLOCKED", decision="CONTROLLER_REFUSED",
                issues=[str(error) if isinstance(error, ValueError) else "owner_closed_ack_stall:" + type(error).__name__],
                cursor=current, state=state, hook_state_sha256=hook_sha,
            )

    def terminalize_observed_spawn_stall(
        self, program: Any
    ) -> dict[str, Any]:
        """Close one batch that stalled after one spawn completed durably.

        The lifecycle can legitimately reach one of five exact cuts: the
        owner dies before advancing the observed first spawn, or it advances
        that result and dies after authorizing but before dispatching the next
        lane, or every spawn completes and every worker dies before its first
        hook event so the drained batch waits for acknowledgements that never
        come, or the drained batch advances to the first continuation, the
        hook seals its completed wire result, and the owner dies when its
        retained observation is refused (generation 48), or every continuation
        is reconciled, the controller records worker_results, and the owner
        dies at the next decision with no action bound (generation 49).  Every
        lane the batch reserved stays held, so the run can neither
        progress nor be released.  The released lanes are derived from the
        batch action itself: lanes that never started are named as such rather
        than inferred from a batch result that never existed, and lanes that
        did start are named with the worker each one created.
        """

        top_fields = {
            "schema",
            "controller_id",
            "expected_cursor",
            "failure_evidence",
        }
        if not isinstance(program, Mapping) or set(program) != top_fields:
            return self._base_report(
                controller_id=(
                    program.get("controller_id")
                    if isinstance(program, Mapping)
                    else None
                ),
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=["observed_spawn_stall:program_shape_invalid"],
            )
        value = deepcopy(dict(program))
        controller_id = value.get("controller_id")
        if (
            value.get("schema")
            != OBSERVED_SPAWN_STALL_TERMINALIZATION_PROGRAM_SCHEMA
            or not _IDENTIFIER.fullmatch(str(controller_id))
            or not _cursor_valid(value.get("expected_cursor"))
            or len(_canonical(value)) > MAX_PROGRAM_BYTES
        ):
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="PROGRAM_REFUSED",
                issues=["observed_spawn_stall:program_invalid"],
            )

        state: Mapping[str, Any] | None = None
        current: Mapping[str, Any] | None = None
        try:
            with self._locked():
                run_id = _controller_run_id(str(controller_id))
                if (
                    not self.grants.owner_matches(str(controller_id), run_id)
                    or not self.store.exists(run_id)
                    or not self.grants.custody_valid()
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=["observed_spawn_stall:controller_not_active"],
                    )
                state, rows = self._state(run_id)
                current = _cursor(rows)
                cursor_issue = self._expected_cursor_issue(
                    value.get("expected_cursor"), current
                )
                if cursor_issue is not None:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[cursor_issue],
                        cursor=current,
                        state=state,
                    )
                activation = state.get("activation")
                identity = (
                    activation.get("identity")
                    if isinstance(activation, Mapping)
                    and isinstance(activation.get("identity"), Mapping)
                    else None
                )
                if not self._hook_runtime_matches(identity):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "observed_spawn_stall:"
                            "historical_runtime_not_active"
                        ],
                        cursor=current,
                        state=state,
                    )
                action = state.get("action")
                grant = state.get("grant")
                stage_report = state.get("stage_report")
                action_evidence = state.get("action_evidence")
                prior_evidence = state.get("last_action_evidence")
                prior_action = (
                    prior_evidence.get("action")
                    if isinstance(prior_evidence, Mapping)
                    and isinstance(prior_evidence.get("action"), Mapping)
                    else None
                )
                batch_lane_ids = (
                    action.get("batch_lane_ids")
                    if isinstance(action, Mapping)
                    and isinstance(action.get("batch_lane_ids"), list)
                    else prior_action.get("batch_lane_ids")
                    if action is None
                    and isinstance(prior_action, Mapping)
                    and isinstance(prior_action.get("batch_lane_ids"), list)
                    else []
                )
                expected_lanes = [
                    str(identity.get("run_id")) + ":" + str(lane)
                    for lane in batch_lane_ids
                ]
                common_stall = bool(
                    isinstance(identity, Mapping)
                    and isinstance(stage_report, Mapping)
                    and stage_report.get("operation") == "capacity_admission"
                    and stage_report.get("status") == "PASS"
                    and stage_report.get("disposition") == "SPAWN_AUTHORIZED"
                    and stage_report.get("issues") == []
                    and isinstance(action, Mapping)
                    and action.get("kind") == "spawn"
                    and action.get("batch_kind") == "spawn"
                    and action.get("batch_phase") == "primary"
                    and len(batch_lane_ids) >= 2
                    and action.get("batch_size") == len(batch_lane_ids)
                    and all(
                        _IDENTIFIER.fullmatch(str(lane))
                        for lane in batch_lane_ids
                    )
                    and len(set(batch_lane_ids)) == len(batch_lane_ids)
                    and action.get("tool_name") == DIRECT_NATIVE_TOOLS["spawn"]
                    and isinstance(grant, Mapping)
                    and grant.get("action_sha256")
                    == action.get("action_sha256")
                    and state.get("terminal") is False
                    and state.get("pending_intent") is None
                    and state.get("action_outcome") is None
                    and state.get("cleanup_required") is False
                    and state.get("last_batch_result") is None
                )
                direct_observed_stall = bool(
                    common_stall
                    and action.get("batch_index") == 0
                    and action.get("lane_ids") == [batch_lane_ids[0]]
                    and grant.get("state") == "POST_OBSERVED"
                    and grant.get("outcome") == "completed"
                    and isinstance(grant.get("tool_use_id"), str)
                    and bool(grant.get("tool_use_id", "").strip())
                    and all(
                        _DIGEST.fullmatch(str(grant.get(field, "")))
                        is not None
                        for field in (
                            "pretool_event_sha256",
                            "pretool_report_sha256",
                            "result_sha256",
                            "result_binding_sha256",
                            "posttool_report_sha256",
                        )
                    )
                    and state.get("grant_state") == "POST_OBSERVED"
                    and state.get("seen_action_ids")
                    == [action.get("action_id")]
                    and action_evidence == []
                    and prior_evidence is None
                )
                prior_result_binding = (
                    prior_evidence.get("result_binding")
                    if isinstance(prior_evidence, Mapping)
                    and isinstance(
                        prior_evidence.get("result_binding"), Mapping
                    )
                    else None
                )
                prior_lanes = (
                    prior_result_binding.get("lanes")
                    if isinstance(prior_result_binding, Mapping)
                    and isinstance(
                        prior_result_binding.get("lanes"), list
                    )
                    else None
                )
                advanced_undispatched_stall = bool(
                    common_stall
                    and len(batch_lane_ids) == 2
                    and action.get("batch_size") == 2
                    and action.get("batch_index") == 1
                    and action.get("lane_ids") == [batch_lane_ids[1]]
                    and grant.get("state") == "AUTHORIZED"
                    and all(
                        grant.get(field) is None
                        for field in (
                            "pretool_event_sha256",
                            "pretool_report_sha256",
                            "tool_use_id",
                            "outcome",
                            "result_sha256",
                            "result_binding_sha256",
                            "posttool_report_sha256",
                        )
                    )
                    and state.get("grant_state") == "AUTHORIZED"
                    and isinstance(prior_evidence, Mapping)
                    and set(prior_evidence)
                    == {
                        "action",
                        "pretool_report_sha256",
                        "pretool_durable_record_sha256",
                        "posttool_report_sha256",
                        "posttool_durable_record_sha256",
                        "result_binding",
                    }
                    and isinstance(prior_action, Mapping)
                    and prior_action.get("kind") == "spawn"
                    and prior_action.get("tool_name")
                    == DIRECT_NATIVE_TOOLS["spawn"]
                    and prior_action.get("batch_index") == 0
                    and prior_action.get("lane_ids") == [batch_lane_ids[0]]
                    and all(
                        prior_action.get(field) == action.get(field)
                        for field in (
                            "actor_thread_id",
                            "adapter_sha256",
                            "batch_id",
                            "batch_kind",
                            "batch_lane_ids",
                            "batch_phase",
                            "batch_requests",
                            "batch_requests_sha256",
                            "batch_schema",
                            "batch_size",
                            "controller_id",
                            "predecessor_receipt_sha256",
                        )
                    )
                    and all(
                        _DIGEST.fullmatch(
                            str(prior_evidence.get(field, ""))
                        )
                        is not None
                        for field in (
                            "pretool_report_sha256",
                            "pretool_durable_record_sha256",
                            "posttool_report_sha256",
                            "posttool_durable_record_sha256",
                        )
                    )
                    and isinstance(prior_result_binding, Mapping)
                    and prior_result_binding.get("schema")
                    == "orch-dork/native-spawn-result/v1"
                    and isinstance(prior_lanes, list)
                    and len(prior_lanes) == 1
                    and isinstance(prior_lanes[0], Mapping)
                    and prior_lanes[0].get("lane_id") == batch_lane_ids[0]
                    and _IDENTIFIER.fullmatch(
                        str(prior_lanes[0].get("agent_id", ""))
                    )
                    is not None
                    and state.get("seen_action_ids")
                    == [prior_action.get("action_id"), action.get("action_id")]
                    and action_evidence == [prior_evidence]
                )
                exact_stall = bool(
                    direct_observed_stall or advanced_undispatched_stall
                )
                batch_result = state.get("last_batch_result")
                batch_binding = (
                    native_result.spawn_result_binding(
                        batch_result.get("result_binding"),
                        batch_result.get("lane_ids"),
                    )
                    if isinstance(batch_result, Mapping)
                    and batch_result.get("kind") == "spawn"
                    else None
                )
                batch_lanes = (
                    deepcopy(list(batch_binding["lanes"]))
                    if isinstance(batch_binding, Mapping)
                    and isinstance(batch_binding.get("lanes"), list)
                    else []
                )
                evidence_rows = (
                    action_evidence
                    if isinstance(action_evidence, list)
                    and all(
                        isinstance(row, Mapping)
                        and isinstance(row.get("action"), Mapping)
                        for row in action_evidence
                    )
                    else []
                )
                # Generation 49: the spawn batch and the continuation batch
                # both drained, the owner reconciled every continuation, the
                # controller recorded worker_results, and the owner died at the
                # next decision with no action bound.  The spawn checks below
                # then read the spawn rows; the continuation rows that follow
                # them are checked as one drained continuation batch.
                last_observed_action = prior_action
                results_view = bool(
                    isinstance(identity, Mapping)
                    and isinstance(stage_report, Mapping)
                    and stage_report.get("operation") == "worker_results"
                    and stage_report.get("status") == "PASS"
                    and stage_report.get("disposition") == "RESULTS_OBSERVED"
                    and stage_report.get("issues") == []
                    and action is None
                    and grant is None
                    and isinstance(prior_action, Mapping)
                    and prior_action.get("kind") == "continue"
                    and len(batch_lane_ids) >= 2
                    and len(evidence_rows) == 2 * len(batch_lane_ids)
                )
                # Generation 86: the owner reconciled the first continuation,
                # the controller authorized the next one, and the hook sealed
                # its completed wire result before the owner's turn failed.
                # Its rows split the same way; the spawn batch result still
                # names every created worker.
                later_continuation_view = bool(
                    not results_view
                    and isinstance(identity, Mapping)
                    and isinstance(stage_report, Mapping)
                    and stage_report.get("operation") == "worker_start"
                    and isinstance(action, Mapping)
                    and action.get("kind") == "continue"
                    and isinstance(prior_action, Mapping)
                    and prior_action.get("kind") == "continue"
                    and len(batch_lane_ids) >= 2
                    and type(action.get("batch_index")) is int
                    and 1 <= action["batch_index"] < len(batch_lane_ids)
                    and len(evidence_rows)
                    == len(batch_lane_ids) + action["batch_index"]
                )
                continue_rows: list[Mapping[str, Any]] = []
                if results_view or later_continuation_view:
                    continue_rows = list(evidence_rows[len(batch_lane_ids):])
                    evidence_rows = list(evidence_rows[: len(batch_lane_ids)])
                    prior_evidence = evidence_rows[-1]
                    prior_action = prior_evidence["action"]
                if results_view:
                    spawn_bindings = [
                        native_result.spawn_result_binding(
                            row.get("result_binding"), [lane]
                        )
                        for row, lane in zip(evidence_rows, batch_lane_ids)
                    ]
                    batch_lanes = (
                        [deepcopy(dict(binding["lanes"][0])) for binding in spawn_bindings]
                        if all(
                            isinstance(binding, Mapping)
                            and isinstance(binding.get("lanes"), list)
                            and len(binding["lanes"]) == 1
                            and isinstance(binding["lanes"][0], Mapping)
                            for binding in spawn_bindings
                        )
                        else []
                    )
                # A spawn batch that drained completely: one durably observed
                # spawn row per lane, the last one being the prior evidence,
                # and the batch result naming every created worker.  Shared
                # by the drained-batch, post-observed-continuation and
                # worker-results cuts; the last reads the spawn rows' own
                # bindings because its batch result is the continuation's.
                drained_spawn_batch = bool(
                    isinstance(prior_evidence, Mapping)
                    and set(prior_evidence)
                    == {
                        "action",
                        "pretool_report_sha256",
                        "pretool_durable_record_sha256",
                        "posttool_report_sha256",
                        "posttool_durable_record_sha256",
                        "result_binding",
                    }
                    and isinstance(prior_action, Mapping)
                    and prior_action.get("kind") == "spawn"
                    and prior_action.get("batch_kind") == "spawn"
                    and prior_action.get("batch_phase") == "primary"
                    and prior_action.get("tool_name")
                    == DIRECT_NATIVE_TOOLS["spawn"]
                    and len(batch_lane_ids) >= 2
                    and prior_action.get("batch_size") == len(batch_lane_ids)
                    and prior_action.get("batch_lane_ids") == batch_lane_ids
                    and all(
                        _IDENTIFIER.fullmatch(str(lane))
                        for lane in batch_lane_ids
                    )
                    and len(set(batch_lane_ids)) == len(batch_lane_ids)
                    and prior_action.get("batch_index")
                    == len(batch_lane_ids) - 1
                    and prior_action.get("lane_ids") == [batch_lane_ids[-1]]
                    and len(evidence_rows) == len(batch_lane_ids)
                    and len(batch_lanes) == len(batch_lane_ids)
                    and evidence_rows[-1] == prior_evidence
                    and all(
                        row["action"].get("batch_index") == index
                        and row["action"].get("kind") == "spawn"
                        and row["action"].get("tool_name")
                        == DIRECT_NATIVE_TOOLS["spawn"]
                        and row["action"].get("lane_ids")
                        == [batch_lane_ids[index]]
                        and all(
                            row["action"].get(field)
                            == prior_action.get(field)
                            for field in (
                                "actor_thread_id",
                                "adapter_sha256",
                                "batch_id",
                                "batch_kind",
                                "batch_lane_ids",
                                "batch_phase",
                                "batch_requests",
                                "batch_requests_sha256",
                                "batch_schema",
                                "batch_size",
                                "controller_id",
                                "predecessor_receipt_sha256",
                            )
                        )
                        and all(
                            _DIGEST.fullmatch(str(row.get(field, "")))
                            is not None
                            for field in (
                                "pretool_report_sha256",
                                "pretool_durable_record_sha256",
                                "posttool_report_sha256",
                                "posttool_durable_record_sha256",
                            )
                        )
                        and native_result.spawn_result_binding(
                            row.get("result_binding"),
                            [batch_lane_ids[index]],
                        )
                        == {
                            "schema": "orch-dork/native-spawn-result/v1",
                            "lanes": [batch_lanes[index]],
                        }
                        for index, row in enumerate(evidence_rows)
                    )
                    and (
                        results_view
                        or (
                            isinstance(batch_result, Mapping)
                            and batch_result.get("batch_id")
                            == prior_action.get("batch_id")
                            and batch_result.get("lane_ids") == batch_lane_ids
                        )
                    )
                    and [row.get("lane_id") for row in batch_lanes]
                    == batch_lane_ids
                    and all(
                        _IDENTIFIER.fullmatch(str(row.get("agent_id", "")))
                        is not None
                        for row in batch_lanes
                    )
                    and len({row.get("agent_id") for row in batch_lanes})
                    == len(batch_lanes)
                )
                spawn_action_ids = [
                    row["action"].get("action_id") for row in evidence_rows
                ]
                batch_complete_stall = bool(
                    not exact_stall
                    and isinstance(identity, Mapping)
                    and isinstance(stage_report, Mapping)
                    and stage_report.get("operation") == "capacity_admission"
                    and stage_report.get("status") == "PASS"
                    and stage_report.get("disposition") == "SPAWN_AUTHORIZED"
                    and stage_report.get("issues") == []
                    and action is None
                    and grant is None
                    and state.get("grant_state") is None
                    and state.get("action_outcome") == "completed"
                    and state.get("terminal") is False
                    and state.get("pending_intent") is None
                    and state.get("cleanup_required") is False
                    and drained_spawn_batch
                    and state.get("seen_action_ids") == spawn_action_ids
                )
                # Generation 48: the drained batch advanced through
                # worker_start to the first continuation, the hook sealed its
                # completed wire result, and the owner died when its retained
                # observation was refused.  The continuation stays bound with
                # a POST_OBSERVED grant, no outcome, and both lanes held.
                # Generation 86 left the same shape on the next continuation
                # after the owner had reconciled the earlier ones.
                post_observed_continuation_stall = bool(
                    not exact_stall
                    and not batch_complete_stall
                    and isinstance(identity, Mapping)
                    and isinstance(stage_report, Mapping)
                    and stage_report.get("operation") == "worker_start"
                    and stage_report.get("status") == "PASS"
                    and stage_report.get("disposition") == "WORK_AUTHORIZED"
                    and stage_report.get("issues") == []
                    and isinstance(action, Mapping)
                    and action.get("kind") == "continue"
                    and action.get("batch_kind") == "continue"
                    and action.get("batch_phase") == "primary"
                    and action.get("batch_index") == len(continue_rows)
                    and len(batch_lane_ids) > len(continue_rows)
                    and len(batch_lane_ids) >= 2
                    and action.get("batch_size") == len(batch_lane_ids)
                    and action.get("lane_ids")
                    == [batch_lane_ids[len(continue_rows)]]
                    and action.get("tool_name")
                    == DIRECT_NATIVE_TOOLS["continue"]
                    and isinstance(grant, Mapping)
                    and grant.get("action_sha256")
                    == action.get("action_sha256")
                    and grant.get("state") == "POST_OBSERVED"
                    and grant.get("outcome") == "completed"
                    and isinstance(grant.get("tool_use_id"), str)
                    and bool(grant.get("tool_use_id", "").strip())
                    and all(
                        _DIGEST.fullmatch(str(grant.get(field, "")))
                        is not None
                        for field in (
                            "pretool_event_sha256",
                            "pretool_report_sha256",
                            "result_sha256",
                            "result_binding_sha256",
                            "posttool_report_sha256",
                        )
                    )
                    and state.get("grant_state") == "POST_OBSERVED"
                    and state.get("action_outcome") is None
                    and state.get("terminal") is False
                    and state.get("pending_intent") is None
                    and state.get("cleanup_required") is False
                    and drained_spawn_batch
                    and state.get("seen_action_ids")
                    == [
                        *spawn_action_ids,
                        *[row["action"].get("action_id") for row in continue_rows],
                        action.get("action_id"),
                    ]
                    and (
                        not continue_rows
                        or (
                            continue_rows[-1]
                            == state.get("last_action_evidence")
                            and _reconciled_continue_rows_valid(
                                continue_rows,
                                batch_id=action.get("batch_id"),
                                batch_lane_ids=batch_lane_ids,
                                batch_lanes=batch_lanes,
                            )
                        )
                    )
                    and self._post_observed_continuation_sealed(grant, action)
                )
                results_bindings = (
                    stage_report.get("receipt", {}).get("bindings")
                    if results_view
                    and isinstance(stage_report.get("receipt"), Mapping)
                    and isinstance(
                        stage_report["receipt"].get("bindings"), Mapping
                    )
                    else None
                )
                last_continue_grant = (
                    self.grants.read_action(
                        str(last_observed_action.get("action_sha256"))
                    )
                    if results_view
                    else None
                )
                worker_results_stall = bool(
                    results_view
                    and not exact_stall
                    and not batch_complete_stall
                    and not post_observed_continuation_stall
                    and drained_spawn_batch
                    and len(continue_rows) == len(batch_lane_ids)
                    and continue_rows[-1] == state.get("last_action_evidence")
                    and isinstance(batch_result, Mapping)
                    and batch_result.get("kind") == "continue"
                    and batch_result.get("batch_id")
                    == last_observed_action.get("batch_id")
                    and batch_result.get("lane_ids") == batch_lane_ids
                    and native_result.continue_result_binding(
                        batch_result.get("result_binding"), batch_lane_ids
                    )
                    is not None
                    and _reconciled_continue_rows_valid(
                        continue_rows,
                        batch_id=last_observed_action.get("batch_id"),
                        batch_lane_ids=batch_lane_ids,
                        batch_lanes=batch_lanes,
                    )
                    and isinstance(results_bindings, Mapping)
                    and results_bindings.get("quality_phase") == "worker_results"
                    and results_bindings.get("current_wave_logical_lane_ids")
                    == batch_lane_ids
                    and sorted(
                        results_bindings.get("capacity_authority_lane_ids") or []
                    )
                    == sorted(expected_lanes)
                    and isinstance(results_bindings.get("lane_bindings"), list)
                    and [
                        (row.get("logical_worker_id"), row.get("worker_id"))
                        for row in results_bindings["lane_bindings"]
                        if isinstance(row, Mapping)
                    ]
                    == [(row["lane_id"], row["agent_id"]) for row in batch_lanes]
                    and state.get("grant_state") is None
                    and state.get("action_outcome") is None
                    and state.get("terminal") is False
                    and state.get("pending_intent") is None
                    and state.get("cleanup_required") is False
                    and state.get("seen_action_ids")
                    == [
                        *spawn_action_ids,
                        *[row["action"].get("action_id") for row in continue_rows],
                    ]
                    and isinstance(last_continue_grant, Mapping)
                    and last_continue_grant.get("action_sha256")
                    == last_observed_action.get("action_sha256")
                    and last_continue_grant.get("state") == "POST_OBSERVED"
                    and last_continue_grant.get("outcome") == "completed"
                    and isinstance(last_continue_grant.get("tool_use_id"), str)
                    and bool(last_continue_grant.get("tool_use_id", "").strip())
                )
                exact_stall = bool(
                    exact_stall
                    or batch_complete_stall
                    or post_observed_continuation_stall
                    or worker_results_stall
                )
                if not exact_stall:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "observed_spawn_stall:exact_stall_state_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                abandoned_action = (
                    last_observed_action
                    if worker_results_stall
                    else prior_action
                    if batch_complete_stall
                    else action
                )
                expected_lifecycle = (
                    {
                        "expected_binding_status": "WAITING",
                        "action_sha256": None,
                        "grant_state": None,
                        "tool_use_id": None,
                    }
                    if batch_complete_stall or worker_results_stall
                    else {
                        "expected_binding_status": "ACTIVE",
                        "action_sha256": action.get("action_sha256"),
                        "grant_state": grant.get("state"),
                        "tool_use_id": grant.get("tool_use_id"),
                    }
                )
                authority = self.grants.canonical_authority()
                lifecycle = (
                    authority.get("lifecycle")
                    if isinstance(authority, Mapping)
                    and isinstance(authority.get("lifecycle"), Mapping)
                    else None
                )
                if (
                    authority.get("status") != "VERIFIED"
                    or authority.get("tip") != current
                    or not isinstance(lifecycle, Mapping)
                    or lifecycle.get("expected_binding_status")
                    != expected_lifecycle["expected_binding_status"]
                    or lifecycle.get("terminal") is not False
                    or lifecycle.get("pending_intent") is not False
                    or lifecycle.get("cleanup_required") is not False
                    or lifecycle.get("action_sha256")
                    != expected_lifecycle["action_sha256"]
                    or lifecycle.get("grant_state")
                    != expected_lifecycle["grant_state"]
                    or lifecycle.get("tool_use_id")
                    != expected_lifecycle["tool_use_id"]
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "observed_spawn_stall:active_authority_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                capacity = self.tower.read_shared_capacity_authority()
                active = (
                    capacity.get("state", {}).get("active_lane_ids")
                    if isinstance(capacity, Mapping)
                    and isinstance(capacity.get("state"), Mapping)
                    else None
                )
                if (
                    capacity.get("status") != "VERIFIED"
                    or capacity.get("continuity_verified") is not True
                    or capacity.get("reason_codes") != []
                    or not isinstance(active, list)
                    or sorted(active) != sorted(expected_lanes)
                    or capacity.get("state_sha256")
                    != capacity.get("state", {}).get("state_sha256")
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "observed_spawn_stall:exact_capacity_required"
                        ],
                        cursor=current,
                        state=state,
                    )
                evidence_issues = self._observed_spawn_stall_evidence_issues(
                    value.get("failure_evidence"),
                    controller_id=str(controller_id),
                    authority=authority,
                    state=state,
                    capacity=capacity,
                )
                if evidence_issues:
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=evidence_issues,
                        cursor=current,
                        state=state,
                    )
                evidence = value["failure_evidence"]
                snapshot = evidence["terminal_snapshot"]
                durable_native = snapshot["durable_posttool_event"][
                    "native_controller"
                ]
                worker_id = durable_native["result_binding"]["lanes"][0][
                    "agent_id"
                ]
                created_lane_id = durable_native["result_binding"]["lanes"][
                    0
                ]["lane_id"]
                created_lanes = (
                    batch_lanes
                    if batch_complete_stall
                    or post_observed_continuation_stall
                    or worker_results_stall
                    else [{"lane_id": created_lane_id, "agent_id": worker_id}]
                )
                created_lane_ids = [row["lane_id"] for row in created_lanes]
                never_started = [
                    lane
                    for lane in batch_lane_ids
                    if lane not in created_lane_ids
                ]
                evaluation_time = self._evaluation_time().isoformat()
                intent = {
                    "operation": "observed_spawn_stall_terminalization",
                    "failure_evidence_sha256": evidence["evidence_sha256"],
                    "evaluation_time": evaluation_time,
                    "proposed_action_sha256": None,
                }
                intent_cursor = self._append(run_id, "stage_intent", intent)
                closed_stage = {
                    "schema": OBSERVED_SPAWN_STALL_STAGE_REPORT_SCHEMA,
                    "operation": "observed_spawn_stall_terminalization",
                    "status": "PASS",
                    "disposition": "OBSERVED_SPAWN_STALL_TERMINALIZED",
                    "issues": [],
                    "receipt": {
                        "failure_evidence_sha256": evidence[
                            "evidence_sha256"
                        ],
                        "terminal_snapshot_report_sha256": snapshot[
                            "report_sha256"
                        ],
                        "historical_runtime_report_sha256": evidence[
                            "historical_runtime_report"
                        ]["report_sha256"],
                        "historical_package_digest": evidence[
                            "historical_runtime_report"
                        ]["package_digest"],
                        "abandoned_task_id": snapshot["task_id"],
                        "abandoned_turn_id": snapshot["turn_id"],
                        "abandoned_action_id": abandoned_action["action_id"],
                        "abandoned_action_sha256": abandoned_action[
                            "action_sha256"
                        ],
                        "abandoned_tool_use_id": (
                            last_continue_grant.get("tool_use_id")
                            if worker_results_stall
                            else durable_native.get("tool_use_id")
                            if batch_complete_stall
                            else grant.get("tool_use_id")
                        ),
                        "observed_outcome": durable_native["outcome"],
                        "created_worker_id": worker_id,
                        "created_logical_lane_id": created_lane_id,
                        "created_lanes": created_lanes,
                        "never_started_logical_lane_ids": never_started,
                        "worker_rollout_artifact_sha256": evidence[
                            "worker_rollout_artifact"
                        ]["artifact_sha256"],
                        "worker_terminal_receipt_observed": False,
                        "worker_process_match_count": snapshot[
                            "worker_process_match_count"
                        ],
                        "owner_process_match_count": snapshot[
                            "owner_process_match_count"
                        ],
                        "owner_process_group_cleaned": (
                            snapshot["owner_process_match_count"] == 0
                        ),
                        "capacity_authority_state_sha256": capacity[
                            "state_sha256"
                        ],
                    },
                    "next_action": "terminal_capacity_settlement",
                }
                terminal_evidence_sha256 = _sha(closed_stage)
                result_cursor = self._append(
                    run_id,
                    "stage_result",
                    {
                        "intent_cursor": intent_cursor,
                        "stage_report": closed_stage,
                        "action": None,
                        "capacity_guard": None,
                        "terminal": True,
                        "cleanup_required": False,
                        "terminal_evidence_sha256": terminal_evidence_sha256,
                        "issues": [],
                    },
                )
                state, _rows = self._state(run_id)
                hook_sha = self._sync_hook(
                    controller_id=str(controller_id),
                    cursor=result_cursor,
                    state=state,
                )
                if (
                    not self.grants.custody_valid()
                    or not self._hook_runtime_matches(identity)
                ):
                    return self._base_report(
                        controller_id=controller_id,
                        status="BLOCKED",
                        decision="CONTROLLER_REFUSED",
                        issues=[
                            "observed_spawn_stall:post_commit_custody_invalid"
                        ],
                        cursor=result_cursor,
                        state=state,
                        hook_state_sha256=hook_sha,
                    )
                return self._base_report(
                    controller_id=controller_id,
                    status="PASS",
                    decision="OBSERVED_SPAWN_STALL_TERMINALIZED",
                    issues=[],
                    cursor=result_cursor,
                    state=state,
                    hook_state_sha256=hook_sha,
                )
        except Exception as error:
            return self._base_report(
                controller_id=controller_id,
                status="BLOCKED",
                decision="CONTROLLER_REFUSED",
                issues=["observed_spawn_stall:" + type(error).__name__],
                cursor=current,
                state=state,
            )


def _owner_closed_completed_worker(
    path, *, reference, worker, expected_spec, root_id, worker_id,
    completed, first_input, frozen_spec,
):
    """Prove ACK then one completed, zero-tool, TaskSpec-bound continuation."""
    raw = owned_file.read_owned_bytes(path, max_bytes=4_194_304, required_mode=0o600)
    if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise ValueError("owner_closed_ack_stall:artifact_changed")
    contexts, starts, finishes, messages = [], [], [], []
    for line in raw.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        value = row.get("payload")
        if not isinstance(value, Mapping):
            raise ValueError("owner_closed_ack_stall:worker_not_completed")
        kind = value.get("type")
        if row.get("type") == "turn_context":
            contexts.append(value)
        elif row.get("type") == "event_msg" and kind == "task_started":
            starts.append(value.get("turn_id"))
        elif row.get("type") == "event_msg" and kind == "task_complete":
            finishes.append(value)
        elif row.get("type") == "response_item":
            if kind not in {"message", "reasoning", "compaction"}:
                raise ValueError("owner_closed_ack_stall:worker_called_tool")
            if kind == "message" and value.get("role") == "user":
                messages.extend(item.get("text") for item in value.get("content", [])
                                if isinstance(item, Mapping))
    ids = [value.get("turn_id") for value in contexts]
    expected_ack = route_policy.task_spec_pre_work_receipt(
        logical_lane_id=expected_spec["logical_worker_id"],
        task_spec_sha256=expected_spec["task_spec_sha256"],
    )
    observation = worker["runtime_observation"]
    if (
        worker.get("session_id") != worker_id
        or worker.get("parent_thread_id") != root_id
        or worker.get("spawn_parent_thread_id") != root_id
        or worker.get("task_complete_count") != 2
        or worker.get("terminal_error_present") is not False
        or len(ids) != 2 or len(set(ids)) != 2
        or ids != starts or ids != [value.get("turn_id") for value in finishes]
        or sorted(ids) != worker.get("turn_ids")
        or ids[-1] != completed["submission_id"]
        or any(value.get("model") != expected_spec["model"]
               or value.get("effort") != expected_spec["effort"] for value in contexts)
        or any(value.get("error") is not None for value in finishes)
        or messages.count(first_input["message"]) != 1
        or routing_verify.validate_session_runtime_observation(observation).get("valid") is not True
        or observation.get("route", {}).get("model") != expected_spec["model"]
        or observation.get("route", {}).get("effort") != expected_spec["effort"]
        or observation.get("usage", {}).get("tool_calls") != 0
    ):
        raise ValueError("owner_closed_ack_stall:worker_not_completed")
    ack = json.loads(finishes[0]["last_agent_message"])
    handoff = json.loads(finishes[1]["last_agent_message"])
    if (
        ack != expected_ack
        or adaptive_contracts.validate_handoff_receipt(handoff, task_spec=frozen_spec).get("valid") is not True
        or handoff.get("task_spec_sha256") != expected_spec["task_spec_sha256"]
        or observation.get("terminal_schema") != adaptive_contracts.HANDOFF_RECEIPT_SCHEMA
        or observation.get("terminal_json_sha256") != _sha(handoff)
    ):
        raise ValueError("owner_closed_ack_stall:worker_not_completed")


def _owner_closed_ack_require(condition: bool, detail: str) -> None:
    if not condition:
        raise ValueError("owner_closed_ack_stall:" + detail)


def _owner_closed_pre_turn_reference(program, *, artifacts, identity):
    """Bind the sealed pre-turn report to the closed controller's root identity."""

    require = _owner_closed_ack_require
    pre_turn = artifacts["pre_turn"].document
    pre_identity = pre_turn.get("controller") or {}
    require(
        pre_turn.get("schema") == "orch-dork/qualification-successor-pre-turn/v5"
        and pre_turn.get("status") == "PASS"
        and pre_turn.get("decision") == "READY_FOR_SESSION_START"
        and pre_turn.get("report_sha256") == _sha({key: value for key, value in pre_turn.items() if key != "report_sha256"})
        and pre_identity.get("controller_id") == program["controller_id"]
        and pre_identity.get("root_thread_id") == identity["root_thread_id"]
        and pre_identity.get("root_session_id") == identity["root_session_id"]
        and pre_identity.get("root_model") == identity["root_model"],
        "pre_turn_binding_invalid",
    )
    return pre_turn, {
        "pre_turn_report_path": str(artifacts["pre_turn"].path),
        "pre_turn_report_sha256": pre_turn["report_sha256"],
    }


def _owner_closed_unreadable_control_proof(
    program, *, artifacts, state, turns, terminal,
):
    """Join the closed owner's unreadable control call to the original rollout.

    Truncated text is evidence of a refused projection, never an action source.
    The independently retained canonical action and grants supply authority.
    """

    require = _owner_closed_ack_require
    identity = state["activation"]["identity"]
    rows = state["action_evidence"]
    lanes = native_result.spawn_result_binding(
        state["last_batch_result"]["result_binding"], state["action"]["batch_lane_ids"],
    )["lanes"]
    pre_turn, reference = _owner_closed_pre_turn_reference(program, artifacts=artifacts, identity=identity)
    require(
        len(turns) == 4 and all(turn.get("status") == "completed" and turn.get("error") is None for turn in turns)
        and all(isinstance(turn.get("id"), str) and turn["id"] for turn in turns)
        and len({turn["id"] for turn in turns}) == 4, "control_turns_invalid",
    )
    controls = [item for turn in turns for item in turn["items"] if item.get("type") == "mcpToolCall"]
    require(
        len(controls) == 2
        and [call.get("tool") for call in controls] == ["authorize_issue94_successor_first_action", "advance_issue94_successor_after_native_action"]
        and controls[0] in turns[0]["items"] and controls[1] in turns[-1]["items"]
        and all(call.get("server") == "orch-dork" and call.get("status") == "completed"
                and call.get("error") is None and call.get("arguments") == reference
                and isinstance(call.get("id"), str) and call["id"] for call in controls)
        and controls[0]["id"] != controls[1]["id"], "control_attribution_invalid",
    )
    lost = controls[1]
    result = lost.get("result")
    require(isinstance(result, Mapping) and result.get("structuredContent") is None, "control_result_not_unreadable")
    content = result.get("content")
    require(isinstance(content, list) and len(content) == 1 and isinstance(content[0], Mapping)
            and content[0].get("type") == "text" and isinstance(content[0].get("text"), str), "control_result_not_unreadable")
    try:
        json.loads(content[0]["text"])
    except json.JSONDecodeError:
        pass
    else:
        raise ValueError("owner_closed_ack_stall:control_result_not_unreadable")

    root_sha256 = program["artifacts"]["root_rollout"]["sha256"]
    read = _read_post_spawn_rollout_rows(
        artifacts["root_rollout"].path, expected_sha256=root_sha256,
    )
    root = _post_spawn_rollout_summary_from_rows(
        read, expected_sha256=root_sha256, role="root", logical_lane_id=None,
    )
    require(
        root.get("session_id") == identity["root_session_id"] and root.get("parent_thread_id") is None
        and root.get("candidate_commit") == terminal["source_commit"]
        and root.get("task_complete_count") == 4 and root.get("terminal_error_present") is False
        and root.get("turn_ids") == sorted(turn["id"] for turn in turns), "root_rollout_invalid",
    )
    calls = []
    outputs = {}
    for row in read.rows:
        payload = row.get("payload", {})
        if row.get("type") != "response_item" or not isinstance(payload, Mapping):
            continue
        kind = payload.get("type")
        require(kind in {"message", "reasoning", "function_call", "function_call_output"}, "extra_root_call")
        if kind == "function_call":
            calls.append(payload)
        elif kind == "function_call_output":
            call_id = payload.get("call_id")
            require(isinstance(call_id, str) and call_id not in outputs, "root_output_invalid")
            outputs[call_id] = payload.get("output")
    require(
        [(call.get("namespace"), call.get("name")) for call in calls] == [
            ("mcp__orch_dork", "authorize_issue94_successor_first_action"),
            ("multi_agent_v1", "spawn_agent"), ("multi_agent_v1", "spawn_agent"),
            ("multi_agent_v1", "wait_agent"),
            ("mcp__orch_dork", "advance_issue94_successor_after_native_action"),
        ] and all(isinstance(call.get("call_id"), str) and call["call_id"] for call in calls)
        and len({call["call_id"] for call in calls}) == 5
        and set(outputs) == {call["call_id"] for call in calls}, "root_call_inventory_invalid",
    )
    arguments = [json.loads(call.get("arguments", "")) for call in calls]
    require(calls[0]["call_id"] == controls[0]["id"] and calls[-1]["call_id"] == lost["id"]
            and arguments[0] == reference and arguments[-1] == reference, "control_attribution_invalid")
    native_items = [item for turn in turns for item in turn["items"] if item.get("type") == "collabAgentToolCall"]
    require([call["call_id"] for call in calls[1:4]] == [item.get("id") for item in native_items], "native_call_identity_invalid")
    for index, lane in enumerate(lanes):
        require(_sha(arguments[index + 1]) == rows[index]["action"]["tool_input_sha256"]
                and json.loads(outputs[calls[index + 1]["call_id"]]).get("agent_id") == lane["agent_id"], "spawn_evidence_invalid")
    workers = [lane["agent_id"] for lane in lanes]
    wait = json.loads(outputs[calls[3]["call_id"]])
    require(isinstance(arguments[3], Mapping) and arguments[3].get("targets") == workers
            and isinstance(wait, Mapping) and wait.get("timed_out") is False
            and isinstance(wait.get("status"), Mapping) and set(wait["status"]) == set(workers), "wait_ack_invalid")
    native_wait = next(item for turn in turns for item in turn["items"] if item.get("type") == "collabAgentToolCall" and item.get("tool") == "wait")
    for lane in lanes:
        worker = lane["agent_id"]
        message = native_wait["agentsStates"][worker].get("message")
        expected = route_policy.task_spec_pre_work_receipt(
            logical_lane_id=lane["lane_id"],
            task_spec_sha256=json.loads(next(row["action"]["tool_input"]["message"] for row in rows if row["action"]["lane_ids"] == [lane["lane_id"]]))["pre_work_receipt"]["task_spec_sha256"],
        )
        require(isinstance(message, str) and json.loads(message) == expected
                and wait["status"][worker] == {"completed": message}, "wait_ack_invalid")
    truncated = outputs[calls[-1]["call_id"]]
    require(isinstance(truncated, str) and re.search(r"…[0-9]+ tokens truncated…", truncated) is not None, "control_output_not_truncated")
    return {
        "control_call_id": lost["id"],
        "control_result_sha256": _sha(result),
        "pre_turn_report_sha256": pre_turn["report_sha256"],
    }


def _owner_closed_root_extra_advance_proof(
    program, *, artifacts, state, turns, terminal,
):
    """Join the root's own advance, made inside its second spawn turn, to the original rollout.

    The owner asks for exactly one native call per turn. Here the root made the
    second spawn and then advanced the controller itself, which authorized the
    first continuation the closed owner never sent. The readable advance result
    must name exactly that authorized action; the independently retained
    canonical action and grants still supply authority.
    """

    require = _owner_closed_ack_require
    identity = state["activation"]["identity"]
    action = state["action"]
    rows = state["action_evidence"]
    lanes = native_result.spawn_result_binding(
        state["last_batch_result"]["result_binding"], action["batch_lane_ids"],
    )["lanes"]
    pre_turn, reference = _owner_closed_pre_turn_reference(program, artifacts=artifacts, identity=identity)
    require(
        len(turns) == 3 and all(turn.get("status") == "completed" and turn.get("error") is None for turn in turns)
        and all(isinstance(turn.get("id"), str) and turn["id"] for turn in turns)
        and len({turn["id"] for turn in turns}) == 3, "control_turns_invalid",
    )
    calls_by_turn = [
        [item for item in turn["items"] if item.get("type") in {"mcpToolCall", "collabAgentToolCall"}]
        for turn in turns
    ]
    require(
        [[item.get("type") for item in calls] for calls in calls_by_turn]
        == [["mcpToolCall"], ["collabAgentToolCall"], ["collabAgentToolCall", "mcpToolCall"]],
        "root_turn_inventory_invalid",
    )
    controls = [calls_by_turn[0][0], calls_by_turn[2][1]]
    require(
        [call.get("tool") for call in controls]
        == ["authorize_issue94_successor_first_action", "advance_issue94_successor_after_native_action"]
        and all(call.get("server") == "orch-dork" and call.get("status") == "completed"
                and call.get("error") is None and call.get("arguments") == reference
                and isinstance(call.get("id"), str) and call["id"] for call in controls)
        and controls[0]["id"] != controls[1]["id"], "control_attribution_invalid",
    )
    advance = controls[1]
    result = advance.get("result")
    projection = result.get("structuredContent") if isinstance(result, Mapping) else None
    boundary = projection.get("boundary") if isinstance(projection, Mapping) else None
    require(
        isinstance(projection, Mapping) and isinstance(boundary, Mapping)
        and projection.get("status") == "PASS"
        and projection.get("decision") == "READY_FOR_NEXT_ACTION"
        and projection.get("controller_id") == program["controller_id"]
        and projection.get("action_projection") == {"action_sha256": action["action_sha256"]}
        and boundary.get("controller_stage_advanced") is True
        and boundary.get("native_action_called_by_bridge") is False
        and boundary.get("worker_acknowledgements_observed") == 2
        and boundary.get("next_action") == DIRECT_NATIVE_TOOLS["continue"],
        "advance_result_invalid",
    )

    root_sha256 = program["artifacts"]["root_rollout"]["sha256"]
    read = _read_post_spawn_rollout_rows(
        artifacts["root_rollout"].path, expected_sha256=root_sha256,
    )
    root = _post_spawn_rollout_summary_from_rows(
        read, expected_sha256=root_sha256, role="root", logical_lane_id=None,
    )
    require(
        root.get("session_id") == identity["root_session_id"] and root.get("parent_thread_id") is None
        and root.get("candidate_commit") == terminal["source_commit"]
        and root.get("task_complete_count") == 3 and root.get("terminal_error_present") is False
        and root.get("turn_ids") == sorted(turn["id"] for turn in turns), "root_rollout_invalid",
    )
    calls = []
    outputs = {}
    for row in read.rows:
        payload = row.get("payload", {})
        if row.get("type") != "response_item" or not isinstance(payload, Mapping):
            continue
        kind = payload.get("type")
        require(kind in {"message", "reasoning", "function_call", "function_call_output"}, "extra_root_call")
        if kind == "function_call":
            calls.append(payload)
        elif kind == "function_call_output":
            call_id = payload.get("call_id")
            require(isinstance(call_id, str) and call_id not in outputs, "root_output_invalid")
            outputs[call_id] = payload.get("output")
    require(
        [(call.get("namespace"), call.get("name")) for call in calls] == [
            ("mcp__orch_dork", "authorize_issue94_successor_first_action"),
            ("multi_agent_v1", "spawn_agent"), ("multi_agent_v1", "spawn_agent"),
            ("mcp__orch_dork", "advance_issue94_successor_after_native_action"),
        ] and all(isinstance(call.get("call_id"), str) and call["call_id"] for call in calls)
        and len({call["call_id"] for call in calls}) == 4
        and set(outputs) == {call["call_id"] for call in calls}, "root_call_inventory_invalid",
    )
    arguments = [json.loads(call.get("arguments", "")) for call in calls]
    require(calls[0]["call_id"] == controls[0]["id"] and calls[-1]["call_id"] == advance["id"]
            and arguments[0] == reference and arguments[-1] == reference, "control_attribution_invalid")
    spawns = [calls_by_turn[1][0], calls_by_turn[2][0]]
    require([call["call_id"] for call in calls[1:3]] == [item.get("id") for item in spawns], "native_call_identity_invalid")
    for index, lane in enumerate(lanes):
        require(_sha(arguments[index + 1]) == rows[index]["action"]["tool_input_sha256"]
                and json.loads(outputs[calls[index + 1]["call_id"]]).get("agent_id") == lane["agent_id"], "spawn_evidence_invalid")
    return {
        "control_call_id": advance["id"],
        "control_result_sha256": _sha(result),
        "pre_turn_report_sha256": pre_turn["report_sha256"],
    }


def _owner_closed_ack_stall_receipt(controller, program, *, state, authority, capacity):
    """Re-derive the exact closed-owner cut before any mutation."""

    require = _owner_closed_ack_require
    cut = native_grant_store.owner_closed_ack_cut_for_program(program["schema"])
    require(cut is not None, "program_invalid")
    unreadable = cut.control_result_unreadable
    control = cut.control_proof
    continuation_index = cut.completed_continuations

    action = state.get("action")
    logical_lanes = action.get("batch_lane_ids") if isinstance(action, Mapping) else None
    require(isinstance(logical_lanes, list) and len(logical_lanes) == 2 and all(isinstance(lane, str) and _IDENTIFIER.fullmatch(lane) for lane in logical_lanes) and len(set(logical_lanes)) == 2, "exact_state_required")
    references = program["artifacts"]
    require(isinstance(references, Mapping) and set(references) == {
        "owner_terminal", "root_rollout", cut.artifact_key, *logical_lanes,
    }, "artifacts_invalid")
    artifacts = {}
    for name, reference in references.items():
        require(isinstance(reference, Mapping) and set(reference) == {"path", "sha256"}, "reference_invalid")
        path = Path(reference["path"])
        require(path.is_absolute() and not path.is_symlink(), "reference_invalid")
        raw = owned_file.read_owned_bytes(path, max_bytes=4_194_304, required_mode=0o600)
        require(_DIGEST.fullmatch(str(reference["sha256"])) and hashlib.sha256(raw).hexdigest() == reference["sha256"], "artifact_changed")
        document = None
        if name in {"owner_terminal", "pretool_denial", "pre_turn"}:
            _, document, _ = _read_post_spawn_json_artifact(path, expected_sha256=reference["sha256"], label="owner_closed_ack_stall:" + name)
        artifacts[name] = _OwnerClosedAckArtifact(path, document)
    runtime = _pre_native_failure_runtime_report(
        program["historical_runtime_root"], expected_package_digest=program["historical_package_digest"],
    )
    require(Path(program["historical_runtime_root"]).resolve() / "hooks/project_ground_hook.py" == controller.hook_definition_path, "historical_hook_mismatch")
    identity = state["activation"]["identity"]
    action = state.get("action")
    grant = state.get("grant")
    stage = state.get("stage_report") or {}
    rows = state.get("action_evidence")
    require(
        state.get("terminal") is False and state.get("pending_intent") is None
        and state.get("cleanup_required") is False and state.get("action_outcome") is None
        and isinstance(action, Mapping) and action.get("kind") == "continue"
        and action.get("batch_kind") == "continue" and action.get("batch_phase") == "primary"
        and action.get("batch_index") == continuation_index and action.get("batch_size") == 2
        and action.get("batch_lane_ids") == logical_lanes
        and action.get("lane_ids") == [logical_lanes[continuation_index]] and action.get("tool_name") == DIRECT_NATIVE_TOOLS["continue"]
        and isinstance(grant, Mapping) and grant.get("state") == "AUTHORIZED"
        and grant.get("action_sha256") == action.get("action_sha256")
        and state.get("grant_state") == "AUTHORIZED"
        and all(grant.get(field) is None for field in (
            "pretool_event_sha256", "pretool_report_sha256", "tool_use_id", "outcome",
            "result_sha256", "result_binding_sha256", "posttool_report_sha256",
        ))
        and stage.get("operation") == "worker_start" and stage.get("status") == "PASS"
        and stage.get("disposition") == "WORK_AUTHORIZED" and stage.get("issues") == []
        and isinstance(rows, list) and len(rows) == 2 + continuation_index
        and all(isinstance(row, Mapping) and isinstance(row.get("action"), Mapping) for row in rows)
        and state.get("last_action_evidence") == rows[-1]
        and state.get("seen_action_ids") == [*(row["action"].get("action_id") for row in rows), action.get("action_id")]
        and controller._retained_hook_evidence_valid(state), "exact_state_required",
    )
    lifecycle = authority.get("lifecycle") or {}
    require(
        authority.get("status") == "VERIFIED" and authority.get("tip") == program["expected_cursor"]
        and lifecycle.get("expected_binding_status") == "ACTIVE"
        and lifecycle.get("terminal") is False and lifecycle.get("pending_intent") is False
        and lifecycle.get("cleanup_required") is False
        and lifecycle.get("action_sha256") == action["action_sha256"]
        and lifecycle.get("grant_state") == "AUTHORIZED" and lifecycle.get("tool_use_id") is None,
        "exact_authority_required",
    )
    batch = state.get("last_batch_result") or {}
    binding = native_result.spawn_result_binding(batch.get("result_binding"), logical_lanes)
    require(batch.get("kind") == "spawn" and binding is not None, "spawn_batch_required")
    lanes = binding["lanes"]
    require([row["lane_id"] for row in lanes] == logical_lanes and len({row["agent_id"] for row in lanes}) == 2, "spawn_batch_invalid")
    for index, (row, lane) in enumerate(zip(rows[:2], lanes)):
        spawn = row["action"]
        require(
            spawn.get("kind") == "spawn" and spawn.get("batch_index") == index
            and spawn.get("batch_size") == 2 and spawn.get("batch_lane_ids") == logical_lanes
            and spawn.get("lane_ids") == [lane["lane_id"]]
            and native_result.spawn_result_binding(row.get("result_binding"), [lane["lane_id"]])
            == {"schema": "orch-dork/native-spawn-result/v1", "lanes": [lane]}, "spawn_evidence_invalid",
        )
    expected_capacity = sorted(identity["run_id"] + ":" + lane["lane_id"] for lane in lanes)
    require(
        capacity.get("status") == "VERIFIED" and capacity.get("continuity_verified") is True
        and capacity.get("reason_codes") == [] and capacity.get("state", {}).get("active_lane_ids") == expected_capacity
        and capacity.get("state_sha256") == capacity.get("state", {}).get("state_sha256"), "exact_capacity_required",
    )
    terminal = artifacts["owner_terminal"].document
    terminal_issues = _owner_terminal_failure_issues(terminal, terminal_path=artifacts["owner_terminal"].path, expected_root_issue=cut.owner_terminal_issue)
    require(not terminal_issues, "owner_terminal_invalid:" + ",".join(terminal_issues))
    cleanup = terminal["host_cleanup"]
    require(all(_DIGEST.fullmatch(str(cleanup.get(field, ""))) for field in ("preparation_report_sha256", "app_server_argv_sha256", "owner_identity_sha256", "stdout_sha256", "stderr_sha256")), "owner_cleanup_identity_invalid")
    require(
        terminal.get("generation") == runtime.get("version")
        and terminal.get("runtime_package_digest") == runtime.get("package_digest")
        and cleanup.get("report_sha256") == _sha({key: value for key, value in cleanup.items() if key != "report_sha256"})
        and all(cleanup.get(key) is True for key in (
            "process_reaped", "output_monitor_closed",
        )),
        "owner_terminal_invalid",
    )
    for field, probe in (("pid", os.kill), ("pgid", os.killpg)):
        pid = cleanup.get(field)
        require(type(pid) is int and pid > 1, "owner_process_invalid")
        try:
            probe(pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise ValueError("owner_closed_ack_stall:owner_still_present")
    read_ref = terminal.get("last_thread_read")
    require(isinstance(read_ref, Mapping) and set(read_ref) == {"path", "sha256", "state"} and read_ref["state"] == "PRESERVED", "last_thread_read_invalid")
    _, thread_read, _ = _read_post_spawn_json_artifact(
        read_ref.get("path", ""), expected_sha256=read_ref.get("sha256", ""), label="owner_closed_ack_stall:last_thread_read",
    )
    response = thread_read.get("response")
    require(isinstance(response, Mapping), "native_projection_invalid")
    result = response.get("result")
    require(isinstance(result, Mapping), "native_projection_invalid")
    thread = result.get("thread")
    require(isinstance(thread, Mapping), "native_projection_invalid")
    require(thread.get("id") == identity["root_thread_id"], "root_identity_invalid")
    turns = thread.get("turns")
    require(isinstance(turns, list) and all(isinstance(turn, Mapping) for turn in turns), "native_projection_invalid")
    native_items = []
    for turn in turns:
        items = turn.get("items")
        require(isinstance(items, list) and all(isinstance(item, Mapping) for item in items), "native_projection_invalid")
        native_items.extend(item for item in items if item.get("type") == "collabAgentToolCall")
    require(
        [item.get("tool") for item in native_items]
        == ["spawnAgent", "spawnAgent"] + ([] if cut.root_extra_advance else ["wait"])
        + (["sendInput"] if cut.worker_terminal_observed else [])
        and all(item.get("senderThreadId") == identity["root_thread_id"] and item.get("status") == "completed" for item in native_items)
        and [item.get("receiverThreadIds") for item in native_items[:2]] == [[lane["agent_id"]] for lane in lanes],
        "native_projection_invalid",
    )
    if control:
        for index, row in enumerate(rows):
            spawn_grant = controller.grants.read_action(row["action"]["action_sha256"])
            require(isinstance(spawn_grant, Mapping)
                    and spawn_grant.get("state") == "POST_OBSERVED"
                    and spawn_grant.get("outcome") == "completed"
                    and spawn_grant.get("tool_use_id") == native_items[index].get("id"), "spawn_grant_identity_invalid")
    workers = [lane["agent_id"] for lane in lanes]
    # The extra-advance cut has no wait: each worker's own rollout below proves its ACK.
    wait = None if cut.root_extra_advance else native_items[2]
    agents = wait.get("agentsStates") if wait is not None else None
    require(
        cut.root_extra_advance
        or (
            (wait.get("receiverThreadIds") == workers
             or (cut.worker_terminal_observed and isinstance(wait.get("receiverThreadIds"), list)
                 and len(wait["receiverThreadIds"]) == 2
                 and sorted(wait["receiverThreadIds"]) == sorted(workers)))
            and isinstance(agents, Mapping)
            and set(agents) == set(workers) and wait.get("error") is None
            and all(isinstance(agents[worker], Mapping) and agents[worker].get("status") == "completed" for worker in workers)
        ),
        "native_projection_invalid",
    )
    completed = None
    if unreadable:
        control_proof = _owner_closed_unreadable_control_proof(
            program, artifacts=artifacts, state=state,
            turns=turns, terminal=terminal,
        )
    elif cut.root_extra_advance:
        control_proof = _owner_closed_root_extra_advance_proof(
            program, artifacts=artifacts, state=state,
            turns=turns, terminal=terminal,
        )
    else:
        root_reader = (_owner_closed_second_continuation_root_rollout_summary
                       if cut.worker_terminal_observed else _post_ack_bridge_root_rollout_summary)
        _, root = root_reader(
            artifacts["root_rollout"].path, expected_sha256=references["root_rollout"]["sha256"],
        )
        denied = root.get("denied_send_input") or {}
        require(
            root.get("session_id") == identity["root_session_id"]
            and root.get("spawn_worker_ids") == [lane["agent_id"] for lane in lanes]
            and root.get("send_input_call_count") == 1 + continuation_index and denied.get("namespace") == "multi_agent_v1"
            and denied.get("hook_tool_name") in {DIRECT_NATIVE_TOOLS["continue"], "multi_agent_v1send_input"}
            and denied.get("tool_input_sha256") != action["tool_input_sha256"]
            and (cut.worker_terminal_observed or (root.get("bridge_refusals") == []
                            and root.get("blocked_bridge_invocation_count") == 0)),
            "root_rollout_invalid",
        )
        completed = None
        if cut.worker_terminal_observed:
            prior = rows[-1]
            first = prior["action"]
            first_grant = controller.grants.read_action(first.get("action_sha256", ""))
            completed = root["completed_send_input"]
            continued = native_items[-1]
            submission = completed["submission_id"]
            require(
                first.get("kind") == "continue" and first.get("batch_kind") == "continue"
                and first.get("batch_phase") == "primary" and first.get("batch_index") == 0
                and first.get("batch_size") == 2 and first.get("batch_id") == action.get("batch_id")
                and first.get("batch_lane_ids") == logical_lanes
                and first.get("batch_requests") == action.get("batch_requests")
                and first.get("lane_ids") == [logical_lanes[0]]
                and first.get("tool_input", {}).get("target") == lanes[0]["agent_id"]
                and action.get("tool_input", {}).get("target") == lanes[1]["agent_id"]
                and first.get("tool_input_sha256") == completed["tool_input_sha256"]
                and first.get("tool_name") == DIRECT_NATIVE_TOOLS["continue"]
                and isinstance(first_grant, Mapping) and first_grant.get("state") == "POST_OBSERVED"
                and first_grant.get("outcome") == "completed"
                and first_grant.get("tool_use_id") == completed["call_id"]
                and first_grant.get("result_sha256") == completed["result_sha256"]
                and prior.get("pretool_report_sha256") == first_grant.get("pretool_report_sha256")
                and prior.get("posttool_report_sha256") == first_grant.get("posttool_report_sha256")
                and prior.get("result_binding") == {
                    "schema": "orch-dork/native-continue-result/v1",
                    "submissions": [{"lane_id": logical_lanes[0], "submission": {"submission_id": submission}}],
                }
                and continued.get("receiverThreadIds") == [lanes[0]["agent_id"]]
                and continued.get("prompt") == first["tool_input"]["message"]
                and all(root["spawn_calls"][i]["tool_input_sha256"]
                        == rows[i]["action"]["tool_input_sha256"] for i in range(2)),
                "first_continuation_invalid",
            )
        denial = artifacts["pretool_denial"].document
        denial_native = denial.get("native_controller") or {}
        canonical_denial, denial_read_issue = controller._read_hook_event(str(denial.get("report_sha256", "")), identity)
        require(denial_read_issue is None, "denial_invalid")
        require(
            canonical_denial == denial and set(denial) == DURABLE_HOOK_EVENT_FIELDS
            and denial.get("schema") == DURABLE_HOOK_EVENT_SCHEMA
            and denial.get("durable_record_sha256") == _sha({key: value for key, value in denial.items() if key != "durable_record_sha256"})
            and denial.get("hook_event_name") == "PreToolUse" and denial.get("status") == "BLOCKED" and denial.get("decision") == "DENY"
            and denial.get("reason_codes") == ["native_controller:exact_action_required"]
            and denial.get("tool_input_sha256") == denied.get("tool_input_sha256")
            and denial.get("identity", {}).get("session_id") == identity["root_session_id"]
            and denial_native.get("controller_id") == program["controller_id"]
            and denial_native.get("controller_seq") == grant.get("controller_seq")
            and denial_native.get("action_id") == action["action_id"] and denial_native.get("status") == "ACTIVE"
            and denial_native.get("matched") is False and denial_native.get("grant_state") is None,
            "denial_invalid",
        )
    specs = {row["logical_worker_id"]: row for row in stage["receipt"]["bindings"]["task_specs"]}
    for lane in lanes:
        lane_id, worker_id = lane["lane_id"], lane["agent_id"]
        _, worker = _post_ack_bridge_worker_rollout_summary(
            artifacts[lane_id].path, expected_sha256=references[lane_id]["sha256"], logical_lane_id=lane_id, observer_id=identity["root_thread_id"],
        )
        if cut.worker_terminal_observed and lane_id == logical_lanes[0]:
            _owner_closed_completed_worker(
                artifacts[lane_id].path, reference=references[lane_id], worker=worker,
                expected_spec=specs[lane_id], root_id=identity["root_thread_id"],
                worker_id=worker_id, completed=completed, first_input=rows[-1]["action"]["tool_input"],
                frozen_spec=next((row["task_spec"] for row in state["activation"]["task_specs"]
                                 if row["logical_worker_id"] == lane_id), None),
            )
            continue
        observation = worker["runtime_observation"]
        expected_ack = route_policy.task_spec_pre_work_receipt(logical_lane_id=lane_id, task_spec_sha256=specs[lane_id]["task_spec_sha256"])
        require(
            worker.get("session_id") == worker_id and worker.get("parent_thread_id") == identity["root_thread_id"]
            and worker.get("spawn_parent_thread_id") == identity["root_thread_id"]
            and worker.get("task_complete_count") == 1 and worker.get("terminal_error_present") is False
            and len(worker.get("turn_ids", [])) == 1
            and routing_verify.validate_session_runtime_observation(observation).get("valid") is True
            and observation.get("terminal_schema") == route_policy.TASK_SPEC_PRE_WORK_RECEIPT_SCHEMA
            and observation.get("terminal_json_sha256") == _sha(expected_ack)
            and observation.get("route", {}).get("model") == specs[lane_id]["model"]
            and observation.get("route", {}).get("effort") == specs[lane_id]["effort"]
            and observation.get("usage", {}).get("tool_calls") == 0, "worker_not_ack_only",
        )
    return {
        "failure_cut": cut.failure_cut,
        "failure_evidence_sha256": _sha(program), "failure_artifacts": deepcopy(dict(references)),
        "historical_runtime_report_sha256": runtime["report_sha256"],
        "historical_package_digest": runtime["package_digest"],
        "abandoned_task_id": identity["root_thread_id"], "abandoned_action_id": action["action_id"],
        "abandoned_action_sha256": action["action_sha256"],
        "authorized_input_sha256": action["tool_input_sha256"],
        **(control_proof if control else {"denied_input_sha256": denied["tool_input_sha256"], "pretool_denial_report_sha256": denial["report_sha256"]}),
        "created_worker_id": lanes[-1]["agent_id"], "created_logical_lane_id": lanes[-1]["lane_id"],
        "created_lanes": deepcopy(lanes), "never_started_logical_lane_ids": [],
        "worker_terminal_receipt_observed": cut.worker_terminal_observed, "worker_process_match_count": 0,
        "owner_process_match_count": 0, "owner_process_group_cleaned": True,
        "capacity_authority_state_sha256": capacity["state_sha256"],
    }


def _owned_state_directory(value: str | os.PathLike[str]) -> Path:
    provided = Path(value).expanduser()
    if not provided.is_absolute() or provided.is_symlink():
        raise ValueError("state directory must be an absolute non-symlink path")
    provided.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = provided.resolve(strict=True)
    metadata = resolved.stat()
    if (
        not resolved.is_dir()
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        or metadata.st_mode & 0o022
    ):
        raise ValueError("state directory ownership or mode is unsafe")
    return resolved


def _source_roots(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for raw in values:
        name, separator, path_text = raw.partition("=")
        if not separator or not _IDENTIFIER.fullmatch(name):
            raise ValueError("source roots require NAME=/absolute/path")
        path = Path(path_text).expanduser()
        if not path.is_absolute() or path.is_symlink() or not path.is_dir():
            raise ValueError("source root must be an absolute non-symlink directory")
        result[name] = path.resolve(strict=True)
    return result


@contextmanager
def open_governed_native_controller(
    *,
    plugin_data: str | os.PathLike[str],
    hook_definition_path: str | os.PathLike[str],
    source_roots: Mapping[str, str | os.PathLike[str]],
) -> Iterator[GovernedNativeController]:
    """Own one canonical host bridge and close its store on every exit."""

    owned_plugin_data = _owned_state_directory(plugin_data)
    state_root = _owned_state_directory(owned_plugin_data / "governed-native")
    if not isinstance(source_roots, Mapping):
        raise ValueError("source_roots must be a mapping")
    encoded_roots: list[str] = []
    for name, raw_path in source_roots.items():
        if not isinstance(name, str) or not isinstance(raw_path, (str, os.PathLike)):
            raise ValueError("source roots require named paths")
        encoded_roots.append(name + "=" + os.fspath(raw_path))
    roots = _source_roots(encoded_roots)
    provided_hook = Path(hook_definition_path).expanduser()
    if (
        not provided_hook.is_absolute()
        or provided_hook.is_symlink()
        or not provided_hook.is_file()
    ):
        raise ValueError("hook definition must be an absolute non-symlink file")
    hook_definition = provided_hook.resolve(strict=True)
    store = run_store.SQLiteRunStore(
        native_grant_store.canonical_database_path(owned_plugin_data),
        max_payload_bytes=MAX_STORE_PAYLOAD_BYTES,
    )
    try:
        controller = GovernedNativeController(
            store=store,
            artifacts=artifact_ledger.FilesystemArtifactLedger(
                state_root / "artifacts"
            ),
            plugin_data=owned_plugin_data,
            hook_definition_path=hook_definition,
            source_roots=roots,
            now=lambda: datetime.now(timezone.utc),
        )
        yield controller
    finally:
        store.close()


def advance_governed_native_controller(
    program: Any,
    *,
    plugin_data: str | os.PathLike[str],
    hook_definition_path: str | os.PathLike[str],
    source_roots: Mapping[str, str | os.PathLike[str]],
) -> dict[str, Any]:
    """Advance through the one canonical provider-free host-owned bridge."""

    with open_governed_native_controller(
        plugin_data=plugin_data,
        hook_definition_path=hook_definition_path,
        source_roots=source_roots,
    ) as controller:
        return controller.advance(program)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Advance one provider-free governed native controller transition."
    )
    parser.add_argument(
        "--state-root",
        help="Compatibility assertion; when supplied it must equal PLUGIN_DATA/governed-native.",
    )
    parser.add_argument(
        "--plugin-data",
        default=os.environ.get("PLUGIN_DATA"),
        help="Codex plugin data root (defaults to PLUGIN_DATA).",
    )
    parser.add_argument("--hook-definition")
    parser.add_argument("--source-root", action="append", default=[])
    args = parser.parse_args(argv)
    if args.plugin_data is None:
        parser.error("--plugin-data or PLUGIN_DATA is required")
    try:
        plugin_data = _owned_state_directory(args.plugin_data)
        state_root = _owned_state_directory(plugin_data / "governed-native")
        if args.state_root is not None and Path(args.state_root).expanduser().resolve() != state_root:
            raise ValueError("state root must be the canonical plugin-data authority")
        roots = _source_roots(args.source_root)
        plugin_root = Path(__file__).resolve().parents[3]
        hook_definition = (
            Path(args.hook_definition).expanduser().resolve(strict=True)
            if args.hook_definition
            else plugin_root / "hooks" / "project_ground_hook.py"
        )
        payload = sys.stdin.buffer.read(MAX_PROGRAM_BYTES + 1)
        if len(payload) > MAX_PROGRAM_BYTES:
            raise ValueError("program exceeds maximum size")
        program = json.loads(payload.decode("utf-8"))
        report = advance_governed_native_controller(
            program,
            plugin_data=plugin_data,
            hook_definition_path=hook_definition,
            source_roots=roots,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
        observer_receipt.ObserverReceiptError,
    ) as error:
        core = {
            "schema": REPORT_SCHEMA,
            "policy_version": CONTROLLER_POLICY_VERSION,
            "status": "BLOCKED",
            "decision": "HOST_ADAPTER_REFUSED",
            "controller_id": None,
            "issues": ["host_adapter:" + type(error).__name__],
            "cursor": None,
            "stage_report": None,
            "next_stage_action": None,
            "action": None,
            "controller_state": {
                "terminal": False,
                "pending_intent": False,
                "action_outcome": None,
                "action_authorized": False,
                "grant_state": None,
                "cleanup_required": False,
            },
            "hook_state_sha256": None,
            "provider_free": True,
            "hosted_calls": 0,
            "model_calls": 0,
            "native_calls": 0,
            "task_creations": 0,
            "worker_creations": 0,
            "credential_reads": 0,
            "authority_grants_minted": 0,
            "native_action_authorizations": 0,
        }
        report = {**core, "report_sha256": _sha(core)}
    sys.stdout.write(_canonical(report).decode("utf-8") + "\n")
    return 0 if report.get("status") == "PASS" else 2

OBSERVED_SPAWN_STALL_TERMINALIZATION_PROGRAM_SCHEMA = (
    "orch-dork/observed-spawn-stall-terminalization-program/v1"
)
OBSERVED_SPAWN_STALL_EVIDENCE_SCHEMA = (
    "orch-dork/observed-spawn-stall-evidence/v1"
)
OBSERVED_SPAWN_STALL_TERMINAL_SNAPSHOT_SCHEMA = (
    "orch-dork/observed-spawn-stall-terminal-snapshot/v1"
)
OBSERVED_SPAWN_STALL_STAGE_REPORT_SCHEMA = (
    "orch-dork/observed-spawn-stall-terminalization-stage/v1"
)


def build_observed_spawn_stall_terminalization_program(
    *,
    controller_id: str,
    expected_cursor: Mapping[str, Any],
    terminal_snapshot_path: str | os.PathLike[str],
    expected_terminal_snapshot_artifact_sha256: str,
    worker_rollout_path: str | os.PathLike[str],
    expected_worker_rollout_artifact_sha256: str,
    historical_runtime_root: str | os.PathLike[str],
    expected_package_digest: str,
) -> dict[str, Any]:
    """Assemble one sealed closure for an observed spawn batch stall.

    The class is narrow on purpose: one spawn was authorized, dispatched and
    observed to complete, then the owner died either before recording it or
    after authorizing but before dispatching the next batch lane.  The demanded
    evidence is exactly what those failures produce -- the controller's sealed
    PostToolUse record, a terminal snapshot of the authority it stranded, and
    the rollout of the one worker that really started.  Lanes that never
    started are named from the batch action itself and are never inferred from
    a batch result that does not exist.
    """

    if not _IDENTIFIER.fullmatch(str(controller_id)) or not _cursor_valid(
        expected_cursor
    ):
        raise ValueError("observed_spawn_stall:identity_invalid")
    snapshot_path, snapshot = _read_pre_native_failure_artifact(
        terminal_snapshot_path,
        expected_sha256=expected_terminal_snapshot_artifact_sha256,
        label="observed_spawn_stall:terminal_snapshot",
    )
    rollout_path = Path(worker_rollout_path)
    try:
        rollout_resolved = rollout_path.resolve(strict=True)
        rollout_info = rollout_resolved.lstat()
        rollout_raw = owned_file.read_owned_bytes(
            rollout_resolved,
            max_bytes=2_097_152,
            required_mode=0o600,
        )
    except (OSError, ValueError) as error:
        raise ValueError(
            "observed_spawn_stall:worker_rollout:reference_invalid"
        ) from error
    if (
        not rollout_path.is_absolute()
        or rollout_path.is_symlink()
        or not stat.S_ISREG(rollout_info.st_mode)
        or rollout_resolved.parent != snapshot_path.parent
        or not _DIGEST.fullmatch(
            str(expected_worker_rollout_artifact_sha256)
        )
        or hashlib.sha256(rollout_raw).hexdigest()
        != expected_worker_rollout_artifact_sha256
    ):
        raise ValueError(
            "observed_spawn_stall:worker_rollout:reference_invalid"
        )
    runtime_report = _pre_native_failure_runtime_report(
        historical_runtime_root,
        expected_package_digest=expected_package_digest,
    )
    evidence_core = {
        "schema": OBSERVED_SPAWN_STALL_EVIDENCE_SCHEMA,
        "terminal_snapshot_artifact": {
            "path": str(snapshot_path),
            "artifact_sha256": expected_terminal_snapshot_artifact_sha256,
        },
        "terminal_snapshot": snapshot,
        "worker_rollout_artifact": {
            "path": str(rollout_resolved),
            "artifact_sha256": expected_worker_rollout_artifact_sha256,
            "size_bytes": len(rollout_raw),
        },
        "historical_runtime_report": runtime_report,
    }
    evidence = {**evidence_core, "evidence_sha256": _sha(evidence_core)}
    program = {
        "schema": OBSERVED_SPAWN_STALL_TERMINALIZATION_PROGRAM_SCHEMA,
        "controller_id": controller_id,
        "expected_cursor": deepcopy(dict(expected_cursor)),
        "failure_evidence": evidence,
    }
    if len(_canonical(program)) > MAX_PROGRAM_BYTES:
        raise ValueError("observed_spawn_stall:program_too_large")
    return program


__all__ = [
    "ACTION_OBSERVATION_SCHEMA",
    "ACTION_PROPOSAL_SCHEMA",
    "ACTION_SCHEMA",
    "ACTIVATION_PREPARATION_POLICY_VERSION",
    "ACTIVATION_PREPARATION_PROGRAM_SCHEMA",
    "ACTIVATION_PREPARATION_REPORT_SCHEMA",
    "ACTIVATION_PREPARATION_ZERO_COUNTERS",
    "CLOSED_NATIVE_ACTION_ADAPTER_SHA256",
    "ClosedNativeActionAdapter",
    "GovernedNativeController",
    "HOOK_BINDING_SCHEMA",
    "NATIVE_ACTION_RECEIPT_SCHEMA",
    "OBSERVED_SPAWN_STALL_EVIDENCE_SCHEMA",
    "OBSERVED_SPAWN_STALL_STAGE_REPORT_SCHEMA",
    "OBSERVED_SPAWN_STALL_TERMINALIZATION_PROGRAM_SCHEMA",
    "OBSERVED_SPAWN_STALL_TERMINAL_SNAPSHOT_SCHEMA",
    "OWNER_TERMINAL_PRE_NATIVE_FAILURE_REPORT_SCHEMA",
    "PARTIAL_NATIVE_FAILURE_EVIDENCE_SCHEMA",
    "PARTIAL_NATIVE_FAILURE_STAGE_REPORT_SCHEMA",
    "PARTIAL_NATIVE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA",
    "POST_ACK_BRIDGE_FAILURE_EVIDENCE_SCHEMA",
    "POST_ACK_BRIDGE_FAILURE_EVIDENCE_SCHEMA_V2",
    "POST_ACK_BRIDGE_FAILURE_STAGE_REPORT_SCHEMA",
    "POST_ACK_BRIDGE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA",
    "POST_SPAWN_FAILURE_EVIDENCE_SCHEMA",
    "POST_SPAWN_FAILURE_STAGE_REPORT_SCHEMA",
    "RETAINED_OWNER_ACTION_EVIDENCE_SCHEMA",
    "RETAINED_OWNER_OBSERVATION_SCHEMA",
    "POST_SPAWN_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA",
    "PRE_NATIVE_FAILURE_EVIDENCE_SCHEMA",
    "PRE_NATIVE_FAILURE_RUNTIME_REPORT_SCHEMA",
    "PRE_NATIVE_FAILURE_STAGE_REPORT_SCHEMA",
    "PRE_NATIVE_FAILURE_TERMINALIZATION_PROGRAM_SCHEMA",
    "PROGRAM_SCHEMA",
    "QUALIFICATION_HOST_CLEANUP_FIELDS",
    "QUALIFICATION_HOST_CLEANUP_SCHEMA",
    "QUALIFICATION_OWNER_ORIGINATOR",
    "QUALIFICATION_OWNER_PARTIAL_PUBLICATION_SCHEMA",
    "QUALIFICATION_OWNER_TERMINAL_FIELDS",
    "QUALIFICATION_OWNER_TERMINAL_SCHEMA",
    "QUALIFICATION_OWNER_TURN_FAILURE_ISSUES",
    "REPORT_SCHEMA",
    "ROOT_ROLLOUT_FAILURE_SUMMARY_SCHEMA",
    "advance_governed_native_controller",
    "open_governed_native_controller",
    "build_governed_native_activation_program",
    "build_governed_native_activation_preparation_program",
    "build_governed_native_stage_program",
    "build_activation_only_failure_terminalization_program",
    "build_owner_terminal_pre_native_failure_report",
    "build_pre_native_failure_terminalization_program",
    "build_partial_native_failure_terminalization_program",
    "build_observed_spawn_stall_terminalization_program",
    "build_post_ack_bridge_failure_terminalization_program",
    "build_post_spawn_failure_terminalization_program",
    "prepare_governed_native_activation",
    "task_specs_identity_sha256",
    "validate_activation_preparation_report",
    "validate_governed_native_controller_report",
]


if __name__ == "__main__":
    raise SystemExit(main())
