#!/usr/bin/env python3
"""Provider-free rehearsal of the exact Issue 94 qualification caller chain.

The driver owns every translation between canonical constructors.  Callers
select one permanent replay case and provide the exact runtime roots; they do
not assemble TaskSpecs, candidates, attempt bindings, requests, or activation
payloads.  The terminal READY decision is rehearsal evidence only and never
creates authority or crosses a network, model, or native-action boundary.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterator


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_adaptive_contracts as contracts  # noqa: E402
import orch_dork_advisory_scan as advisory_scan  # noqa: E402
import orch_dork_governed_native_controller as native_controller  # noqa: E402
import orch_dork_live_zero_tool as zero_tool  # noqa: E402
import orch_dork_live_zero_tool_qualification as transport_qualification  # noqa: E402
import orch_dork_model_profile_registry as model_profiles  # noqa: E402
import orch_dork_project_adapter as project_adapter  # noqa: E402
import orch_dork_project_ground_enforcement as ground_enforcement  # noqa: E402
import orch_dork_qualification_route_canary as route_canary  # noqa: E402
import orch_dork_worker_default as worker_default  # noqa: E402


REPLAY_CORPUS_SCHEMA = (
    "orch-dork/qualification-rehearsal-replay-corpus/v1"
)
HISTORICAL_REPLAY_CASE_IDS = frozenset(
    {
        "issue163-cycle10",
        "issue163-cycle11",
        "issue163-cycle12",
        "issue163-cycle13",
        "issue163-cycle14",
        "issue163-cycle15",
        "issue163-cycle16",
        "issue163-cycle18",
        "issue163-cycle19",
        "issue163-cycle20",
        "issue163-cycle21",
        "issue163-cycle22",
        "issue163-cycle23",
        "issue163-cycle24",
        "issue163-cycle25",
        "issue163-cycle26",
        "issue163-cycle27",
        "issue163-cycle28",
        "issue163-cycle29",
        "issue163-cycle30",
        "issue163-cycle31",
        "issue163-cycle32",
        "issue163-cycle33",
        "issue163-cycle34",
        "issue171-owner-launch-v6",
        "issue171-owner-launch-v7",
        "issue171-owner-launch-v8",
        "issue171-owner-launch-v9",
        "issue171-owner-launch-v10",
        "issue171-owner-launch-v11",
        "issue171-owner-launch-v12",
        "issue171-live-pricing-v13",
        "issue171-owner-launch-v14",
        "issue171-controller-root-v15",
    }
)
REPLAY_SCHEMA = "orch-dork/qualification-rehearsal-replay/v1"
REPLAY_SCHEMA_V2 = "orch-dork/qualification-rehearsal-replay/v2"
REPLAY_SCHEMA_V3 = "orch-dork/qualification-rehearsal-replay/v3"
REPLAY_SCHEMA_V4 = "orch-dork/qualification-rehearsal-replay/v4"
REPLAY_SCHEMA_V5 = "orch-dork/qualification-rehearsal-replay/v5"
REPLAY_SCHEMA_V6 = "orch-dork/qualification-rehearsal-replay/v6"
REPLAY_SCHEMA_V7 = "orch-dork/qualification-rehearsal-replay/v7"
REPLAY_SCHEMA_V8 = "orch-dork/qualification-rehearsal-replay/v8"
REPLAY_SCHEMA_V9 = "orch-dork/qualification-rehearsal-replay/v9"
REPLAY_SCHEMA_V10 = "orch-dork/qualification-rehearsal-replay/v10"
REPLAY_SCHEMA_V11 = "orch-dork/qualification-rehearsal-replay/v11"
REPLAY_SCHEMA_V12 = "orch-dork/qualification-rehearsal-replay/v12"
REPLAY_SCHEMA_V13 = "orch-dork/qualification-rehearsal-replay/v13"
REPLAY_SCHEMA_V14 = "orch-dork/qualification-rehearsal-replay/v14"
REPLAY_SCHEMA_V15 = "orch-dork/qualification-rehearsal-replay/v15"
REPLAY_SCHEMA_V16 = "orch-dork/qualification-rehearsal-replay/v16"
REPLAY_SCHEMA_V17 = "orch-dork/qualification-rehearsal-replay/v17"
REPLAY_SCHEMA_V18 = "orch-dork/qualification-rehearsal-replay/v18"
REPLAY_SCHEMA_V19 = "orch-dork/qualification-rehearsal-replay/v19"
REPLAY_SCHEMA_V20 = "orch-dork/qualification-rehearsal-replay/v20"
REPLAY_SCHEMA_V21 = "orch-dork/qualification-rehearsal-replay/v21"
REPLAY_SCHEMA_V22 = "orch-dork/qualification-rehearsal-replay/v22"
REPLAY_SCHEMA_V23 = "orch-dork/qualification-rehearsal-replay/v23"
REPLAY_SCHEMA_V24 = "orch-dork/qualification-rehearsal-replay/v24"
REPLAY_SCHEMA_V25 = "orch-dork/qualification-rehearsal-replay/v25"
REPLAY_SCHEMA_V26 = "orch-dork/qualification-rehearsal-replay/v26"
REPLAY_SCHEMA_V27 = "orch-dork/qualification-rehearsal-replay/v27"
REPLAY_SCHEMA_V28 = "orch-dork/qualification-rehearsal-replay/v28"
REPLAY_SCHEMA_V29 = "orch-dork/qualification-rehearsal-replay/v29"
REPLAY_SCHEMA_V30 = "orch-dork/qualification-rehearsal-replay/v30"
PROGRAM_SCHEMA = "orch-dork/qualification-rehearsal-program/v1"
ATTEMPT_SCHEMA = "orch-dork/qualification-rehearsal-attempt/v1"
PREFLIGHT_PLACEHOLDER_SCHEMA = (
    "orch-dork/qualification-rehearsal-preflight-placeholder/v1"
)
APPROVAL_PREFLIGHT_SCHEMA = "live-test-preflight/report/v1"
REPORT_SCHEMA = "orch-dork/qualification-rehearsal-report/v1"
ARTIFACT_RECEIPT_SCHEMA = (
    "orch-dork/qualification-rehearsal-artifact-receipt/v1"
)
DECISION_READY = "READY_FOR_ONE_ATTEMPT"
DECISION_REFUSED = "REFUSED"
STOP_BOUNDARY = "before_network_model_native"
CORPUS_RELATIVE = (
    "skills/orch-dork/runtime/qualification-rehearsal-replays-v1.json"
)

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_REPLAY_FIELDS_V1 = frozenset(
    {
        "schema",
        "case_id",
        "terminal_packet_sha256",
        "failure_evidence_sha256",
        "failure_stage",
        "failure_code",
        "legacy_route_input_refs",
        "legacy_candidate_digest_field",
        "legacy_preflight_runtime_globals",
        "legacy_validator_transport_failures",
        "legacy_endpoint_resolution",
    }
)
_REPLAY_FIELDS_V2 = frozenset(
    {*_REPLAY_FIELDS_V1, "legacy_research_source_paths"}
)
_REPLAY_FIELDS_V3 = frozenset(
    {
        *_REPLAY_FIELDS_V2,
        "legacy_ticket_admission_program_schema",
        "required_ticket_admission_program_schema",
        "legacy_pre_spawn_assembly",
    }
)
_REPLAY_FIELDS_V4 = frozenset(
    {
        *_REPLAY_FIELDS_V3,
        "legacy_enrollment_program_schema",
        "required_enrollment_program_schema",
        "activation_failure_codes",
        "legacy_enrollment_assembly",
    }
)
_REPLAY_FIELDS_V5 = frozenset(
    {
        *_REPLAY_FIELDS_V4,
        "legacy_hook_trust_assembly",
        "required_hook_trust_payload_schema",
        "required_hook_trust_assembly",
        "hook_trust_activation_failure_codes",
    }
)
_REPLAY_FIELDS_V6 = frozenset(
    {
        *_REPLAY_FIELDS_V5,
        "legacy_controller_bootstrap",
        "legacy_controller_source_roots",
        "required_controller_source_roots",
        "required_controller_bootstrap",
        "controller_stage_report_sha256",
        "controller_inspection_report_sha256",
        "pre_spawn_failure_codes",
    }
)
_REPLAY_FIELDS_V7 = frozenset(
    {
        *_REPLAY_FIELDS_V6,
        "legacy_owner_hook_inventory",
        "required_owner_hook_inventory",
        "required_hook_enablement",
        "native_hook_failure_codes",
        "predecessor_settlement_required",
        "terminal_controller_report_sha256",
        "terminal_inspection_report_sha256",
    }
)
_REPLAY_FIELDS_V8 = frozenset(
    {
        *_REPLAY_FIELDS_V7,
        "legacy_terminal_session_start_policy",
        "required_terminal_session_start_policy",
        "terminal_session_failure_codes",
    }
)
_REPLAY_FIELDS_V9 = frozenset(
    {
        *_REPLAY_FIELDS_V8,
        "legacy_successor_pre_turn_order",
        "required_successor_pre_turn_order",
        "legacy_lifecycle_rehearsal_terminal",
        "required_lifecycle_rehearsal_terminal",
        "successor_first_action_failure_codes",
        "pre_activation_stop_failure_codes",
    }
)
_REPLAY_FIELDS_V10 = frozenset(
    {
        *_REPLAY_FIELDS_V9,
        "legacy_thread_start_hook_assumption",
        "required_first_turn_startup_order",
        "startup_observation_failure_codes",
        "turn_started",
    }
)
_REPLAY_FIELDS_V11 = frozenset(
    {
        *_REPLAY_FIELDS_V10,
        "legacy_capacity_action_assembly",
        "required_capacity_action_assembly",
        "capacity_action_failure_codes",
        "reserved_logical_lane_ids",
        "capacity_controller_report_sha256",
        "capacity_inspection_report_sha256",
        "cleanup_required",
        "authority_grants_minted",
        "native_action_authorizations",
        "task_creations",
        "worker_creations",
    }
)
_REPLAY_FIELDS_V12 = frozenset(
    {
        *_REPLAY_FIELDS_V11,
        "legacy_predecessor_capacity_state",
        "required_predecessor_capacity_settlement",
        "unsettled_logical_lane_ids",
        "capacity_authority_state_sha256",
        "failed_capacity_settlement_code",
        "required_cleanup_status",
        "predecessor_action_created",
        "predecessor_grant_created",
        "pre_turn_successor_prepared",
        "live_canary_calls",
    }
)
_REPLAY_FIELDS_V13 = frozenset(
    {
        *_REPLAY_FIELDS_V12,
        "legacy_first_action_handoff",
        "required_first_action_handoff",
        "pre_turn_report_sha256",
        "predecessor_settlement_report_sha256",
        "first_action_bridge_report_sha256",
        "underlying_failure_code",
        "runtime_binding_failure_code",
        "mcp_bridge_calls",
        "predecessor_capacity_settled",
        "session_start_observed",
        "owner_interrupt_required",
        "stop_failure_code",
        "pretool_allow_protocol_failure_code",
        "required_pretool_allow_encoding",
    }
)
_REPLAY_FIELDS_V14 = frozenset(
    {
        *_REPLAY_FIELDS_V13,
        "cycle28_dedicated_result_sha256",
        "cycle28_predecessor_authority_sha256",
        "cycle28_corrected_capacity_read_sha256",
        "cycle28_pre_turn_task_id",
        "cycle27_controller_run_id",
        "cycle27_controller_run_seq",
        "cycle27_controller_event_sha256",
        "cycle27_predecessor_generation",
        "cycle27_predecessor_package_digest",
    }
)
_REPLAY_FIELDS_V15 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "legacy_posttool_result_assembly",
        "required_posttool_result_assembly",
        "native_hook_failure_codes",
        "cycle29_terminal_snapshot_sha256",
        "cycle29_terminal_report_sha256",
        "cycle29_dedicated_result_sha256",
        "cycle29_root_rollout_sha256",
        "cycle29_worker_rollout_sha256",
        "cycle29_worker_state_sha256",
        "cycle29_worker_report_sha256",
        "cycle29_posttool_report_sha256",
        "cycle29_result_sha256",
        "cycle29_first_action_sha256",
        "cycle29_capacity_state_sha256",
        "cycle29_task_id",
        "cycle29_worker_id",
        "cycle29_controller_id",
        "cycle29_controller_seq",
        "cycle29_generation",
        "cycle29_candidate_commit",
        "cycle29_package_digest",
        "pre_turn_successor_prepared",
        "session_start_observed",
        "turn_started",
        "mcp_bridge_calls",
        "native_actions_attempted",
        "workers_created",
        "native_grant_state",
        "worker_process_match_count",
        "worker_terminal_disposition",
        "terminal_recovery_required",
        "retry_same_generation_permitted",
    }
)
_REPLAY_FIELDS_V16 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "cycle30_dedicated_result_sha256",
        "cycle30_activation_refusal_sha256",
        "cycle30_canary_report_sha256",
        "cycle30_predecessor_settlement_report_sha256",
        "cycle30_task_id",
        "cycle30_generation",
        "cycle30_candidate_commit",
        "cycle30_package_digest",
        "cycle29_first_action_sha256",
        "legacy_owner_rotation_scope",
        "required_owner_rotation_scope",
        "predecessor_grant_state",
        "predecessor_grant_tool_use_claimed",
        "predecessor_controller_terminal",
        "predecessor_capacity_active_lane_ids",
        "predecessor_recovery_completed",
        "required_terminal_grant_state",
        "historical_native_outcome",
        "terminal_transition_consumes_native_authority",
        "pre_turn_successor_prepared",
        "turn_started",
        "live_canary_calls",
        "model_calls",
        "retries",
        "controller_activations",
        "capacity_reservations",
        "native_actions_attempted",
        "workers_created",
        "owned_process_group_cleaned",
        "retry_same_generation_permitted",
    }
)
_REPLAY_FIELDS_V17 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "cycle31_dedicated_result_sha256",
        "cycle31_pre_turn_artifact_sha256",
        "cycle31_pre_turn_report_sha256",
        "cycle31_attempt_envelope_sha256",
        "cycle31_root_rollout_sha256",
        "cycle31_spec_rollout_sha256",
        "cycle31_standards_rollout_sha256",
        "cycle31_action_batch_event_sha256",
        "cycle31_refused_stage_event_sha256",
        "cycle31_task_id",
        "cycle31_turn_id",
        "cycle31_spec_worker_id",
        "cycle31_standards_worker_id",
        "cycle31_controller_id",
        "cycle31_action_batch_seq",
        "cycle31_controller_seq",
        "cycle31_generation",
        "cycle31_candidate_commit",
        "cycle31_package_digest",
        "completed_spawn_observations",
        "spawn_batch_result_complete",
        "bridge_decision",
        "caller_authored_stage",
        "controller_disposition",
        "cleanup_required",
        "active_logical_lane_ids",
        "worker_terminal_disposition",
        "owned_process_group_cleaned",
        "qualification_receipt_emitted",
        "retry_same_generation_permitted",
    }
)
_REPLAY_FIELDS_V18 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "cycle32_dedicated_result_sha256",
        "cycle32_pre_turn_artifact_sha256",
        "cycle32_pre_turn_report_sha256",
        "cycle32_attempt_envelope_sha256",
        "cycle32_root_rollout_sha256",
        "cycle32_spec_rollout_sha256",
        "cycle32_standards_rollout_sha256",
        "cycle32_action_batch_event_sha256",
        "cycle32_controller_event_hash",
        "cycle32_bridge_refusal_report_sha256",
        "cycle32_first_action_advance_report_sha256",
        "cycle32_authorization_report_sha256",
        "cycle32_task_id",
        "cycle32_turn_id",
        "cycle32_spec_worker_id",
        "cycle32_standards_worker_id",
        "cycle32_controller_id",
        "cycle32_controller_seq",
        "cycle32_generation",
        "cycle32_candidate_commit",
        "cycle32_package_digest",
        "completed_spawn_observations",
        "spawn_batch_result_complete",
        "bridge_decision",
        "bridge_refusal_invocations",
        "acknowledged_worker_count",
        "worker_substantive_work_started",
        "continuation_actions",
        "controller_disposition",
        "cleanup_required",
        "active_logical_lane_ids",
        "root_task_complete_count",
        "stop_denial_count",
        "worker_terminal_disposition",
        "owned_process_group_cleaned",
        "qualification_receipt_emitted",
        "retry_same_generation_permitted",
    }
)
_REPLAY_FIELDS_V19 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "cycle33_dedicated_result_sha256",
        "cycle33_pre_turn_artifact_sha256",
        "cycle33_pre_turn_report_sha256",
        "cycle33_attempt_envelope_sha256",
        "cycle33_root_rollout_sha256",
        "cycle33_spec_rollout_sha256",
        "cycle33_standards_rollout_sha256",
        "cycle33_controller_event_hash",
        "cycle33_bridge_refusal_report_sha256",
        "cycle33_first_action_authorization_report_sha256",
        "cycle33_first_action_advance_report_sha256",
        "cycle33_task_id",
        "cycle33_turn_id",
        "cycle33_spec_worker_id",
        "cycle33_standards_worker_id",
        "cycle33_controller_id",
        "cycle33_controller_run_id",
        "cycle33_controller_seq",
        "cycle33_generation",
        "cycle33_candidate_commit",
        "cycle33_package_digest",
        "completed_spawn_observations",
        "spawn_batch_result_complete",
        "bridge_decision",
        "bridge_refusal_invocations",
        "acknowledged_worker_count",
        "worker_substantive_work_started",
        "continuation_actions",
        "controller_disposition",
        "cleanup_required",
        "active_logical_lane_ids",
        "root_task_complete_count",
        "stop_denial_count",
        "wait_call_count",
        "worker_terminal_disposition",
        "worker_runtime_validations_passed",
        "worker_tool_calls",
        "codex_home_mode",
        "worker_rollout_mode",
        "owned_process_group_cleaned",
        "qualification_receipt_emitted",
        "retry_same_generation_permitted",
    }
)
_REPLAY_FIELDS_V20 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "cycle34_dedicated_result_sha256",
        "cycle34_pre_turn_artifact_sha256",
        "cycle34_pre_turn_report_sha256",
        "cycle34_attempt_envelope_sha256",
        "cycle34_root_rollout_sha256",
        "cycle34_spec_rollout_sha256",
        "cycle34_standards_rollout_sha256",
        "cycle34_pretool_denial_artifact_sha256",
        "cycle34_pretool_denial_report_sha256",
        "cycle34_pretool_denial_durable_record_sha256",
        "cycle34_controller_event_hash",
        "cycle34_action_authorization_report_sha256",
        "cycle34_last_pass_bridge_report_sha256",
        "cycle34_task_id",
        "cycle34_turn_id",
        "cycle34_spec_worker_id",
        "cycle34_standards_worker_id",
        "cycle34_controller_id",
        "cycle34_controller_run_id",
        "cycle34_controller_seq",
        "cycle34_generation",
        "cycle34_candidate_commit",
        "cycle34_package_digest",
        "cycle34_continuation_action_id",
        "cycle34_continuation_action_sha256",
        "cycle34_continuation_tool_input_sha256",
        "expected_controller_tool_name",
        "observed_hook_tool_name",
        "completed_spawn_observations",
        "spawn_batch_result_complete",
        "acknowledged_worker_count",
        "continuation_actions_authorized",
        "continuation_actions_executed",
        "send_input_call_count",
        "pretool_denial_count",
        "bridge_refusal_invocations",
        "blocked_bridge_invocations",
        "controller_disposition",
        "grant_state",
        "worker_substantive_work_started",
        "cleanup_required",
        "active_logical_lane_ids",
        "root_task_complete_count",
        "stop_denial_count",
        "wait_call_count",
        "worker_terminal_disposition",
        "worker_runtime_validations_passed",
        "worker_tool_calls",
        "codex_home_mode",
        "worker_rollout_mode",
        "owned_process_group_cleaned",
        "qualification_receipt_emitted",
        "fallbacks",
        "replacements",
        "retry_same_generation_permitted",
    }
)
_REPLAY_FIELDS_V21 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "issue171_terminal_receipt_file_sha256",
        "issue171_terminal_report_sha256",
        "issue171_owner_failure_file_sha256",
        "issue171_owner_failure_report_sha256",
        "issue171_rollout_sha256",
        "issue171_host_preparation_file_sha256",
        "issue171_host_preparation_report_sha256",
        "issue171_owner_inventory_file_sha256",
        "issue171_owner_inventory_report_sha256",
        "issue171_app_server_argv_sha256",
        "issue171_task_id",
        "issue171_turn_id",
        "issue171_generation",
        "issue171_candidate_commit",
        "issue171_package_digest",
        "blocking_controller_id",
        "blocking_root_session_id",
        "blocking_controller_seq",
        "blocking_controller_status",
        "blocking_pending_action_kind",
        "blocking_pending_action_sha256",
        "blocking_pending_action_tool",
        "session_start_source",
        "session_start_hook_decision",
        "same_connection_retained",
        "thread_resume_calls",
        "task_creations",
        "turn_starts",
        "session_start_hooks",
        "model_calls",
        "provider_calls",
        "worker_sessions_started",
        "native_actions",
        "registration_mutations",
        "root_mutations",
        "protected_state_mutated",
        "owned_process_group_cleaned",
        "legacy_qualification_owner_context",
        "required_qualification_owner_context",
        "same_task_may_resume",
        "retry_same_generation_permitted",
    }
)
_REPLAY_FIELDS_V22 = frozenset(
    {
        *_REPLAY_FIELDS_V21,
        "issue171_hook_event_file_sha256",
        "issue171_hook_report_sha256",
        "issue171_hook_durable_record_sha256",
        "active_hook_definition_sha256",
        "observed_hook_definition_sha256",
        "hook_registration_sha256",
        "protected_state_file_sha256",
        "session_start_reason_codes",
        "qualification_owner_context_sealed",
        "qualification_owner_context_admitted",
        "owner_report_envelope_present",
        "terminal_error",
        "credential_reads",
        "network_calls",
        "ocx_worker_calls",
        "openrouter_calls",
        "qwen_calls",
        "local_qwen_probes",
        "controller_mutations",
        "capacity_reservations",
        "retries",
        "fallbacks",
        "replacements",
    }
)
_REPLAY_FIELDS_V23 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "issue171_terminal_receipt_file_sha256",
        "issue171_terminal_report_sha256",
        "issue171_owner_failure_file_sha256",
        "issue171_owner_failure_report_sha256",
        "issue171_thread_start_response_file_sha256",
        "issue171_app_server_transcript_file_sha256",
        "issue171_host_preparation_file_sha256",
        "issue171_host_preparation_report_sha256",
        "issue171_owner_inventory_file_sha256",
        "issue171_owner_inventory_report_sha256",
        "issue171_app_server_argv_sha256",
        "issue171_task_id",
        "issue171_generation",
        "issue171_candidate_commit",
        "issue171_package_digest",
        "protected_state_file_sha256",
        "thread_start_git_info",
        "thread_start_history_mode",
        "thread_start_status",
        "thread_start_turn_count",
        "rollout_materialized",
        "first_turn_started",
        "caller_provenance_gate",
        "required_provenance_gate",
        "terminal_error_type",
        "terminal_error",
        "same_connection_retained",
        "thread_resume_calls",
        "task_creations",
        "turn_starts",
        "session_start_hooks",
        "model_calls",
        "provider_calls",
        "credential_reads",
        "network_calls",
        "ocx_worker_calls",
        "openrouter_calls",
        "qwen_calls",
        "local_qwen_probes",
        "worker_sessions_started",
        "native_actions",
        "registration_mutations",
        "controller_mutations",
        "capacity_reservations",
        "root_mutations",
        "retries",
        "fallbacks",
        "replacements",
        "protected_state_mutated",
        "owned_process_group_cleaned",
        "same_task_may_resume",
        "retry_same_generation_permitted",
    }
)
_REPLAY_FIELDS_V24 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "issue171_terminal_receipt_file_sha256",
        "issue171_terminal_report_sha256",
        "issue171_owner_failure_file_sha256",
        "issue171_owner_failure_report_sha256",
        "issue171_app_server_transcript_file_sha256",
        "issue171_checkout_file_sha256",
        "issue171_checkout_report_sha256",
        "issue171_host_preparation_file_sha256",
        "issue171_host_preparation_report_sha256",
        "issue171_owner_inventory_file_sha256",
        "issue171_owner_inventory_report_sha256",
        "issue171_app_server_argv_sha256",
        "issue171_owner_client_file_sha256",
        "issue171_task_creation_intent_file_sha256",
        "issue171_task_creation_pre_call_report_file_sha256",
        "issue171_generation",
        "issue171_candidate_commit",
        "issue171_package_digest",
        "protected_state_file_sha256",
        "thread_start_project_id",
        "requested_history_mode",
        "experimental_api_capability_advertised",
        "thread_start_error_code",
        "thread_start_error_message",
        "thread_start_response_persisted",
        "checkout_pre_call_sealed",
        "required_request_builder",
        "terminal_error_type",
        "terminal_error",
        "same_connection_retained",
        "thread_resume_calls",
        "task_creation_requests",
        "task_creations",
        "turn_starts",
        "session_start_hooks",
        "model_calls",
        "provider_calls",
        "credential_reads",
        "network_calls",
        "ocx_worker_calls",
        "openrouter_calls",
        "qwen_calls",
        "local_qwen_probes",
        "worker_sessions_started",
        "native_actions",
        "registration_mutations",
        "controller_mutations",
        "capacity_reservations",
        "root_mutations",
        "retries",
        "fallbacks",
        "replacements",
        "protected_state_mutated",
        "future_attempt_paths_created",
        "owned_process_group_cleaned",
        "same_task_may_resume",
        "retry_same_generation_permitted",
    }
)
_REPLAY_FIELDS_V25 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "issue171_terminal_receipt_file_sha256",
        "issue171_terminal_report_sha256",
        "issue171_owner_failure_file_sha256",
        "issue171_owner_failure_report_sha256",
        "issue171_app_server_transcript_file_sha256",
        "issue171_checkout_file_sha256",
        "issue171_checkout_report_sha256",
        "issue171_host_preparation_file_sha256",
        "issue171_host_preparation_report_sha256",
        "issue171_owner_inventory_file_sha256",
        "issue171_owner_inventory_report_sha256",
        "issue171_app_server_argv_sha256",
        "issue171_owner_client_file_sha256",
        "issue171_task_creation_intent_file_sha256",
        "issue171_task_creation_pre_call_report_file_sha256",
        "issue171_generation",
        "issue171_candidate_commit",
        "issue171_package_digest",
        "protected_state_file_sha256",
        "requested_project_id",
        "allow_provider_model_fallback_requested",
        "capability_gated_field",
        "experimental_only_request_fields",
        "standard_thread_start_schema_sha256",
        "experimental_thread_start_schema_sha256",
        "standard_thread_start_fields",
        "thread_start_error_code",
        "thread_start_error_message",
        "thread_start_response_persisted",
        "checkout_pre_call_sealed",
        "required_request_builder",
        "terminal_error_type",
        "terminal_error",
        "same_connection_retained",
        "thread_resume_calls",
        "task_creation_requests",
        "task_creations",
        "turn_starts",
        "session_start_hooks",
        "model_calls",
        "provider_calls",
        "credential_reads",
        "network_calls",
        "ocx_worker_calls",
        "openrouter_calls",
        "qwen_calls",
        "local_qwen_probes",
        "worker_sessions_started",
        "native_actions",
        "registration_mutations",
        "controller_mutations",
        "capacity_reservations",
        "root_mutations",
        "retries",
        "fallbacks",
        "replacements",
        "protected_state_mutated",
        "future_attempt_paths_created",
        "owned_process_group_cleaned",
        "same_task_may_resume",
        "retry_same_generation_permitted",
    }
)
_REPLAY_FIELDS_V26 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "cleanup_report_file_sha256",
        "controller_mutations",
        "fallbacks",
        "issue171_candidate_commit",
        "issue171_generation",
        "issue171_package_digest",
        "owned_process_group_cleaned",
        "owner_gate_tool_calls",
        "owner_report",
        "owner_report_contains_task_id",
        "protected_state_sha256",
        "qwen_calls",
        "reconciliation_fixture_sha256",
        "registration_mutations",
        "replacements",
        "retries",
        "retry_same_generation_permitted",
        "same_task_may_resume",
        "task_creations",
        "task_id",
        "thread_read_response_file_sha256",
        "turn_id",
        "turn_starts",
        "worker_sessions",
    }
)
_ISSUE171_OWNER_LAUNCH_V11_REPLAY_SHA256 = (
    "9ab62fb1a2b569e0ca67f890a1ebea8a4d3a59dab7f348ac9d97cd082605e900"
)
_REPLAY_FIELDS_V27 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "loaded_task_ids",
        "owned_process_group_cleaned",
        "owner_subscription_retained",
        "reconciliation_fixture_sha256",
        "retry_same_generation_permitted",
        "same_task_may_resume",
        "task_status",
        "worker_cost_usd",
        "worker_sessions",
        "worker_tokens",
    }
)
_ISSUE171_OWNER_LAUNCH_V12_REPLAY_SHA256 = (
    "0124e6ccc817be2085d211496f3e567cfbc6bc0bd77acdb0783bb85cf3fb295e"
)
_REPLAY_FIELDS_V28 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "discount_metadata",
        "original_price_response_preserved",
        "owned_process_group_cleaned",
        "owner_subscription_retained",
        "post_terminal_response_sha256",
        "pricing_fixture_sha256",
        "retry_same_generation_permitted",
        "same_task_may_resume",
        "worker_cost_usd",
        "worker_sessions",
        "worker_tokens",
    }
)
_ISSUE171_LIVE_PRICING_V13_REPLAY_SHA256 = (
    "29e70f6039b0c01f1e8a91285aff4811fb5406537eff33e07fdf57a2031b94eb"
)
_REPLAY_FIELDS_V29 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "owned_process_group_cleaned",
        "owner_subscription_retained",
        "owner_turns",
        "read_created_at",
        "retry_same_generation_permitted",
        "rollout_materialized",
        "same_task_may_resume",
        "start_created_at",
        "timestamp_fixture_sha256",
        "worker_cost_usd",
        "worker_sessions",
        "worker_tokens",
    }
)
_ISSUE171_OWNER_LAUNCH_V14_REPLAY_SHA256 = (
    "042b658c86e97f67c24e42a0ce1a5cd41dec648d58cd2073f34616f4dac59540"
)
_REPLAY_FIELDS_V30 = frozenset(
    {
        *_REPLAY_FIELDS_V1,
        "directory_fixture_sha256",
        "host_installations",
        "mcp_registration_changes",
        "missing_controller_parent",
        "owned_process_group_cleaned",
        "owner_subscription_retained",
        "owner_turns",
        "retry_same_generation_permitted",
        "same_task_may_resume",
        "worker_cost_usd",
        "worker_sessions",
        "worker_tokens",
    }
)
_ISSUE171_CONTROLLER_ROOT_V15_REPLAY_SHA256 = (
    "28b289aed278e2b402a41adf3d328bafb28302775292c34017da2b6c8b20b8ce"
)
_CYCLE25_CAPACITY_ACTION_FAILURE_CODES = [
    "proposed_action.action_id:invalid",
    "proposed_action:adapter_identity_mismatch",
    "proposed_action:adapter_unrecognized",
    "proposed_action:kind_invalid",
    "proposed_action:not_exact_next_action",
    "proposed_action:not_object",
    "proposed_action:root_owner_required",
    "proposed_action:schema_invalid",
]
_CYCLE21_NATIVE_HOOK_FAILURE_CODES = [
    "observation.tool_use_id:invalid",
    "observation:hook_report_required",
    "observation:result_unobserved",
]
_CYCLE29_REPLAY_BINDINGS = {
    "terminal_packet_sha256": (
        "bc72c96b6f885fa1a1a5a5119b7b88b3e03d0266ae135f6b479cd151d2c0e8ec"
    ),
    "failure_evidence_sha256": (
        "5c5e25d3ed45501ba7696fb39d75e44bf389fd4ca42109775b53e101968c7669"
    ),
    "cycle29_terminal_snapshot_sha256": (
        "bc72c96b6f885fa1a1a5a5119b7b88b3e03d0266ae135f6b479cd151d2c0e8ec"
    ),
    "cycle29_terminal_report_sha256": (
        "caff15d4e5552a69f10ff841ac70cc6a36ae4cde6326259ee5affe277c8b58d6"
    ),
    "cycle29_dedicated_result_sha256": (
        "be1001ec613f2ed4f77677f1ec7e6c5f857ae706663a05cd2ff7f493e43500d2"
    ),
    "cycle29_root_rollout_sha256": (
        "0b65857d697d7aa024f556bfe984b42acb3da68693cf3171cad9ca69cd8ff0cd"
    ),
    "cycle29_worker_rollout_sha256": (
        "516e3624bae9c9ae58bb7ca4a732414df86114e0b3e8a533ab2eb9e745c4cc7f"
    ),
    "cycle29_worker_state_sha256": (
        "a8f3cbf55bb16ed1257fcb245eb4170cfbb226472b3f15c4ebc5aaf3ae870784"
    ),
    "cycle29_worker_report_sha256": (
        "4d6ea57142b6e2f36e9f87d1edd647f06f2f563b283484440a59e30d1f39ce46"
    ),
    "cycle29_posttool_report_sha256": (
        "5c5e25d3ed45501ba7696fb39d75e44bf389fd4ca42109775b53e101968c7669"
    ),
    "cycle29_result_sha256": (
        "60e61cbbd34f5bf7c84a9e0a4310a5f06208e36e49efc7889d7b8c4a58e44c34"
    ),
    "cycle29_first_action_sha256": (
        "ceb961b5eb6ee4d5f172ffd0d86e724cdf6f455720ef43356c2ab2f415560ef7"
    ),
    "cycle29_capacity_state_sha256": (
        "b65bc9072e2fe6a22292c1e08000f9e802e76f78cba09f1195d53803a0ba16bd"
    ),
    "cycle29_task_id": "01a06181-9496-7a52-904b-0db49e9a9f68",
    "cycle29_worker_id": "01a06183-4b72-7173-96b2-2b6bf5e0490d",
    "cycle29_controller_id": "issue163-cycle29-controller",
    "cycle29_controller_seq": 5,
    "cycle29_generation": "0.1.0+codex.20260902093900",
    "cycle29_candidate_commit": "126636c58219c982e3f5cb372a4a2ea4643cac5e",
    "cycle29_package_digest": (
        "5cdf9a6d92f395ea00e72ae0b9392aa5396615002e836c955b19b278b5f747c0"
    ),
}
_CYCLE30_REPLAY_BINDINGS = {
    "terminal_packet_sha256": (
        "d5ff6cc3c94a9d6d6b1d2fdac9796452621feda0f22303929a2db33ec071d520"
    ),
    "failure_evidence_sha256": (
        "8cf553357886edfbc55e64d0cb407c1a2ffaf62b5e75ec55a5b1633e31bbe8db"
    ),
    "cycle30_dedicated_result_sha256": (
        "d5ff6cc3c94a9d6d6b1d2fdac9796452621feda0f22303929a2db33ec071d520"
    ),
    "cycle30_activation_refusal_sha256": (
        "8cf553357886edfbc55e64d0cb407c1a2ffaf62b5e75ec55a5b1633e31bbe8db"
    ),
    "cycle30_canary_report_sha256": (
        "1f2b883a0e2c77bf9b15452fa0e6ce34b8c453bed2db96e92a3d897e314dd694"
    ),
    "cycle30_predecessor_settlement_report_sha256": (
        "24b44de5a1a5e4054f1e090526daf1009c7830d533e0936c4f17d1bf12d4f368"
    ),
    "cycle30_task_id": "01a0636b-b8dc-7823-8f8e-81f818c2d9b7",
    "cycle30_generation": "0.1.0+codex.20260902122518",
    "cycle30_candidate_commit": "bc6f6259d13d38f75ce63789f56d5177afa4fe05",
    "cycle30_package_digest": (
        "6dd897945bce70cbd82cd3d3d6840a3010c260bd12bae60a7313a79e8dfc6a62"
    ),
    "cycle29_first_action_sha256": (
        "ceb961b5eb6ee4d5f172ffd0d86e724cdf6f455720ef43356c2ab2f415560ef7"
    ),
}
_CYCLE31_REPLAY_BINDINGS = {
    "terminal_packet_sha256": (
        "4c72812c3e29587fb56c345d7c3b1609d272112fc0a1a3fa2cbaa2a3a65210ff"
    ),
    "failure_evidence_sha256": (
        "7cb8d697d636fd3836b28016b4e97e0ddecd9fb3db585842d8b9c191a07c3e25"
    ),
    "cycle31_dedicated_result_sha256": (
        "4c72812c3e29587fb56c345d7c3b1609d272112fc0a1a3fa2cbaa2a3a65210ff"
    ),
    "cycle31_pre_turn_artifact_sha256": (
        "f57f2deb25293b829afd720ff408d70e46a6246e91747515fe58e491020388a7"
    ),
    "cycle31_pre_turn_report_sha256": (
        "4893cdff156b29204f399ed53e9df5794ed3918487ae9e4f70a25a5ab0b4898c"
    ),
    "cycle31_attempt_envelope_sha256": (
        "dbb6ccf772d8488d0d2457dc8964b06112936a3732bf667ec600a559888ea78f"
    ),
    "cycle31_root_rollout_sha256": (
        "31d19aef010461758d3e530e5ee61936a1966751b2b6d07285b4a0b9558280ee"
    ),
    "cycle31_spec_rollout_sha256": (
        "434cee81af7f89a94d5139e8ee7dfdecae2ca3fbaace938b3bee2548efa626ab"
    ),
    "cycle31_standards_rollout_sha256": (
        "9709c3026d79e1938b6872c641bd6ab690406f1eaa80c07d684711caf62cb839"
    ),
    "cycle31_action_batch_event_sha256": (
        "65c8b5823e018767c78d4ecef4e5246facc8dce363f1b0440526c570a199d7e5"
    ),
    "cycle31_refused_stage_event_sha256": (
        "7cb8d697d636fd3836b28016b4e97e0ddecd9fb3db585842d8b9c191a07c3e25"
    ),
    "cycle31_task_id": "01a063ca-d371-78e0-80f4-b4843ae1338f",
    "cycle31_turn_id": "01a063cb-2531-79c1-ae2b-7b0557c6fc41",
    "cycle31_spec_worker_id": "01a063cc-063b-74d0-972a-42a68cb860e1",
    "cycle31_standards_worker_id": "01a063cc-677d-73d1-b049-50ec8de6b3c7",
    "cycle31_controller_id": "issue163-cycle31-controller",
    "cycle31_action_batch_seq": 9,
    "cycle31_controller_seq": 11,
    "cycle31_generation": "0.1.0+codex.20260902201733",
    "cycle31_candidate_commit": "7edbe90f3e12450a50e4a0940ccd81e7d46d2b55",
    "cycle31_package_digest": (
        "a29331849efb5532ee475a27615e784010c7eb75a1d0cc08beb48cdae6810684"
    ),
}
_CYCLE32_REPLAY_BINDINGS = {
    "terminal_packet_sha256": (
        "68161abf83e85c04a2f11fc2c143546e70d5ddf915ac677db7b3acdc65438852"
    ),
    "failure_evidence_sha256": (
        "c9ab42de26e48ae4b5cac70e8f5426f192399f6a747f2cae4b871c46c97b63af"
    ),
    "cycle32_dedicated_result_sha256": (
        "68161abf83e85c04a2f11fc2c143546e70d5ddf915ac677db7b3acdc65438852"
    ),
    "cycle32_pre_turn_artifact_sha256": (
        "b53c1a32da10c673117d5772b4b5fe613c6e897e2461acc499b91d0166c0cdff"
    ),
    "cycle32_pre_turn_report_sha256": (
        "73f11453acee484562d388ecf1b34e3e3a7228aaa2238f1411e6c73c7eaeefe4"
    ),
    "cycle32_attempt_envelope_sha256": (
        "a8239807565740da85536634a9249ffc7b61df6cecf657a16edaa968d49f993d"
    ),
    "cycle32_root_rollout_sha256": (
        "2e60bb5d16435c118abcdcb7d98aa667367f67edb36b346360f9df7d6e574fcf"
    ),
    "cycle32_spec_rollout_sha256": (
        "402545257f289e86136cb3585b2b928cdc1068f2238325c5727ddf77b361dd31"
    ),
    "cycle32_standards_rollout_sha256": (
        "75b8411bc838ba1abfbf563805c7f06598ab04d2e6e3bb0617b9d962b4ad2c40"
    ),
    "cycle32_action_batch_event_sha256": (
        "4e6339699bbe7c226ec33347ea17e869219331995ffa7da045a82e4d4b5c9af2"
    ),
    "cycle32_controller_event_hash": (
        "8f5f7b81562ee370a3904b4d59e2cc5d457d44088d01649f72cec57fba1d7c04"
    ),
    "cycle32_bridge_refusal_report_sha256": (
        "c9ab42de26e48ae4b5cac70e8f5426f192399f6a747f2cae4b871c46c97b63af"
    ),
    "cycle32_first_action_advance_report_sha256": (
        "fae5e7e4df16046e2db6902c56ab9280b85456a45a4c3487a752ea1d8bbbdcc5"
    ),
    "cycle32_authorization_report_sha256": (
        "6d2cb2e62fb3b47de8421730717ce979d8b82187c5f42700022eba24292fa108"
    ),
    "cycle32_task_id": "01a06475-55d9-7392-887a-833bdbf5f215",
    "cycle32_turn_id": "01a06475-cb0f-7243-81fc-dd72f1f0fb9d",
    "cycle32_spec_worker_id": "01a06476-4009-77e3-bb86-a3b23ee17b49",
    "cycle32_standards_worker_id": "01a06476-9b04-7250-9ed3-fab50ef2f8d0",
    "cycle32_controller_id": "issue163-cycle32-controller",
    "cycle32_controller_seq": 9,
    "cycle32_generation": "0.1.0+codex.20260902231352",
    "cycle32_candidate_commit": "ec49a9faf33341982fb60eeb812a7f5856574cc8",
    "cycle32_package_digest": (
        "7e7934c05b20b200fb781d0d643dd8a2b400894942988b62a67d05c967a8f792"
    ),
}
_CYCLE33_REPLAY_BINDINGS = {
    "terminal_packet_sha256": (
        "32bd7678dc955706390493828a08fd1e9459b26c879a693340b84d4472e48a69"
    ),
    "failure_evidence_sha256": (
        "8de1dcf14f57651048d3512521f578c92a4a57b4e4d23cba1c8cd535d074c638"
    ),
    "cycle33_dedicated_result_sha256": (
        "32bd7678dc955706390493828a08fd1e9459b26c879a693340b84d4472e48a69"
    ),
    "cycle33_pre_turn_artifact_sha256": (
        "229a1bd9fc4b1518c5720a43901aa834e1514b5ef388a05b50d65fe7d943108c"
    ),
    "cycle33_pre_turn_report_sha256": (
        "311c5e5b48750ba46ea19b81245360d72dbc0a72adc9114bd9911c8bad965338"
    ),
    "cycle33_attempt_envelope_sha256": (
        "4bc85852663f7f111ed2cb3591f99ac09ea949d25a70e9683917d940b48bb85a"
    ),
    "cycle33_root_rollout_sha256": (
        "a244a329bad410e991a9af5e386695890118a7a4fd2d791baf47e5ff9d57ac0e"
    ),
    "cycle33_spec_rollout_sha256": (
        "af5ae53cb63326c92ceba79ef0bca66e1658dc80f8ebe814c87606a775b1c093"
    ),
    "cycle33_standards_rollout_sha256": (
        "7f45e3d605d2dd78a13b2f98687752398adf708e51a9a01cc5a2937ac47fbe1a"
    ),
    "cycle33_controller_event_hash": (
        "a5e8ff0ae2d6ebc6a143b43f0433d4925d223d3e81de6f5e630db0e0195ad861"
    ),
    "cycle33_bridge_refusal_report_sha256": (
        "8de1dcf14f57651048d3512521f578c92a4a57b4e4d23cba1c8cd535d074c638"
    ),
    "cycle33_first_action_authorization_report_sha256": (
        "c615d988d9aab0279e54480c8965296d9ad3462ed4e2c631627dae63c2c7fff2"
    ),
    "cycle33_first_action_advance_report_sha256": (
        "e6db51dc564f608888ff4f83ffaddd09f4dfd3fca942417025843f2760be3f3a"
    ),
    "cycle33_task_id": "01a064e2-a7cb-7633-8d69-295e1b33ee05",
    "cycle33_turn_id": "01a064e3-27ff-7bd2-aea8-369d18c90ff5",
    "cycle33_spec_worker_id": "01a064e3-b18f-7f82-b4cf-1d26df6cd839",
    "cycle33_standards_worker_id": "01a064e4-0a87-7d91-854b-59d12a411303",
    "cycle33_controller_id": "issue163-cycle33-controller",
    "cycle33_controller_run_id": "nativecontroller-8bcaf214c2b831b56034ee03",
    "cycle33_controller_seq": 9,
    "cycle33_generation": "0.1.0+codex.20260903011835",
    "cycle33_candidate_commit": "47888674e18b4e35559aed2eca6b78db0ce25507",
    "cycle33_package_digest": (
        "e645bb052b6bb7cf717544a1b9764e323b368acd7f02cd6df2d4a371c0ead955"
    ),
}
_CYCLE34_REPLAY_BINDINGS = {
    "terminal_packet_sha256": (
        "7b273c8220ec11dbf50a6ca0614c6e90e31cad58d3cb26c796849b06e5b2dcae"
    ),
    "failure_evidence_sha256": (
        "109d4302c2d292ff67ce281d72e8fe39e926ea0b7222bcdf66072c95e0b2854c"
    ),
    "cycle34_dedicated_result_sha256": (
        "7b273c8220ec11dbf50a6ca0614c6e90e31cad58d3cb26c796849b06e5b2dcae"
    ),
    "cycle34_pre_turn_artifact_sha256": (
        "5d8067bfd20dab6344d0c35eb4500ddfdc5d2e4401e7040209cbe2d0911e4a91"
    ),
    "cycle34_pre_turn_report_sha256": (
        "b90c4eb4061461b42052632c4e5a4c8ecf1ce8358b5e47ce2e428e3c5071cc78"
    ),
    "cycle34_attempt_envelope_sha256": (
        "24d75531f0e75b3ba2efc28509a1d356b747628f10efc20df2e20a9a1a04609d"
    ),
    "cycle34_root_rollout_sha256": (
        "8a3e9254147bad218eafdccc13b9e7ba83ba85d31e82e320334991ac8d99e84d"
    ),
    "cycle34_spec_rollout_sha256": (
        "70bca1254f34d9f2804b08e080089f5cd7d77b30eb4322595c79aa1ce64cf9a6"
    ),
    "cycle34_standards_rollout_sha256": (
        "e5b50c29aaf0213bc8c9f5bacb14405a7809b27a2b7a9ae89f49ade8ca98bd9b"
    ),
    "cycle34_pretool_denial_artifact_sha256": (
        "6aca846ecd38122f3f17a8eedc6308b227363ade1ec0b2a61300bea2c788dda2"
    ),
    "cycle34_pretool_denial_report_sha256": (
        "109d4302c2d292ff67ce281d72e8fe39e926ea0b7222bcdf66072c95e0b2854c"
    ),
    "cycle34_pretool_denial_durable_record_sha256": (
        "a8c7aadc91d66baf491500419ca2ee31083bce238936a6a9d385cb37d2401da7"
    ),
    "cycle34_controller_event_hash": (
        "7184e9ca209091f4a9895273ebe671af6ce5b144a7236a8db219f61e2bd52d7b"
    ),
    "cycle34_action_authorization_report_sha256": (
        "253690acc34c6c8679d2196418aaae0b63fea8f444d3522c309d125252973fad"
    ),
    "cycle34_last_pass_bridge_report_sha256": (
        "32909985b0342eec42ed1ded0e9e931fbe86c4ee7b8e8c596642901499662164"
    ),
    "cycle34_task_id": "01a06540-b267-7fe2-8cb6-b6db5a7b2a0e",
    "cycle34_turn_id": "01a06541-356a-7091-865e-ee56a064b817",
    "cycle34_spec_worker_id": "01a06541-cb51-7382-ba6a-350e6a8da88e",
    "cycle34_standards_worker_id": "01a06542-18b6-7013-8a22-d27b68fe703f",
    "cycle34_controller_id": "issue163-cycle34-controller",
    "cycle34_controller_run_id": "nativecontroller-a9f6fe08526a13624c2389c6",
    "cycle34_controller_seq": 11,
    "cycle34_generation": "0.1.0+codex.20260903025431",
    "cycle34_candidate_commit": "f5b495821ab2803cf43d6daeefb609cae910cc88",
    "cycle34_package_digest": (
        "e4f36764e71e217411405f6dee1a37bdd97288fdd51bc862373fcc24d3f286b1"
    ),
    "cycle34_continuation_action_id": (
        "issue94-worker-start-5f09eaee8a0645d4339c7fac"
    ),
    "cycle34_continuation_action_sha256": (
        "2a22bca0e81a64e9169fd9d1c212a7c66115ccc54ce6722f757ec297d767da91"
    ),
    "cycle34_continuation_tool_input_sha256": (
        "181614559bc3c86b50585e5918cf38bc7f53bc8498084168d84f4800948c0e21"
    ),
}
_ISSUE171_OWNER_LAUNCH_V6_REPLAY_BINDINGS = {
    "terminal_packet_sha256": (
        "13db14c01a844f03ec04baa48320633b07c4c4f788151909e4246a21419f21c1"
    ),
    "failure_evidence_sha256": (
        "de70adca5042a96e341b4871e45d341f4cfd5068cf5edae87cfb144f33ee246a"
    ),
    "issue171_terminal_receipt_file_sha256": (
        "13db14c01a844f03ec04baa48320633b07c4c4f788151909e4246a21419f21c1"
    ),
    "issue171_terminal_report_sha256": (
        "5361be513d43b44f92661323c9536c3d35fcae84cfa5c31fb29fe0df0f9fc32d"
    ),
    "issue171_owner_failure_file_sha256": (
        "960ddfaba9e2224e25256f86d0a2a4147efcc861bcb788d5a539e61d4a6de968"
    ),
    "issue171_owner_failure_report_sha256": (
        "3a0f4f09399b156cd0724464539d2257400e41acdf1acdf5274d5b35411aa56d"
    ),
    "issue171_rollout_sha256": (
        "de70adca5042a96e341b4871e45d341f4cfd5068cf5edae87cfb144f33ee246a"
    ),
    "issue171_host_preparation_file_sha256": (
        "51424fb3a28a201ea0e13a48885f75ec7170e3cd5a865c2e5f2348207ed2d5ad"
    ),
    "issue171_host_preparation_report_sha256": (
        "0ef65c14c2ac17aa33405cbd013660ce18ba14a1af310eef6f9dfa4431bb4ccf"
    ),
    "issue171_owner_inventory_file_sha256": (
        "0c8f7d2a2dfaaba298416ef3b9c54653a686b4762d778ca12211359495f7a54f"
    ),
    "issue171_owner_inventory_report_sha256": (
        "e1f245be4619ca432a1de8722268f9d6572929cf97e6621c248b306b668d0c1f"
    ),
    "issue171_app_server_argv_sha256": (
        "853eacc056a80bdb59b30577d4ea4a3da44a5cb5df49ec403328708f7cd46941"
    ),
    "issue171_task_id": "01a06b7a-a7e4-77d0-a718-ddfefc9daafc",
    "issue171_turn_id": "01a06b7a-a918-76a2-861f-47dd6b7dbef4",
    "issue171_generation": "0.1.0+codex.20260904075801",
    "issue171_candidate_commit": (
        "2a4f86e772f8f830b2ffe91faa270e0b1181b39c"
    ),
    "issue171_package_digest": (
        "6840fa9b1cdac4a225623396ab13f2ed90bd1cb23e8f3920a1a1c17e37c7baab"
    ),
    "blocking_controller_id": "issue163-cycle36-controller",
    "blocking_root_session_id": "01a065d8-81ae-77c1-bb06-1a6251eca391",
    "blocking_controller_seq": 13,
    "blocking_pending_action_sha256": (
        "9c094ee406c4d1af27e0254e10a434be3e96fae83d9a4883fdbf98d1d5f0ad88"
    ),
}
_ISSUE171_OWNER_LAUNCH_V7_REPLAY_BINDINGS = {
    "terminal_packet_sha256": (
        "0a0025e53262412d6eb8121f89206acb6b412ed4c1ce5eb6141be09cd07c21ba"
    ),
    "failure_evidence_sha256": (
        "98a32693dea06191f7d0bbe8d75c509373292d8933fd81043c74beafb5032e2e"
    ),
    "issue171_terminal_receipt_file_sha256": (
        "0a0025e53262412d6eb8121f89206acb6b412ed4c1ce5eb6141be09cd07c21ba"
    ),
    "issue171_terminal_report_sha256": (
        "680d3911a8c13b0b9e2a1fb09d51a5f83e7fa041e4a3651d11ec8707ffc1885a"
    ),
    "issue171_owner_failure_file_sha256": (
        "e9f82332ccc28fded3283147b5f565b1dc88750851cf3a5a462d52b658a141ee"
    ),
    "issue171_owner_failure_report_sha256": (
        "4c064ad9cc62e941017507c46dc6c059f1c2d093a62a273c601b93eceea1dcd9"
    ),
    "issue171_rollout_sha256": (
        "3bf58853f0bdc8453053c57bee66d0754b8091c9ede153d1b8f629d02631a045"
    ),
    "issue171_host_preparation_file_sha256": (
        "cf234b21c52408134e9fcb6502f965f6739c673341bc4a8d056607a36166b5ae"
    ),
    "issue171_host_preparation_report_sha256": (
        "51df3565c29bae28c72abfddd93f2983a9120cfaa5d8a799fce027d178c9a45c"
    ),
    "issue171_owner_inventory_file_sha256": (
        "db988e201564b3e7cb642f9caad7fb7bb7315e02287896090d93a48e49139438"
    ),
    "issue171_owner_inventory_report_sha256": (
        "b305bb3969a6b7e6efc32e3397ee3ada0712a3ecf36420fe75c397c5eb058518"
    ),
    "issue171_app_server_argv_sha256": (
        "395ea029e61844516fa38b66179e4da9691f07c59b6e3e7928c1def488d0ab3e"
    ),
    "issue171_hook_event_file_sha256": (
        "98a32693dea06191f7d0bbe8d75c509373292d8933fd81043c74beafb5032e2e"
    ),
    "issue171_hook_report_sha256": (
        "54541b991a48aef2d9cbcb2405c4a6d33ec890aa5a25817172b6525ed01b0140"
    ),
    "issue171_hook_durable_record_sha256": (
        "91080d88acb60d63fefc1a73f1f722fdf2a6547166c6aee4c82f843cf75dac5f"
    ),
    "issue171_task_id": "01a06d98-809d-7153-b939-18a665770f65",
    "issue171_turn_id": "01a06d98-81d6-7071-bf32-0cdc57a9e853",
    "issue171_generation": "0.1.0+codex.20260904091446",
    "issue171_candidate_commit": (
        "ef946d1f363d64d0202b508d0d49d6f088364b43"
    ),
    "issue171_package_digest": (
        "cdbabaafefef64f79541c361b3fa594c1ebe0892138fe54177a2f5392790e1c7"
    ),
    "blocking_controller_id": "issue163-cycle36-controller",
    "blocking_root_session_id": "01a065d8-81ae-77c1-bb06-1a6251eca391",
    "blocking_controller_seq": 13,
    "blocking_pending_action_sha256": (
        "9c094ee406c4d1af27e0254e10a434be3e96fae83d9a4883fdbf98d1d5f0ad88"
    ),
    "active_hook_definition_sha256": (
        "074ecc6ae4239d4e09360bf5f35cfa2ba249eac06a02f9292d06ba936dfc6535"
    ),
    "observed_hook_definition_sha256": (
        "645457bf99707fde2542024d97f0ce21a4ff879f8d2dfd1b1653caadbe82f1b1"
    ),
    "hook_registration_sha256": (
        "bd87338452f4c66635bbaab6a41255dec546cbe1318718d472b438ffc20a210a"
    ),
    "protected_state_file_sha256": (
        "c6879d96fe5db5b0516a687d427e12ce435d129c6f74b245fad9a577cbd2fb90"
    ),
}
_ISSUE171_OWNER_LAUNCH_V8_REPLAY_BINDINGS = {
    "terminal_packet_sha256": (
        "67a25df153c7edcb19fd9dc63ac5272accd90061a4244f4cf004b33f1beec4d3"
    ),
    "failure_evidence_sha256": (
        "f56e7f493876971a4bfdb07969c625722525c1fc9fd93455c9f63dd34bb18662"
    ),
    "issue171_terminal_receipt_file_sha256": (
        "67a25df153c7edcb19fd9dc63ac5272accd90061a4244f4cf004b33f1beec4d3"
    ),
    "issue171_terminal_report_sha256": (
        "2005702600bdfc80390868c496c66e2a5b2b53f7afa0a060bbd32b5fd4ec0fb4"
    ),
    "issue171_owner_failure_file_sha256": (
        "794f6ade2dd508914f60001377a6b93a2709ad8228ddbc813b0774cc1c9bf685"
    ),
    "issue171_owner_failure_report_sha256": (
        "d2c0cf6a29cc25875e891049068eea1f8b76ee178ab7efa4b03b4a54e193546b"
    ),
    "issue171_thread_start_response_file_sha256": (
        "f56e7f493876971a4bfdb07969c625722525c1fc9fd93455c9f63dd34bb18662"
    ),
    "issue171_app_server_transcript_file_sha256": (
        "847ab138c0fdd9f6361df9f02df7ec9daf5c0c5a5143495ed9ed5b8e4a0f35d1"
    ),
    "issue171_host_preparation_file_sha256": (
        "232a2912ae06366c1aa1e2000b53eb0d740c7f3035ef77964574f87028ce9c2b"
    ),
    "issue171_host_preparation_report_sha256": (
        "d2ef97ba73daeb90c4be846720ccf7b0b212066036b74f27f96f9e2ad2609bc5"
    ),
    "issue171_owner_inventory_file_sha256": (
        "cc712e9217a57940d527df37d50d50daae11acb5416f709d7fe3755070e88c40"
    ),
    "issue171_owner_inventory_report_sha256": (
        "d2fe5b8d6b2ebaa0ab08a5767fef383e547b019e9d7f9a6fd2e2c4e6e620c601"
    ),
    "issue171_app_server_argv_sha256": (
        "bf9f682b3ac40570f666e3ce59843b03281dcaac41c458769884a3fd9840e757"
    ),
    "issue171_task_id": "01a06dd4-b2fa-70d3-90c5-ee36d8a54e08",
    "issue171_generation": "0.1.0+codex.20260904185808",
    "issue171_candidate_commit": (
        "de91bc8e9c3a0574ef83e70a642e114e87ab33f7"
    ),
    "issue171_package_digest": (
        "0a814a01465e4f08fae407fc8e1cf4b658861c2b3d1f3304d4abbc58fad970d1"
    ),
    "protected_state_file_sha256": (
        "c6879d96fe5db5b0516a687d427e12ce435d129c6f74b245fad9a577cbd2fb90"
    ),
}
_ISSUE171_OWNER_LAUNCH_V9_REPLAY_BINDINGS = {
    "terminal_packet_sha256": (
        "5ce07f12c097e0585fab4d9831a00a2e04f977adc924803a5b5eddd6ccb94217"
    ),
    "failure_evidence_sha256": (
        "7f0023eb054d924494afa5f36b0a24ee76a9cbc73ee102a4361d3101f69427f4"
    ),
    "issue171_terminal_receipt_file_sha256": (
        "5ce07f12c097e0585fab4d9831a00a2e04f977adc924803a5b5eddd6ccb94217"
    ),
    "issue171_terminal_report_sha256": (
        "a134f061cf547b410018a6472f1dc5d82d15ab516c25bc183f6f2608f0eb4011"
    ),
    "issue171_owner_failure_file_sha256": (
        "098926aef4b5df2316f45a66b1e5e36316ed9ab62b07c858184d166fa0344600"
    ),
    "issue171_owner_failure_report_sha256": (
        "d7a357fcf24138e434b2ada13106b0fa9c2a31e8c35ba1d04c89267a3a83422e"
    ),
    "issue171_app_server_transcript_file_sha256": (
        "7f0023eb054d924494afa5f36b0a24ee76a9cbc73ee102a4361d3101f69427f4"
    ),
    "issue171_checkout_file_sha256": (
        "ee2768ad83ad6a437e14840e729bfabfb9015dc0f1c8c0a0e4549e12fe448bc2"
    ),
    "issue171_checkout_report_sha256": (
        "ad8f862bd8fff1024f471b1102e997736a3959330454d9efbfecdce34932277f"
    ),
    "issue171_host_preparation_file_sha256": (
        "fe6d792cd317fc92a08d87ffaf34aa582a464207fc190abc650cd4fa1f854895"
    ),
    "issue171_host_preparation_report_sha256": (
        "526c6e484f24083943bc5a116adbcfee9757ba738acb6675138558da4fd309da"
    ),
    "issue171_owner_inventory_file_sha256": (
        "fd43a0d9940d191260f21b18b53d91360399332afb3186b764900dc1f63538bb"
    ),
    "issue171_owner_inventory_report_sha256": (
        "3889955d3712d54bf07e83ccc18c4041bbc27667842e2e08cd92b23e0a097a95"
    ),
    "issue171_app_server_argv_sha256": (
        "c213cecd90309f3c98c6f69c49d90b6fb84991982321445bc536aa40f37b53c5"
    ),
    "issue171_owner_client_file_sha256": (
        "aa7d344b09a7f3ba0ac109ee5a022e1d8bef1e4aec8a572e2541f32f9fc58c32"
    ),
    "issue171_task_creation_intent_file_sha256": (
        "cc4213c0918fd25b93596fe6877448cca01a9feb3a685bf97a2020a2ec1b65d1"
    ),
    "issue171_task_creation_pre_call_report_file_sha256": (
        "ddca0a6a1cf1f9ac0916a4b06e95f255393ce7b727928bb3137fede936f1b0c8"
    ),
    "issue171_generation": "0.1.0+codex.20260904201511",
    "issue171_candidate_commit": (
        "270cabbb26db15411c51ae5b2132689e5b2ab4cd"
    ),
    "issue171_package_digest": (
        "fbeea60a72d23b938f10e22626c44200f0b1e3980b028f20de8335ff47fe205f"
    ),
    "protected_state_file_sha256": (
        "c6879d96fe5db5b0516a687d427e12ce435d129c6f74b245fad9a577cbd2fb90"
    ),
}
_ISSUE171_OWNER_LAUNCH_V10_REPLAY_BINDINGS = {
    "terminal_packet_sha256": (
        "36ae816ce7ea8a4a7c5ea3e6ef644d00d5ddc097b9cab01b5b020f00e9637b56"
    ),
    "failure_evidence_sha256": (
        "fa9eec6323bf3866b4438d202a7c10552f08221cd5fa448438c6aca7dfdb865b"
    ),
    "issue171_terminal_receipt_file_sha256": (
        "36ae816ce7ea8a4a7c5ea3e6ef644d00d5ddc097b9cab01b5b020f00e9637b56"
    ),
    "issue171_terminal_report_sha256": (
        "3c5d7d52ce4a920cfb2c94a4497a31b21de7799df8445f580d9ed97da0ec2e1e"
    ),
    "issue171_owner_failure_file_sha256": (
        "f8820788b06cdb0a7b73b7b21fab01351a2ba45454a420d3b936774011666362"
    ),
    "issue171_owner_failure_report_sha256": (
        "85349836ad909bb6fd1690eb482c9ab3ec91271fd8f6bd861d02f32180275e53"
    ),
    "issue171_app_server_transcript_file_sha256": (
        "fa9eec6323bf3866b4438d202a7c10552f08221cd5fa448438c6aca7dfdb865b"
    ),
    "issue171_checkout_file_sha256": (
        "13b79db14e6db851d077348d5366138b492c40f17d7299cf5f8db51c75e538e2"
    ),
    "issue171_checkout_report_sha256": (
        "bcb9cae90b92b2efc5e24d88d16b6a46fce54feda7cfe57134dbced17bd47fa2"
    ),
    "issue171_host_preparation_file_sha256": (
        "c0670389343b9d2405887a76119e93376c39052e2a11d355054a84daf7260383"
    ),
    "issue171_host_preparation_report_sha256": (
        "92aa85cd3a8373decef31d599bb01158d038a7d8a24e68b6336695198a886aeb"
    ),
    "issue171_owner_inventory_file_sha256": (
        "a8e1b1d9e2a7da0d4e7df3138ca9c7622886c96b576bcff696ef5dea4cc0eaa5"
    ),
    "issue171_owner_inventory_report_sha256": (
        "f7f6b2291f30fe8e84083c73b76b05df3f9030c4609333fff2696716f1db090f"
    ),
    "issue171_app_server_argv_sha256": (
        "315d1826de8bd47969951eb7ba1f4e5efcce1dae20e2ffe3405c0d6ceef0ae3a"
    ),
    "issue171_owner_client_file_sha256": (
        "7c8b03665bc9692d6acdb66d9b2f214082a5be038de2e498eb9620a322a7c051"
    ),
    "issue171_task_creation_intent_file_sha256": (
        "c0bf40927fe27844748e311bd5f85edb3d3039e106623b680ce9d1bfc41594c8"
    ),
    "issue171_task_creation_pre_call_report_file_sha256": (
        "a92886534df53f6daeed29a1ef0ffccdefb4acc225464d762e3b3f4d0c7ef50c"
    ),
    "issue171_generation": "0.1.0+codex.20260904211719",
    "issue171_candidate_commit": (
        "b97e03ea120a620260abc77b84bc3a17188f6738"
    ),
    "issue171_package_digest": (
        "d9680f74005c8da8130250e6456004edb830f95bc08b3cc379a4bb5fcaedf23f"
    ),
    "protected_state_file_sha256": (
        "c6879d96fe5db5b0516a687d427e12ce435d129c6f74b245fad9a577cbd2fb90"
    ),
}
_CYCLE20_PRE_SPAWN_FAILURE_CODES = [
    "execution_readiness:environment:runtime_binding_invalid",
    "execution_readiness:not_ready",
    "hard_admission:component:capability:expired",
    "hard_admission:component:capability:source_locator_unavailable",
    "hard_admission:component:custody:expired",
    "hard_admission:component:custody:source_locator_unavailable",
    "hard_admission:component:graph:expired",
    "hard_admission:component:graph:source_locator_unavailable",
    "hard_admission:component:inventory:expired",
    "hard_admission:component:inventory:source_locator_unavailable",
    "hard_admission:component:native_receipt:expired",
    "hard_admission:component:native_receipt:source_locator_unavailable",
    "hard_admission:component:spawn:expired",
    "hard_admission:component:spawn:source_locator_unavailable",
    "hard_admission:not_admitted",
]
_ARTIFACT_VALIDATION_NAMES = (
    "rehearsal",
    "approval_preflight",
    "route_request",
    "route_canary_program",
    "activation_preparation",
    "structural_qualification",
    "structural_validation",
)
_MAX_ARTIFACT_BYTES = 1_048_576
_PROGRAM_FIELDS = frozenset(
    {
        "schema",
        "case",
        "advisory_program",
        "route_task_spec_template",
        "route",
        "activation",
    }
)
_STAGE_NAMES = frozenset(
    {
        "advisory_preparation",
        "route_task_spec",
        "candidate_validation",
        "route_request",
        "route_canary_preparation",
        "activation_preparation",
        "structural_qualification",
        "structural_validation",
        "approval_preflight",
    }
)
_STAGE_FIELDS = frozenset({"status", "report"})
_COUNTER_FIELDS = frozenset(
    {
        "credential_reads",
        "network_calls",
        "provider_calls",
        "model_calls",
        "hosted_calls",
        "live_preflights",
        "canary_calls",
        "controller_activations",
        "capacity_reservations",
        "authority_grants",
        "native_actions",
        "workers",
        "retries",
        "fallbacks",
        "replacements",
    }
)
_REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "decision",
        "qualified",
        "issues",
        "case_id",
        "replay",
        "runtime_projected",
        "runtime_module_root",
        "stages",
        "qualification_payload",
        "boundary",
        "counters",
        "report_sha256",
    }
)
_APPROVAL_PREFLIGHT_FIELDS = frozenset(
    {
        "schema",
        "checkpoint",
        "disposition",
        "objective",
        "frozen_attempt_sha256",
        "approval_target_sha256",
        "target",
        "gates",
        "counters",
        "request_binding_unchanged",
        "next_authorized_action",
        "report_sha256",
    }
)
_APPROVAL_TARGET_FIELDS = frozenset(
    {
        "attempt_sha256",
        "approval_target_sha256",
        "installed_generation",
        "request_sha256",
        "runtime_identity_sha256",
        "structural_qualification_sha256",
        "structural_validation_sha256",
        "activation_preparation_sha256",
    }
)
_APPROVAL_GATE_IDS = (
    "attempt_identity",
    "target_generation",
    "offline_contracts",
    "inputs",
    "dependencies",
    "authority_scope",
    "authority_freshness",
    "budgets",
    "containment",
    "request_contract",
    "one_attempt",
    "observability",
    "success_settlement",
    "failure_settlement",
    "cleanup_recovery",
    "live_availability",
)
_APPROVAL_OBJECTIVE = (
    "Owner-bound fresh Local qualification of Issue 94/FR63"
)
_NEXT_AUTHORIZED_ACTION = (
    "revalidate exact route request and synthetic structural report, then "
    "invoke the one-shot route canary"
)


class QualificationRehearsalError(ValueError):
    """Stable refusal raised before a live or native boundary."""


def _replay_fields(value: Any) -> frozenset[str]:
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA:
        return _REPLAY_FIELDS_V1
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V2:
        return _REPLAY_FIELDS_V2
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V3:
        return _REPLAY_FIELDS_V3
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V4:
        return _REPLAY_FIELDS_V4
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V5:
        return _REPLAY_FIELDS_V5
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V6:
        return _REPLAY_FIELDS_V6
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V7:
        return _REPLAY_FIELDS_V7
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V8:
        return _REPLAY_FIELDS_V8
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V9:
        return _REPLAY_FIELDS_V9
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V10:
        return _REPLAY_FIELDS_V10
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V11:
        return _REPLAY_FIELDS_V11
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V12:
        return _REPLAY_FIELDS_V12
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V13:
        return _REPLAY_FIELDS_V13
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V14:
        return _REPLAY_FIELDS_V14
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V15:
        return _REPLAY_FIELDS_V15
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V16:
        return _REPLAY_FIELDS_V16
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V17:
        return _REPLAY_FIELDS_V17
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V18:
        return _REPLAY_FIELDS_V18
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V19:
        return _REPLAY_FIELDS_V19
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V20:
        return _REPLAY_FIELDS_V20
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V21:
        return _REPLAY_FIELDS_V21
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V22:
        return _REPLAY_FIELDS_V22
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V23:
        return _REPLAY_FIELDS_V23
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V24:
        return _REPLAY_FIELDS_V24
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V25:
        return _REPLAY_FIELDS_V25
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V26:
        return _REPLAY_FIELDS_V26
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V27:
        return _REPLAY_FIELDS_V27
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V28:
        return _REPLAY_FIELDS_V28
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V29:
        return _REPLAY_FIELDS_V29
    if isinstance(value, Mapping) and value.get("schema") == REPLAY_SCHEMA_V30:
        return _REPLAY_FIELDS_V30
    raise QualificationRehearsalError("replay:version_invalid")


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


def _module_plugin_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _closed(value: Any, fields: frozenset[str], issue: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise QualificationRehearsalError(issue)
    return value


@dataclass(frozen=True, slots=True)
class ValidatedContractReport:
    """Typed access to the generic adaptive-contract validation envelope."""

    report: dict[str, Any]
    normalized: dict[str, Any]
    digest: str

    @classmethod
    def from_report(
        cls,
        report: Any,
        *,
        stage: str,
        contract_schema: str,
    ) -> "ValidatedContractReport":
        required = {
            "schema",
            "contract_schema",
            "status",
            "valid",
            "issues",
            "normalized",
            "digest",
        }
        if not isinstance(report, Mapping) or not required.issubset(report):
            raise QualificationRehearsalError(
                stage + ":report_shape_invalid"
            )
        normalized = report.get("normalized")
        digest = report.get("digest")
        normalized_seal_valid = False
        if isinstance(normalized, Mapping) and _is_sha(digest):
            for key, item in normalized.items():
                if (
                    key.endswith("_sha256")
                    and item == digest
                    and contracts.json_sha256(
                        {
                            field: child
                            for field, child in normalized.items()
                            if field != key
                        }
                    )
                    == digest
                ):
                    normalized_seal_valid = True
                    break
        if (
            report.get("schema") != contracts.VALIDATION_SCHEMA
            or report.get("contract_schema") != contract_schema
            or report.get("status") != "PASS"
            or report.get("valid") is not True
            or report.get("issues") != []
            or not isinstance(normalized, Mapping)
            or not _is_sha(digest)
            or not normalized_seal_valid
        ):
            raise QualificationRehearsalError(
                stage + ":report_invalid"
            )
        return cls(
            report=deepcopy(dict(report)),
            normalized=deepcopy(dict(normalized)),
            digest=str(digest),
        )


@dataclass(frozen=True, slots=True)
class CandidateValidationReport:
    """Typed candidate report with a distinct five-field submitted value."""

    report: dict[str, Any]
    candidate: dict[str, Any]
    digest: str

    @classmethod
    def from_report(cls, report: Any) -> "CandidateValidationReport":
        envelope = ValidatedContractReport.from_report(
            report,
            stage="candidate_validation",
            contract_schema=contracts.HANDOFF_PREFLIGHT_CANDIDATE_SCHEMA,
        )
        if envelope.normalized.get("candidate_sha256") != envelope.digest:
            raise QualificationRehearsalError(
                "candidate_validation:digest_binding_invalid"
            )
        candidate = deepcopy(envelope.normalized)
        candidate.pop("candidate_sha256", None)
        if set(candidate) != {
            "schema",
            "preflight_id",
            "task_spec_sha256",
            "capability_profile",
            "handoff_receipt",
        }:
            raise QualificationRehearsalError(
                "candidate_validation:candidate_shape_invalid"
            )
        return cls(
            report=envelope.report,
            candidate=candidate,
            digest=envelope.digest,
        )


@dataclass(frozen=True, slots=True)
class AdvisoryPreparationReport:
    """Strict typed view over one complete advisory preparation report."""

    report: dict[str, Any]
    logical_plan: dict[str, Any]
    logical_plan_sha256: str
    task_specs: tuple[dict[str, Any], ...]

    @classmethod
    def from_report(cls, report: Any) -> "AdvisoryPreparationReport":
        if not isinstance(report, Mapping):
            raise QualificationRehearsalError(
                "advisory_preparation:report_shape_invalid"
            )
        logical_plan = report.get("logical_plan")
        logical_plan_sha256 = report.get("logical_plan_sha256")
        raw_specs = report.get("task_specs")
        report_sha256 = report.get("report_sha256")
        try:
            report_sealed = report_sha256 == _sha(
                {
                    key: item
                    for key, item in report.items()
                    if key != "report_sha256"
                }
            )
        except (TypeError, ValueError, OverflowError):
            report_sealed = False
        if (
            report.get("schema") not in {advisory_scan.REPORT_SCHEMA_V2, advisory_scan.REPORT_SCHEMA_V3}
            or report.get("status") != "PASS"
            or report.get("decision") != "PREPARED"
            or report.get("issues") != []
            or not isinstance(logical_plan, Mapping)
            or not _is_sha(logical_plan_sha256)
            or _sha(logical_plan) != logical_plan_sha256
            or not isinstance(raw_specs, list)
            or len(raw_specs) != 2
            or not report_sealed
        ):
            raise QualificationRehearsalError(
                "advisory_preparation:report_invalid"
            )
        task_specs: list[dict[str, Any]] = []
        lane_ids: list[str] = []
        for row in raw_specs:
            if not isinstance(row, Mapping) or set(row) != {
                "lane_id",
                "task_spec_sha256",
                "task_spec",
            }:
                raise QualificationRehearsalError(
                    "advisory_preparation:task_spec_binding_invalid"
                )
            envelope = ValidatedContractReport.from_report(
                contracts.validate_task_spec(row.get("task_spec")),
                stage="advisory_preparation.task_spec",
                contract_schema=contracts.TASK_SPEC_SCHEMA,
            )
            lane_id = row.get("lane_id")
            if (
                not isinstance(lane_id, str)
                or envelope.normalized.get("id") != lane_id
                or row.get("task_spec_sha256") != envelope.digest
            ):
                raise QualificationRehearsalError(
                    "advisory_preparation:task_spec_binding_invalid"
                )
            lane_ids.append(lane_id)
            task_specs.append(
                {
                    "logical_worker_id": lane_id,
                    "task_spec": envelope.normalized,
                }
            )
        if sorted(lane_ids) != ["spec", "standards"]:
            raise QualificationRehearsalError(
                "advisory_preparation:lane_set_invalid"
            )
        normalized = native_controller.normalized_task_specs(task_specs)
        return cls(
            report=deepcopy(dict(report)),
            logical_plan=deepcopy(dict(logical_plan)),
            logical_plan_sha256=str(logical_plan_sha256),
            task_specs=tuple(deepcopy(normalized)),
        )


@dataclass(frozen=True, slots=True)
class ActivationPreparationReport:
    """Typed ready-only activation-preparation envelope."""

    report: dict[str, Any]
    prepared_activation_payload: dict[str, Any]

    @classmethod
    def from_report(cls, report: Any) -> "ActivationPreparationReport":
        validation = native_controller.validate_activation_preparation_report(
            report
        )
        payload = (
            report.get("prepared_activation_payload")
            if isinstance(report, Mapping)
            else None
        )
        if (
            validation != {"valid": True, "issues": []}
            or report.get("status") != "PASS"
            or report.get("decision") != "READY_FOR_ACTIVATION"
            or not isinstance(payload, Mapping)
        ):
            raise QualificationRehearsalError(
                "activation_preparation:report_invalid"
            )
        return cls(
            report=deepcopy(dict(report)),
            prepared_activation_payload=deepcopy(dict(payload)),
        )


@dataclass(frozen=True, slots=True)
class StructuralQualificationReport:
    """Typed access to canonical qualification and runtime seals."""

    report: dict[str, Any]
    validation: dict[str, Any]
    runtime_identity_digest: str
    qualification_digest: str
    request_digest: str
    validation_digest: str

    @classmethod
    def from_reports(
        cls,
        report: Any,
        validation: Any,
    ) -> "StructuralQualificationReport":
        value = deepcopy(dict(report)) if isinstance(report, Mapping) else {}
        expected = (
            transport_qualification.validate_zero_tool_transport_qualification(
                value
            )
        )
        runtime = value.get("runtime_identity")
        if (
            expected != validation
            or expected.get("status") != "PASS"
            or expected.get("valid") is not True
            or expected.get("issues") != []
            or value.get("status") != "PASS"
            or value.get("qualified") is not True
            or not isinstance(runtime, Mapping)
            or not _is_sha(runtime.get("runtime_identity_sha256"))
            or not _is_sha(value.get("qualification_sha256"))
            or not _is_sha(value.get("request_sha256"))
            or not _is_sha(expected.get("report_sha256"))
        ):
            raise QualificationRehearsalError(
                "structural_qualification:report_invalid"
            )
        return cls(
            report=value,
            validation=deepcopy(dict(expected)),
            runtime_identity_digest=str(
                runtime["runtime_identity_sha256"]
            ),
            qualification_digest=str(value["qualification_sha256"]),
            request_digest=str(value["request_sha256"]),
            validation_digest=str(expected["report_sha256"]),
        )


@dataclass(frozen=True, slots=True)
class ApprovalPreflightReport:
    """Typed access to the repository-owned approval report and seal."""

    report: dict[str, Any]
    target: dict[str, Any]
    approval_target_digest: str
    digest: str

    @classmethod
    def from_report(cls, report: Any) -> "ApprovalPreflightReport":
        validation = validate_approval_preflight_report(report)
        target = report.get("target") if isinstance(
            report, Mapping
        ) else None
        digest = report.get("report_sha256") if isinstance(
            report, Mapping
        ) else None
        if (
            validation != {"valid": True, "issues": []}
            or not isinstance(target, Mapping)
            or not _is_sha(report.get("approval_target_sha256"))
            or not _is_sha(digest)
        ):
            raise QualificationRehearsalError(
                "approval_preflight:report_invalid"
            )
        return cls(
            report=deepcopy(dict(report)),
            target=deepcopy(dict(target)),
            approval_target_digest=str(
                report["approval_target_sha256"]
            ),
            digest=str(digest),
        )


def _frozen_worker_route(value: Any) -> tuple[str, str] | None:
    report = value if isinstance(value, Mapping) else {}
    payload = report.get("qualification_payload")
    plan = payload.get("logical_plan") if isinstance(payload, Mapping) else None
    execution = plan.get("execution") if isinstance(plan, Mapping) else None
    model = execution.get("worker_model") if isinstance(execution, Mapping) else None
    effort = execution.get("worker_effort") if isinstance(execution, Mapping) else None
    if not isinstance(model, str) or not model or not isinstance(effort, str) or not effort:
        return None
    return model, effort


@contextmanager
def _bind_frozen_worker_route(value: Any) -> Iterator[None]:
    route = _frozen_worker_route(value)
    if route is None:
        yield
        return
    model, effort = route
    with worker_default.pinned(
        model=model,
        effort=effort,
    ), zero_tool.pinned_route(model=model, effort=effort):
        yield


@dataclass(frozen=True, slots=True)
class QualificationArtifact:
    """Strict typed access to one complete persisted rehearsal handoff."""

    report: dict[str, Any]
    report_sha256: str
    route_request: dict[str, Any]
    route_canary_program: dict[str, Any]
    approval_preflight_report: dict[str, Any]
    prepared_activation_payload: dict[str, Any]
    structural_qualification_report: dict[str, Any]
    structural_validation_report: dict[str, Any]

    @classmethod
    def from_report(cls, report: Any) -> "QualificationArtifact":
        validation = validate_qualification_rehearsal(report)
        if validation != {"valid": True, "issues": []}:
            raise QualificationRehearsalError(
                "qualification_artifact:report_invalid"
            )
        value = deepcopy(dict(report))
        payload = value.get("qualification_payload")
        stages = value.get("stages")
        if not isinstance(payload, Mapping) or not isinstance(
            stages, Mapping
        ):
            raise QualificationRehearsalError(
                "qualification_artifact:report_invalid"
            )
        route_request = payload.get("route_request")
        route_canary_program = payload.get("route_canary_program")
        approval = payload.get("approval_preflight_report")
        activation = payload.get("prepared_activation_payload")
        structural_stage = stages.get("structural_qualification")
        validation_stage = stages.get("structural_validation")
        structural = (
            structural_stage.get("report")
            if isinstance(structural_stage, Mapping)
            else None
        )
        structural_validation = (
            validation_stage.get("report")
            if isinstance(validation_stage, Mapping)
            else None
        )
        if not all(
            isinstance(item, Mapping)
            for item in (
                route_request,
                route_canary_program,
                approval,
                activation,
                structural,
                structural_validation,
            )
        ):
            raise QualificationRehearsalError(
                "qualification_artifact:report_invalid"
            )
        ApprovalPreflightReport.from_report(approval)
        with _bind_frozen_worker_route(value):
            if route_canary.validate_route_canary_program(
                route_canary_program
            ) != {"valid": True, "issues": []}:
                raise QualificationRehearsalError(
                    "qualification_artifact:report_invalid"
                )
        if route_canary_program.get("route_request") != route_request:
            raise QualificationRehearsalError(
                "qualification_artifact:report_invalid"
            )
        StructuralQualificationReport.from_reports(
            structural,
            structural_validation,
        )
        report_sha256 = value.get("report_sha256")
        if not _is_sha(report_sha256):
            raise QualificationRehearsalError(
                "qualification_artifact:report_invalid"
            )
        return cls(
            report=value,
            report_sha256=str(report_sha256),
            route_request=deepcopy(dict(route_request)),
            route_canary_program=deepcopy(dict(route_canary_program)),
            approval_preflight_report=deepcopy(dict(approval)),
            prepared_activation_payload=deepcopy(dict(activation)),
            structural_qualification_report=deepcopy(dict(structural)),
            structural_validation_report=deepcopy(
                dict(structural_validation)
            ),
        )


def load_replay_corpus(
    plugin_root: str | Path | None = None,
) -> dict[str, Any]:
    """Load and strictly validate the permanent pre-live failure corpus."""

    root = _module_plugin_root() if plugin_root is None else Path(plugin_root)
    path = root / CORPUS_RELATIVE
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationRehearsalError(
            "replay_corpus:unavailable"
        ) from error
    if (
        not isinstance(value, Mapping)
        or set(value) != {"schema", "cases"}
        or value.get("schema") != REPLAY_CORPUS_SCHEMA
        or not isinstance(value.get("cases"), list)
    ):
        raise QualificationRehearsalError("replay_corpus:shape_invalid")
    case_ids: list[str] = []
    for case in value["cases"]:
        try:
            replay_fields = _replay_fields(case)
        except QualificationRehearsalError as error:
            raise QualificationRehearsalError(
                "replay_corpus:case_invalid"
            ) from error
        _closed(case, replay_fields, "replay_corpus:case_shape_invalid")
        if (
            case.get("schema") == REPLAY_SCHEMA_V26
            and _sha(case) != _ISSUE171_OWNER_LAUNCH_V11_REPLAY_SHA256
        ):
            raise QualificationRehearsalError("replay_corpus:case_invalid")
        if (
            case.get("schema") == REPLAY_SCHEMA_V27
            and _sha(case) != _ISSUE171_OWNER_LAUNCH_V12_REPLAY_SHA256
        ):
            raise QualificationRehearsalError("replay_corpus:case_invalid")
        if (
            case.get("schema") == REPLAY_SCHEMA_V28
            and _sha(case) != _ISSUE171_LIVE_PRICING_V13_REPLAY_SHA256
        ):
            raise QualificationRehearsalError("replay_corpus:case_invalid")
        if (
            case.get("schema") == REPLAY_SCHEMA_V29
            and _sha(case) != _ISSUE171_OWNER_LAUNCH_V14_REPLAY_SHA256
        ):
            raise QualificationRehearsalError("replay_corpus:case_invalid")
        if (
            case.get("schema") == REPLAY_SCHEMA_V30
            and _sha(case) != _ISSUE171_CONTROLLER_ROOT_V15_REPLAY_SHA256
        ):
            raise QualificationRehearsalError("replay_corpus:case_invalid")
        if (
            not isinstance(case.get("case_id"), str)
            or not _is_sha(case.get("terminal_packet_sha256"))
            or not _is_sha(case.get("failure_evidence_sha256"))
            or not isinstance(case.get("failure_stage"), str)
            or not isinstance(case.get("failure_code"), str)
            or not isinstance(case.get("legacy_route_input_refs"), list)
            or any(
                not isinstance(item, str) or not item
                for item in case.get("legacy_route_input_refs", [])
            )
            or case.get("legacy_candidate_digest_field")
            not in {None, "candidate_sha256"}
            or not isinstance(
                case.get("legacy_preflight_runtime_globals"), list
            )
            or any(
                item not in {"TextEncoder", "crypto"}
                for item in case.get(
                    "legacy_preflight_runtime_globals", []
                )
            )
            or len(case.get("legacy_preflight_runtime_globals", []))
            != len(
                set(case.get("legacy_preflight_runtime_globals", []))
            )
            or not isinstance(
                case.get("legacy_validator_transport_failures"), list
            )
            or any(
                not isinstance(item, str) or not item
                for item in case.get(
                    "legacy_validator_transport_failures", []
                )
            )
            or len(case.get("legacy_validator_transport_failures", []))
            != len(
                set(case.get("legacy_validator_transport_failures", []))
            )
            or case.get("legacy_endpoint_resolution")
            not in {
                None,
                "mixed_sensitivity_runtime_metadata:runtime-port.json",
            }
            or (
                case.get("schema")
                in {
                    REPLAY_SCHEMA_V2,
                    REPLAY_SCHEMA_V3,
                    REPLAY_SCHEMA_V4,
                    REPLAY_SCHEMA_V5,
                    REPLAY_SCHEMA_V6,
                    REPLAY_SCHEMA_V7,
                    REPLAY_SCHEMA_V8,
                    REPLAY_SCHEMA_V9,
                    REPLAY_SCHEMA_V10,
                    REPLAY_SCHEMA_V11,
                    REPLAY_SCHEMA_V12,
                    REPLAY_SCHEMA_V13,
                    REPLAY_SCHEMA_V14,
                }
                and (
                    not isinstance(
                        case.get("legacy_research_source_paths"), list
                    )
                    or any(
                        not isinstance(item, str) or not item
                        for item in case.get(
                            "legacy_research_source_paths", []
                        )
                    )
                    or len(case.get("legacy_research_source_paths", []))
                    != len(
                        set(case.get("legacy_research_source_paths", []))
                    )
                )
            )
            or (
                case.get("schema")
                in {
                    REPLAY_SCHEMA_V3,
                    REPLAY_SCHEMA_V4,
                    REPLAY_SCHEMA_V5,
                    REPLAY_SCHEMA_V6,
                    REPLAY_SCHEMA_V7,
                    REPLAY_SCHEMA_V8,
                    REPLAY_SCHEMA_V9,
                    REPLAY_SCHEMA_V10,
                    REPLAY_SCHEMA_V11,
                    REPLAY_SCHEMA_V12,
                    REPLAY_SCHEMA_V13,
                    REPLAY_SCHEMA_V14,
                }
                and (
                    case.get("legacy_ticket_admission_program_schema")
                    != "orch-dork/ticket-admission-program/v1"
                    or case.get("required_ticket_admission_program_schema")
                    != "orch-dork/ticket-admission-program/v2"
                    or case.get("legacy_pre_spawn_assembly")
                    != "ephemeral_field_translation"
                )
            )
            or (
                case.get("schema")
                in {
                    REPLAY_SCHEMA_V4,
                    REPLAY_SCHEMA_V5,
                    REPLAY_SCHEMA_V6,
                    REPLAY_SCHEMA_V7,
                    REPLAY_SCHEMA_V8,
                    REPLAY_SCHEMA_V9,
                    REPLAY_SCHEMA_V10,
                    REPLAY_SCHEMA_V11,
                    REPLAY_SCHEMA_V12,
                    REPLAY_SCHEMA_V13,
                    REPLAY_SCHEMA_V14,
                }
                and (
                    case.get("legacy_enrollment_program_schema")
                    != "orch-dork/project-binding/v1"
                    or case.get("required_enrollment_program_schema")
                    != "orch-dork/project-enrollment-program/v1"
                    or case.get("activation_failure_codes")
                    != [
                        "activation:enrollment_not_active",
                        "activation:enrollment_identity_mismatch",
                    ]
                    or case.get("legacy_enrollment_assembly")
                    != "binding_manifest_as_enrollment_program"
                )
            )
            or (
                case.get("schema") in {REPLAY_SCHEMA_V5, REPLAY_SCHEMA_V6}
                and (
                    case.get("legacy_hook_trust_assembly")
                    != "caller_self_seal"
                    or case.get("required_hook_trust_payload_schema")
                    != "orch-dork/hook-trust-observation/v1"
                    or case.get("required_hook_trust_assembly")
                    != "host_signed_content_addressed_receipt"
                    or case.get("hook_trust_activation_failure_codes")
                    != ["activation:hook_trust_receipt_missing"]
                )
            )
            or (
                case.get("schema")
                in {
                    REPLAY_SCHEMA_V7,
                    REPLAY_SCHEMA_V8,
                    REPLAY_SCHEMA_V9,
                    REPLAY_SCHEMA_V10,
                    REPLAY_SCHEMA_V11,
                    REPLAY_SCHEMA_V12,
                    REPLAY_SCHEMA_V13,
                    REPLAY_SCHEMA_V14,
                }
                and (
                    case.get("legacy_hook_trust_assembly")
                    != "caller_self_seal"
                    or case.get("required_hook_trust_payload_schema")
                    != native_controller.HOOK_TRUST_PAYLOAD_SCHEMA
                    or case.get("required_hook_trust_assembly")
                    != "host_signed_content_addressed_receipt"
                    or case.get("hook_trust_activation_failure_codes")
                    != ["activation:hook_trust_receipt_missing"]
                )
            )
            or (
                case.get("schema")
                in {
                    REPLAY_SCHEMA_V6,
                    REPLAY_SCHEMA_V7,
                    REPLAY_SCHEMA_V8,
                    REPLAY_SCHEMA_V9,
                    REPLAY_SCHEMA_V10,
                    REPLAY_SCHEMA_V11,
                    REPLAY_SCHEMA_V12,
                    REPLAY_SCHEMA_V13,
                    REPLAY_SCHEMA_V14,
                }
                and (
                    case.get("legacy_controller_bootstrap")
                    != "ephemeral_activation_then_stage"
                    or case.get("legacy_controller_source_roots")
                    != ["source"]
                    or case.get("required_controller_source_roots")
                    != ["evidence", "source"]
                    or case.get("required_controller_bootstrap")
                    != "repository_owned_atomic_activation_pre_spawn"
                    or not _is_sha(
                        case.get("controller_stage_report_sha256")
                    )
                    or not _is_sha(
                        case.get("controller_inspection_report_sha256")
                    )
                    or case.get("pre_spawn_failure_codes")
                    != _CYCLE20_PRE_SPAWN_FAILURE_CODES
                )
            )
            or (
                case.get("schema")
                in {
                    REPLAY_SCHEMA_V7,
                    REPLAY_SCHEMA_V8,
                    REPLAY_SCHEMA_V9,
                    REPLAY_SCHEMA_V10,
                    REPLAY_SCHEMA_V11,
                    REPLAY_SCHEMA_V12,
                    REPLAY_SCHEMA_V13,
                    REPLAY_SCHEMA_V14,
                }
                and (
                    case.get("legacy_owner_hook_inventory")
                    != "all_required_hooks_disabled"
                    or case.get("required_owner_hook_inventory")
                    != "owner_observed_enabled"
                    or case.get("required_hook_enablement")
                    != "invocation_local_config_overlay"
                    or case.get("native_hook_failure_codes")
                    != _CYCLE21_NATIVE_HOOK_FAILURE_CODES
                    or case.get("predecessor_settlement_required") is not True
                    or not _is_sha(
                        case.get("terminal_controller_report_sha256")
                    )
                    or not _is_sha(
                        case.get("terminal_inspection_report_sha256")
                    )
                )
            )
            or (
                case.get("schema")
                in {
                    REPLAY_SCHEMA_V8,
                    REPLAY_SCHEMA_V9,
                    REPLAY_SCHEMA_V10,
                    REPLAY_SCHEMA_V11,
                    REPLAY_SCHEMA_V12,
                    REPLAY_SCHEMA_V13,
                    REPLAY_SCHEMA_V14,
                }
                and (
                    case.get("legacy_terminal_session_start_policy")
                    != "bind_all_sessions_to_predecessor_root"
                    or case.get("required_terminal_session_start_policy")
                    != "clean_terminal_fresh_startup_only"
                    or case.get("terminal_session_failure_codes")
                    != ["native_controller:root_session_mismatch"]
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V8
                and (
                    case.get("failure_stage") != "fresh_task_session_start"
                    or case.get("failure_code")
                    != "native_controller:root_session_mismatch"
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V9
                and (
                    case.get("failure_stage")
                    != "fresh_task_first_runtime_observer"
                    or case.get("failure_code")
                    != "native_controller:exact_action_required"
                    or case.get("legacy_successor_pre_turn_order")
                    != "turn_started_before_successor_activation"
                    or case.get("required_successor_pre_turn_order")
                    != (
                        "session_start_then_repository_owned_activation_"
                        "then_turn"
                    )
                    or case.get("legacy_lifecycle_rehearsal_terminal")
                    != "native_pre_tool_denied"
                    or case.get("required_lifecycle_rehearsal_terminal")
                    != "successor_controller_ready_before_turn"
                    or case.get("successor_first_action_failure_codes")
                    != ["native_controller:exact_action_required"]
                    or case.get("pre_activation_stop_failure_codes")
                    != ["native_controller:terminal_state_required"]
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V10
                and (
                    case.get("failure_stage")
                    != "idle_task_before_first_turn_session_start"
                    or case.get("failure_code")
                    != "successor_startup:session_health_unavailable"
                    or case.get("legacy_successor_pre_turn_order")
                    != "thread_start_then_session_observation_then_activation"
                    or case.get("required_successor_pre_turn_order")
                    != "idle_owner_activation_then_turn_session_start"
                    or case.get("legacy_lifecycle_rehearsal_terminal")
                    != "session_start_before_successor_controller"
                    or case.get("required_lifecycle_rehearsal_terminal")
                    != "successor_controller_then_real_session_start"
                    or case.get("successor_first_action_failure_codes") != []
                    or case.get("pre_activation_stop_failure_codes") != []
                    or case.get("legacy_thread_start_hook_assumption")
                    != "thread_start_completed_session_start"
                    or case.get("required_first_turn_startup_order")
                    != "activate_idle_task_before_turn_start"
                    or case.get("startup_observation_failure_codes")
                    != ["successor_startup:session_health_unavailable"]
                    or case.get("turn_started") is not False
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V11
                and (
                    case.get("failure_stage")
                    != "capacity_admission_without_atomic_spawn_intent"
                    or case.get("failure_code")
                    != "proposed_action:not_object"
                    or case.get("legacy_successor_pre_turn_order")
                    != "idle_owner_activation_then_turn_session_start"
                    or case.get("required_successor_pre_turn_order")
                    != "idle_owner_activation_then_turn_session_start"
                    or case.get("legacy_lifecycle_rehearsal_terminal")
                    != "successor_controller_then_real_session_start"
                    or case.get("required_lifecycle_rehearsal_terminal")
                    != "repository_owned_first_action_ready"
                    or case.get("successor_first_action_failure_codes")
                    != _CYCLE25_CAPACITY_ACTION_FAILURE_CODES
                    or case.get("pre_activation_stop_failure_codes") != []
                    or case.get("legacy_thread_start_hook_assumption")
                    != "thread_start_does_not_run_session_start"
                    or case.get("required_first_turn_startup_order")
                    != "activate_idle_task_before_turn_start"
                    or case.get("startup_observation_failure_codes") != []
                    or case.get("turn_started") is not True
                    or case.get("legacy_capacity_action_assembly")
                    != "capacity_stage_with_null_proposed_action"
                    or case.get("required_capacity_action_assembly")
                    != (
                        "repository_owned_atomic_capacity_stage_and_"
                        "spawn_intent"
                    )
                    or case.get("capacity_action_failure_codes")
                    != _CYCLE25_CAPACITY_ACTION_FAILURE_CODES
                    or case.get("reserved_logical_lane_ids")
                    != ["spec", "standards"]
                    or not _is_sha(
                        case.get("capacity_controller_report_sha256")
                    )
                    or not _is_sha(
                        case.get("capacity_inspection_report_sha256")
                    )
                    or case.get("cleanup_required") is not True
                    or any(
                        case.get(counter) != 0
                        for counter in (
                            "authority_grants_minted",
                            "native_action_authorizations",
                            "task_creations",
                            "worker_creations",
                        )
                    )
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V12
                and (
                    case.get("failure_stage")
                    != "successor_activation_with_unsettled_terminal_capacity"
                    or case.get("failure_code")
                    != "activation:active_controller_conflict"
                    or case.get("legacy_successor_pre_turn_order")
                    != "idle_owner_activation_without_predecessor_capacity_settlement"
                    or case.get("required_successor_pre_turn_order")
                    != "idle_owner_settlement_then_activation_then_turn_session_start"
                    or case.get("legacy_lifecycle_rehearsal_terminal")
                    != "terminal_predecessor_with_active_capacity"
                    or case.get("required_lifecycle_rehearsal_terminal")
                    != "host_signed_settlement_then_successor_controller_then_real_session_start"
                    or case.get("successor_first_action_failure_codes") != []
                    or case.get("pre_activation_stop_failure_codes")
                    != ["activation:active_controller_conflict"]
                    or case.get("legacy_thread_start_hook_assumption")
                    != "thread_start_does_not_run_session_start"
                    or case.get("required_first_turn_startup_order")
                    != "activate_idle_task_before_turn_start"
                    or case.get("startup_observation_failure_codes") != []
                    or case.get("turn_started") is not False
                    or case.get("legacy_capacity_action_assembly")
                    != "capacity_stage_with_null_proposed_action"
                    or case.get("required_capacity_action_assembly")
                    != (
                        "repository_owned_atomic_capacity_stage_and_"
                        "spawn_intent"
                    )
                    or case.get("capacity_action_failure_codes")
                    != _CYCLE25_CAPACITY_ACTION_FAILURE_CODES
                    or case.get("reserved_logical_lane_ids")
                    != ["spec", "standards"]
                    or not _is_sha(
                        case.get("capacity_controller_report_sha256")
                    )
                    or not _is_sha(
                        case.get("capacity_inspection_report_sha256")
                    )
                    or case.get("cleanup_required") is not False
                    or any(
                        case.get(counter) != 0
                        for counter in (
                            "authority_grants_minted",
                            "native_action_authorizations",
                            "task_creations",
                            "worker_creations",
                        )
                    )
                    or case.get("legacy_predecessor_capacity_state")
                    != "terminal_action_null_with_active_unmaterialized_reservations"
                    or case.get("required_predecessor_capacity_settlement")
                    != "repository_owned_host_signed_pre_activation_settlement"
                    or case.get("unsettled_logical_lane_ids")
                    != ["spec", "standards"]
                    or not _is_sha(
                        case.get("capacity_authority_state_sha256")
                    )
                    or case.get("failed_capacity_settlement_code")
                    != "shared_capacity:release_receipt_set_invalid"
                    or case.get("required_cleanup_status")
                    != "not_required"
                    or case.get("predecessor_action_created") is not False
                    or case.get("predecessor_grant_created") is not False
                    or case.get("pre_turn_successor_prepared") is not False
                    or case.get("live_canary_calls") != 1
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V13
                and (
                    case.get("failure_stage")
                    != "successor_first_action_mcp_host_bridge"
                    or case.get("failure_code")
                    != (
                        "successor_first_action_host_bridge:"
                        "evaluation_failed"
                    )
                    or case.get("legacy_successor_pre_turn_order")
                    != (
                        "idle_owner_settlement_then_activation_then_"
                        "turn_session_start"
                    )
                    or case.get("required_successor_pre_turn_order")
                    != (
                        "idle_owner_settlement_then_activation_then_"
                        "turn_session_start"
                    )
                    or case.get("legacy_lifecycle_rehearsal_terminal")
                    != "direct_same_runtime_first_action_rehearsal"
                    or case.get("required_lifecycle_rehearsal_terminal")
                    != "projected_mcp_first_action_rehearsal"
                    or case.get("successor_first_action_failure_codes")
                    != [
                        "successor_first_action_host_bridge:"
                        "evaluation_failed"
                    ]
                    or case.get("pre_activation_stop_failure_codes") != []
                    or case.get("legacy_thread_start_hook_assumption")
                    != "thread_start_does_not_run_session_start"
                    or case.get("required_first_turn_startup_order")
                    != "activate_idle_task_before_turn_start"
                    or case.get("startup_observation_failure_codes") != []
                    or case.get("turn_started") is not True
                    or case.get("legacy_capacity_action_assembly")
                    != "capacity_stage_with_null_proposed_action"
                    or case.get("required_capacity_action_assembly")
                    != (
                        "repository_owned_atomic_capacity_stage_and_"
                        "spawn_intent"
                    )
                    or case.get("capacity_action_failure_codes")
                    != _CYCLE25_CAPACITY_ACTION_FAILURE_CODES
                    or case.get("reserved_logical_lane_ids")
                    != ["spec", "standards"]
                    or case.get("cleanup_required") is not False
                    or any(
                        case.get(counter) != 0
                        for counter in (
                            "authority_grants_minted",
                            "native_action_authorizations",
                            "task_creations",
                            "worker_creations",
                        )
                    )
                    or case.get("legacy_predecessor_capacity_state")
                    != (
                        "terminal_action_null_with_active_"
                        "unmaterialized_reservations"
                    )
                    or case.get("required_predecessor_capacity_settlement")
                    != (
                        "repository_owned_host_signed_pre_activation_"
                        "settlement"
                    )
                    or case.get("unsettled_logical_lane_ids") != []
                    or not _is_sha(
                        case.get("capacity_authority_state_sha256")
                    )
                    or case.get("failed_capacity_settlement_code")
                    != "shared_capacity:release_receipt_set_invalid"
                    or case.get("required_cleanup_status")
                    != "not_required"
                    or case.get("predecessor_action_created") is not False
                    or case.get("predecessor_grant_created") is not False
                    or case.get("pre_turn_successor_prepared") is not True
                    or case.get("live_canary_calls") != 1
                    or case.get("legacy_first_action_handoff")
                    != "bootstrap_revalidation_in_consumer_runtime"
                    or case.get("required_first_action_handoff")
                    != "sealed_prepared_controller_program"
                    or not _is_sha(case.get("pre_turn_report_sha256"))
                    or not _is_sha(
                        case.get("predecessor_settlement_report_sha256")
                    )
                    or not _is_sha(
                        case.get("first_action_bridge_report_sha256")
                    )
                    or case.get("underlying_failure_code")
                    != "successor_first_action:bootstrap_invalid"
                    or case.get("runtime_binding_failure_code")
                    != "environment:runtime_binding_invalid"
                    or case.get("mcp_bridge_calls") != 1
                    or case.get("predecessor_capacity_settled") is not True
                    or case.get("session_start_observed") is not True
                    or case.get("owner_interrupt_required") is not True
                    or case.get("stop_failure_code")
                    != "native_controller:terminal_state_required"
                    or case.get("pretool_allow_protocol_failure_code")
                    != "unsupported permissionDecision:allow"
                    or case.get("required_pretool_allow_encoding")
                    != "implicit_allow_by_omission"
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V14
                and (
                    case.get("case_id") != "issue163-cycle28"
                    or case.get("failure_stage")
                    != "successor_pre_turn_predecessor_validation"
                    or case.get("failure_code")
                    != "successor_startup:predecessor_not_clean_terminal"
                    or not _is_sha(
                        case.get("cycle28_dedicated_result_sha256")
                    )
                    or not _is_sha(
                        case.get("cycle28_predecessor_authority_sha256")
                    )
                    or not _is_sha(
                        case.get("cycle28_corrected_capacity_read_sha256")
                    )
                    or not re.fullmatch(
                        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{12}",
                        case.get("cycle28_pre_turn_task_id", ""),
                    )
                    or case.get("failure_evidence_sha256")
                    != case.get("cycle28_dedicated_result_sha256")
                    or case.get("pre_turn_successor_prepared") is not False
                    or case.get("session_start_observed") is not False
                    or case.get("turn_started") is not False
                    or case.get("live_canary_calls") != 0
                    or case.get("mcp_bridge_calls") != 0
                    or case.get("cycle27_controller_run_id")
                    != "issue163-cycle27-controller"
                    or case.get("cycle27_controller_run_seq") != 3
                    or not _is_sha(
                        case.get("cycle27_controller_event_sha256")
                    )
                    or case.get("cycle27_predecessor_generation")
                    != "0.1.0+codex.20260902054821"
                    or not _is_sha(
                        case.get("cycle27_predecessor_package_digest")
                    )
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V15
                and (
                    case.get("case_id") != "issue163-cycle29"
                    or case.get("failure_stage")
                    != "first_native_action_posttool_observation"
                    or case.get("failure_code")
                    != "native_controller:native_result_unavailable"
                    or case.get("legacy_posttool_result_assembly")
                    != "top_level_json_string_rejected_as_non_mapping"
                    or case.get("required_posttool_result_assembly")
                    != "decode_top_level_json_string_then_require_mapping"
                    or case.get("native_hook_failure_codes")
                    != [
                        "native_controller:native_result_unavailable",
                        "native_controller:posttool_grant_unavailable",
                    ]
                    or any(
                        case.get(field) != expected
                        for field, expected in _CYCLE29_REPLAY_BINDINGS.items()
                    )
                    or any(
                        not _is_sha(case.get(field))
                        for field in (
                            "cycle29_terminal_snapshot_sha256",
                            "cycle29_terminal_report_sha256",
                            "cycle29_dedicated_result_sha256",
                            "cycle29_root_rollout_sha256",
                            "cycle29_worker_rollout_sha256",
                            "cycle29_worker_state_sha256",
                            "cycle29_worker_report_sha256",
                            "cycle29_posttool_report_sha256",
                            "cycle29_result_sha256",
                            "cycle29_first_action_sha256",
                            "cycle29_capacity_state_sha256",
                            "cycle29_package_digest",
                        )
                    )
                    or case.get("terminal_packet_sha256")
                    != case.get("cycle29_terminal_snapshot_sha256")
                    or case.get("failure_evidence_sha256")
                    != case.get("cycle29_posttool_report_sha256")
                    or any(
                        re.fullmatch(
                            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                            r"[0-9a-f]{4}-[0-9a-f]{12}",
                            str(case.get(field, "")),
                        )
                        is None
                        for field in ("cycle29_task_id", "cycle29_worker_id")
                    )
                    or case.get("cycle29_controller_id")
                    != "issue163-cycle29-controller"
                    or case.get("cycle29_controller_seq") != 5
                    or case.get("cycle29_generation")
                    != "0.1.0+codex.20260902093900"
                    or not re.fullmatch(
                        r"[0-9a-f]{40}",
                        str(case.get("cycle29_candidate_commit", "")),
                    )
                    or case.get("pre_turn_successor_prepared") is not True
                    or case.get("session_start_observed") is not True
                    or case.get("turn_started") is not True
                    or case.get("mcp_bridge_calls") != 1
                    or case.get("native_actions_attempted") != 1
                    or case.get("workers_created") != 1
                    or case.get("native_grant_state") != "OUTCOME_UNKNOWN"
                    or case.get("worker_process_match_count") != 0
                    or case.get("worker_terminal_disposition") != "BLOCKED"
                    or case.get("terminal_recovery_required") is not True
                    or case.get("retry_same_generation_permitted") is not False
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V16
                and (
                    case.get("case_id") != "issue163-cycle30"
                    or case.get("failure_stage")
                    != "successor_activation_after_partial_native_recovery"
                    or case.get("failure_code")
                    != "activation:active_controller_conflict"
                    or any(
                        case.get(field) != expected
                        for field, expected in _CYCLE30_REPLAY_BINDINGS.items()
                    )
                    or case.get("terminal_packet_sha256")
                    != case.get("cycle30_dedicated_result_sha256")
                    or case.get("failure_evidence_sha256")
                    != case.get("cycle30_activation_refusal_sha256")
                    or not re.fullmatch(
                        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{12}",
                        str(case.get("cycle30_task_id", "")),
                    )
                    or not re.fullmatch(
                        r"[0-9a-f]{40}",
                        str(case.get("cycle30_candidate_commit", "")),
                    )
                    or case.get("legacy_owner_rotation_scope")
                    != "unclaimed_authorized_stale_spawn_only"
                    or case.get("required_owner_rotation_scope")
                    != (
                        "claimed_unknown_partial_failure_terminalization_"
                        "after_empty_capacity"
                    )
                    or case.get("predecessor_grant_state")
                    != "OUTCOME_UNKNOWN"
                    or case.get("predecessor_grant_tool_use_claimed") is not True
                    or case.get("predecessor_controller_terminal") is not True
                    or case.get("predecessor_capacity_active_lane_ids") != []
                    or case.get("predecessor_recovery_completed") is not True
                    or case.get("required_terminal_grant_state")
                    != "TERMINAL_OUTCOME_UNKNOWN"
                    or case.get("historical_native_outcome") != "unknown"
                    or case.get("terminal_transition_consumes_native_authority")
                    is not False
                    or case.get("pre_turn_successor_prepared") is not False
                    or case.get("turn_started") is not False
                    or case.get("live_canary_calls") != 1
                    or case.get("model_calls") != 1
                    or case.get("retries") != 0
                    or case.get("controller_activations") != 0
                    or case.get("capacity_reservations") != 0
                    or case.get("native_actions_attempted") != 0
                    or case.get("workers_created") != 0
                    or case.get("owned_process_group_cleaned") is not True
                    or case.get("retry_same_generation_permitted") is not False
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V17
                and (
                    case.get("case_id") != "issue163-cycle31"
                    or case.get("failure_stage")
                    != "caller_authored_post_spawn_stage"
                    or case.get("failure_code")
                    != "program:operation_invalid"
                    or any(
                        case.get(field) != expected
                        for field, expected in _CYCLE31_REPLAY_BINDINGS.items()
                    )
                    or case.get("terminal_packet_sha256")
                    != case.get("cycle31_dedicated_result_sha256")
                    or case.get("failure_evidence_sha256")
                    != case.get("cycle31_refused_stage_event_sha256")
                    or any(
                        re.fullmatch(
                            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                            r"[0-9a-f]{4}-[0-9a-f]{12}",
                            str(case.get(field, "")),
                        )
                        is None
                        for field in (
                            "cycle31_task_id",
                            "cycle31_turn_id",
                            "cycle31_spec_worker_id",
                            "cycle31_standards_worker_id",
                        )
                    )
                    or case.get("completed_spawn_observations") != 2
                    or case.get("spawn_batch_result_complete") is not True
                    or case.get("bridge_decision")
                    != "ACTION_BATCH_OBSERVED"
                    or case.get("caller_authored_stage") != "spawn_outcome"
                    or case.get("controller_disposition")
                    != "PROGRAM_REFUSED"
                    or case.get("cleanup_required") is not True
                    or case.get("active_logical_lane_ids")
                    != ["spec", "standards"]
                    or case.get("worker_terminal_disposition") != "BLOCKED"
                    or case.get("owned_process_group_cleaned") is not True
                    or case.get("qualification_receipt_emitted") is not False
                    or case.get("retry_same_generation_permitted") is not False
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V18
                and (
                    case.get("case_id") != "issue163-cycle32"
                    or case.get("failure_stage")
                    != "worker_acknowledgement_rollout_discovery"
                    or case.get("failure_code")
                    != "successor_action_advance:codex_home_unavailable"
                    or any(
                        case.get(field) != expected
                        for field, expected in _CYCLE32_REPLAY_BINDINGS.items()
                    )
                    or case.get("terminal_packet_sha256")
                    != case.get("cycle32_dedicated_result_sha256")
                    or case.get("failure_evidence_sha256")
                    != case.get("cycle32_bridge_refusal_report_sha256")
                    or any(
                        re.fullmatch(
                            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                            r"[0-9a-f]{4}-[0-9a-f]{12}",
                            str(case.get(field, "")),
                        )
                        is None
                        for field in (
                            "cycle32_task_id",
                            "cycle32_turn_id",
                            "cycle32_spec_worker_id",
                            "cycle32_standards_worker_id",
                        )
                    )
                    or case.get("completed_spawn_observations") != 2
                    or case.get("spawn_batch_result_complete") is not True
                    or case.get("bridge_decision") != "REFUSED"
                    or case.get("bridge_refusal_invocations") != 8
                    or case.get("acknowledged_worker_count") != 2
                    or case.get("worker_substantive_work_started") is not False
                    or case.get("continuation_actions") != 0
                    or case.get("controller_disposition")
                    != "WAITING_FOR_STAGE"
                    or case.get("cleanup_required") is not False
                    or case.get("active_logical_lane_ids")
                    != ["spec", "standards"]
                    or case.get("root_task_complete_count") != 0
                    or case.get("stop_denial_count") != 11
                    or case.get("worker_terminal_disposition")
                    != "ACK_ONLY_TERMINAL"
                    or case.get("owned_process_group_cleaned") is not True
                    or case.get("qualification_receipt_emitted") is not False
                    or case.get("retry_same_generation_permitted") is not False
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V19
                and (
                    case.get("case_id") != "issue163-cycle33"
                    or case.get("failure_stage")
                    != "worker_acknowledgement_rollout_mode_validation"
                    or case.get("failure_code")
                    != "successor_action_advance:worker_rollout_invalid"
                    or any(
                        case.get(field) != expected
                        for field, expected in _CYCLE33_REPLAY_BINDINGS.items()
                    )
                    or case.get("terminal_packet_sha256")
                    != case.get("cycle33_dedicated_result_sha256")
                    or case.get("failure_evidence_sha256")
                    != case.get("cycle33_bridge_refusal_report_sha256")
                    or any(
                        re.fullmatch(
                            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                            r"[0-9a-f]{4}-[0-9a-f]{12}",
                            str(case.get(field, "")),
                        )
                        is None
                        for field in (
                            "cycle33_task_id",
                            "cycle33_turn_id",
                            "cycle33_spec_worker_id",
                            "cycle33_standards_worker_id",
                        )
                    )
                    or case.get("completed_spawn_observations") != 2
                    or case.get("spawn_batch_result_complete") is not True
                    or case.get("bridge_decision") != "REFUSED"
                    or case.get("bridge_refusal_invocations") != 2
                    or case.get("acknowledged_worker_count") != 2
                    or case.get("worker_substantive_work_started") is not False
                    or case.get("continuation_actions") != 0
                    or case.get("controller_disposition")
                    != "WAITING_FOR_STAGE"
                    or case.get("cleanup_required") is not False
                    or case.get("active_logical_lane_ids")
                    != ["spec", "standards"]
                    or case.get("root_task_complete_count") != 0
                    or case.get("stop_denial_count") != 10
                    or case.get("wait_call_count") != 4
                    or case.get("worker_terminal_disposition")
                    != "ACK_ONLY_TERMINAL"
                    or case.get("worker_runtime_validations_passed") != 2
                    or case.get("worker_tool_calls") != 0
                    or case.get("codex_home_mode") != "0700"
                    or case.get("worker_rollout_mode") != "0664"
                    or case.get("owned_process_group_cleaned") is not True
                    or case.get("qualification_receipt_emitted") is not False
                    or case.get("retry_same_generation_permitted") is not False
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V20
                and (
                    case.get("case_id") != "issue163-cycle34"
                    or case.get("failure_stage")
                    != "first_controller_authorized_continuation_pretool"
                    or case.get("failure_code")
                    != "native_controller:exact_action_required"
                    or any(
                        case.get(field) != expected
                        for field, expected in _CYCLE34_REPLAY_BINDINGS.items()
                    )
                    or case.get("terminal_packet_sha256")
                    != case.get("cycle34_dedicated_result_sha256")
                    or case.get("failure_evidence_sha256")
                    != case.get("cycle34_pretool_denial_report_sha256")
                    or any(
                        re.fullmatch(
                            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                            r"[0-9a-f]{4}-[0-9a-f]{12}",
                            str(case.get(field, "")),
                        )
                        is None
                        for field in (
                            "cycle34_task_id",
                            "cycle34_turn_id",
                            "cycle34_spec_worker_id",
                            "cycle34_standards_worker_id",
                        )
                    )
                    or case.get("expected_controller_tool_name")
                    != "multi_agent_v1__send_input"
                    or case.get("observed_hook_tool_name")
                    != "multi_agent_v1send_input"
                    or case.get("completed_spawn_observations") != 2
                    or case.get("spawn_batch_result_complete") is not True
                    or case.get("acknowledged_worker_count") != 2
                    or case.get("continuation_actions_authorized") != 1
                    or case.get("continuation_actions_executed") != 0
                    or case.get("send_input_call_count") != 1
                    or case.get("pretool_denial_count") != 1
                    or case.get("bridge_refusal_invocations") != 0
                    or case.get("blocked_bridge_invocations") != 2
                    or case.get("controller_disposition") != "ACTION_PENDING"
                    or case.get("grant_state") != "AUTHORIZED"
                    or case.get("worker_substantive_work_started") is not False
                    or case.get("cleanup_required") is not False
                    or case.get("active_logical_lane_ids")
                    != ["spec", "standards"]
                    or case.get("root_task_complete_count") != 0
                    or case.get("stop_denial_count") != 10
                    or case.get("wait_call_count") != 0
                    or case.get("worker_terminal_disposition")
                    != "ACK_ONLY_TERMINAL"
                    or case.get("worker_runtime_validations_passed") != 2
                    or case.get("worker_tool_calls") != 0
                    or case.get("codex_home_mode") != "0700"
                    or case.get("worker_rollout_mode") != "0664"
                    or case.get("owned_process_group_cleaned") is not True
                    or case.get("qualification_receipt_emitted") is not False
                    or case.get("fallbacks") != 0
                    or case.get("replacements") != 0
                    or case.get("retry_same_generation_permitted") is not False
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V21
                and (
                    case.get("case_id") != "issue171-owner-launch-v6"
                    or case.get("failure_stage")
                    != "qualification_owner_first_session_start"
                    or case.get("failure_code")
                    != "native_controller:root_session_mismatch"
                    or any(
                        case.get(field) != expected
                        for field, expected in (
                            _ISSUE171_OWNER_LAUNCH_V6_REPLAY_BINDINGS.items()
                        )
                    )
                    or case.get("terminal_packet_sha256")
                    != case.get("issue171_terminal_receipt_file_sha256")
                    or case.get("failure_evidence_sha256")
                    != case.get("issue171_rollout_sha256")
                    or any(
                        re.fullmatch(
                            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                            r"[0-9a-f]{4}-[0-9a-f]{12}",
                            str(case.get(field, "")),
                        )
                        is None
                        for field in ("issue171_task_id", "issue171_turn_id")
                    )
                    or case.get("blocking_controller_status") != "ACTIVE"
                    or case.get("blocking_pending_action_kind") != "continue"
                    or case.get("blocking_pending_action_tool")
                    != "multi_agent_v1__send_input"
                    or case.get("session_start_source") != "startup"
                    or case.get("session_start_hook_decision") != "READ_ONLY"
                    or case.get("same_connection_retained") is not True
                    or case.get("thread_resume_calls") != 0
                    or case.get("task_creations") != 1
                    or case.get("turn_starts") != 1
                    or case.get("session_start_hooks") != 1
                    or any(
                        case.get(counter) != 0
                        for counter in (
                            "model_calls",
                            "provider_calls",
                            "worker_sessions_started",
                            "native_actions",
                            "registration_mutations",
                            "root_mutations",
                        )
                    )
                    or case.get("protected_state_mutated") is not False
                    or case.get("owned_process_group_cleaned") is not True
                    or case.get("legacy_qualification_owner_context")
                    is not None
                    or case.get("required_qualification_owner_context")
                    != "sealed_process_ancestor_read_only_qualification_owner"
                    or case.get("same_task_may_resume") is not False
                    or case.get("retry_same_generation_permitted") is not False
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V22
                and (
                    case.get("case_id") != "issue171-owner-launch-v7"
                    or case.get("failure_stage")
                    != "qualification_owner_cross_generation_first_session_start"
                    or case.get("failure_code")
                    != "native_controller:hook_definition_mismatch"
                    or any(
                        case.get(field) != expected
                        for field, expected in (
                            _ISSUE171_OWNER_LAUNCH_V7_REPLAY_BINDINGS.items()
                        )
                    )
                    or case.get("terminal_packet_sha256")
                    != case.get("issue171_terminal_receipt_file_sha256")
                    or case.get("failure_evidence_sha256")
                    != case.get("issue171_hook_event_file_sha256")
                    or any(
                        re.fullmatch(
                            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                            r"[0-9a-f]{4}-[0-9a-f]{12}",
                            str(case.get(field, "")),
                        )
                        is None
                        for field in ("issue171_task_id", "issue171_turn_id")
                    )
                    or case.get("blocking_controller_status") != "ACTIVE"
                    or case.get("blocking_pending_action_kind") != "continue"
                    or case.get("blocking_pending_action_tool")
                    != "multi_agent_v1__send_input"
                    or case.get("active_hook_definition_sha256")
                    == case.get("observed_hook_definition_sha256")
                    or case.get("session_start_source") != "startup"
                    or case.get("session_start_hook_decision") != "READ_ONLY"
                    or case.get("session_start_reason_codes")
                    != [
                        "native_controller:hook_definition_mismatch",
                        "native_controller:root_session_mismatch",
                    ]
                    or case.get("qualification_owner_context_sealed") is not True
                    or case.get("qualification_owner_context_admitted") is not False
                    or case.get("owner_report_envelope_present") is not False
                    or case.get("terminal_error")
                    != "final response lacks owner_report JSON envelope"
                    or case.get("same_connection_retained") is not True
                    or case.get("thread_resume_calls") != 0
                    or case.get("task_creations") != 1
                    or case.get("turn_starts") != 1
                    or case.get("session_start_hooks") != 1
                    or any(
                        case.get(counter) != 0
                        for counter in (
                            "model_calls",
                            "provider_calls",
                            "credential_reads",
                            "network_calls",
                            "ocx_worker_calls",
                            "openrouter_calls",
                            "qwen_calls",
                            "local_qwen_probes",
                            "worker_sessions_started",
                            "native_actions",
                            "registration_mutations",
                            "controller_mutations",
                            "capacity_reservations",
                            "root_mutations",
                            "retries",
                            "fallbacks",
                            "replacements",
                        )
                    )
                    or case.get("protected_state_mutated") is not False
                    or case.get("owned_process_group_cleaned") is not True
                    or case.get("legacy_qualification_owner_context")
                    is not None
                    or case.get("required_qualification_owner_context")
                    != "sealed_process_ancestor_read_only_qualification_owner"
                    or case.get("same_task_may_resume") is not False
                    or case.get("retry_same_generation_permitted") is not False
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V23
                and (
                    case.get("case_id") != "issue171-owner-launch-v8"
                    or case.get("failure_stage")
                    != "qualification_owner_post_thread_start_reconciliation"
                    or case.get("failure_code")
                    != "qualification_owner:thread_start_git_info_nullable"
                    or any(
                        case.get(field) != expected
                        for field, expected in (
                            _ISSUE171_OWNER_LAUNCH_V8_REPLAY_BINDINGS.items()
                        )
                    )
                    or case.get("terminal_packet_sha256")
                    != case.get("issue171_terminal_receipt_file_sha256")
                    or case.get("failure_evidence_sha256")
                    != case.get(
                        "issue171_thread_start_response_file_sha256"
                    )
                    or re.fullmatch(
                        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{12}",
                        str(case.get("issue171_task_id", "")),
                    )
                    is None
                    or case.get("thread_start_git_info") is not None
                    or case.get("thread_start_history_mode") != "paginated"
                    or case.get("thread_start_status") != "idle"
                    or case.get("thread_start_turn_count") != 0
                    or case.get("rollout_materialized") is not False
                    or case.get("first_turn_started") is not False
                    or case.get("caller_provenance_gate")
                    != "thread_start_optional_git_info_dereference"
                    or case.get("required_provenance_gate")
                    != "clean_checkout_then_authoritative_thread_read"
                    or case.get("terminal_error_type") != "AttributeError"
                    or case.get("terminal_error")
                    != "'NoneType' object has no attribute 'get'"
                    or case.get("same_connection_retained") is not True
                    or case.get("thread_resume_calls") != 0
                    or case.get("task_creations") != 1
                    or case.get("turn_starts") != 0
                    or case.get("session_start_hooks") != 0
                    or any(
                        case.get(counter) != 0
                        for counter in (
                            "model_calls",
                            "provider_calls",
                            "credential_reads",
                            "network_calls",
                            "ocx_worker_calls",
                            "openrouter_calls",
                            "qwen_calls",
                            "local_qwen_probes",
                            "worker_sessions_started",
                            "native_actions",
                            "registration_mutations",
                            "controller_mutations",
                            "capacity_reservations",
                            "root_mutations",
                            "retries",
                            "fallbacks",
                            "replacements",
                        )
                    )
                    or case.get("protected_state_mutated") is not False
                    or case.get("owned_process_group_cleaned") is not True
                    or case.get("same_task_may_resume") is not False
                    or case.get("retry_same_generation_permitted") is not False
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V24
                and (
                    case.get("case_id") != "issue171-owner-launch-v9"
                    or case.get("failure_stage")
                    != "qualification_owner_thread_start_request"
                    or case.get("failure_code")
                    != (
                        "qualification_owner:"
                        "thread_start_experimental_capability_required"
                    )
                    or any(
                        case.get(field) != expected
                        for field, expected in (
                            _ISSUE171_OWNER_LAUNCH_V9_REPLAY_BINDINGS.items()
                        )
                    )
                    or case.get("terminal_packet_sha256")
                    != case.get("issue171_terminal_receipt_file_sha256")
                    or case.get("failure_evidence_sha256")
                    != case.get(
                        "issue171_app_server_transcript_file_sha256"
                    )
                    or re.fullmatch(
                        r"orch-dork-qualification-[0-9a-f]{64}",
                        str(case.get("thread_start_project_id", "")),
                    )
                    is None
                    or case.get("requested_history_mode") != "paginated"
                    or case.get("experimental_api_capability_advertised")
                    is not False
                    or case.get("thread_start_error_code") != -32600
                    or case.get("thread_start_error_message")
                    != (
                        "thread/start.historyMode requires experimentalApi "
                        "capability"
                    )
                    or case.get("thread_start_response_persisted") is not False
                    or case.get("checkout_pre_call_sealed") is not True
                    or case.get("required_request_builder")
                    != "installed_build_qualification_thread_start_params"
                    or case.get("terminal_error_type") != "RuntimeError"
                    or case.get("terminal_error")
                    != (
                        'thread/start failed: {"code": -32600, "message": '
                        '"thread/start.historyMode requires experimentalApi '
                        'capability"}'
                    )
                    or case.get("same_connection_retained") is not True
                    or case.get("thread_resume_calls") != 0
                    or case.get("task_creation_requests") != 1
                    or any(
                        case.get(counter) != 0
                        for counter in (
                            "task_creations",
                            "turn_starts",
                            "session_start_hooks",
                            "model_calls",
                            "provider_calls",
                            "credential_reads",
                            "network_calls",
                            "ocx_worker_calls",
                            "openrouter_calls",
                            "qwen_calls",
                            "local_qwen_probes",
                            "worker_sessions_started",
                            "native_actions",
                            "registration_mutations",
                            "controller_mutations",
                            "capacity_reservations",
                            "root_mutations",
                            "retries",
                            "fallbacks",
                            "replacements",
                        )
                    )
                    or case.get("protected_state_mutated") is not False
                    or case.get("future_attempt_paths_created") is not False
                    or case.get("owned_process_group_cleaned") is not True
                    or case.get("same_task_may_resume") is not False
                    or case.get("retry_same_generation_permitted") is not False
                )
            )
            or (
                case.get("schema") == REPLAY_SCHEMA_V25
                and (
                    case.get("case_id") != "issue171-owner-launch-v10"
                    or case.get("failure_stage")
                    != "qualification_owner_thread_start_request"
                    or case.get("failure_code")
                    != (
                        "qualification_owner:"
                        "thread_start_project_capability_required"
                    )
                    or any(
                        case.get(field) != expected
                        for field, expected in (
                            _ISSUE171_OWNER_LAUNCH_V10_REPLAY_BINDINGS.items()
                        )
                    )
                    or case.get("terminal_packet_sha256")
                    != case.get("issue171_terminal_receipt_file_sha256")
                    or case.get("failure_evidence_sha256")
                    != case.get(
                        "issue171_app_server_transcript_file_sha256"
                    )
                    or re.fullmatch(
                        r"orch-dork-qualification-[0-9a-f]{64}",
                        str(case.get("requested_project_id", "")),
                    )
                    is None
                    or case.get("allow_provider_model_fallback_requested")
                    is not False
                    or case.get("capability_gated_field") != "projectId"
                    or case.get("experimental_only_request_fields")
                    != [
                        "allowProviderModelFallback",
                        "historyMode",
                        "projectId",
                    ]
                    or case.get("standard_thread_start_schema_sha256")
                    != (
                        "792e2f32e37cece971bd616664ea2053741acbed4e9c92e9d"
                        "1766427718f2ecd"
                    )
                    or case.get("experimental_thread_start_schema_sha256")
                    != (
                        "25f490368ec6df52a2a3b82a5469d2413307eb93439121b3"
                        "09f415b5648eee7a"
                    )
                    or case.get("standard_thread_start_fields")
                    != [
                        "approvalPolicy",
                        "approvalsReviewer",
                        "baseInstructions",
                        "config",
                        "cwd",
                        "developerInstructions",
                        "ephemeral",
                        "model",
                        "modelProvider",
                        "personality",
                        "sandbox",
                        "serviceName",
                        "serviceTier",
                        "sessionStartSource",
                        "threadSource",
                    ]
                    or case.get("thread_start_error_code") != -32600
                    or case.get("thread_start_error_message")
                    != (
                        "thread/start.projectId requires experimentalApi "
                        "capability"
                    )
                    or case.get("thread_start_response_persisted") is not False
                    or case.get("checkout_pre_call_sealed") is not True
                    or case.get("required_request_builder")
                    != "installed_build_qualification_thread_start_params"
                    or case.get("terminal_error_type") != "RuntimeError"
                    or case.get("terminal_error")
                    != (
                        'thread/start failed: {"code": -32600, "message": '
                        '"thread/start.projectId requires experimentalApi '
                        'capability"}'
                    )
                    or case.get("same_connection_retained") is not True
                    or case.get("thread_resume_calls") != 0
                    or case.get("task_creation_requests") != 1
                    or any(
                        case.get(counter) != 0
                        for counter in (
                            "task_creations",
                            "turn_starts",
                            "session_start_hooks",
                            "model_calls",
                            "provider_calls",
                            "credential_reads",
                            "network_calls",
                            "ocx_worker_calls",
                            "openrouter_calls",
                            "qwen_calls",
                            "local_qwen_probes",
                            "worker_sessions_started",
                            "native_actions",
                            "registration_mutations",
                            "controller_mutations",
                            "capacity_reservations",
                            "root_mutations",
                            "retries",
                            "fallbacks",
                            "replacements",
                        )
                    )
                    or case.get("protected_state_mutated") is not False
                    or case.get("future_attempt_paths_created") is not False
                    or case.get("owned_process_group_cleaned") is not True
                    or case.get("same_task_may_resume") is not False
                    or case.get("retry_same_generation_permitted") is not False
                )
            )
        ):
            raise QualificationRehearsalError(
                "replay_corpus:case_invalid"
            )
        case_ids.append(case["case_id"])
    if case_ids != sorted(set(case_ids)) or case_ids != sorted(
        HISTORICAL_REPLAY_CASE_IDS
    ):
        raise QualificationRehearsalError("replay_corpus:case_set_invalid")
    return deepcopy(dict(value))


def _replay_case(case_id: str, plugin_root: Path) -> dict[str, Any]:
    corpus = load_replay_corpus(plugin_root)
    for case in corpus["cases"]:
        if case["case_id"] == case_id:
            return deepcopy(case)
    raise QualificationRehearsalError("replay_case:unknown")


def _route_task_spec_template(
    case_id: str,
    legacy_input_refs: list[str],
) -> dict[str, Any]:
    return {
        "schema": contracts.TASK_SPEC_SCHEMA,
        "id": case_id + "-route-canary",
        "kind": "probe",
        "goal": (
            "Return the exact frozen five-field HandoffPreflightCandidateV1 "
            "for Qwen route qualification."
        ),
        "rationale": (
            "Bind one structural zero-tool canary to the qualification "
            "rehearsal attempt."
        ),
        "non_goals": [
            "Use a tool",
            "Mutate any resource",
            "Return self-authored runtime facts",
        ],
        "dependencies": [],
        "input_refs": deepcopy(legacy_input_refs),
        "read_scope": ["route-canary/self-contained"],
        "write_scope": [],
        "deliverable": {
            "schema": contracts.HANDOFF_PREFLIGHT_CANDIDATE_SCHEMA,
            "media_type": "application/json",
            "description": "Exact TaskSpec-bound tool-free route candidate",
        },
        "acceptance_checks": [
            {
                "id": "runtime-check",
                "description": "Return the exact TaskSpec-bound candidate",
                "required": True,
            }
        ],
        "executor": "subagent",
        # The canary keeps the implementer profile's expand-step alias so the
        # closed corpus's task-spec digests replay byte-identically.
        "model_profile": model_profiles.default_profile("implementer")["aliases"][0],
        "allowed_tools": ["caller-tool-must-be-overwritten"],
        "risk": {"level": "low", "reasons": ["read_only"]},
        "budgets": {
            "context_tokens": 8_000,
            "output_tokens": 4_000,
            "handoff_tokens": 1_200,
            "tool_calls": 9,
            "retries": 7,
        },
        "may_request_decomposition": False,
        "failure_policy": {
            "on_blocked": "return_receipt",
            "on_failed": "return_receipt",
            "on_budget_exhausted": "return_receipt",
        },
    }


# The root a rehearsal plans under.  The closed corpus replays under the
# registry's default orchestrator; a live successor pins the exact root its
# owner request names, which must be a registered orchestrator profile
# (Issue 185).  There is no root literal here: the root's effort and
# observed surface come from its registry profile.
_ROOT_PIN: dict[str, str] = {}


@contextmanager
def pinned_root(model: Any = None) -> Iterator[None]:
    """Hold the rehearsal root fixed for one block; None keeps the default."""

    previous = dict(_ROOT_PIN)
    if model is not None:
        if not isinstance(model, str) or not model_profiles.root_admitted(model):
            raise QualificationRehearsalError("rehearsal:root_model_not_onboarded")
        _ROOT_PIN["model"] = model
    try:
        yield
    finally:
        _ROOT_PIN.clear()
        _ROOT_PIN.update(previous)


def _root_route() -> dict[str, str]:
    model = _ROOT_PIN.get("model") or model_profiles.default_root_model()
    profile = model_profiles.root_profile(model)
    effort = profile["default_effort"] if profile is not None else None
    if profile is None:
        # An onboarded root that is not registered rehearses at the effort
        # its probe ran (ADR 0012).
        onboarded = model_profiles.onboarded_profiles.onboarded(model)
        effort = onboarded["sample"]["effort"] if onboarded is not None else None
    if effort is None:
        raise QualificationRehearsalError("rehearsal:root_model_not_onboarded")
    return {
        "model": model,
        "effort": effort,
        # Every governed task runs on V1 (ADR 0012).
        "surface": model_profiles.worker_default.GOVERNED_SURFACE,
    }


# The reviewer a live successor routes its standards lane to (Issue 203): the
# owner request names it and the lane runs on its onboarded identifier at the
# exact effort, so the frozen plan binds the reviewer's onboarded profile.
# Unpinned, every lane runs the registry's default implementer as every
# historical attempt froze.
_REVIEWER_PIN: dict[str, str] = {}
REVIEWED_LANE = "standards"


@contextmanager
def pinned_reviewer(model: Any = None, effort: Any = None) -> Iterator[None]:
    """Route the standards lane to one onboarded reviewer for one block."""

    previous = dict(_REVIEWER_PIN)
    if model is not None or effort is not None:
        if not isinstance(model, str) or not isinstance(effort, str):
            raise QualificationRehearsalError("rehearsal:reviewer_route_invalid")
        profile_id = model_profiles.onboarded_profile_id("reviewer", model, effort)
        refusal = model_profiles.onboarded_v1_refusal(profile_id)
        if refusal is not None:
            raise QualificationRehearsalError("rehearsal:reviewer_cannot_reach_v1:" + refusal)
        if model_profiles.onboarded_capability_profile(profile_id) is None:
            raise QualificationRehearsalError("rehearsal:reviewer_not_onboarded")
        _REVIEWER_PIN["profile_id"] = profile_id
    try:
        yield
    finally:
        _REVIEWER_PIN.clear()
        _REVIEWER_PIN.update(previous)


def _lane_profile(axis: str) -> dict[str, str]:
    if axis == REVIEWED_LANE and "profile_id" in _REVIEWER_PIN:
        return {"model_profile": _REVIEWER_PIN["profile_id"]}
    return {}


def _advisory_program(case_id: str) -> dict[str, Any]:
    root = _root_route()
    return {
        "schema": advisory_scan.PROGRAM_SCHEMA_V3,
        "operation": "prepare",
        "scan_id": case_id + "-issue94-review",
        "root": {
            "thread_id": case_id + "-root",
            "model": root["model"],
            "effort": root["effort"],
        },
        "objective": (
            "Independently review Issue 94 evidence on Standards and Spec axes."
        ),
        "lanes": [
            {
                "id": axis,
                "objective": (
                    "Review the frozen Issue 94 evidence on the "
                    + axis
                    + " axis."
                ),
                "read_scope": ["TICKETS.md", "SPEC.md", "AGENTS.md"],
                "excluded_scope": ["repository-mutation"],
                "deliverable": "Strict " + axis + " review handoff",
                "verification": [
                    "Return one typed " + axis + " finding set"
                ],
                "allowed_tools": [],
                **_lane_profile(axis),
            }
            for axis in ("standards", "spec")
        ],
        "authority": {
            "authority_id": case_id + "-provider-free-review",
            "status": "granted",
            "scope": "read_only",
        },
        "protected_resources": [
            "TICKETS.md",
            "SPEC.md",
            "AGENTS.md",
        ],
        "limits": {
            "context_tokens": 16_000,
            "output_tokens": 4_000,
            "handoff_tokens": 1_200,
            "tool_calls": 1,
        },
        "runtime": None,
    }


def build_rehearsal_program(
    case_id: str,
    plugin_root: str | Path | None = None,
) -> dict[str, Any]:
    """Build the closed declarative input for one permanent replay case."""

    root = _module_plugin_root() if plugin_root is None else Path(plugin_root)
    case = _replay_case(case_id, root)
    return {
        "schema": PROGRAM_SCHEMA,
        "case": case,
        "advisory_program": _advisory_program(case_id),
        "route_task_spec_template": _route_task_spec_template(
            case_id,
            case["legacy_route_input_refs"],
        ),
        "route": {
            "preflight_id": case_id + "-qwen-smart-xhigh-canary",
            "request_id": case_id + "-route-canary-structural",
            "max_output_tokens": 4_000,
            "max_total_tokens": 50_000,
            "max_response_bytes": 65_536,
            "timeout_ms": 120_000,
        },
        "activation": {
            "project_id": "orch-dork-source",
            "ticket_id": "issue-94",
            "root_session_id": case_id + "-root-session",
            "run_id": case_id + "-run",
            "attempt_id": case_id + "-attempt",
            "admission_sha256": "a" * 64,
            "authority_scope_sha256": "b" * 64,
            "hook_trust_receipt_sha256": "c" * 64,
        },
    }


def build_route_preflight_candidate(
    task_spec: Any,
    *,
    preflight_id: str,
) -> dict[str, Any]:
    """Construct and seal a candidate without exposing digest translation."""

    task = ValidatedContractReport.from_report(
        contracts.validate_task_spec(task_spec),
        stage="route_task_spec",
        contract_schema=contracts.TASK_SPEC_SCHEMA,
    )
    artifact = {
        "schema": contracts.ARTIFACT_REF_SCHEMA,
        "uri": "artifact://sha256/" + task.digest,
        "sha256": task.digest,
        "size_bytes": len(contracts.canonical_bytes(task.normalized)),
        "media_type": "application/json",
    }
    handoff = contracts.seal_handoff_receipt(
        {
            "schema": contracts.HANDOFF_RECEIPT_SCHEMA,
            "disposition": "complete",
            "task_spec_sha256": task.digest,
            "result_summary": (
                "The exact constructor-owned route candidate is preserved "
                "for independent structural observation."
            ),
            "claims": [
                {
                    "id": "runtime-evidence",
                    "statement": (
                        "The candidate is bound to the constructor-owned "
                        "route-canary TaskSpec."
                    ),
                    "epistemic_status": "verified",
                    "evidence_refs": [artifact],
                }
            ],
            "artifact_refs": [artifact],
            "checks": [
                {
                    "id": "runtime-check",
                    "status": "passed",
                    "required": True,
                    "evidence_refs": [artifact],
                }
            ],
            "conflicts": [],
            "unknowns": [],
            "requested_decisions": [],
            "raw_trace_ref": None,
        },
        task_spec=task.normalized,
    )
    return contracts.seal_handoff_preflight_candidate(
        {
            "schema": contracts.HANDOFF_PREFLIGHT_CANDIDATE_SCHEMA,
            "preflight_id": preflight_id,
            "task_spec_sha256": task.digest,
            "capability_profile": "tool-free-canary",
            "handoff_receipt": handoff,
        },
        task_spec=task.normalized,
    )


def _adapter_definition() -> dict[str, Any]:
    configuration = {
        "verification_profile": "python-unit",
        "artifact_format": "json",
    }
    return {
        "schema": project_adapter.ADAPTER_SCHEMA,
        "adapter_id": "orch-dork-rehearsal-adapter",
        "version": "adapter-v1",
        "project_kind": "coding",
        "configuration": configuration,
        "configuration_sha256": project_adapter._sha256(configuration),
        "workspace_root": "/workspace/orch-dork-rehearsal",
        "focused_verification": [
            {
                "verification_id": "focused-unit",
                "kind": "command",
                "argv": [
                    "python3",
                    "-B",
                    "-m",
                    "unittest",
                    "tests.test_orch_dork_qualification_rehearsal",
                ],
                "target_pointer": "workspace",
                "source_pointer": "rehearsal#focused-unit",
            }
        ],
        "final_verification": [
            {
                "verification_id": "final-suite",
                "kind": "command",
                "argv": ["python3", "-B", "-m", "unittest", "discover"],
                "target_pointer": "workspace",
                "source_pointer": "rehearsal#final-suite",
            }
        ],
        "protected_resources": [
            "protected/user-work",
            "semantic:external-publication",
        ],
        "workspace_baseline": {
            "required": True,
            "algorithm": "sha256",
            "dirty_policy": "preserve",
            "source_pointer": "rehearsal#baseline-policy",
        },
        "external_systems": [
            {
                "system_id": "publication-system",
                "actions": ["publish"],
                "customer_visible": True,
                "source_pointer": "rehearsal#publication-system",
            }
        ],
        "approval_checkpoints": [
            {
                "checkpoint_id": "publish-checkpoint",
                "system_id": "publication-system",
                "action": "publish",
                "required": True,
                "source_pointer": "rehearsal#publish-checkpoint",
            }
        ],
        "source_pointer": "rehearsal#adapter-v1",
    }


def _authority_boundary(source_pointer: str) -> dict[str, Any]:
    return {
        "sandbox_scope_sha256": "d" * 64,
        "approval_policy": "never",
        "external_action_grants": [
            {
                "grant_id": "grant-publish",
                "system_id": "publication-system",
                "actions": ["publish"],
                "scope_sha256": "e" * 64,
                "source_pointer": "rehearsal#grant-publish",
            }
        ],
        "source_pointer": source_pointer,
    }


def _ticket_admission(
    *,
    ticket_id: str,
    root_task_id: str,
    admission_sha256: str,
) -> dict[str, Any]:
    return {
        "schema": project_adapter.TICKET_ADMISSION_SCHEMA,
        "policy_version": project_adapter.TICKET_ADMISSION_POLICY_VERSION,
        "decision": "ATOMIC_ADMITTED",
        "admitted": True,
        "ticket_id": ticket_id,
        "root_task_id": root_task_id,
        "identity": {
            "ticket_id": ticket_id,
            "ticket_spec_sha256": "1" * 64,
            "acceptance_criteria_sha256": "2" * 64,
            "authority_scope_sha256": "3" * 64,
            "writable_scope_sha256": "4" * 64,
            "root_task_id": root_task_id,
            "invocation_identity_sha256": "5" * 64,
            "classification_evidence_sha256": "6" * 64,
            "candidate_lanes_sha256": "7" * 64,
        },
        "admission_sha256": admission_sha256,
        "events": [],
    }


def _project_adapter_report(activation: Mapping[str, Any]) -> dict[str, Any]:
    definition = _adapter_definition()
    root_task_id = str(activation["root_task_id"])
    ticket_id = str(activation["ticket_id"])
    admission_sha256 = str(activation["admission_sha256"])
    admission = _ticket_admission(
        ticket_id=ticket_id,
        root_task_id=root_task_id,
        admission_sha256=admission_sha256,
    )
    event = {
        "ticket_id": ticket_id,
        "admission_sha256": admission_sha256,
        "source_pointer": "rehearsal#ticket-event",
    }
    program = {
        "schema": project_adapter.PROGRAM_SCHEMA,
        "evaluation_id": "adapter-evaluation-rehearsal",
        "phase": "pre_implementation",
        "policy_version": project_adapter.POLICY_VERSION,
        "requirement": {
            "required": True,
            "expected_adapter_id": definition["adapter_id"],
            "expected_version": definition["version"],
            "expected_config_sha256": definition["configuration_sha256"],
            "source_pointer": "rehearsal#adapter-requirement",
        },
        "adapter": {
            "status": "available",
            "definition": definition,
            "source_pointer": "rehearsal#adapter",
        },
        "authority_boundary": {
            "root": _authority_boundary("rehearsal#root-boundary"),
            "delegated": _authority_boundary(
                "rehearsal#delegated-boundary"
            ),
            "source_pointer": "rehearsal#boundary-comparison",
        },
        "workspace_observation": {
            "status": "known",
            "workspace_root": "/workspace/orch-dork-rehearsal",
            "baseline_sha256": "8" * 64,
            "dirty_paths": [],
            "source_pointer": "rehearsal#workspace-baseline",
        },
        "results": {
            "focused_verification": [],
            "final_verification": [],
            "checkpoint_results": [],
            "external_action_results": [],
            "source_pointer": "rehearsal#empty-results",
        },
        "ticket_admission": admission,
        "ticket_id": ticket_id,
        "root_task_id": root_task_id,
        "admission_events": [
            {**event, "type": "ticket.claimed"},
            {**event, "type": "implementation.started"},
            {**event, "type": "resource.access", "operation": "write"},
        ],
    }
    report = project_adapter.evaluate_project_adapter(program)
    if (
        report.get("status") != "PASS"
        or report.get("implementation_permitted") is not True
    ):
        raise QualificationRehearsalError(
            "activation_preparation:project_adapter_invalid"
        )
    return deepcopy(report)


def _ground_state(
    activation: Mapping[str, Any],
    *,
    plan_sha256: str,
    adapter_report: Mapping[str, Any],
) -> dict[str, Any]:
    ticket_id = str(activation["ticket_id"])
    admission_sha256 = str(activation["admission_sha256"])
    root_task_id = str(activation["root_task_id"])
    root_session_id = str(activation["root_session_id"])
    project_id = str(activation["project_id"])
    ground_program = {
        "schema": ground_enforcement.PROGRAM_SCHEMA,
        "event": {
            "hook_event_name": "SessionStart",
            "session_id": root_session_id,
            "turn_id": None,
            "cwd": "/workspace/orch-dork-rehearsal",
            "model": _root_route()["model"],
            "permission_mode": "dontAsk",
            "source": "resume",
            "agent_id": None,
            "agent_type": None,
            "stop_hook_active": False,
            "tool_name": None,
            "tool_use_id": None,
            "tool_input": {},
            "tool_response": None,
            "code_mode_nested": False,
        },
        "state": {
            "hook": {
                "enabled": True,
                "trusted": True,
                "managed": False,
                "source": "plugin",
                "status": "ready",
                "expected_sha256": "9" * 64,
                "observed_sha256": "9" * 64,
                "timeout_ms": 10_000,
                "matching_decisions": ["allow"],
            },
            "prerequisites": {
                "ticket_admission": {
                    "status": "PASS",
                    "decision": "ATOMIC_ADMITTED",
                    "ticket_id": ticket_id,
                    "admission_sha256": admission_sha256,
                    "implementation_permitted": False,
                    "plan_sha256": plan_sha256,
                },
                "enrollment": {
                    "status": "PASS",
                    "decision": "ACTIVE",
                    "project_id": project_id,
                    "generation": 1,
                    "manifest_sha256": "a" * 64,
                    "record_sha256": "b" * 64,
                },
                "adapter": {
                    "status": "BLOCKED",
                    "decision": "DENY",
                    "snapshot_sha256": None,
                    "report_sha256": None,
                },
                "execution_readiness": {
                    "status": "PASS",
                    "report_sha256": "c" * 64,
                },
                "lease": {
                    "status": "active_successor",
                    "version": 1,
                    "owner_thread_id": root_task_id,
                    "current_thread_id": root_task_id,
                    "checkpoint_sha256": "d" * 64,
                    "cas_valid": True,
                },
                "active_controller": {
                    "status": "PASS",
                    "report_sha256": "e" * 64,
                },
                "capsule": {
                    "status": "PASS",
                    "capsule_sha256": "f" * 64,
                },
                "authority": {
                    "scope_sha256": str(
                        activation["authority_scope_sha256"]
                    ),
                    "writable_scope_sha256": "1" * 64,
                    "grants_sha256": "2" * 64,
                    "narrowed": True,
                },
                "workspace": {
                    "baseline_sha256": "3" * 64,
                    "current_sha256": "3" * 64,
                    "baseline_valid": True,
                },
            },
            "lifecycle": {
                "session_health": None,
                "resumed": True,
                "compacted": False,
                "duplicate_task": False,
                "concurrent_writers": 1,
                "binding_revalidated": True,
                "mutation_seq": 0,
                "expected_mutation_seq": 0,
            },
            "sandbox": {
                "status": "PASS",
                "profile": "narrow-local",
                "covered_classes": sorted(
                    ground_enforcement.GATEWAY_ONLY_CLASSES
                ),
                "writable_roots": ["/workspace/orch-dork-rehearsal"],
                "source_pointer": "rehearsal#sandbox",
            },
            "source_pointer": "rehearsal#ground-state",
        },
        "tool_policy": {
            "supported_hook_classes": sorted(
                ground_enforcement.SUPPORTED_PRETOOL_CLASSES
            ),
            "gateway_only_classes": sorted(
                ground_enforcement.GATEWAY_ONLY_CLASSES
            ),
            "read_only_tools": ["view_image"],
            "max_tool_input_bytes": 100_000,
        },
        "protected_resources": [
            ".orch-dork/project-adapter.json",
            "execution-lease.json",
            *sorted(ground_enforcement.REQUIRED_PROTECTED_RESOURCES),
        ],
        "gateways": [],
        "completion": {
            "final_verification_valid": False,
            "final_verification_sha256": None,
            "independent_observation": "UNBOUND",
            "governed_controller_status": "PENDING",
        },
        "source_pointer": "rehearsal#ground-program",
    }
    return {
        "schema": ground_enforcement.HOOK_STATE_SCHEMA,
        "program": ground_program,
        "program_sha256": ground_enforcement._sha(ground_program),
    }


def build_activation_preparation_program(
    activation_seed: Any,
    advisory: AdvisoryPreparationReport,
    *,
    plugin_version: str,
) -> dict[str, Any]:
    """Bind the whole advisory report into one real activation preparation."""

    seed = _closed(
        activation_seed,
        frozenset(
            {
                "project_id",
                "ticket_id",
                "root_session_id",
                "run_id",
                "attempt_id",
                "admission_sha256",
                "authority_scope_sha256",
                "hook_trust_receipt_sha256",
            }
        ),
        "activation_preparation:seed_shape_invalid",
    )
    for field in (
        "admission_sha256",
        "authority_scope_sha256",
        "hook_trust_receipt_sha256",
    ):
        if not _is_sha(seed.get(field)):
            raise QualificationRehearsalError(
                "activation_preparation:" + field + "_invalid"
            )
    root_task_id = str(advisory.report["logical_plan"]["planner"]["root_thread_id"])
    activation = {**deepcopy(dict(seed)), "root_task_id": root_task_id}
    task_specs = [deepcopy(row) for row in advisory.task_specs]
    adapter_report = _project_adapter_report(activation)
    identity = {
        "project_id": seed["project_id"],
        "enrollment_generation": 1,
        "installed_plugin_version": plugin_version,
        "ticket_id": seed["ticket_id"],
        "admission_sha256": seed["admission_sha256"],
        "authority_scope_sha256": seed["authority_scope_sha256"],
        "root_thread_id": root_task_id,
        "root_session_id": seed["root_session_id"],
        "run_id": seed["run_id"],
        "attempt_id": seed["attempt_id"],
        "root_model": _root_route()["model"],
        "root_effort": _root_route()["effort"],
        "source_version": plugin_version,
        "task_loaded_version": plugin_version,
        "fresh_task": True,
        "plan_sha256": advisory.logical_plan_sha256,
        "task_specs_sha256": native_controller.task_specs_identity_sha256(
            task_specs
        ),
        "hook_definition_sha256": "4" * 64,
        "hook_registration_sha256": "5" * 64,
        "native_adapter_sha256": (
            native_controller.CLOSED_NATIVE_ACTION_ADAPTER_SHA256
        ),
    }
    payload = {
        "identity": identity,
        "enrollment_program": {
            "schema": "orch-dork/qualification-rehearsal-enrollment/v1",
            "operation": "inspect",
            "project_id": seed["project_id"],
        },
        "project_ground_state": _ground_state(
            activation,
            plan_sha256=advisory.logical_plan_sha256,
            adapter_report=adapter_report,
        ),
        "hook_trust_receipt_sha256": seed[
            "hook_trust_receipt_sha256"
        ],
        "task_specs": task_specs,
    }
    return {
        "schema": native_controller.ACTIVATION_PREPARATION_PROGRAM_SCHEMA,
        "activation_payload": payload,
        "project_adapter_report": adapter_report,
    }


def _runtime_identity(
    runtime: Any,
    *,
    require_projected: bool,
) -> tuple[Path, str, bool]:
    if not isinstance(runtime, transport_qualification.TransportRuntime):
        raise QualificationRehearsalError("runtime:type_invalid")
    module_root = _module_plugin_root()
    try:
        runtime_root = runtime.plugin_root.resolve(strict=True)
        declared_root = Path(runtime.plugin_root)
        manifest_path = runtime_root / ".codex-plugin/plugin.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationRehearsalError("runtime:plugin_invalid") from error
    if (
        declared_root.is_symlink()
        or runtime_root != module_root
        or not isinstance(manifest, Mapping)
        or not isinstance(manifest.get("version"), str)
    ):
        raise QualificationRehearsalError("runtime:module_root_mismatch")
    projected = not (runtime_root / "TICKETS.md").exists() and not (
        runtime_root / "tests"
    ).exists()
    if require_projected and not projected:
        raise QualificationRehearsalError("runtime:not_projected")
    return runtime_root, str(manifest["version"]), projected


def _attempt(
    case: Mapping[str, Any],
    advisory: AdvisoryPreparationReport,
    task: ValidatedContractReport,
    candidate: CandidateValidationReport,
    *,
    plugin_version: str,
) -> dict[str, Any]:
    worker_route = zero_tool._required_route()
    return {
        "schema": ATTEMPT_SCHEMA,
        "case_id": case["case_id"],
        "qualification_target": "issue-94-fr63",
        "terminal_replay_sha256": case["terminal_packet_sha256"],
        "installed_plugin_version": plugin_version,
        "advisory_report_sha256": advisory.report["report_sha256"],
        "logical_plan_sha256": advisory.logical_plan_sha256,
        "task_specs_sha256": native_controller.task_specs_identity_sha256(
            list(advisory.task_specs)
        ),
        "canary_task_spec_sha256": task.digest,
        "canary_candidate_sha256": candidate.digest,
        "root_route": _root_route(),
        "worker_route": {
            "model": worker_route["model"],
            "effort": worker_route["effort"],
            "history": "none",
            "tools": [],
        },
        "limits": {
            "canary_calls": 1,
            "substantive_lanes": 2,
            "retries": 0,
            "fallbacks": 0,
            "replacements": 0,
        },
        "stop_rule": (
            "Stop before network, provider, model, controller, capacity, "
            "grant, or native action."
        ),
    }


def validate_approval_preflight_report(value: Any) -> dict[str, Any]:
    """Validate one sealed provider-free approval report locally."""

    issues: list[str] = []
    report = value if isinstance(value, Mapping) else {}
    if not isinstance(value, Mapping) or set(value) != (
        _APPROVAL_PREFLIGHT_FIELDS
    ):
        issues.append("approval_preflight:shape_invalid")
    if report.get("schema") != APPROVAL_PREFLIGHT_SCHEMA:
        issues.append("approval_preflight:schema_invalid")
    if (
        report.get("checkpoint") != "approval"
        or report.get("disposition") != DECISION_READY
        or report.get("objective") != _APPROVAL_OBJECTIVE
        or not _is_sha(report.get("frozen_attempt_sha256"))
        or not _is_sha(report.get("approval_target_sha256"))
    ):
        issues.append("approval_preflight:disposition_invalid")
    target = report.get("target")
    if (
        not isinstance(target, Mapping)
        or set(target) != _APPROVAL_TARGET_FIELDS
        or not isinstance(target.get("installed_generation"), str)
        or not target.get("installed_generation")
        or any(
            not _is_sha(item)
            for key, item in target.items()
            if key != "installed_generation"
        )
        or target.get("attempt_sha256")
        != report.get("frozen_attempt_sha256")
        or target.get("approval_target_sha256")
        != report.get("approval_target_sha256")
    ):
        issues.append("approval_preflight:target_invalid")
    gates = report.get("gates")
    if not isinstance(gates, list) or len(gates) != len(
        _APPROVAL_GATE_IDS
    ):
        issues.append("approval_preflight:gates_invalid")
    else:
        for expected_id, gate in zip(_APPROVAL_GATE_IDS, gates):
            if expected_id == "live_availability":
                expected = {
                    "id": expected_id,
                    "status": "LIVE_ONLY",
                    "reason": (
                        "Credential, network, provider, model, and response "
                        "facts exist only beyond the stopped boundary."
                    ),
                }
                if gate != expected:
                    issues.append(
                        "approval_preflight:live_gate_invalid"
                    )
            elif (
                not isinstance(gate, Mapping)
                or set(gate) != {"id", "status", "evidence"}
                or gate.get("id") != expected_id
                or gate.get("status") != "PASS"
                or not _is_sha(gate.get("evidence"))
            ):
                issues.append("approval_preflight:gate_invalid")
    if report.get("request_binding_unchanged") is not True:
        issues.append("approval_preflight:request_binding_invalid")
    if report.get("next_authorized_action") != _NEXT_AUTHORIZED_ACTION:
        issues.append("approval_preflight:next_action_invalid")
    counters = report.get("counters")
    if (
        not isinstance(counters, Mapping)
        or set(counters) != _COUNTER_FIELDS
        or any(item != 0 for item in counters.values())
    ):
        issues.append("approval_preflight:counters_invalid")
    try:
        expected_sha256 = _sha(
            {
                key: item
                for key, item in report.items()
                if key != "report_sha256"
            }
        )
    except (TypeError, ValueError, OverflowError):
        expected_sha256 = None
    if (
        not _is_sha(report.get("report_sha256"))
        or report.get("report_sha256") != expected_sha256
    ):
        issues.append("approval_preflight:seal_invalid")
    return {"valid": not issues, "issues": sorted(set(issues))}


def build_approval_preflight_report(
    *,
    attempt: Any,
    approval_target: Any,
    route_request: Any,
    activation_preparation_report: Any,
    structural_qualification_report: Any,
    structural_validation_report: Any,
    installed_generation: str,
) -> dict[str, Any]:
    """Build and seal approval evidence from whole canonical reports."""

    if (
        not isinstance(attempt, Mapping)
        or attempt.get("schema") != ATTEMPT_SCHEMA
    ):
        raise QualificationRehearsalError(
            "approval_preflight:attempt_invalid"
        )
    attempt_sha256 = _sha(attempt)
    for field in (
        "task_specs_sha256",
        "terminal_replay_sha256",
        "advisory_report_sha256",
        "logical_plan_sha256",
        "canary_task_spec_sha256",
        "canary_candidate_sha256",
    ):
        if not _is_sha(attempt.get(field)):
            raise QualificationRehearsalError(
                "approval_preflight:attempt_invalid"
            )
    target = _closed(
        approval_target,
        frozenset(
            {
                "schema",
                "attempt_sha256",
                "decision",
                "rehearsal_only",
                "authority_created",
            }
        ),
        "approval_preflight:target_invalid",
    )
    if target != {
        "schema": PREFLIGHT_PLACEHOLDER_SCHEMA,
        "attempt_sha256": attempt_sha256,
        "decision": DECISION_READY,
        "rehearsal_only": True,
        "authority_created": False,
    }:
        raise QualificationRehearsalError(
            "approval_preflight:target_invalid"
        )
    approval_target_sha256 = _sha(target)

    request_validation = zero_tool.validate_route_preflight_zero_tool_request(
        route_request
    )
    request = route_request if isinstance(route_request, Mapping) else {}
    request_bindings = request.get("bindings")
    if (
        request_validation.get("status") != "PASS"
        or request_validation.get("valid") is not True
        or request_validation.get("issues") != []
        or not isinstance(request_bindings, Mapping)
        or request_bindings.get("attempt_sha256") != attempt_sha256
        or request_bindings.get("live_preflight_sha256")
        != approval_target_sha256
    ):
        raise QualificationRehearsalError(
            "approval_preflight:request_invalid"
        )

    if not isinstance(installed_generation, str) or not installed_generation:
        raise QualificationRehearsalError(
            "approval_preflight:generation_invalid"
        )
    if attempt.get("installed_plugin_version") != installed_generation:
        raise QualificationRehearsalError(
            "approval_preflight:generation_mismatch"
        )
    activation = ActivationPreparationReport.from_report(
        activation_preparation_report
    )
    structural = StructuralQualificationReport.from_reports(
        structural_qualification_report,
        structural_validation_report,
    )
    if (
        request_validation.get("request_sha256")
        != structural.request_digest
        or not _is_sha(activation.report.get("report_sha256"))
    ):
        raise QualificationRehearsalError(
            "approval_preflight:structural_invalid"
        )

    preflight_target = {
        "attempt_sha256": attempt_sha256,
        "approval_target_sha256": approval_target_sha256,
        "installed_generation": installed_generation,
        "request_sha256": str(request_validation["request_sha256"]),
        "runtime_identity_sha256": structural.runtime_identity_digest,
        "structural_qualification_sha256": (
            structural.qualification_digest
        ),
        "structural_validation_sha256": structural.validation_digest,
        "activation_preparation_sha256": str(
            activation.report["report_sha256"]
        ),
    }
    evidence_by_gate = {
        "attempt_identity": preflight_target["attempt_sha256"],
        "target_generation": preflight_target[
            "runtime_identity_sha256"
        ],
        "offline_contracts": preflight_target[
            "structural_qualification_sha256"
        ],
        "inputs": str(attempt["task_specs_sha256"]),
        "dependencies": preflight_target["runtime_identity_sha256"],
        "authority_scope": preflight_target["approval_target_sha256"],
        "authority_freshness": preflight_target[
            "approval_target_sha256"
        ],
        "budgets": preflight_target["attempt_sha256"],
        "containment": preflight_target[
            "activation_preparation_sha256"
        ],
        "request_contract": preflight_target["request_sha256"],
        "one_attempt": preflight_target["attempt_sha256"],
        "observability": preflight_target[
            "structural_validation_sha256"
        ],
        "success_settlement": preflight_target[
            "activation_preparation_sha256"
        ],
        "failure_settlement": preflight_target["attempt_sha256"],
        "cleanup_recovery": preflight_target[
            "structural_qualification_sha256"
        ],
    }
    gates = [
        {
            "id": gate_id,
            "status": "PASS",
            "evidence": evidence_by_gate[gate_id],
        }
        for gate_id in _APPROVAL_GATE_IDS
        if gate_id != "live_availability"
    ]
    gates.append(
        {
            "id": "live_availability",
            "status": "LIVE_ONLY",
            "reason": (
                "Credential, network, provider, model, and response facts "
                "exist only beyond the stopped boundary."
            ),
        }
    )
    core = {
        "schema": APPROVAL_PREFLIGHT_SCHEMA,
        "checkpoint": "approval",
        "disposition": DECISION_READY,
        "objective": _APPROVAL_OBJECTIVE,
        "frozen_attempt_sha256": attempt_sha256,
        "approval_target_sha256": approval_target_sha256,
        "target": preflight_target,
        "gates": gates,
        "counters": {
            field: 0 for field in sorted(_COUNTER_FIELDS)
        },
        "request_binding_unchanged": True,
        "next_authorized_action": _NEXT_AUTHORIZED_ACTION,
    }
    report = {**core, "report_sha256": _sha(core)}
    if validate_approval_preflight_report(report) != {
        "valid": True,
        "issues": [],
    }:
        raise QualificationRehearsalError(
            "approval_preflight:self_invalid"
        )
    return report


def _sealed_report(
    *,
    case: Mapping[str, Any],
    projected: bool,
    module_root: Path,
    stages: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    core = {
        "schema": REPORT_SCHEMA,
        "status": "PASS",
        "decision": DECISION_READY,
        "qualified": True,
        "issues": [],
        "case_id": case["case_id"],
        "replay": deepcopy(dict(case)),
        "runtime_projected": projected,
        "runtime_module_root": str(module_root),
        "stages": deepcopy(dict(stages)),
        "qualification_payload": deepcopy(dict(payload)),
        "boundary": {
            "rehearsal_only": True,
            "dispatch_permitted": False,
            "authority_created": False,
            "stopped_at": STOP_BOUNDARY,
        },
        "counters": {field: 0 for field in sorted(_COUNTER_FIELDS)},
    }
    return {**core, "report_sha256": _sha(core)}


def rehearse_qualification(
    program: Any,
    runtime_closure: Any,
    *,
    evidence_root: str | Path,
    runner: Callable[..., Mapping[str, Any]] | None = None,
    require_projected: bool = False,
) -> dict[str, Any]:
    """Run the exact provider-free chain and stop before every live boundary."""

    value = _closed(
        program,
        _PROGRAM_FIELDS,
        "rehearsal_program:shape_invalid",
    )
    if value.get("schema") != PROGRAM_SCHEMA:
        raise QualificationRehearsalError("rehearsal_program:schema_invalid")
    case_value = value.get("case")
    try:
        case_fields = _replay_fields(case_value)
    except QualificationRehearsalError as error:
        raise QualificationRehearsalError(
            "rehearsal_program:case_invalid"
        ) from error
    case = _closed(
        case_value,
        case_fields,
        "rehearsal_program:case_invalid",
    )
    module_root, plugin_version, projected = _runtime_identity(
        runtime_closure,
        require_projected=require_projected,
    )

    advisory_raw = advisory_scan.evaluate_advisory_scan(
        value["advisory_program"]
    )
    advisory = AdvisoryPreparationReport.from_report(advisory_raw)

    task_spec = zero_tool.build_route_preflight_task_spec(
        value["route_task_spec_template"]
    )
    task = ValidatedContractReport.from_report(
        contracts.validate_task_spec(task_spec),
        stage="route_task_spec",
        contract_schema=contracts.TASK_SPEC_SCHEMA,
    )

    route = value.get("route")
    if not isinstance(route, Mapping):
        raise QualificationRehearsalError("route:shape_invalid")
    candidate_value = build_route_preflight_candidate(
        task.normalized,
        preflight_id=str(route.get("preflight_id")),
    )
    candidate = CandidateValidationReport.from_report(
        contracts.validate_handoff_preflight_candidate(
            candidate_value,
            task_spec=task.normalized,
        ),
    )

    attempt = _attempt(
        case,
        advisory,
        task,
        candidate,
        plugin_version=plugin_version,
    )
    attempt_sha256 = _sha(attempt)
    preflight_placeholder = {
        "schema": PREFLIGHT_PLACEHOLDER_SCHEMA,
        "attempt_sha256": attempt_sha256,
        "decision": DECISION_READY,
        "rehearsal_only": True,
        "authority_created": False,
    }
    request = zero_tool.build_route_preflight_zero_tool_request(
        candidate.candidate,
        task_spec=task.normalized,
        attempt_sha256=attempt_sha256,
        live_preflight_sha256=_sha(preflight_placeholder),
        request_id=str(route.get("request_id")),
        max_output_tokens=route.get("max_output_tokens"),
        max_total_tokens=route.get("max_total_tokens"),
        max_response_bytes=route.get("max_response_bytes"),
        timeout_ms=route.get("timeout_ms"),
        evidence_root=evidence_root,
    )
    request_validation = zero_tool.validate_route_preflight_zero_tool_request(
        request
    )
    if request_validation.get("status") != "PASS":
        raise QualificationRehearsalError("route_request:validation_failed")
    route_canary_program = route_canary.build_route_canary_program(
        request,
        case_id=case["case_id"],
    )
    route_canary_validation = route_canary.validate_route_canary_program(
        route_canary_program
    )
    if route_canary_validation != {"valid": True, "issues": []}:
        raise QualificationRehearsalError(
            "route_canary_preparation:validation_failed"
        )

    activation_program = build_activation_preparation_program(
        value["activation"],
        advisory,
        plugin_version=plugin_version,
    )
    activation = ActivationPreparationReport.from_report(
        native_controller.prepare_governed_native_activation(
            activation_program
        )
    )

    structural_raw = transport_qualification.qualify_zero_tool_transport(
        request,
        runtime_closure,
        runner=runner,
    )
    structural_validation = (
        transport_qualification.validate_zero_tool_transport_qualification(
            structural_raw
        )
    )
    if (
        structural_raw.get("status") != "PASS"
        or structural_raw.get("qualified") is not True
        or structural_validation.get("status") != "PASS"
        or structural_validation.get("valid") is not True
        or structural_validation.get("issues") != []
    ):
        raise QualificationRehearsalError(
            "structural_qualification:validation_failed"
        )

    approval = ApprovalPreflightReport.from_report(
        build_approval_preflight_report(
            attempt=attempt,
            approval_target=preflight_placeholder,
            route_request=request,
            activation_preparation_report=activation.report,
            structural_qualification_report=structural_raw,
            structural_validation_report=structural_validation,
            installed_generation=plugin_version,
        )
    )

    stages = {
        "advisory_preparation": {
            "status": "PASS",
            "report": advisory.report,
        },
        "route_task_spec": {"status": "PASS", "report": task.report},
        "candidate_validation": {
            "status": "PASS",
            "report": candidate.report,
        },
        "route_request": {
            "status": "PASS",
            "report": deepcopy(request_validation),
        },
        "route_canary_preparation": {
            "status": "PASS",
            "report": deepcopy(route_canary_validation),
        },
        "activation_preparation": {
            "status": "PASS",
            "report": activation.report,
        },
        "structural_qualification": {
            "status": "PASS",
            "report": deepcopy(structural_raw),
        },
        "structural_validation": {
            "status": "PASS",
            "report": deepcopy(structural_validation)
        },
        "approval_preflight": {
            "status": "PASS",
            "report": approval.report,
        },
    }
    payload = {
        "attempt": attempt,
        "attempt_sha256": attempt_sha256,
        "preflight_placeholder": preflight_placeholder,
        "preflight_placeholder_sha256": _sha(preflight_placeholder),
        "logical_plan": advisory.logical_plan,
        "task_specs": [deepcopy(row) for row in advisory.task_specs],
        "canary_task_spec": task.normalized,
        "canary_candidate": candidate.candidate,
        "route_request": deepcopy(request),
        "route_canary_program": deepcopy(route_canary_program),
        "approval_preflight_report": approval.report,
        "prepared_activation_payload": (
            activation.prepared_activation_payload
        ),
    }
    report = _sealed_report(
        case=case,
        projected=projected,
        module_root=module_root,
        stages=stages,
        payload=payload,
    )
    validation = validate_qualification_rehearsal(report)
    if validation != {"valid": True, "issues": []}:
        raise QualificationRehearsalError("rehearsal_report:self_invalid")
    return report


def rehearse_replay_case(
    case_id: str,
    runtime_closure: Any,
    *,
    evidence_root: str | Path,
    runner: Callable[..., Mapping[str, Any]] | None = None,
    require_projected: bool = False,
    worker_model: str | None = None,
    worker_effort: str | None = None,
    root_model: str | None = None,
    reviewer_model: str | None = None,
    reviewer_effort: str | None = None,
) -> dict[str, Any]:
    """Load one tracked replay and run the repository-owned rehearsal.

    root_model is the exact root a live successor plans under (its owner
    request's root, a registered orchestrator); None replays the closed
    corpus under the registry's default orchestrator.  reviewer_model and
    reviewer_effort route a live successor's standards lane to an onboarded
    reviewer (Issue 203); None keeps every lane on the worker route.
    """

    plugin_root = (
        runtime_closure.plugin_root
        if isinstance(runtime_closure, transport_qualification.TransportRuntime)
        else _module_plugin_root()
    )
    # The default reconstructs the closed corpus under its historical route.
    # A live successor may instead freeze its already host-sealed forward
    # route into the new plan without changing the historical replay facts.
    selected_model = worker_model or zero_tool.REQUEST_MODEL
    selected_effort = worker_effort or zero_tool.REQUIRED_EFFORT
    with worker_default.pinned(
        model=selected_model,
        effort=selected_effort,
    ), zero_tool.pinned_route(
        model=selected_model,
        effort=selected_effort,
    ), pinned_root(root_model), pinned_reviewer(reviewer_model, reviewer_effort):
        return rehearse_qualification(
            build_rehearsal_program(case_id, plugin_root),
            runtime_closure,
            evidence_root=evidence_root,
            runner=runner,
            require_projected=require_projected,
        )


def _validate_qualification_rehearsal(value: Any) -> dict[str, Any]:
    """Recompute the closed ready-only report without granting authority."""

    issues: list[str] = []
    report = value if isinstance(value, Mapping) else {}
    if not isinstance(value, Mapping) or set(value) != _REPORT_FIELDS:
        issues.append("rehearsal:shape_invalid")
    if report.get("schema") != REPORT_SCHEMA:
        issues.append("rehearsal:schema_invalid")
    if (
        report.get("status") != "PASS"
        or report.get("decision") != DECISION_READY
        or report.get("qualified") is not True
        or report.get("issues") != []
    ):
        issues.append("rehearsal:disposition_invalid")
    replay = report.get("replay")
    try:
        replay_fields = _replay_fields(replay)
    except QualificationRehearsalError:
        replay_fields = frozenset()
    if not isinstance(replay, Mapping) or set(replay) != replay_fields:
        issues.append("rehearsal:replay_invalid")
    elif report.get("case_id") != replay.get("case_id"):
        issues.append("rehearsal:case_binding_invalid")
    stages = report.get("stages")
    if not isinstance(stages, Mapping) or set(stages) != _STAGE_NAMES:
        issues.append("rehearsal:stages_invalid")
        stages = {}
    elif any(
        not isinstance(stage, Mapping)
        or set(stage) != _STAGE_FIELDS
        or stage.get("status") != "PASS"
        for stage in stages.values()
    ):
        issues.append("rehearsal:stage_envelope_invalid")
        stages = {}
    counters = report.get("counters")
    if (
        not isinstance(counters, Mapping)
        or set(counters) != _COUNTER_FIELDS
        or any(value != 0 for value in counters.values())
    ):
        issues.append("rehearsal:counters_invalid")
    if report.get("boundary") != {
        "rehearsal_only": True,
        "dispatch_permitted": False,
        "authority_created": False,
        "stopped_at": STOP_BOUNDARY,
    }:
        issues.append("rehearsal:boundary_invalid")
    payload = report.get("qualification_payload")
    if not isinstance(payload, Mapping):
        issues.append("rehearsal:payload_invalid")
        payload = {}
    try:
        task = ValidatedContractReport.from_report(
            stages["route_task_spec"]["report"],
            stage="route_task_spec",
            contract_schema=contracts.TASK_SPEC_SCHEMA,
        )
        candidate = CandidateValidationReport.from_report(
            stages["candidate_validation"]["report"],
        )
        request = payload["route_request"]
        request_validation = (
            zero_tool.validate_route_preflight_zero_tool_request(request)
        )
        if (
            payload.get("canary_task_spec") != task.normalized
            or payload.get("canary_candidate") != candidate.candidate
            or request_validation.get("status") != "PASS"
            or request.get("bindings", {}).get("candidate_sha256")
            != candidate.digest
        ):
            issues.append("rehearsal:caller_chain_invalid")
        route_canary_program = payload["route_canary_program"]
        route_canary_validation = (
            route_canary.validate_route_canary_program(
                route_canary_program
            )
        )
        if (
            route_canary_validation != {"valid": True, "issues": []}
            or route_canary_program.get("route_request") != request
            or stages["route_canary_preparation"]["report"]
            != route_canary_validation
        ):
            issues.append("rehearsal:route_canary_preparation_invalid")
        activation_report = stages["activation_preparation"]["report"]
        if native_controller.validate_activation_preparation_report(
            activation_report
        ) != {"valid": True, "issues": []}:
            issues.append("rehearsal:activation_invalid")
        structural_report = stages["structural_qualification"]["report"]
        structural_validation = (
            transport_qualification.validate_zero_tool_transport_qualification(
                structural_report
            )
        )
        if (
            structural_validation.get("status") != "PASS"
            or structural_validation.get("valid") is not True
            or structural_validation.get("issues") != []
            or stages["structural_validation"]["report"]
            != structural_validation
        ):
            issues.append("rehearsal:structural_invalid")
        approval = ApprovalPreflightReport.from_report(
            stages["approval_preflight"]["report"]
        )
        expected_approval = build_approval_preflight_report(
            attempt=payload["attempt"],
            approval_target=payload["preflight_placeholder"],
            route_request=request,
            activation_preparation_report=activation_report,
            structural_qualification_report=structural_report,
            structural_validation_report=structural_validation,
            installed_generation=payload["attempt"][
                "installed_plugin_version"
            ],
        )
        if (
            approval.report != expected_approval
            or payload.get("approval_preflight_report")
            != approval.report
            or request.get("bindings", {}).get(
                "live_preflight_sha256"
            )
            != approval.approval_target_digest
        ):
            issues.append("rehearsal:approval_preflight_invalid")
    except (KeyError, TypeError, QualificationRehearsalError):
        issues.append("rehearsal:caller_chain_invalid")
    try:
        expected_sha256 = _sha(
            {
                key: item
                for key, item in report.items()
                if key != "report_sha256"
            }
        )
    except (TypeError, ValueError, OverflowError):
        expected_sha256 = None
    if not _is_sha(report.get("report_sha256")) or report.get(
        "report_sha256"
    ) != expected_sha256:
        issues.append("rehearsal:seal_invalid")
    return {"valid": not issues, "issues": sorted(set(issues))}


def validate_qualification_rehearsal(value: Any) -> dict[str, Any]:
    """Validate current reports and bind archived Issue 163 reports to history."""

    report = value if isinstance(value, Mapping) else {}
    if (
        isinstance(report.get("case_id"), str)
        and report["case_id"] in HISTORICAL_REPLAY_CASE_IDS
        and _frozen_worker_route(report) is not None
    ):
        with _bind_frozen_worker_route(report):
            return _validate_qualification_rehearsal(value)
    return _validate_qualification_rehearsal(value)


def _artifact_bytes(path: Path) -> bytes:
    if not path.is_absolute():
        raise QualificationRehearsalError(
            "qualification_artifact:absolute_path_required"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise QualificationRehearsalError(
            "qualification_artifact:unavailable"
        ) from error
    except OSError as error:
        raise QualificationRehearsalError(
            "qualification_artifact:unsafe_path"
        ) from error
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_size <= 0
            or details.st_size > _MAX_ARTIFACT_BYTES
            or details.st_mode & 0o077
            or (
                hasattr(os, "getuid")
                and details.st_uid != os.getuid()
            )
        ):
            raise QualificationRehearsalError(
                "qualification_artifact:unsafe_file"
            )
        chunks: list[bytes] = []
        remaining = details.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise QualificationRehearsalError(
                    "qualification_artifact:short_read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise QualificationRehearsalError(
                "qualification_artifact:size_changed"
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_qualification_artifact(
    path: str | Path,
) -> QualificationArtifact:
    """Load one private artifact and revalidate its whole sealed report."""

    payload = _artifact_bytes(Path(path))
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise QualificationRehearsalError(
            "qualification_artifact:json_invalid"
        ) from error
    return QualificationArtifact.from_report(value)


def _artifact_validations(
    artifact: QualificationArtifact,
) -> tuple[dict[str, str], dict[str, Any]]:
    report = artifact.report
    rehearsal_validation = validate_qualification_rehearsal(report)
    approval_validation = validate_approval_preflight_report(
        artifact.approval_preflight_report
    )
    with _bind_frozen_worker_route(report):
        request_validation = (
            zero_tool.validate_route_preflight_zero_tool_request(
                artifact.route_request
            )
        )
        route_canary_validation = route_canary.validate_route_canary_program(
            artifact.route_canary_program
        )
    activation_stage = report["stages"]["activation_preparation"]["report"]
    activation_validation = (
        native_controller.validate_activation_preparation_report(
            activation_stage
        )
    )
    structural_validation = (
        transport_qualification.validate_zero_tool_transport_qualification(
            artifact.structural_qualification_report
        )
    )
    stored_structural_validation = artifact.structural_validation_report
    valid = {
        "rehearsal": rehearsal_validation
        == {"valid": True, "issues": []},
        "approval_preflight": approval_validation
        == {"valid": True, "issues": []},
        "route_request": request_validation.get("status") == "PASS"
        and request_validation.get("valid") is True
        and request_validation.get("issues") == [],
        "route_canary_program": (
            route_canary_validation == {"valid": True, "issues": []}
            and artifact.route_canary_program.get("route_request")
            == artifact.route_request
        ),
        "activation_preparation": activation_validation
        == {"valid": True, "issues": []},
        "structural_qualification": (
            artifact.structural_qualification_report.get("status") == "PASS"
            and artifact.structural_qualification_report.get("qualified")
            is True
            and structural_validation.get("status") == "PASS"
        ),
        "structural_validation": (
            structural_validation == stored_structural_validation
            and structural_validation.get("status") == "PASS"
            and structural_validation.get("valid") is True
            and structural_validation.get("issues") == []
        ),
    }
    if set(valid) != set(_ARTIFACT_VALIDATION_NAMES) or not all(
        valid.values()
    ):
        raise QualificationRehearsalError(
            "qualification_artifact:readback_validation_failed"
        )
    return (
        {name: "PASS" for name in _ARTIFACT_VALIDATION_NAMES},
        request_validation,
    )


def _write_create_only(path: Path, payload: bytes) -> None:
    if not path.is_absolute():
        raise QualificationRehearsalError(
            "qualification_artifact:absolute_path_required"
        )
    if len(payload) > _MAX_ARTIFACT_BYTES:
        raise QualificationRehearsalError(
            "qualification_artifact:too_large"
        )
    if path.exists() or path.is_symlink():
        raise QualificationRehearsalError(
            "qualification_artifact:already_exists"
        )
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise QualificationRehearsalError(
            "qualification_artifact:parent_invalid"
        ) from error
    if not parent.is_dir() or path.parent.is_symlink():
        raise QualificationRehearsalError(
            "qualification_artifact:parent_invalid"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise QualificationRehearsalError(
            "qualification_artifact:already_exists"
        ) from error
    except QualificationRehearsalError:
        raise
    except OSError as error:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise QualificationRehearsalError(
            "qualification_artifact:write_failed"
        ) from error


def persist_qualification_artifact(
    report: Any,
    output_path: str | Path,
) -> dict[str, Any]:
    """Persist, reread, and independently validate one complete handoff."""

    artifact = QualificationArtifact.from_report(report)
    output = Path(output_path)
    payload = _canonical(artifact.report) + b"\n"
    _write_create_only(output, payload)
    persisted = read_qualification_artifact(output)
    if persisted.report != artifact.report:
        raise QualificationRehearsalError(
            "qualification_artifact:readback_mismatch"
        )
    validations, request_validation = _artifact_validations(persisted)
    approval = ApprovalPreflightReport.from_report(
        persisted.approval_preflight_report
    )
    structural = StructuralQualificationReport.from_reports(
        persisted.structural_qualification_report,
        persisted.structural_validation_report,
    )
    core = {
        "schema": ARTIFACT_RECEIPT_SCHEMA,
        "status": "PASS",
        "decision": DECISION_READY,
        "issues": [],
        "case_id": persisted.report["case_id"],
        "installed_generation": persisted.report[
            "qualification_payload"
        ]["attempt"]["installed_plugin_version"],
        "artifact_path": str(output),
        "artifact_size_bytes": len(payload),
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "report_sha256": persisted.report_sha256,
        "approval_preflight_report_sha256": approval.digest,
        "route_request_sha256": request_validation["request_sha256"],
        "route_canary_program_sha256": (
            persisted.route_canary_program["program_sha256"]
        ),
        "structural_qualification_sha256": (
            structural.qualification_digest
        ),
        "structural_validation_sha256": structural.validation_digest,
        "runtime_projected": persisted.report["runtime_projected"],
        "validations": validations,
        "boundary": deepcopy(persisted.report["boundary"]),
        "counters": deepcopy(persisted.report["counters"]),
    }
    return {**core, "receipt_sha256": _sha(core)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run one projected provider-free qualification rehearsal."
    )
    parser.add_argument("--case", required=True)
    parser.add_argument("--plugin-root", required=True)
    parser.add_argument("--opencodex-root", required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--worker-model")
    parser.add_argument("--worker-effort")
    parser.add_argument("--root-model")
    parser.add_argument("--reviewer-model")
    parser.add_argument("--reviewer-effort")
    parser.add_argument(
        "--output",
        help=(
            "create-only private path for the complete sealed report; "
            "stdout becomes a compact readback-validation receipt"
        ),
    )
    args = parser.parse_args(argv)
    runtime = transport_qualification.TransportRuntime(
        plugin_root=Path(args.plugin_root),
        opencodex_root=Path(args.opencodex_root),
    )
    try:
        report = rehearse_replay_case(
            args.case,
            runtime,
            evidence_root=Path(args.evidence_root),
            require_projected=True,
            worker_model=args.worker_model,
            worker_effort=args.worker_effort,
            root_model=args.root_model,
            reviewer_model=args.reviewer_model,
            reviewer_effort=args.reviewer_effort,
        )
        output = (
            persist_qualification_artifact(report, args.output)
            if args.output is not None
            else report
        )
    except QualificationRehearsalError as error:
        output = {
            "schema": (
                ARTIFACT_RECEIPT_SCHEMA
                if args.output is not None
                else REPORT_SCHEMA
            ),
            "status": "FAIL",
            "decision": DECISION_REFUSED,
            "qualified": False,
            "issues": [str(error)],
        }
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0 if output.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "REPLAY_CORPUS_SCHEMA",
    "HISTORICAL_REPLAY_CASE_IDS",
    "REPLAY_SCHEMA",
    "REPLAY_SCHEMA_V2",
    "REPLAY_SCHEMA_V3",
    "REPLAY_SCHEMA_V4",
    "REPLAY_SCHEMA_V5",
    "REPLAY_SCHEMA_V6",
    "REPLAY_SCHEMA_V7",
    "REPLAY_SCHEMA_V8",
    "REPLAY_SCHEMA_V9",
    "REPLAY_SCHEMA_V10",
    "REPLAY_SCHEMA_V11",
    "REPLAY_SCHEMA_V12",
    "REPLAY_SCHEMA_V13",
    "REPLAY_SCHEMA_V14",
    "REPLAY_SCHEMA_V15",
    "REPLAY_SCHEMA_V16",
    "REPLAY_SCHEMA_V17",
    "REPLAY_SCHEMA_V18",
    "REPLAY_SCHEMA_V19",
    "REPLAY_SCHEMA_V20",
    "REPLAY_SCHEMA_V21",
    "REPLAY_SCHEMA_V22",
    "REPLAY_SCHEMA_V23",
    "REPLAY_SCHEMA_V24",
    "REPLAY_SCHEMA_V25",
    "REPLAY_SCHEMA_V26",
    "REPLAY_SCHEMA_V27",
    "REPLAY_SCHEMA_V28",
    "REPLAY_SCHEMA_V29",
    "REPLAY_SCHEMA_V30",
    "PROGRAM_SCHEMA",
    "ATTEMPT_SCHEMA",
    "APPROVAL_PREFLIGHT_SCHEMA",
    "REPORT_SCHEMA",
    "ARTIFACT_RECEIPT_SCHEMA",
    "DECISION_READY",
    "QualificationRehearsalError",
    "ValidatedContractReport",
    "CandidateValidationReport",
    "AdvisoryPreparationReport",
    "ActivationPreparationReport",
    "StructuralQualificationReport",
    "ApprovalPreflightReport",
    "QualificationArtifact",
    "load_replay_corpus",
    "build_rehearsal_program",
    "build_route_preflight_candidate",
    "build_activation_preparation_program",
    "build_approval_preflight_report",
    "rehearse_qualification",
    "rehearse_replay_case",
    "validate_qualification_rehearsal",
    "validate_approval_preflight_report",
    "read_qualification_artifact",
    "persist_qualification_artifact",
]
