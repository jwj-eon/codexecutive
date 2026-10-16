#!/usr/bin/env python3
"""Failure-aware successor packets for Issue 111 live measurements.

The module is downstream of both :mod:`orch_dork_live_sweep` and
:mod:`orch_dork_live_zero_tool`.  It grants no authority and owns no model,
transport, campaign-registration, reservation, or settlement call.  Its
interface derives immutable historical evidence, revalidates the immediate
closed tranche, seals the smallest v8 N=2 transport-recovery successor, and
renders its exact bounded authority terms. Legacy packet v1 and successor
packet v2 remain replay-only; every new scope, sheet, bundle, or grant path
requires qualified packet v3 plus fresh predecessor and transport re-reads.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_experiment_campaign as campaign_contract  # noqa: E402
import orch_dork_live_sweep as live_sweep  # noqa: E402
import orch_dork_live_zero_tool as zero_tool  # noqa: E402
import orch_dork_live_zero_tool_qualification as zero_tool_qualification  # noqa: E402
import orch_dork_routing_verify as routing  # noqa: E402
import orch_dork_standing_authority as standing_authority  # noqa: E402


EVIDENCE_MANIFEST_SCHEMA = "orch-dork/issue111-v8-evidence-manifest/v1"
HISTORY_SPEC_SCHEMA = "orch-dork/issue111-v8-history-spec/v1"
PACKET_SCHEMA = "orch-dork/issue111-v8-n2-recovery-packet/v1"
SUCCESSOR_PACKET_SCHEMA = "orch-dork/issue111-v8-n2-recovery-packet/v2"
QUALIFIED_SUCCESSOR_PACKET_SCHEMA = (
    "orch-dork/issue111-v8-n2-recovery-packet/v3"
)
PACKET_VALIDATION_SCHEMA = (
    "orch-dork/issue111-v8-n2-recovery-packet-validation/v1"
)
SUCCESSOR_PACKET_VALIDATION_SCHEMA = (
    "orch-dork/issue111-v8-n2-recovery-packet-validation/v2"
)
QUALIFIED_SUCCESSOR_PACKET_VALIDATION_SCHEMA = (
    "orch-dork/issue111-v8-n2-recovery-packet-validation/v3"
)
TERMINAL_PREDECESSOR_CAPSULE_SCHEMA = (
    "orch-dork/live-recovery-terminal-predecessor/v1"
)
TRANSPORT_IDENTITY_SCHEMA = (
    "orch-dork/structural-zero-tool-transport-identity/v2"
)
RUNTIME_CLOSURE_SCHEMA = "orch-dork/issue111-v8-runtime-closure/v1"
AUTHORITY_BINDING_SCHEMA = "orch-dork/issue111-v8-authority-binding/v4"
AUTHORITY_SCOPE_SCHEMA = "orch-dork/issue111-v8-authority-scope/v1"
SUCCESSOR_AUTHORITY_SCOPE_SCHEMA = "orch-dork/issue111-v8-authority-scope/v2"
QUALIFIED_SUCCESSOR_AUTHORITY_SCOPE_SCHEMA = (
    "orch-dork/issue111-v8-authority-scope/v3"
)
BUNDLE_RECEIPT_SCHEMA = "orch-dork/issue111-v8-recovery-bundle-receipt/v4"

PER_LANE_TOTAL_TOKENS = 27_000
PER_LANE_OUTPUT_TOKENS = 4_096
AGGREGATE_TOTAL_TOKENS = 54_000
MAX_RESPONSE_BYTES = 65_536
LANE_TIMEOUT_MS = 120_000
MAX_WALL_TIME_MS = 600_000
MAX_CELLS_IN_FLIGHT = 1
MAX_LIVE_LANE_SESSIONS = 2
MAX_PREDECESSOR_ARTIFACT_BYTES = 262_144

AUTHORITY_SCOPE_RUNTIME_FILES = (
    "orch_dork_campaign_power.py",
    "orch_dork_campaign_prereg.py",
    "orch_dork_dispatch_packet.py",
    "orch_dork_evidence_rate.py",
    "orch_dork_live_recovery.py",
    "orch_dork_standing_authority.py",
    "orch_dork_adaptive_contracts.py",
    "orch_dork_ownership.py",
    "orch_dork_live_zero_tool.py",
    "orch_dork_live_zero_tool_qualification.py",
    "orch_dork_process_containment.py",
    "orch_dork_live_sweep.py",
    "orch_dork_routing_verify.py",
    "orch_dork_experiment_campaign.py",
    "orch_dork_hostile_input.py",
    "orch_dork_sweep_harness.py",
    "orch_dork_trace.py",
    "orch_dork_tranche_ladder.py",
    "orch_dork_record_replay.py",
    "orch_dork_refusal_tiers.py",
    "orch_dork_decomposition.py",
)

_FIXED_GRANT_TERMS = {
    "cells": 1,
    "lane_sessions": 2,
    "per_lane_total_tokens": PER_LANE_TOTAL_TOKENS,
    "per_lane_output_tokens": PER_LANE_OUTPUT_TOKENS,
    "aggregate_total_tokens": AGGREGATE_TOTAL_TOKENS,
    "max_response_bytes": MAX_RESPONSE_BYTES,
    "lane_timeout_ms": LANE_TIMEOUT_MS,
    "max_wall_time_ms": MAX_WALL_TIME_MS,
    "max_cells_in_flight": MAX_CELLS_IN_FLIGHT,
    "max_live_lane_sessions": MAX_LIVE_LANE_SESSIONS,
    "preparation_sessions": 0,
    "review_sessions": 0,
    "retries": 0,
    "fallbacks": 0,
    "replacements": 0,
    "hosted_calls": 0,
}

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_AUTOMATIC_AUTHORITY = object()
_LABEL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_TRANSPORT_FIELDS = frozenset(
    {
        "schema",
        "plugin_version",
        "request_schema",
        "transport",
        "module_sha256",
        "runtime_closure_sha256",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "stream",
        "store",
        "retry_count",
        "fallback_count",
        "replacement_count",
    }
)
_PACKET_FIELDS = frozenset(
    {
        "schema",
        "status",
        "issues",
        "campaign_label",
        "prepared_at",
        "campaign",
        "grant_terms",
        "transport",
        "failure_aware_basis",
        "terminal_rule",
        "evidence_manifest_sha256",
        "predecessor_failure_record_sha256",
        "authorized",
        "grants_authority",
        "authority_status",
        "authority_note",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "packet_sha256",
    }
)
_SUCCESSOR_PACKET_FIELDS = _PACKET_FIELDS | frozenset(
    {"terminal_predecessor"}
)
_QUALIFIED_SUCCESSOR_PACKET_FIELDS = _SUCCESSOR_PACKET_FIELDS | frozenset(
    {"transport_qualification"}
)
_TERMINAL_PREDECESSOR_CAPSULE_FIELDS = frozenset(
    {
        "schema",
        "status",
        "issues",
        "predecessor",
        "authority",
        "execution",
        "artifacts",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "capsule_sha256",
    }
)
_TERMINAL_PREDECESSOR_FIELDS = frozenset(
    {
        "attempt_id",
        "state",
        "terminal_reason",
        "terminal_issues",
        "packet_sha256",
        "authority_scope_sha256",
        "authority_source_sha256",
        "authority_binding_sha256",
        "campaign_sha256",
        "grant_sha256",
        "reservation_record_sha256",
        "stop_record_sha256",
    }
)
_TERMINAL_PREDECESSOR_AUTHORITY_FIELDS = frozenset(
    {
        "terminal_summary_sha256",
        "consumption_record_sha256",
        "consumed",
        "continuing_authority",
    }
)
_TERMINAL_PREDECESSOR_EXECUTION_FIELDS = frozenset(
    {
        "attempted_live_posts",
        "known_model_calls",
        "lane_2_dispatched",
        "attempted_usage_status",
        "accepted_receipts",
        "raw_response_persisted",
        "retries",
        "fallbacks",
        "replacements",
        "continuations",
        "hosted_calls",
    }
)
_TERMINAL_PREDECESSOR_ARTIFACT_FIELDS = frozenset(
    {
        "terminal_summary_file_sha256",
        "authority_consumption_file_sha256",
        "canonical_ledger_sha256",
        "family_shard_sha256",
        "terminal_stop_report_sha256",
        "terminal_stop_file_sha256",
        "family_shard_report_sha256",
        "lane_dispatch_report_sha256",
        "lane_dispatch_file_sha256",
        "invocation_report_file_sha256",
        "response_sha256",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "status",
        "issues",
        "history",
        "v7_failure",
        "population",
        "unknowns",
        "non_session_reservations",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "manifest_sha256",
    }
)
_HISTORY_FIELDS = frozenset({"campaigns", "history_sha256"})
_HISTORY_CAMPAIGN_FIELDS = frozenset(
    {
        "campaign_id",
        "campaign_sha256",
        "state",
        "canonical_file_sha256",
        "shard_file_sha256s",
        "auxiliary_file_sha256s",
        "record_sha256s",
    }
)
_V7_FAILURE_PROJECTION_FIELDS = frozenset(
    {
        "failure_record_sha256",
        "reservation_record_sha256",
        "request_sha256",
        "lane_count",
        "transport_failed_lane_sessions",
        "compliant_lane",
        "transport_contaminated_lane",
    }
)
_POPULATION_FIELDS = frozenset(
    {
        "scored_lane_sessions",
        "malformed_lane_sessions",
        "evidence_failed_lane_slots",
        "evidence_failed_usage_status",
        "transport_failed_lane_sessions",
        "unstarted_reserved_lane_slots",
        "compliant_single_response_lane_sessions_all_lane_counts",
        "n2_estimator",
    }
)
_N2_ESTIMATOR_FIELDS = frozenset(
    {"eligible_lane_sessions", "total_tokens", "output_tokens"}
)
_UNKNOWN_FIELDS = frozenset(
    {
        "campaign_id",
        "reservation_record_sha256",
        "kind",
        "lane_slots",
        "usage",
    }
)
_NON_SESSION_RESERVATION_FIELDS = _UNKNOWN_FIELDS
_CAMPAIGN_WRAPPER_FIELDS = frozenset(
    {
        "campaign_sha256",
        "sealed",
        "cell_count",
        "lane_counts",
        "seeds",
        "task_families",
        "purpose",
    }
)
_GRANT_TERM_FIELDS = frozenset(
    {
        "cells",
        "lane_sessions",
        "per_lane_total_tokens",
        "per_lane_output_tokens",
        "aggregate_total_tokens",
        "max_response_bytes",
        "lane_timeout_ms",
        "max_wall_time_ms",
        "max_cells_in_flight",
        "max_live_lane_sessions",
        "preparation_sessions",
        "review_sessions",
        "retries",
        "fallbacks",
        "replacements",
        "hosted_calls",
        "reservation_basis",
    }
)
_RESERVATION_BASIS_FIELDS = frozenset(
    {
        "population",
        "eligible_lane_sessions",
        "observed_total_tokens",
        "observed_output_tokens",
        "contaminated_continuation_excluded",
        "unknown_unsettled_usage_excluded",
    }
)
_DISTRIBUTION_FIELDS = frozenset(
    {
        "sum",
        "minimum",
        "median_numerator",
        "median_denominator",
        "p95_nearest_rank",
        "maximum",
    }
)
_FAILURE_BASIS_FIELDS = frozenset(
    {
        "scored_lane_sessions",
        "malformed_lane_sessions",
        "evidence_failed_lane_slots",
        "evidence_failed_usage_status",
        "unstarted_reserved_lane_slots",
        "compliant_single_response_lane_sessions_all_lane_counts",
        "v7_compliant_lane",
        "v7_transport_contaminated_lane",
    }
)
_COMPLIANT_LANE_FIELDS = frozenset(
    {"total_tokens", "output_tokens", "tool_calls"}
)
_CONTAMINATED_LANE_FIELDS = frozenset(
    {"total_tokens", "output_tokens", "tool_calls", "response_count"}
)
_TERMINAL_RULE_FIELDS = frozenset({"pass", "failure", "successor"})
_FILE_BINDING_FIELDS = frozenset({"name", "sha256"})
_CAMPAIGN_SPEC_FIELDS = frozenset(
    {
        "directory",
        "campaign_id",
        "campaign_sha256",
        "grant_sha256",
        "expected_state",
        "canonical_file",
        "shard_files",
        "auxiliary_files",
        "expected_records",
    }
)
_EXPECTED_RECORD_FIELDS = frozenset(
    {
        "registration",
        "replay_plan",
        "start",
        "terminal",
        "reservations",
        "completions",
    }
)
_V7_FAILURE_SPEC_FIELDS = frozenset(
    {
        "campaign_id",
        "file",
        "failure_record_sha256",
        "request_sha256",
        "reservation_record_sha256",
    }
)
_FAILURE_FIELDS = frozenset(
    {
        "schema",
        "failure_class",
        "campaign_sha256",
        "grant_sha256",
        "request_sha256",
        "reservation_record_sha256",
        "reserved_tokens",
        "aggregate_usage",
        "overage_tokens",
        "completion_refusal_issues",
        "runtime_observations",
        "offending_tool_records",
        "automatic_retries",
        "automatic_fallbacks",
        "automatic_replacements",
        "hosted_calls",
        "drain_evidence",
        "settlement",
        "recovery",
        "record_sha256",
    }
)
_TERMINAL_SUMMARY_FIELDS = frozenset(
    {
        "schema",
        "attempt_id",
        "state",
        "terminal_reason",
        "terminal_issues",
        "owner_approval_consumed",
        "continuing_authority",
        "current_packet_sha256",
        "authority_scope_sha256",
        "authority_source_sha256",
        "authority_binding_sha256",
        "admission",
        "campaign",
        "execution",
        "credential_boundary",
        "privacy",
        "reportable",
        "training_eligible",
        "summary_sha256",
    }
)
_TERMINAL_SUMMARY_CAMPAIGN_FIELDS = frozenset(
    {
        "campaign_sha256",
        "grant_sha256",
        "registration_record_sha256",
        "start_record_sha256",
        "reservation_record_sha256",
        "stop_record_sha256",
        "canonical_ledger_sha256",
        "shard_sha256",
        "campaign_report_sha256",
    }
)
_TERMINAL_SUMMARY_EXECUTION_FIELDS = frozenset(
    {
        "attempted_live_posts",
        "known_model_calls",
        "authorized_lane_sessions",
        "lane_2_dispatched",
        "completed_cells",
        "accepted_receipts",
        "attempted_call_usage",
        "raw_response_persisted",
        "response_sha256",
        "retries",
        "fallbacks",
        "replacements",
        "continuations",
        "hosted_calls",
    }
)
_AUTHORITY_CONSUMPTION_FIELDS = frozenset(
    {
        "schema",
        "packet_sha256",
        "authority_scope_sha256",
        "authority_source_sha256",
        "grant_sha256",
        "reservation_record_sha256",
        "terminal_summary_sha256",
        "consumed",
        "continuing_authority",
        "record_sha256",
    }
)
_LANE_DISPATCH_FIELDS = frozenset(
    {
        "schema",
        "status",
        "state",
        "terminal_reason",
        "attempted_live_posts",
        "known_model_calls",
        "model_calls_unknown",
        "lane_2_dispatched",
        "observed_total_tokens",
        "accepted_receipts",
        "retries",
        "fallbacks",
        "replacements",
        "continuations",
        "hosted_calls",
        "credential_reads",
        "credential_setup_defects",
        "process_local_admission_tokens",
        "lane_reports",
        "privacy",
        "report_sha256",
    }
)
_LANE_DISPATCH_LANE_FIELDS = frozenset(
    {
        "lane_index",
        "status",
        "issues",
        "request_sha256",
        "response_sha256",
        "response_persisted",
        "receipt",
        "runtime_observation",
        "transport_failure",
        "terminal_result",
    }
)
_INVOCATION_REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "issues",
        "request_sha256",
        "response_sha256",
        "response_persisted",
        "attempted_requests",
        "model_calls",
        "receipt",
        "runtime_observation",
        "transport_failure",
        "terminal_result",
        "retries",
        "fallbacks",
        "replacements",
        "hosted_calls",
        "provider_free",
    }
)
_R4_TERMINAL_SUMMARY_FIELDS = _TERMINAL_SUMMARY_FIELDS | {"terminal_kind"}
_R4_TERMINAL_SUMMARY_SHA256 = (
    "324e5d98eecd340284235f5169f64e907986fe946b201be97d953d626751dd89"
)
_R4_AUTHORITY_CONSUMPTION_SHA256 = (
    "a4b6297b9a2df0469070361a2ba69507d1299f7129deb2097416fd50867f715f"
)
_R4_LANE_DISPATCH_REPORT_SHA256 = (
    "b31ce57cd7866a74546d61198700715835288afe9672075c558e3d11d693a7f6"
)
_R4_TERMINAL_SUMMARY_CAMPAIGN_FIELDS = frozenset(
    {
        "campaign_sha256",
        "grant_sha256",
        "registration_record_sha256",
        "start_record_sha256",
        "reservation_record_sha256",
        "terminal_record_sha256",
        "canonical_ledger_sha256",
        "shard_sha256s",
        "campaign_report_sha256",
    }
)
_R4_TERMINAL_SUMMARY_EXECUTION_FIELDS = frozenset(
    {
        "attempted_live_posts",
        "known_model_calls",
        "authorized_lane_sessions",
        "lane_2_dispatched",
        "completed_cells",
        "accepted_receipts",
        "attempted_call_usage",
        "raw_responses_persisted",
        "response_sha256s",
        "retries",
        "fallbacks",
        "replacements",
        "continuations",
        "hosted_calls",
    }
)
_R4_ADMISSION_FIELDS = frozenset(
    {
        "ticket_admission_sha256",
        "classification_audit_sha256",
        "hard_admission_sha256",
        "readiness_receipt_sha256",
        "route_report_sha256",
        "project_ground_report_sha256",
        "campaign_verification_sha256",
        "packet_validation_sha256",
    }
)
_R4_CREDENTIAL_BOUNDARY_FIELDS = frozenset(
    {
        "approved_config_reads",
        "usable_stored_credential_found",
        "stored_credential_values_enumerated",
        "credential_value_output",
        "credential_value_persisted",
        "credential_value_used",
        "process_local_admission_tokens",
        "process_local_admission_token_persisted",
        "setup_defects_count_as_model_attempts",
    }
)
_R4_AUTHORITY_CONSUMPTION_FIELDS = _AUTHORITY_CONSUMPTION_FIELDS | {
    "terminal_record_sha256"
}
_R4_LANE_DISPATCH_LANE_FIELDS = frozenset(
    {
        "lane_index",
        "status",
        "issues",
        "request_sha256",
        "response_sha256",
        "response_persisted",
        "model_calls",
        "receipt_sha256",
        "runtime_observation_sha256",
    }
)
_PRIVACY_FIELDS = frozenset(
    {
        "credential_persisted",
        "endpoint_persisted",
        "request_body_public",
        "response_body_public",
    }
)
_USAGE_FIELDS = (
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_tokens",
    "total_tokens",
    "tool_calls",
)

_LEGACY_AUTHORITY_NOTE = (
    "This packet grants no authority. Registration and every local-Qwen call "
    "require one fresh exact bounded Owner approval of its authority scope digest."
)
_STANDING_AUTHORITY_NOTE = (
    "This packet grants no authority. Registration and every local-Qwen call "
    "require a freshly validated one-use grant. Standing Owner authority binds "
    "the exact qualified scope automatically without a per-run approval message."
)
_TERMINAL_RULE = {
    "pass": (
        "Both exact lanes produce one strict completed output-text "
        "response with zero tools and no continuation, fit their "
        "per-lane and aggregate ceilings, and settle through the "
        "ordinary governed completion path."
    ),
    "failure": (
        "Any route, tool, continuation, schema, usage, source, "
        "authority, transport, or settlement mismatch drains and "
        "terminally stops the campaign without retry, fallback, "
        "replacement, repair, or extrapolation."
    ),
    "successor": (
        "A terminal PASS or failure authorizes nothing further; the "
        "sealed result must derive a new successor packet."
    ),
}
_PINNED_HISTORY_SPEC_PATH = (
    Path(__file__).resolve().parent.parent
    / "runtime"
    / "issue111-v8-history-spec.json"
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _safe_segment(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value not in {".", ".."}
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
    )


def _terminal_predecessor_refusal(issues: list[str]) -> dict[str, Any]:
    core = {
        "schema": TERMINAL_PREDECESSOR_CAPSULE_SCHEMA,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "predecessor": None,
        "authority": None,
        "execution": None,
        "artifacts": None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "capsule_sha256": _sha256(core)}


def _strict_json_object(
    payload: bytes,
    label: str,
    issues: list[str],
) -> Mapping[str, Any] | None:
    def closed_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=closed_pairs,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        _issue(issues, f"predecessor:{label}_json_invalid")
        return None
    if not isinstance(value, Mapping):
        _issue(issues, f"predecessor:{label}_shape_invalid")
        return None
    return value


def _terminal_predecessor_root(value: str | Path) -> Path:
    root = Path(value)
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("predecessor:root_invalid")
    resolved = root.resolve(strict=True)
    if resolved != root or not resolved.is_dir():
        raise ValueError("predecessor:root_invalid")
    info = resolved.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("predecessor:root_not_owner_private")
    return resolved


def _read_terminal_predecessor_artifact(
    root: Path,
    relative: str,
    *,
    label: str,
    issues: list[str],
    max_bytes: int = MAX_PREDECESSOR_ARTIFACT_BYTES,
) -> bytes | None:
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(
        part in {"", ".", ".."} for part in parts
    ):
        _issue(issues, f"predecessor:{label}_path_invalid")
        return None
    path = root.joinpath(*parts)
    try:
        current = root
        for part in parts[:-1]:
            current = current / part
            if current.is_symlink() or not current.is_dir():
                raise OSError
            info = current.stat()
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                _issue(issues, f"predecessor:{label}_not_owner_private")
                return None
        if path.is_symlink() or not path.is_file():
            raise OSError
        resolved = path.resolve(strict=True)
        if root not in resolved.parents:
            raise OSError
        info = resolved.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            _issue(issues, f"predecessor:{label}_not_owner_private")
            return None
        if info.st_size > max_bytes:
            _issue(issues, f"predecessor:{label}_too_large")
            return None
        payload = resolved.read_bytes()
    except OSError:
        _issue(issues, f"predecessor:{label}_unavailable")
        return None
    if len(payload) > max_bytes:
        _issue(issues, f"predecessor:{label}_too_large")
        return None
    return payload


def _semantic_seal_valid(value: Mapping[str, Any], field: str) -> bool:
    supplied = value.get(field)
    core = {
        key: deepcopy(item)
        for key, item in value.items()
        if key != field
    }
    return _is_sha(supplied) and supplied == _sha256(core)


def _normalize_r4_terminal_artifacts(
    decoded: Mapping[str, Mapping[str, Any]],
    payloads: Mapping[str, bytes],
    issues: list[str],
) -> dict[str, Mapping[str, Any]] | None:
    """Validate immutable r4 shapes and project the generic policy facts."""

    summary = decoded["terminal_summary"]
    campaign = summary.get("campaign")
    execution = summary.get("execution")
    admission = summary.get("admission")
    credential = summary.get("credential_boundary")
    privacy = summary.get("privacy")
    usage = (
        execution.get("attempted_call_usage")
        if isinstance(execution, Mapping)
        else None
    )
    terminal_issues = summary.get("terminal_issues")
    response_sha = hashlib.sha256(payloads["response"]).hexdigest()
    terminal_stop = decoded["terminal_stop"]
    if (
        set(summary) != _R4_TERMINAL_SUMMARY_FIELDS
        or summary.get("schema")
        != "orch-dork/issue111-v8-r4-terminal-summary/v1"
        or not _semantic_seal_valid(summary, "summary_sha256")
        or summary.get("summary_sha256") != _R4_TERMINAL_SUMMARY_SHA256
        or summary.get("terminal_kind") != "FAILURE"
        or not _safe_segment(summary.get("attempt_id"))
        or summary.get("state") != "INCOMPLETE_FAILURE"
        or not isinstance(summary.get("terminal_reason"), str)
        or not summary.get("terminal_reason")
        or not isinstance(terminal_issues, list)
        or not terminal_issues
        or any(not isinstance(item, str) or not item for item in terminal_issues)
        or terminal_issues != sorted(set(terminal_issues))
        or summary.get("terminal_reason") not in terminal_issues
        or summary.get("owner_approval_consumed") is not True
        or summary.get("continuing_authority") is not False
        or summary.get("reportable") is not False
        or summary.get("training_eligible") is not False
        or not all(
            _is_sha(summary.get(field))
            for field in (
                "current_packet_sha256",
                "authority_scope_sha256",
                "authority_source_sha256",
                "authority_binding_sha256",
                "summary_sha256",
            )
        )
        or not isinstance(admission, Mapping)
        or set(admission) != _R4_ADMISSION_FIELDS
        or not all(_is_sha(item) for item in admission.values())
        or not isinstance(credential, Mapping)
        or set(credential) != _R4_CREDENTIAL_BOUNDARY_FIELDS
        or credential.get("approved_config_reads") != 0
        or credential.get("usable_stored_credential_found") is not False
        or credential.get("stored_credential_values_enumerated") is not False
        or credential.get("credential_value_output") is not False
        or credential.get("credential_value_persisted") is not False
        or credential.get("credential_value_used") is not False
        or credential.get("process_local_admission_tokens") != 1
        or credential.get("process_local_admission_token_persisted") is not False
        or credential.get("setup_defects_count_as_model_attempts") is not False
        or not isinstance(privacy, Mapping)
        or set(privacy) != _PRIVACY_FIELDS
        or any(privacy.get(field) is not False for field in _PRIVACY_FIELDS)
        or not isinstance(campaign, Mapping)
        or set(campaign) != _R4_TERMINAL_SUMMARY_CAMPAIGN_FIELDS
        or not all(
            _is_sha(campaign.get(field))
            for field in _R4_TERMINAL_SUMMARY_CAMPAIGN_FIELDS
            if field != "shard_sha256s"
        )
        or not isinstance(campaign.get("shard_sha256s"), Mapping)
        or set(campaign["shard_sha256s"]) != {"evidence_extraction"}
        or not _is_sha(campaign["shard_sha256s"].get("evidence_extraction"))
        or campaign.get("campaign_report_sha256") != _sha256(terminal_stop)
        or campaign.get("terminal_record_sha256")
        != terminal_stop.get("stop_record_sha256")
        or not isinstance(execution, Mapping)
        or set(execution) != _R4_TERMINAL_SUMMARY_EXECUTION_FIELDS
        or execution.get("attempted_live_posts") != 1
        or execution.get("known_model_calls") != 1
        or execution.get("authorized_lane_sessions") != 2
        or execution.get("lane_2_dispatched") is not False
        or execution.get("completed_cells") != 0
        or execution.get("accepted_receipts") != 0
        or not isinstance(usage, Mapping)
        or set(usage) != {"status", "reason"}
        or usage.get("status") != "UNKNOWN"
        or not isinstance(usage.get("reason"), str)
        or not usage.get("reason")
        or execution.get("raw_responses_persisted") != 1
        or execution.get("response_sha256s") != [response_sha]
        or any(
            execution.get(field) != 0
            for field in (
                "retries",
                "fallbacks",
                "replacements",
                "continuations",
                "hosted_calls",
            )
        )
    ):
        _issue(issues, "predecessor:r4_terminal_summary_invalid")

    consumption = decoded["authority_consumption"]
    if (
        set(consumption) != _R4_AUTHORITY_CONSUMPTION_FIELDS
        or consumption.get("schema")
        != "orch-dork/issue111-v8-r4-authority-consumption/v1"
        or not _semantic_seal_valid(consumption, "record_sha256")
        or consumption.get("record_sha256")
        != _R4_AUTHORITY_CONSUMPTION_SHA256
        or consumption.get("consumed") is not True
        or consumption.get("continuing_authority") is not False
        or not all(
            _is_sha(consumption.get(field))
            for field in _R4_AUTHORITY_CONSUMPTION_FIELDS
            if field.endswith("sha256")
        )
        or consumption.get("packet_sha256")
        != summary.get("current_packet_sha256")
        or consumption.get("authority_scope_sha256")
        != summary.get("authority_scope_sha256")
        or consumption.get("authority_source_sha256")
        != summary.get("authority_source_sha256")
        or not isinstance(campaign, Mapping)
        or consumption.get("grant_sha256") != campaign.get("grant_sha256")
        or consumption.get("reservation_record_sha256")
        != campaign.get("reservation_record_sha256")
        or consumption.get("terminal_record_sha256")
        != campaign.get("terminal_record_sha256")
        or consumption.get("terminal_summary_sha256")
        != summary.get("summary_sha256")
    ):
        _issue(issues, "predecessor:r4_authority_consumption_invalid")

    dispatch = decoded["lane_dispatch"]
    dispatch_lanes = dispatch.get("lane_reports")
    dispatch_lane = (
        dispatch_lanes[0]
        if isinstance(dispatch_lanes, list) and len(dispatch_lanes) == 1
        else None
    )
    if (
        set(dispatch) != _LANE_DISPATCH_FIELDS
        or dispatch.get("schema")
        != "orch-dork/issue111-v8-r4-lane-dispatch-report/v1"
        or not _semantic_seal_valid(dispatch, "report_sha256")
        or dispatch.get("report_sha256") != _R4_LANE_DISPATCH_REPORT_SHA256
        or dispatch.get("status") != "FAIL"
        or dispatch.get("state") != "INCOMPLETE_FAILURE"
        or dispatch.get("terminal_reason") != summary.get("terminal_reason")
        or dispatch.get("attempted_live_posts") != 1
        or dispatch.get("known_model_calls") != 1
        or dispatch.get("model_calls_unknown") is not False
        or dispatch.get("lane_2_dispatched") is not False
        or dispatch.get("observed_total_tokens") != 0
        or dispatch.get("accepted_receipts") != 0
        or any(
            dispatch.get(field) != 0
            for field in (
                "credential_reads",
                "credential_setup_defects",
                "retries",
                "fallbacks",
                "replacements",
                "continuations",
                "hosted_calls",
            )
        )
        or dispatch.get("process_local_admission_tokens") != 1
        or dispatch.get("privacy") != privacy
        or not isinstance(dispatch_lane, Mapping)
        or set(dispatch_lane) != _R4_LANE_DISPATCH_LANE_FIELDS
        or dispatch_lane.get("lane_index") != 1
        or dispatch_lane.get("status") != "FAIL"
        or dispatch_lane.get("issues") != terminal_issues
        or dispatch_lane.get("response_persisted") is not True
        or dispatch_lane.get("model_calls") != 1
        or dispatch_lane.get("receipt_sha256") is not None
        or dispatch_lane.get("runtime_observation_sha256") is not None
        or dispatch_lane.get("response_sha256") != response_sha
        or not _is_sha(dispatch_lane.get("request_sha256"))
    ):
        _issue(issues, "predecessor:r4_lane_dispatch_invalid")

    if issues:
        return None

    normalized_summary_core = {
        key: deepcopy(item)
        for key, item in summary.items()
        if key not in {"summary_sha256", "terminal_kind"}
    }
    normalized_summary_core["schema"] = "orch-dork/issue111-v8-terminal-summary/v1"
    normalized_summary_core["campaign"] = {
        "campaign_sha256": campaign["campaign_sha256"],
        "grant_sha256": campaign["grant_sha256"],
        "registration_record_sha256": campaign["registration_record_sha256"],
        "start_record_sha256": campaign["start_record_sha256"],
        "reservation_record_sha256": campaign["reservation_record_sha256"],
        "stop_record_sha256": campaign["terminal_record_sha256"],
        "canonical_ledger_sha256": campaign["canonical_ledger_sha256"],
        "shard_sha256": campaign["shard_sha256s"]["evidence_extraction"],
        "campaign_report_sha256": terminal_stop["report_sha256"],
    }
    normalized_summary_core["execution"] = {
        "attempted_live_posts": execution["attempted_live_posts"],
        "known_model_calls": execution["known_model_calls"],
        "authorized_lane_sessions": execution["authorized_lane_sessions"],
        "lane_2_dispatched": execution["lane_2_dispatched"],
        "completed_cells": execution["completed_cells"],
        "accepted_receipts": execution["accepted_receipts"],
        "attempted_call_usage": deepcopy(execution["attempted_call_usage"]),
        "raw_response_persisted": True,
        "response_sha256": response_sha,
        "retries": execution["retries"],
        "fallbacks": execution["fallbacks"],
        "replacements": execution["replacements"],
        "continuations": execution["continuations"],
        "hosted_calls": execution["hosted_calls"],
    }
    normalized_summary = {
        **normalized_summary_core,
        "summary_sha256": _sha256(normalized_summary_core),
    }

    normalized_consumption_core = {
        key: deepcopy(item)
        for key, item in consumption.items()
        if key not in {"record_sha256", "terminal_record_sha256"}
    }
    normalized_consumption_core["schema"] = (
        "orch-dork/issue111-v8-authority-consumption/v1"
    )
    normalized_consumption_core["terminal_summary_sha256"] = normalized_summary[
        "summary_sha256"
    ]
    normalized_consumption = {
        **normalized_consumption_core,
        "record_sha256": _sha256(normalized_consumption_core),
    }

    normalized_lane = {
        "lane_index": dispatch_lane["lane_index"],
        "status": dispatch_lane["status"],
        "issues": deepcopy(dispatch_lane["issues"]),
        "request_sha256": dispatch_lane["request_sha256"],
        "response_sha256": dispatch_lane["response_sha256"],
        "response_persisted": dispatch_lane["response_persisted"],
        "receipt": None,
        "runtime_observation": None,
        "transport_failure": None,
        "terminal_result": None,
    }
    normalized_dispatch_core = {
        key: deepcopy(item)
        for key, item in dispatch.items()
        if key != "report_sha256"
    }
    normalized_dispatch_core["schema"] = (
        "orch-dork/issue111-v8-lane-dispatch-report/v1"
    )
    normalized_dispatch_core["state"] = "LANE_1_FAILED"
    normalized_dispatch_core["lane_reports"] = [normalized_lane]
    normalized_dispatch = {
        **normalized_dispatch_core,
        "report_sha256": _sha256(normalized_dispatch_core),
    }
    return {
        **decoded,
        "terminal_summary": normalized_summary,
        "authority_consumption": normalized_consumption,
        "lane_dispatch": normalized_dispatch,
    }


def derive_terminal_predecessor_capsule(
    terminal_root: str | Path,
) -> dict[str, Any]:
    """Re-read one exact closed tranche into a path-free successor capsule.

    The operation performs no grant, registration, reservation, credential,
    transport, provider, or model action.  It accepts only the owner-private
    terminal artifact set emitted by the bounded Issue 111 recovery runner.
    """

    issues: list[str] = []
    try:
        root = _terminal_predecessor_root(terminal_root)
    except (OSError, ValueError) as exc:
        return _terminal_predecessor_refusal([str(exc)])

    specifications = {
        "terminal_summary": ("final-summary.json", MAX_PREDECESSOR_ARTIFACT_BYTES),
        "authority_consumption": (
            "authority-consumption.json",
            MAX_PREDECESSOR_ARTIFACT_BYTES,
        ),
        "canonical_ledger": ("canonical.jsonl", MAX_PREDECESSOR_ARTIFACT_BYTES),
        "family_shard": (
            "evidence_extraction.jsonl",
            MAX_PREDECESSOR_ARTIFACT_BYTES,
        ),
        "terminal_stop": (
            "terminal-stop-report.json",
            MAX_PREDECESSOR_ARTIFACT_BYTES,
        ),
        "lane_dispatch": (
            "lane-dispatch-report.json",
            MAX_PREDECESSOR_ARTIFACT_BYTES,
        ),
        "invocation": (
            "lane-1/invocation-report.json",
            MAX_PREDECESSOR_ARTIFACT_BYTES,
        ),
        "response": ("lane-1/response.json", MAX_RESPONSE_BYTES),
    }
    payloads: dict[str, bytes] = {}
    for label, (relative, maximum) in specifications.items():
        payload = _read_terminal_predecessor_artifact(
            root,
            relative,
            label=label,
            issues=issues,
            max_bytes=maximum,
        )
        if payload is not None:
            payloads[label] = payload
    if issues:
        return _terminal_predecessor_refusal(issues)

    decoded: dict[str, Mapping[str, Any]] = {}
    for label in (
        "terminal_summary",
        "authority_consumption",
        "terminal_stop",
        "lane_dispatch",
        "invocation",
    ):
        value = _strict_json_object(payloads[label], label, issues)
        if value is not None:
            decoded[label] = value
    if issues:
        return _terminal_predecessor_refusal(issues)

    source_terminal_summary_sha256 = decoded["terminal_summary"].get(
        "summary_sha256"
    )
    source_consumption_record_sha256 = decoded["authority_consumption"].get(
        "record_sha256"
    )
    source_dispatch_report_sha256 = decoded["lane_dispatch"].get("report_sha256")
    if (
        decoded["terminal_summary"].get("schema")
        == "orch-dork/issue111-v8-r4-terminal-summary/v1"
    ):
        normalized = _normalize_r4_terminal_artifacts(decoded, payloads, issues)
        if normalized is None:
            return _terminal_predecessor_refusal(issues)
        decoded = normalized

    summary = decoded["terminal_summary"]
    campaign = summary.get("campaign")
    execution = summary.get("execution")
    usage = (
        execution.get("attempted_call_usage")
        if isinstance(execution, Mapping)
        else None
    )
    terminal_issues = summary.get("terminal_issues")
    if (
        set(summary) != _TERMINAL_SUMMARY_FIELDS
        or summary.get("schema") != "orch-dork/issue111-v8-terminal-summary/v1"
        or not _semantic_seal_valid(summary, "summary_sha256")
        or not _safe_segment(summary.get("attempt_id"))
        or summary.get("state") != "INCOMPLETE_FAILURE"
        or not isinstance(summary.get("terminal_reason"), str)
        or not summary.get("terminal_reason")
        or not isinstance(terminal_issues, list)
        or not terminal_issues
        or any(not isinstance(item, str) or not item for item in terminal_issues)
        or len(terminal_issues) != len(set(terminal_issues))
        or summary.get("terminal_reason") not in terminal_issues
        or summary.get("owner_approval_consumed") is not True
        or summary.get("continuing_authority") is not False
        or summary.get("reportable") is not False
        or summary.get("training_eligible") is not False
        or not all(
            _is_sha(summary.get(field))
            for field in (
                "current_packet_sha256",
                "authority_scope_sha256",
                "authority_source_sha256",
                "authority_binding_sha256",
                "summary_sha256",
            )
        )
        or not isinstance(campaign, Mapping)
        or set(campaign) != _TERMINAL_SUMMARY_CAMPAIGN_FIELDS
        or not all(_is_sha(campaign.get(field)) for field in campaign)
        or not isinstance(execution, Mapping)
        or set(execution) != _TERMINAL_SUMMARY_EXECUTION_FIELDS
        or execution.get("attempted_live_posts") != 1
        or execution.get("known_model_calls") != 1
        or execution.get("authorized_lane_sessions") != 2
        or execution.get("lane_2_dispatched") is not False
        or execution.get("completed_cells") != 0
        or execution.get("accepted_receipts") != 0
        or not isinstance(usage, Mapping)
        or set(usage) != {"status", "reason"}
        or usage.get("status") != "UNKNOWN"
        or not isinstance(usage.get("reason"), str)
        or not usage.get("reason")
        or execution.get("raw_response_persisted") is not True
        or not _is_sha(execution.get("response_sha256"))
        or any(
            execution.get(field) != 0
            for field in (
                "retries",
                "fallbacks",
                "replacements",
                "continuations",
                "hosted_calls",
            )
        )
    ):
        _issue(issues, "predecessor:terminal_summary_invalid")

    consumption = decoded["authority_consumption"]
    if (
        set(consumption) != _AUTHORITY_CONSUMPTION_FIELDS
        or consumption.get("schema")
        != "orch-dork/issue111-v8-authority-consumption/v1"
        or not _semantic_seal_valid(consumption, "record_sha256")
        or consumption.get("consumed") is not True
        or consumption.get("continuing_authority") is not False
        or not all(
            _is_sha(consumption.get(field))
            for field in _AUTHORITY_CONSUMPTION_FIELDS
            if field.endswith("sha256")
        )
        or consumption.get("packet_sha256")
        != summary.get("current_packet_sha256")
        or consumption.get("authority_scope_sha256")
        != summary.get("authority_scope_sha256")
        or consumption.get("authority_source_sha256")
        != summary.get("authority_source_sha256")
        or not isinstance(campaign, Mapping)
        or consumption.get("grant_sha256") != campaign.get("grant_sha256")
        or consumption.get("reservation_record_sha256")
        != campaign.get("reservation_record_sha256")
        or consumption.get("terminal_summary_sha256")
        != summary.get("summary_sha256")
    ):
        _issue(issues, "predecessor:authority_consumption_invalid")

    canonical_sha = hashlib.sha256(payloads["canonical_ledger"]).hexdigest()
    shard_sha = hashlib.sha256(payloads["family_shard"]).hexdigest()
    terminal_stop = decoded["terminal_stop"]
    if isinstance(campaign, Mapping):
        campaign_report = live_sweep.summarize_live_campaign(
            root / "canonical.jsonl",
            str(campaign.get("campaign_sha256")),
        )
        shard_report = live_sweep.summarize_live_shard(
            root / "evidence_extraction.jsonl",
            str(campaign.get("campaign_sha256")),
            "evidence_extraction",
        )
    else:
        campaign_report = {}
        shard_report = {}
    shard_counts = shard_report.get("counts") if isinstance(shard_report, Mapping) else None
    if (
        not isinstance(campaign, Mapping)
        or canonical_sha != campaign.get("canonical_ledger_sha256")
        or shard_sha != campaign.get("shard_sha256")
        or campaign_report != terminal_stop
        or campaign_report.get("status") != "PASS"
        or campaign_report.get("state") != "INCOMPLETE_FAILURE"
        or campaign_report.get("report_sha256")
        != campaign.get("campaign_report_sha256")
        or campaign_report.get("stop_record_sha256")
        != campaign.get("stop_record_sha256")
        or shard_report.get("status") != "PASS"
        or not isinstance(shard_counts, Mapping)
        or shard_counts.get("expected_runs") != 1
        or shard_counts.get("reserved_runs") != 1
        or shard_counts.get("completed_runs") != 0
        or shard_report.get("model_calls") != 0
        or shard_report.get("observed_tokens") != 0
        or not _is_sha(shard_report.get("report_sha256"))
    ):
        _issue(issues, "predecessor:terminal_ledgers_invalid")

    dispatch = decoded["lane_dispatch"]
    dispatch_lanes = dispatch.get("lane_reports")
    dispatch_lane = (
        dispatch_lanes[0]
        if isinstance(dispatch_lanes, list) and len(dispatch_lanes) == 1
        else None
    )
    if (
        set(dispatch) != _LANE_DISPATCH_FIELDS
        or dispatch.get("schema")
        != "orch-dork/issue111-v8-lane-dispatch-report/v1"
        or not _semantic_seal_valid(dispatch, "report_sha256")
        or dispatch.get("status") != "FAIL"
        or dispatch.get("state") != "LANE_1_FAILED"
        or dispatch.get("terminal_reason") != summary.get("terminal_reason")
        or dispatch.get("attempted_live_posts") != 1
        or dispatch.get("known_model_calls") != 1
        or dispatch.get("model_calls_unknown") is not False
        or dispatch.get("lane_2_dispatched") is not False
        or dispatch.get("observed_total_tokens") != 0
        or dispatch.get("accepted_receipts") != 0
        or any(
            dispatch.get(field) != 0
            for field in (
                "retries",
                "fallbacks",
                "replacements",
                "continuations",
                "hosted_calls",
            )
        )
        or not isinstance(dispatch_lane, Mapping)
        or set(dispatch_lane) != _LANE_DISPATCH_LANE_FIELDS
        or dispatch_lane.get("lane_index") != 1
        or dispatch_lane.get("status") != "FAIL"
        or dispatch_lane.get("issues") != terminal_issues
        or dispatch_lane.get("response_persisted") is not True
        or dispatch_lane.get("response_sha256")
        != execution.get("response_sha256")
        or any(
            dispatch_lane.get(field) is not None
            for field in (
                "receipt",
                "runtime_observation",
                "transport_failure",
                "terminal_result",
            )
        )
    ):
        _issue(issues, "predecessor:lane_dispatch_invalid")

    invocation = decoded["invocation"]
    if (
        set(invocation) != _INVOCATION_REPORT_FIELDS
        or invocation.get("schema")
        != "orch-dork/live-zero-tool-invocation-report/v2"
        or invocation.get("status") != "FAIL"
        or invocation.get("issues") != terminal_issues
        or invocation.get("attempted_requests") != 1
        or invocation.get("model_calls") != 1
        or invocation.get("response_persisted") is not True
        or invocation.get("request_sha256") != (
            dispatch_lane.get("request_sha256")
            if isinstance(dispatch_lane, Mapping)
            else None
        )
        or invocation.get("response_sha256")
        != execution.get("response_sha256")
        or any(
            invocation.get(field) is not None
            for field in (
                "receipt",
                "runtime_observation",
                "transport_failure",
                "terminal_result",
            )
        )
        or any(
            invocation.get(field) != 0
            for field in (
                "retries",
                "fallbacks",
                "replacements",
                "hosted_calls",
            )
        )
        or invocation.get("provider_free") is not False
    ):
        _issue(issues, "predecessor:invocation_report_invalid")

    response_sha = hashlib.sha256(payloads["response"]).hexdigest()
    if (
        response_sha != execution.get("response_sha256")
        or response_sha != invocation.get("response_sha256")
    ):
        _issue(issues, "predecessor:response_digest_mismatch")
    if issues:
        return _terminal_predecessor_refusal(issues)

    predecessor = {
        "attempt_id": summary["attempt_id"],
        "state": summary["state"],
        "terminal_reason": summary["terminal_reason"],
        "terminal_issues": deepcopy(terminal_issues),
        "packet_sha256": summary["current_packet_sha256"],
        "authority_scope_sha256": summary["authority_scope_sha256"],
        "authority_source_sha256": summary["authority_source_sha256"],
        "authority_binding_sha256": summary["authority_binding_sha256"],
        "campaign_sha256": campaign["campaign_sha256"],
        "grant_sha256": campaign["grant_sha256"],
        "reservation_record_sha256": campaign["reservation_record_sha256"],
        "stop_record_sha256": campaign["stop_record_sha256"],
    }
    authority = {
        "terminal_summary_sha256": source_terminal_summary_sha256,
        "consumption_record_sha256": source_consumption_record_sha256,
        "consumed": True,
        "continuing_authority": False,
    }
    execution_projection = {
        "attempted_live_posts": execution["attempted_live_posts"],
        "known_model_calls": execution["known_model_calls"],
        "lane_2_dispatched": execution["lane_2_dispatched"],
        "attempted_usage_status": usage["status"],
        "accepted_receipts": execution["accepted_receipts"],
        "raw_response_persisted": execution["raw_response_persisted"],
        "retries": execution["retries"],
        "fallbacks": execution["fallbacks"],
        "replacements": execution["replacements"],
        "continuations": execution["continuations"],
        "hosted_calls": execution["hosted_calls"],
    }
    artifacts = {
        "terminal_summary_file_sha256": hashlib.sha256(
            payloads["terminal_summary"]
        ).hexdigest(),
        "authority_consumption_file_sha256": hashlib.sha256(
            payloads["authority_consumption"]
        ).hexdigest(),
        "canonical_ledger_sha256": canonical_sha,
        "family_shard_sha256": shard_sha,
        "terminal_stop_report_sha256": terminal_stop["report_sha256"],
        "terminal_stop_file_sha256": hashlib.sha256(
            payloads["terminal_stop"]
        ).hexdigest(),
        "family_shard_report_sha256": shard_report["report_sha256"],
        "lane_dispatch_report_sha256": source_dispatch_report_sha256,
        "lane_dispatch_file_sha256": hashlib.sha256(
            payloads["lane_dispatch"]
        ).hexdigest(),
        "invocation_report_file_sha256": hashlib.sha256(
            payloads["invocation"]
        ).hexdigest(),
        "response_sha256": response_sha,
    }
    core = {
        "schema": TERMINAL_PREDECESSOR_CAPSULE_SCHEMA,
        "status": "PASS",
        "issues": [],
        "predecessor": predecessor,
        "authority": authority,
        "execution": execution_projection,
        "artifacts": artifacts,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "capsule_sha256": _sha256(core)}


def _history_root(value: str | Path) -> Path:
    root = Path(value)
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("history:root_invalid")
    resolved = root.resolve(strict=True)
    if resolved != root or not resolved.is_dir():
        raise ValueError("history:root_invalid")
    return resolved


def _bound_file(
    directory: Path,
    binding: Any,
    label: str,
    issues: list[str],
) -> tuple[Path | None, str | None]:
    if not isinstance(binding, Mapping) or set(binding) != _FILE_BINDING_FIELDS:
        _issue(issues, f"{label}:binding_invalid")
        return None, None
    name = binding.get("name")
    expected = binding.get("sha256")
    if not _safe_segment(name) or not _is_sha(expected):
        _issue(issues, f"{label}:binding_invalid")
        return None, None
    path = directory / str(name)
    try:
        if path.is_symlink() or not path.is_file() or path.resolve(strict=True).parent != directory:
            raise OSError
        data = path.read_bytes()
    except OSError:
        _issue(issues, f"{label}:unavailable")
        return None, None
    observed = hashlib.sha256(data).hexdigest()
    if observed != expected:
        _issue(issues, f"{label}:sha256_mismatch")
    return path, observed


def _history_spec_valid(value: Any, issues: list[str]) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "campaigns",
        "v7_failure",
        "spec_sha256",
    }:
        _issue(issues, "history_spec:shape_invalid")
        return False
    if value.get("schema") != HISTORY_SPEC_SCHEMA:
        _issue(issues, "history_spec:schema_invalid")
    campaigns = value.get("campaigns")
    if not isinstance(campaigns, list) or not campaigns or len(campaigns) > 8:
        _issue(issues, "history_spec:campaigns_invalid")
    failure = value.get("v7_failure")
    if not isinstance(failure, Mapping) or set(failure) != _V7_FAILURE_SPEC_FIELDS:
        _issue(issues, "history_spec:v7_failure_invalid")
    supplied = value.get("spec_sha256")
    core = {key: deepcopy(item) for key, item in value.items() if key != "spec_sha256"}
    if not _is_sha(supplied) or supplied != _sha256(core):
        _issue(issues, "history_spec:seal_mismatch")
    return not issues


def _integer_usage(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if any(type(value.get(field)) is not int or value[field] < 0 for field in _USAGE_FIELDS):
        return False
    return (
        value["cached_input_tokens"] <= value["input_tokens"]
        and value["reasoning_tokens"] <= value["output_tokens"]
        and value["total_tokens"]
        == value["input_tokens"] + value["output_tokens"]
    )


def _distribution(values: list[int]) -> dict[str, int] | None:
    if not values:
        return None
    ordered = sorted(values)
    count = len(ordered)
    middle = count // 2
    if count % 2:
        median_numerator = ordered[middle]
        median_denominator = 1
    else:
        median_numerator = ordered[middle - 1] + ordered[middle]
        median_denominator = 2
    nearest_rank = (95 * count + 99) // 100
    return {
        "sum": sum(ordered),
        "minimum": ordered[0],
        "median_numerator": median_numerator,
        "median_denominator": median_denominator,
        "p95_nearest_rank": ordered[nearest_rank - 1],
        "maximum": ordered[-1],
    }


def _manifest_refusal(
    issues: list[str],
    *,
    unknowns: list[dict[str, Any]] | None = None,
    non_session_reservations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    core = {
        "schema": EVIDENCE_MANIFEST_SCHEMA,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "history": None,
        "v7_failure": None,
        "population": None,
        "unknowns": deepcopy(unknowns or []),
        "non_session_reservations": deepcopy(non_session_reservations or []),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "manifest_sha256": _sha256(core)}


def _campaign_records(
    history_root: Path,
    campaign_spec: Any,
    issues: list[str],
) -> dict[str, Any] | None:
    if not isinstance(campaign_spec, Mapping) or set(campaign_spec) != _CAMPAIGN_SPEC_FIELDS:
        _issue(issues, "campaign_spec:shape_invalid")
        return None
    directory_name = campaign_spec.get("directory")
    campaign_id = campaign_spec.get("campaign_id")
    if not _safe_segment(directory_name) or not _safe_segment(campaign_id):
        _issue(issues, "campaign_spec:identity_invalid")
        return None
    directory = history_root / str(directory_name)
    try:
        if directory.is_symlink() or not directory.is_dir() or directory.resolve(strict=True).parent != history_root:
            raise OSError
    except OSError:
        _issue(issues, f"campaign:{campaign_id}:directory_unavailable")
        return None

    canonical_path, canonical_sha = _bound_file(
        directory,
        campaign_spec.get("canonical_file"),
        f"campaign:{campaign_id}:canonical",
        issues,
    )
    shard_bindings = campaign_spec.get("shard_files")
    if not isinstance(shard_bindings, Mapping) or not shard_bindings:
        _issue(issues, f"campaign:{campaign_id}:shards_invalid")
        shard_bindings = {}
    shard_paths: dict[str, Path] = {}
    shard_shas: dict[str, str] = {}
    for family, binding in sorted(shard_bindings.items()):
        if not _safe_segment(family):
            _issue(issues, f"campaign:{campaign_id}:family_invalid")
            continue
        path, digest = _bound_file(
            directory,
            binding,
            f"campaign:{campaign_id}:shard:{family}",
            issues,
        )
        if path is not None and digest is not None:
            shard_paths[str(family)] = path
            shard_shas[str(family)] = digest
    auxiliary = campaign_spec.get("auxiliary_files")
    if not isinstance(auxiliary, list):
        _issue(issues, f"campaign:{campaign_id}:auxiliary_invalid")
        auxiliary = []
    auxiliary_shas: dict[str, str] = {}
    for index, binding in enumerate(auxiliary):
        path, digest = _bound_file(
            directory,
            binding,
            f"campaign:{campaign_id}:auxiliary:{index}",
            issues,
        )
        if path is not None and digest is not None:
            auxiliary_shas[path.name] = digest
    if canonical_path is None:
        return None
    entries, chain_issues = live_sweep._entries(canonical_path)
    for item in chain_issues:
        _issue(issues, f"campaign:{campaign_id}:canonical:{item}")
    registrations = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema")
        == live_sweep.LIVE_CAMPAIGN_RECORD_SCHEMA
    ]
    if len(registrations) != 1:
        _issue(issues, f"campaign:{campaign_id}:registration_invalid")
        return None
    registration = registrations[0]
    campaign = registration.get("campaign")
    grant = registration.get("grant")
    if (
        not isinstance(campaign, Mapping)
        or campaign.get("campaign_id") != campaign_id
        or campaign.get("campaign_sha256") != campaign_spec.get("campaign_sha256")
        or registration.get("campaign_sha256") != campaign_spec.get("campaign_sha256")
        or registration.get("grant_sha256") != campaign_spec.get("grant_sha256")
        or not isinstance(grant, Mapping)
        or grant.get("grant_sha256") != campaign_spec.get("grant_sha256")
        or campaign_contract.verify_campaign(campaign).get("status") != "PASS"
        or live_sweep.derive_grant_shape(campaign, grant).get("status") != "PASS"
    ):
        _issue(issues, f"campaign:{campaign_id}:registration_binding_invalid")
    summary = live_sweep.summarize_live_campaign(
        canonical_path, str(campaign_spec.get("campaign_sha256"))
    )
    if summary.get("status") != "PASS" or summary.get("state") != campaign_spec.get("expected_state"):
        _issue(issues, f"campaign:{campaign_id}:summary_invalid")

    all_records: list[Mapping[str, Any]] = []
    shard_reports: dict[str, Any] = {}
    for family, path in sorted(shard_paths.items()):
        report = live_sweep.summarize_live_shard(
            path, str(campaign_spec.get("campaign_sha256")), family
        )
        if report.get("status") != "PASS":
            _issue(issues, f"campaign:{campaign_id}:shard_summary_invalid:{family}")
        shard_reports[family] = report
        shard_entries, shard_chain_issues = live_sweep._entries(path)
        for item in shard_chain_issues:
            _issue(issues, f"campaign:{campaign_id}:shard:{family}:{item}")
        all_records.extend(
            row["record"]
            for row in shard_entries
            if isinstance(row.get("record"), Mapping)
        )

    starts = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema") == live_sweep.LIVE_START_RECORD_SCHEMA
    ]
    if len(starts) != 1:
        _issue(issues, f"campaign:{campaign_id}:start_invalid")
        start = {}
    else:
        start = starts[0]
        observed_paths = {
            family: hashlib.sha256(
                str(path.resolve(strict=True)).encode("utf-8")
            ).hexdigest()
            for family, path in shard_paths.items()
        }
        bound_paths = {
            row.get("task_family"): row.get("path_sha256")
            for row in start.get("family_shards", [])
            if isinstance(row, Mapping)
        }
        if observed_paths != bound_paths:
            _issue(issues, f"campaign:{campaign_id}:shard_path_binding_mismatch")

    expected = campaign_spec.get("expected_records")
    if expected is not None and (
        not isinstance(expected, Mapping)
        or set(expected) != _EXPECTED_RECORD_FIELDS
    ):
        _issue(issues, f"campaign:{campaign_id}:expected_records_invalid")
        expected = None
    canonical_records = [
        row["record"] for row in entries if isinstance(row.get("record"), Mapping)
    ]
    replay_rows = [
        row
        for row in canonical_records
        if row.get("schema") == "orch-dork/record-replay-plan-record/v1"
    ]
    terminal_rows = [
        row
        for row in canonical_records
        if row.get("schema")
        in {
            live_sweep.LIVE_STOP_RECORD_SCHEMA,
            live_sweep.LIVE_STOP_RECORD_SCHEMA_V2,
            live_sweep.LIVE_OWNER_TERMINATION_RECORD_SCHEMA,
            live_sweep.LIVE_JOIN_RECORD_SCHEMA,
            live_sweep.LIVE_JOIN_RECORD_SCHEMA_V2,
            live_sweep.LIVE_JOIN_RECORD_SCHEMA_V3,
        }
    ]
    reservations = [
        row for row in all_records if row.get("schema") == live_sweep.LIVE_RESERVATION_RECORD_SCHEMA
    ]
    completions = [
        row
        for row in all_records
        if row.get("schema")
        in {
            live_sweep.LIVE_COMPLETION_RECORD_SCHEMA,
            live_sweep.LIVE_COMPLETION_RECORD_SCHEMA_V2,
        }
    ]
    actual_expected = {
        "registration": registration.get("record_sha256"),
        "replay_plan": replay_rows[0].get("record_sha256") if len(replay_rows) == 1 else None,
        "start": start.get("record_sha256"),
        "terminal": terminal_rows[-1].get("record_sha256") if len(terminal_rows) == 1 else None,
        "reservations": [row.get("record_sha256") for row in reservations],
        "completions": [row.get("record_sha256") for row in completions],
    }
    if expected is not None and dict(expected) != actual_expected:
        _issue(issues, f"campaign:{campaign_id}:record_manifest_mismatch")

    evidence_failures = [
        row
        for row in all_records
        if row.get("schema") in live_sweep.EVIDENCE_FAILURE_RECORD_SCHEMAS
    ]
    terminal = terminal_rows[-1] if len(terminal_rows) == 1 else {}
    return {
        "campaign_id": campaign_id,
        "campaign_sha256": campaign_spec.get("campaign_sha256"),
        "grant_sha256": campaign_spec.get("grant_sha256"),
        "state": summary.get("state"),
        "canonical_file_sha256": canonical_sha,
        "shard_file_sha256s": shard_shas,
        "auxiliary_file_sha256s": auxiliary_shas,
        "record_sha256s": actual_expected,
        "campaign": campaign,
        "grant": grant,
        "terminal": terminal,
        "reservations": reservations,
        "completions": completions,
        "evidence_failures": evidence_failures,
        "shard_reports": shard_reports,
    }


def _validate_failure_artifact(
    path: Path,
    spec: Mapping[str, Any],
    campaign_row: Mapping[str, Any],
    issues: list[str],
) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        _issue(issues, "v7_failure:json_invalid")
        return None
    if not isinstance(value, Mapping) or set(value) != _FAILURE_FIELDS:
        _issue(issues, "v7_failure:shape_invalid")
        return None
    supplied = value.get("record_sha256")
    core = {key: deepcopy(item) for key, item in value.items() if key != "record_sha256"}
    if (
        value.get("schema") != "orch-dork/issue111-v7-contract-failure/v1"
        or supplied != _sha256(core)
        or supplied != spec.get("failure_record_sha256")
        or value.get("campaign_sha256") != campaign_row.get("campaign_sha256")
        or value.get("grant_sha256") != campaign_row.get("grant_sha256")
        or value.get("request_sha256") != spec.get("request_sha256")
        or value.get("reservation_record_sha256")
        != spec.get("reservation_record_sha256")
        or value.get("failure_class") != "sealed_execution_contract_failure"
    ):
        _issue(issues, "v7_failure:binding_invalid")
    reservations = {
        row.get("record_sha256"): row for row in campaign_row.get("reservations", [])
    }
    reservation = reservations.get(value.get("reservation_record_sha256"))
    if (
        not isinstance(reservation, Mapping)
        or reservation.get("request_sha256") != value.get("request_sha256")
        or reservation.get("reserved_tokens") != value.get("reserved_tokens")
    ):
        _issue(issues, "v7_failure:reservation_invalid")
        request = {}
    else:
        request = reservation.get("request", {})
    observations = value.get("runtime_observations")
    lane_count = request.get("lane_count") if isinstance(request, Mapping) else None
    if not isinstance(observations, list) or len(observations) != lane_count:
        _issue(issues, "v7_failure:observation_count_invalid")
        observations = []
    normalized: list[Mapping[str, Any]] = []
    for observation in observations:
        report = routing.validate_session_runtime_observation(observation)
        if report.get("status") != "PASS":
            _issue(issues, "v7_failure:observation_invalid")
            continue
        route = observation.get("route", {})
        if route != {
            "session_id": route.get("session_id"),
            "model": "qwen-local/qwen-smart",
            "effort": "xhigh",
            "context_policy": "none",
            "inherited_history": False,
        }:
            _issue(issues, "v7_failure:route_invalid")
        if not _integer_usage(observation.get("usage")):
            _issue(issues, "v7_failure:usage_invalid")
        normalized.append(observation)
    aggregate = value.get("aggregate_usage")
    if not _integer_usage(aggregate):
        _issue(issues, "v7_failure:aggregate_usage_invalid")
    elif any(
        aggregate[field]
        != sum(row.get("usage", {}).get(field, -1) for row in normalized)
        for field in _USAGE_FIELDS
    ):
        _issue(issues, "v7_failure:aggregate_usage_mismatch")
    if (
        type(value.get("reserved_tokens")) is not int
        or value.get("reserved_tokens") != 54_000
        or value.get("overage_tokens")
        != (aggregate or {}).get("total_tokens", 0) - value.get("reserved_tokens", 0)
        or value.get("overage_tokens", 0) <= 0
    ):
        _issue(issues, "v7_failure:overage_invalid")
    if set(value.get("completion_refusal_issues", [])) != {
        "grant:cell_token_reservation_exhausted",
        "runtime:tool_calls_forbidden",
    }:
        _issue(issues, "v7_failure:refusal_issues_invalid")
    if any(
        value.get(field) != 0
        for field in (
            "automatic_retries",
            "automatic_fallbacks",
            "automatic_replacements",
            "hosted_calls",
        )
    ):
        _issue(issues, "v7_failure:automatic_action_invalid")
    if value.get("settlement") != "reservation_left_outstanding_by_contract":
        _issue(issues, "v7_failure:settlement_invalid")
    tool_free = [row for row in normalized if row["usage"]["tool_calls"] == 0]
    contaminated = [row for row in normalized if row["usage"]["tool_calls"] == 1]
    if len(tool_free) != 1 or len(contaminated) != 1:
        _issue(issues, "v7_failure:tool_partition_invalid")
        return None
    offending = value.get("offending_tool_records")
    contaminated_session = contaminated[0]["route"]["session_id"]
    if (
        not isinstance(offending, list)
        or len(offending) != 1
        or not isinstance(offending[0], Mapping)
        or offending[0].get("session_id") != contaminated_session
        or offending[0].get("tool_name") != "exec"
        or not _is_sha(offending[0].get("record_sha256"))
        or not _is_sha(offending[0].get("tool_input_sha256"))
    ):
        _issue(issues, "v7_failure:offending_tool_record_invalid")
    return {
        "failure_record_sha256": supplied,
        "reservation_record_sha256": value.get("reservation_record_sha256"),
        "request_sha256": value.get("request_sha256"),
        "lane_count": lane_count,
        "transport_failed_lane_sessions": len(contaminated),
        "compliant_lane": {
            "total_tokens": tool_free[0]["usage"]["total_tokens"],
            "output_tokens": tool_free[0]["usage"]["output_tokens"],
            "tool_calls": 0,
        },
        "transport_contaminated_lane": {
            "total_tokens": contaminated[0]["usage"]["total_tokens"],
            "output_tokens": contaminated[0]["usage"]["output_tokens"],
            "tool_calls": 1,
            "response_count": contaminated[0]["usage"]["tool_calls"] + 1,
        },
    }


def _terminal_proves_no_unsettled_model_calls(
    campaign_row: Mapping[str, Any],
) -> bool:
    terminal = campaign_row.get("terminal")
    if not isinstance(terminal, Mapping) or terminal.get("schema") not in {
        live_sweep.LIVE_JOIN_RECORD_SCHEMA,
        live_sweep.LIVE_JOIN_RECORD_SCHEMA_V2,
        live_sweep.LIVE_JOIN_RECORD_SCHEMA_V3,
    }:
        return False
    counts = terminal.get("counts")
    reservations = campaign_row.get("reservations")
    completions = campaign_row.get("completions")
    evidence_failures = campaign_row.get("evidence_failures")
    if not all(
        isinstance(value, list)
        for value in (reservations, completions, evidence_failures)
    ) or not isinstance(counts, Mapping):
        return False
    accounted_rows = list(completions) + list(evidence_failures)
    if any(
        not isinstance(row, Mapping)
        or type(row.get("model_calls")) is not int
        or row["model_calls"] < 0
        for row in accounted_rows
    ):
        return False
    return (
        counts.get("reserved_runs") == len(reservations)
        and counts.get("completed_runs") == len(completions)
        and counts.get("failed_runs") == len(evidence_failures)
        and terminal.get("live_model_calls")
        == sum(row["model_calls"] for row in accounted_rows)
        and terminal.get("hosted_calls") == 0
    )


def _classify_unsettled_reservations(
    campaign_row: Mapping[str, Any],
    *,
    failure_reservation: str | None,
    issues: list[str],
) -> dict[str, Any]:
    """Classify every reservation absent an ordinary terminal settlement."""

    completed = {
        row.get("reservation_record_sha256")
        for row in campaign_row.get("completions", [])
        if isinstance(row, Mapping)
    }
    evidence_failed = {
        row.get("reservation_record_sha256")
        for row in campaign_row.get("evidence_failures", [])
        if isinstance(row, Mapping)
    }
    outstanding = [
        row
        for row in campaign_row.get("reservations", [])
        if isinstance(row, Mapping)
        and row.get("record_sha256") not in completed | evidence_failed
        and row.get("record_sha256") != failure_reservation
    ]
    unstarted_proven = _terminal_proves_no_unsettled_model_calls(campaign_row)
    stop_reason = campaign_row.get("terminal", {}).get("reason_code")
    result: dict[str, Any] = {
        "evidence_failed_lane_slots": 0,
        "unstarted_reserved_lane_slots": 0,
        "unknowns": [],
        "non_session_reservations": [],
    }
    for reservation in outstanding:
        reservation_sha = reservation.get("record_sha256")
        lane_count = reservation.get("request", {}).get("lane_count")
        if not _is_sha(reservation_sha) or type(lane_count) is not int or lane_count < 1:
            _issue(
                issues,
                f"population:unsettled_reservation_invalid:{campaign_row.get('campaign_id')}",
            )
            continue
        common = {
            "campaign_id": campaign_row.get("campaign_id"),
            "reservation_record_sha256": reservation_sha,
            "lane_slots": lane_count,
        }
        if unstarted_proven:
            result["unstarted_reserved_lane_slots"] += lane_count
            result["non_session_reservations"].append(
                {
                    **common,
                    "kind": "reserved_unstarted",
                    "usage": "ZERO_MODEL_CALLS_BY_TERMINAL_LEDGER",
                }
            )
            continue
        result["evidence_failed_lane_slots"] += lane_count
        result["unknowns"].append(
            {
                **common,
                "kind": "unsettled_reservation_usage",
                "usage": "UNKNOWN",
            }
        )
        if stop_reason != "evidence_failure":
            _issue(
                issues,
                f"population:unsettled_reservation_unknown:{campaign_row.get('campaign_id')}",
            )
    return result


def derive_v8_evidence_manifest(
    history_root: str | Path, history_spec: Any
) -> dict[str, Any]:
    """Re-read sealed Stage-1 history and derive the v8 estimator population."""

    issues: list[str] = []
    if not _history_spec_valid(history_spec, issues):
        return _manifest_refusal(issues)
    try:
        root = _history_root(history_root)
    except (OSError, ValueError):
        return _manifest_refusal(["history:root_invalid"])
    campaign_rows: list[dict[str, Any]] = []
    for raw in history_spec["campaigns"]:
        row = _campaign_records(root, raw, issues)
        if row is not None:
            campaign_rows.append(row)
    by_id = {row["campaign_id"]: row for row in campaign_rows}
    if len(by_id) != len(campaign_rows):
        _issue(issues, "history:duplicate_campaign")
    failure_spec = history_spec["v7_failure"]
    failure_campaign = by_id.get(failure_spec.get("campaign_id"))
    failure_path: Path | None = None
    if failure_campaign is None:
        _issue(issues, "v7_failure:campaign_missing")
    else:
        raw_campaign_spec = next(
            row
            for row in history_spec["campaigns"]
            if row.get("campaign_id") == failure_spec.get("campaign_id")
        )
        directory = root / raw_campaign_spec["directory"]
        failure_path, _ = _bound_file(
            directory,
            failure_spec.get("file"),
            "v7_failure:file",
            issues,
        )
    failure = (
        _validate_failure_artifact(failure_path, failure_spec, failure_campaign, issues)
        if failure_path is not None and failure_campaign is not None
        else None
    )

    scored: list[dict[str, int]] = []
    malformed: list[dict[str, int]] = []
    evidence_failed_lane_slots = 0
    unstarted_reserved_lane_slots = 0
    unknowns: list[dict[str, Any]] = []
    non_session_reservations: list[dict[str, Any]] = []
    failure_reservation = (
        failure.get("reservation_record_sha256") if isinstance(failure, Mapping) else None
    )
    for campaign_row in campaign_rows:
        for completion in campaign_row["completions"]:
            lane_count = completion.get("request", {}).get("lane_count")
            for projection in completion.get("runtime_projections", []):
                usage = projection.get("usage")
                if not _integer_usage(usage) or usage.get("tool_calls") != 0:
                    _issue(issues, "population:scored_projection_invalid")
                    continue
                scored.append(
                    {
                        "lane_count": lane_count,
                        "total_tokens": usage["total_tokens"],
                        "output_tokens": usage["output_tokens"],
                    }
                )
            for projection in completion.get("malformed_projections", []):
                usage = projection.get("usage")
                if not _integer_usage(usage) or usage.get("tool_calls") != 0:
                    _issue(issues, "population:malformed_projection_invalid")
                    continue
                malformed.append(
                    {
                        "lane_count": lane_count,
                        "total_tokens": usage["total_tokens"],
                        "output_tokens": usage["output_tokens"],
                    }
                )
        for evidence_row in campaign_row["evidence_failures"]:
            calls = evidence_row.get("model_calls")
            if type(calls) is not int or calls < 1:
                _issue(issues, "population:evidence_failure_invalid")
            else:
                evidence_failed_lane_slots += calls
        unsettled = _classify_unsettled_reservations(
            campaign_row,
            failure_reservation=failure_reservation,
            issues=issues,
        )
        evidence_failed_lane_slots += unsettled["evidence_failed_lane_slots"]
        unstarted_reserved_lane_slots += unsettled[
            "unstarted_reserved_lane_slots"
        ]
        unknowns.extend(unsettled["unknowns"])
        non_session_reservations.extend(
            unsettled["non_session_reservations"]
        )

    if failure is None:
        _issue(issues, "v7_failure:invalid")
        return _manifest_refusal(issues)
    compliant = {
        "lane_count": failure["lane_count"],
        "total_tokens": failure["compliant_lane"]["total_tokens"],
        "output_tokens": failure["compliant_lane"]["output_tokens"],
    }
    eligible = scored + [compliant]
    n2 = [row for row in eligible if row.get("lane_count") == 2]
    total_distribution = _distribution([row["total_tokens"] for row in n2])
    output_distribution = _distribution([row["output_tokens"] for row in n2])
    if total_distribution is None or output_distribution is None:
        _issue(issues, "population:n2_estimator_empty")
    if issues:
        return _manifest_refusal(
            issues,
            unknowns=unknowns,
            non_session_reservations=non_session_reservations,
        )

    history_campaigns = [
        {
            "campaign_id": row["campaign_id"],
            "campaign_sha256": row["campaign_sha256"],
            "state": row["state"],
            "canonical_file_sha256": row["canonical_file_sha256"],
            "shard_file_sha256s": row["shard_file_sha256s"],
            "auxiliary_file_sha256s": row["auxiliary_file_sha256s"],
            "record_sha256s": row["record_sha256s"],
        }
        for row in campaign_rows
    ]
    history_core = {"campaigns": history_campaigns}
    history = {**history_core, "history_sha256": _sha256(history_core)}
    manifest_core = {
        "schema": EVIDENCE_MANIFEST_SCHEMA,
        "status": "PASS",
        "issues": [],
        "history": history,
        "v7_failure": failure,
        "population": {
            "scored_lane_sessions": len(scored),
            "malformed_lane_sessions": len(malformed),
            "evidence_failed_lane_slots": evidence_failed_lane_slots,
            "evidence_failed_usage_status": "UNKNOWN",
            "transport_failed_lane_sessions": failure[
                "transport_failed_lane_sessions"
            ],
            "unstarted_reserved_lane_slots": unstarted_reserved_lane_slots,
            "compliant_single_response_lane_sessions_all_lane_counts": len(
                eligible
            ),
            "n2_estimator": {
                "eligible_lane_sessions": len(n2),
                "total_tokens": total_distribution,
                "output_tokens": output_distribution,
            },
        },
        "unknowns": sorted(
            unknowns,
            key=lambda row: (
                row["campaign_id"],
                row["kind"],
                row["reservation_record_sha256"],
            ),
        ),
        "non_session_reservations": sorted(
            non_session_reservations,
            key=lambda row: (
                row["campaign_id"],
                row["reservation_record_sha256"],
            ),
        ),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**manifest_core, "manifest_sha256": _sha256(manifest_core)}


def issue111_v8_history_spec() -> dict[str, Any]:
    """Load and verify the shipped exact v4-v7 predecessor specification."""

    try:
        value = json.loads(_PINNED_HISTORY_SPEC_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("history_spec:bundled_unavailable") from exc
    issues: list[str] = []
    if not _history_spec_valid(value, issues):
        raise ValueError("history_spec:bundled_invalid:" + ",".join(issues))
    return deepcopy(value)


def derive_issue111_v8_evidence(history_root: str | Path) -> dict[str, Any]:
    """Derive Issue 134 evidence only from the pinned historical manifest."""

    try:
        spec = issue111_v8_history_spec()
    except ValueError as exc:
        return _manifest_refusal([str(exc)])
    return derive_v8_evidence_manifest(history_root, spec)


def derive_structural_transport_identity(
    plugin_root: str | Path | None = None,
) -> dict[str, Any]:
    """Bind the zero-tool contract to one exact installed/source runtime.

    The identity is intentionally derived from the plugin manifest and the
    transport module bytes.  Callers cannot substitute a descriptive claim
    for the implementation that will own the live request boundary.
    """

    root = (
        Path(__file__).resolve().parents[3]
        if plugin_root is None
        else Path(plugin_root)
    )
    try:
        if not root.is_absolute() or root.is_symlink():
            raise OSError
        resolved_root = root.resolve(strict=True)
        if resolved_root != root or not resolved_root.is_dir():
            raise OSError
        manifest_path = root / ".codex-plugin" / "plugin.json"
        scripts_root = (
            root
            / "skills"
            / "orch-dork"
            / "scripts"
        )
        module_path = scripts_root / "orch_dork_live_zero_tool.py"
        for path in (manifest_path, module_path):
            if (
                path.is_symlink()
                or not path.is_file()
                or root not in path.resolve(strict=True).parents
            ):
                raise OSError
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        module_sha256 = hashlib.sha256(module_path.read_bytes()).hexdigest()
        closure_files = []
        for name in AUTHORITY_SCOPE_RUNTIME_FILES:
            path = scripts_root / name
            if (
                path.is_symlink()
                or not path.is_file()
                or scripts_root != path.resolve(strict=True).parent
            ):
                raise OSError
            closure_files.append(
                {
                    "name": name,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        runtime_closure_sha256 = _sha256(
            {"schema": RUNTIME_CLOSURE_SCHEMA, "files": closure_files}
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("transport_identity:runtime_unavailable") from exc
    version = manifest.get("version") if isinstance(manifest, Mapping) else None
    if (
        not isinstance(manifest, Mapping)
        or manifest.get("name") != "orch-dork"
        or not isinstance(version, str)
        or not version
    ):
        raise ValueError("transport_identity:manifest_invalid")
    return {
        "schema": TRANSPORT_IDENTITY_SCHEMA,
        "plugin_version": version,
        "request_schema": zero_tool.REQUEST_SCHEMA_V1,
        "transport": zero_tool.TRANSPORT,
        "module_sha256": module_sha256,
        "runtime_closure_sha256": runtime_closure_sha256,
        "tools": [],
        "tool_choice": "none",
        "parallel_tool_calls": False,
        "stream": False,
        "store": False,
        "retry_count": 0,
        "fallback_count": 0,
        "replacement_count": 0,
    }


def _distribution_summary_valid(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != _DISTRIBUTION_FIELDS:
        return False
    if any(type(value.get(field)) is not int for field in _DISTRIBUTION_FIELDS):
        return False
    denominator = value["median_denominator"]
    return (
        denominator in {1, 2}
        and value["minimum"] >= 0
        and value["sum"] >= value["maximum"]
        and value["minimum"]
        <= value["p95_nearest_rank"]
        <= value["maximum"]
        and value["minimum"] * denominator
        <= value["median_numerator"]
        <= value["maximum"] * denominator
    )


def _manifest_valid(value: Any) -> bool:
    if (
        not isinstance(value, Mapping)
        or set(value) != _MANIFEST_FIELDS
        or value.get("schema") != EVIDENCE_MANIFEST_SCHEMA
        or value.get("status") != "PASS"
        or value.get("issues") != []
        or value.get("provider_free") is not True
        or value.get("model_calls") != 0
        or value.get("hosted_calls") != 0
    ):
        return False
    seal = value.get("manifest_sha256")
    core = {key: deepcopy(item) for key, item in value.items() if key != "manifest_sha256"}
    if not _is_sha(seal) or seal != _sha256(core):
        return False
    history = value.get("history")
    if not isinstance(history, Mapping) or set(history) != _HISTORY_FIELDS:
        return False
    campaigns = history.get("campaigns")
    if not isinstance(campaigns, list) or not campaigns:
        return False
    if any(
        not isinstance(row, Mapping)
        or set(row) != _HISTORY_CAMPAIGN_FIELDS
        or not _safe_segment(row.get("campaign_id"))
        or not _is_sha(row.get("campaign_sha256"))
        or not _is_sha(row.get("canonical_file_sha256"))
        or not isinstance(row.get("shard_file_sha256s"), Mapping)
        or not row["shard_file_sha256s"]
        or any(not _is_sha(digest) for digest in row["shard_file_sha256s"].values())
        or not isinstance(row.get("auxiliary_file_sha256s"), Mapping)
        or any(not _is_sha(digest) for digest in row["auxiliary_file_sha256s"].values())
        or not isinstance(row.get("record_sha256s"), Mapping)
        for row in campaigns
    ):
        return False
    history_core = {"campaigns": deepcopy(campaigns)}
    if (
        not _is_sha(history.get("history_sha256"))
        or history["history_sha256"] != _sha256(history_core)
    ):
        return False
    population = value.get("population")
    failure = value.get("v7_failure")
    if (
        not isinstance(population, Mapping)
        or set(population) != _POPULATION_FIELDS
        or not isinstance(failure, Mapping)
        or set(failure) != _V7_FAILURE_PROJECTION_FIELDS
    ):
        return False
    estimator = population.get("n2_estimator")
    if (
        not isinstance(estimator, Mapping)
        or set(estimator) != _N2_ESTIMATOR_FIELDS
        or type(estimator.get("eligible_lane_sessions")) is not int
        or estimator["eligible_lane_sessions"] < 1
        or not _distribution_summary_valid(estimator.get("total_tokens"))
        or not _distribution_summary_valid(estimator.get("output_tokens"))
    ):
        return False
    integer_counts = (
        "scored_lane_sessions",
        "malformed_lane_sessions",
        "evidence_failed_lane_slots",
        "transport_failed_lane_sessions",
        "unstarted_reserved_lane_slots",
        "compliant_single_response_lane_sessions_all_lane_counts",
    )
    if any(
        type(population.get(field)) is not int or population[field] < 0
        for field in integer_counts
    ):
        return False
    compliant = failure.get("compliant_lane")
    contaminated = failure.get("transport_contaminated_lane")
    if not (
        all(
            _is_sha(failure.get(field))
            for field in (
                "failure_record_sha256",
                "reservation_record_sha256",
                "request_sha256",
            )
        )
        and type(failure.get("lane_count")) is int
        and failure["lane_count"] >= 1
        and failure.get("transport_failed_lane_sessions") == 1
        and isinstance(compliant, Mapping)
        and set(compliant) == _COMPLIANT_LANE_FIELDS
        and compliant.get("tool_calls") == 0
        and isinstance(contaminated, Mapping)
        and set(contaminated) == _CONTAMINATED_LANE_FIELDS
        and contaminated.get("tool_calls") == 1
        and contaminated.get("response_count")
        == contaminated.get("tool_calls") + 1
        and all(
            type(row.get(field)) is int and row[field] >= 0
            for row in (compliant, contaminated)
            for field in ("total_tokens", "output_tokens", "tool_calls")
        )
    ):
        return False
    unknowns = value.get("unknowns")
    if not isinstance(unknowns, list) or any(
        not isinstance(row, Mapping)
        or set(row) != _UNKNOWN_FIELDS
        or not _safe_segment(row.get("campaign_id"))
        or not _is_sha(row.get("reservation_record_sha256"))
        or row.get("kind") != "unsettled_reservation_usage"
        or type(row.get("lane_slots")) is not int
        or row["lane_slots"] < 1
        or row.get("usage") != "UNKNOWN"
        for row in unknowns
    ):
        return False
    non_session_reservations = value.get("non_session_reservations")
    if not isinstance(non_session_reservations, list) or any(
        not isinstance(row, Mapping)
        or set(row) != _NON_SESSION_RESERVATION_FIELDS
        or not _safe_segment(row.get("campaign_id"))
        or not _is_sha(row.get("reservation_record_sha256"))
        or row.get("kind") != "reserved_unstarted"
        or type(row.get("lane_slots")) is not int
        or row["lane_slots"] < 1
        or row.get("usage") != "ZERO_MODEL_CALLS_BY_TERMINAL_LEDGER"
        for row in non_session_reservations
    ):
        return False
    return (
        population["evidence_failed_usage_status"] == "UNKNOWN"
        and population["transport_failed_lane_sessions"]
        == failure["transport_failed_lane_sessions"]
        and population[
            "compliant_single_response_lane_sessions_all_lane_counts"
        ]
        == population["scored_lane_sessions"] + 1
        and estimator["eligible_lane_sessions"]
        <= population[
            "compliant_single_response_lane_sessions_all_lane_counts"
        ]
        and sum(row["lane_slots"] for row in unknowns)
        <= population["evidence_failed_lane_slots"]
        and sum(row["lane_slots"] for row in non_session_reservations)
        == population["unstarted_reserved_lane_slots"]
    )


def _transport_valid(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != _TRANSPORT_FIELDS:
        return False
    structurally_valid = (
        value.get("schema") == TRANSPORT_IDENTITY_SCHEMA
        and isinstance(value.get("plugin_version"), str)
        and bool(value.get("plugin_version"))
        and value.get("request_schema") == "orch-dork/live-zero-tool-request/v1"
        and value.get("transport") == "openai-responses/v1"
        and _is_sha(value.get("module_sha256"))
        and _is_sha(value.get("runtime_closure_sha256"))
        and value.get("tools") == []
        and value.get("tool_choice") == "none"
        and value.get("parallel_tool_calls") is False
        and value.get("stream") is False
        and value.get("store") is False
        and value.get("retry_count") == 0
        and value.get("fallback_count") == 0
        and value.get("replacement_count") == 0
    )
    if not structurally_valid:
        return False
    try:
        current = derive_structural_transport_identity()
    except ValueError:
        return False
    return dict(value) == current


def _build_recovery_campaign(campaign_label: str) -> dict[str, Any] | None:
    axes = {
        "schema": live_sweep.CAMPAIGN_AXES_SCHEMA,
        "campaign_id": campaign_label,
        "question": {
            "question_id": campaign_label + "-question",
            "statement": (
                "Can the structural zero-tool transport complete one fresh "
                "N=2 evidence-extraction cell without tool or continuation "
                "contamination?"
            ),
            "primary_metric": "verified_success_bps",
            "population": "sealed-local-qwen-transport-recovery-fixture",
            "null_hypothesis": (
                "The structural transport does not complete the N=2 cell "
                "within every sealed execution constraint."
            ),
        },
        "task_families": ["evidence_extraction"],
        "lane_counts": [2],
        "cut_strategies": ["acceptance_unit"],
        "workload_buckets": {
            "high": {"item_count": 16, "coupling_density_bps": 5_000}
        },
        "seeds": [11_101],
        "decision_rule": {
            "metric": "verified_success_bps",
            "operator": "greater_than_or_equal",
            "threshold": {"numerator": 8_000, "denominator": 10_000},
            "minimum_complete_replicates": 1,
            "pass_disposition": "retain_default",
            "fail_disposition": "retain_default",
            "incomplete_disposition": "inconclusive",
        },
    }
    try:
        draft = live_sweep.build_live_campaign_draft(axes)
    except (TypeError, ValueError):
        return None
    sealed = campaign_contract.seal_campaign(draft)
    if sealed.get("status") != "PASS":
        return None
    return sealed["result"]["campaign"]


def _packet_refusal(issues: list[str]) -> dict[str, Any]:
    core = {
        "schema": PACKET_SCHEMA,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "campaign": None,
        "grant_terms": None,
        "transport": None,
        "evidence_manifest_sha256": None,
        "authorized": False,
        "grants_authority": False,
        "authority_status": "UNAVAILABLE",
        "authority_note": _LEGACY_AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "packet_sha256": _sha256(core)}


def _successor_packet_refusal(issues: list[str]) -> dict[str, Any]:
    core = {
        "schema": SUCCESSOR_PACKET_SCHEMA,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "campaign": None,
        "grant_terms": None,
        "transport": None,
        "terminal_predecessor": None,
        "evidence_manifest_sha256": None,
        "authorized": False,
        "grants_authority": False,
        "authority_status": "UNAVAILABLE",
        "authority_note": _LEGACY_AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "packet_sha256": _sha256(core)}


def _qualified_successor_packet_refusal(
    issues: list[str],
    *,
    transport_qualification: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a diagnostic result that cannot become authorization-ready."""

    core = {
        "schema": QUALIFIED_SUCCESSOR_PACKET_SCHEMA,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "campaign": None,
        "grant_terms": None,
        "transport": None,
        "terminal_predecessor": None,
        "transport_qualification": (
            deepcopy(dict(transport_qualification))
            if isinstance(transport_qualification, Mapping)
            else None
        ),
        "evidence_manifest_sha256": None,
        "authorized": False,
        "grants_authority": False,
        "authority_status": "UNAVAILABLE",
        "authority_note": _STANDING_AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "packet_sha256": _sha256(core)}


def _terminal_predecessor_capsule_valid(value: Any) -> bool:
    if (
        not isinstance(value, Mapping)
        or set(value) != _TERMINAL_PREDECESSOR_CAPSULE_FIELDS
        or value.get("schema") != TERMINAL_PREDECESSOR_CAPSULE_SCHEMA
        or value.get("status") != "PASS"
        or value.get("issues") != []
        or value.get("provider_free") is not True
        or value.get("model_calls") != 0
        or value.get("hosted_calls") != 0
        or not _semantic_seal_valid(value, "capsule_sha256")
    ):
        return False
    predecessor = value.get("predecessor")
    authority = value.get("authority")
    execution = value.get("execution")
    artifacts = value.get("artifacts")
    if (
        not isinstance(predecessor, Mapping)
        or set(predecessor) != _TERMINAL_PREDECESSOR_FIELDS
        or not _safe_segment(predecessor.get("attempt_id"))
        or predecessor.get("state") != "INCOMPLETE_FAILURE"
        or not isinstance(predecessor.get("terminal_reason"), str)
        or not predecessor.get("terminal_reason")
        or "/" in predecessor.get("terminal_reason", "")
        or "\\" in predecessor.get("terminal_reason", "")
        or not isinstance(predecessor.get("terminal_issues"), list)
        or not predecessor["terminal_issues"]
        or any(
            not isinstance(item, str)
            or not item
            or "/" in item
            or "\\" in item
            for item in predecessor["terminal_issues"]
        )
        or len(predecessor["terminal_issues"])
        != len(set(predecessor["terminal_issues"]))
        or predecessor.get("terminal_reason")
        not in predecessor["terminal_issues"]
        or any(
            not _is_sha(predecessor.get(field))
            for field in _TERMINAL_PREDECESSOR_FIELDS
            if field.endswith("sha256")
        )
        or not isinstance(authority, Mapping)
        or set(authority) != _TERMINAL_PREDECESSOR_AUTHORITY_FIELDS
        or not _is_sha(authority.get("terminal_summary_sha256"))
        or not _is_sha(authority.get("consumption_record_sha256"))
        or authority.get("consumed") is not True
        or authority.get("continuing_authority") is not False
        or not isinstance(execution, Mapping)
        or set(execution) != _TERMINAL_PREDECESSOR_EXECUTION_FIELDS
        or execution.get("attempted_live_posts") != 1
        or execution.get("known_model_calls") != 1
        or execution.get("lane_2_dispatched") is not False
        or execution.get("attempted_usage_status") != "UNKNOWN"
        or execution.get("accepted_receipts") != 0
        or execution.get("raw_response_persisted") is not True
        or any(
            execution.get(field) != 0
            for field in (
                "retries",
                "fallbacks",
                "replacements",
                "continuations",
                "hosted_calls",
            )
        )
        or not isinstance(artifacts, Mapping)
        or set(artifacts) != _TERMINAL_PREDECESSOR_ARTIFACT_FIELDS
        or any(not _is_sha(artifacts.get(field)) for field in artifacts)
    ):
        return False
    return True


def build_v8_recovery_packet(
    evidence_manifest: Any,
    transport_identity: Any,
    *,
    campaign_label: str,
    prepared_at: str,
) -> dict[str, Any]:
    """Seal the smallest fresh N=2 structural-transport recovery tranche."""

    issues: list[str] = []
    if not _manifest_valid(evidence_manifest):
        issues.append("packet:evidence_manifest_invalid")
    if not _transport_valid(transport_identity):
        issues.append("packet:transport_identity_invalid")
    if not isinstance(campaign_label, str) or _LABEL.fullmatch(campaign_label) is None:
        issues.append("packet:campaign_label_invalid")
    if not isinstance(prepared_at, str) or _TIMESTAMP.fullmatch(prepared_at) is None:
        issues.append("packet:prepared_at_invalid")
    if issues:
        return _packet_refusal(issues)

    campaign = _build_recovery_campaign(campaign_label)
    if campaign is None or live_sweep.expected_run_count(campaign) != 1:
        return _packet_refusal(["packet:campaign_invalid"])

    estimator = evidence_manifest["population"]["n2_estimator"]
    core = {
        "schema": PACKET_SCHEMA,
        "status": "PASS",
        "issues": [],
        "campaign_label": campaign_label,
        "prepared_at": prepared_at,
        "campaign": {
            "campaign_sha256": campaign["campaign_sha256"],
            "sealed": campaign,
            "cell_count": 1,
            "lane_counts": [2],
            "seeds": [11_101],
            "task_families": ["evidence_extraction"],
            "purpose": "structural_zero_tool_transport_recovery_only",
        },
        "grant_terms": {
            **_FIXED_GRANT_TERMS,
            "reservation_basis": {
                "population": "compliant_single_response_n2_lanes",
                "eligible_lane_sessions": estimator["eligible_lane_sessions"],
                "observed_total_tokens": deepcopy(estimator["total_tokens"]),
                "observed_output_tokens": deepcopy(estimator["output_tokens"]),
                "contaminated_continuation_excluded": True,
                "unknown_unsettled_usage_excluded": True,
            },
        },
        "transport": deepcopy(transport_identity),
        "failure_aware_basis": {
            "scored_lane_sessions": evidence_manifest["population"][
                "scored_lane_sessions"
            ],
            "malformed_lane_sessions": evidence_manifest["population"][
                "malformed_lane_sessions"
            ],
            "evidence_failed_lane_slots": evidence_manifest["population"][
                "evidence_failed_lane_slots"
            ],
            "evidence_failed_usage_status": evidence_manifest["population"][
                "evidence_failed_usage_status"
            ],
            "unstarted_reserved_lane_slots": evidence_manifest["population"][
                "unstarted_reserved_lane_slots"
            ],
            "compliant_single_response_lane_sessions_all_lane_counts": (
                evidence_manifest["population"][
                    "compliant_single_response_lane_sessions_all_lane_counts"
                ]
            ),
            "v7_compliant_lane": deepcopy(
                evidence_manifest["v7_failure"]["compliant_lane"]
            ),
            "v7_transport_contaminated_lane": deepcopy(
                evidence_manifest["v7_failure"][
                    "transport_contaminated_lane"
                ]
            ),
        },
        "terminal_rule": deepcopy(_TERMINAL_RULE),
        "evidence_manifest_sha256": evidence_manifest["manifest_sha256"],
        "predecessor_failure_record_sha256": evidence_manifest["v7_failure"][
            "failure_record_sha256"
        ],
        "authorized": False,
        "grants_authority": False,
        "authority_status": "OWNER_APPROVAL_REQUIRED",
        "authority_note": _LEGACY_AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "packet_sha256": _sha256(core)}


def build_v8_successor_packet(
    evidence_manifest: Any,
    transport_identity: Any,
    *,
    terminal_predecessor_root: str | Path,
    campaign_label: str,
    prepared_at: str,
) -> dict[str, Any]:
    """Seal a successor only after re-reading its immediate closed tranche."""

    terminal_predecessor = derive_terminal_predecessor_capsule(
        terminal_predecessor_root
    )
    if not _terminal_predecessor_capsule_valid(terminal_predecessor):
        return _successor_packet_refusal(
            ["packet:terminal_predecessor_invalid"]
        )
    legacy = build_v8_recovery_packet(
        evidence_manifest,
        transport_identity,
        campaign_label=campaign_label,
        prepared_at=prepared_at,
    )
    if legacy.get("status") != "PASS":
        return _successor_packet_refusal(list(legacy.get("issues", [])))
    core = {
        key: deepcopy(item)
        for key, item in legacy.items()
        if key != "packet_sha256"
    }
    core["schema"] = SUCCESSOR_PACKET_SCHEMA
    core["terminal_predecessor"] = terminal_predecessor
    return {**core, "packet_sha256": _sha256(core)}


def _transport_qualification_request(
    packet: Mapping[str, Any],
    *,
    plugin_root: str | Path,
) -> dict[str, Any]:
    """Build the fixed semantic request exercised before authority binding."""

    campaign = packet.get("campaign")
    campaign_sha256 = (
        campaign.get("campaign_sha256")
        if isinstance(campaign, Mapping)
        else None
    )
    if not _is_sha(campaign_sha256):
        raise ValueError("qualification:campaign_invalid")
    transport = packet.get("transport")
    semantic_transport = (
        {
            key: deepcopy(item)
            for key, item in transport.items()
            if key != "plugin_version"
        }
        if isinstance(transport, Mapping)
        else None
    )
    request_seed = _sha256(
        {
            "schema": "orch-dork/zero-tool-qualification-request-seed/v1",
            "campaign_sha256": campaign_sha256,
            "transport": semantic_transport,
        }
    )
    assignment_core = {
        "schema": live_sweep.LIVE_LANE_ASSIGNMENT_SCHEMA,
        "lane_id": "issue140-qualification-lane-1",
        "request_sha256": request_seed,
        "task_family": "evidence_extraction",
        "cut_strategy": "acceptance_unit",
        "task": {
            "rules": {"finding_rule": "severity is high"},
            "items": [
                {"id": "item-00", "severity": "high"},
                {"id": "item-01", "severity": "low"},
            ],
        },
        "output_schema": live_sweep.LIVE_LANE_RESULT_SCHEMA,
    }
    assignment = {
        **assignment_core,
        "assignment_sha256": _sha256(assignment_core),
    }
    grant_sha256 = _sha256(
        {
            "schema": "orch-dork/zero-tool-qualification-grant/v1",
            "campaign_sha256": campaign_sha256,
        }
    )
    reservation_sha256 = _sha256(
        {
            "schema": "orch-dork/zero-tool-qualification-reservation/v1",
            "campaign_sha256": campaign_sha256,
        }
    )
    return zero_tool.build_live_zero_tool_request(
        assignment,
        campaign_sha256=campaign_sha256,
        grant_sha256=grant_sha256,
        reservation_sha256=reservation_sha256,
        request_id="issue140-qualification-lane-1",
        max_output_tokens=PER_LANE_OUTPUT_TOKENS,
        max_total_tokens=PER_LANE_TOTAL_TOKENS,
        max_response_bytes=MAX_RESPONSE_BYTES,
        timeout_ms=LANE_TIMEOUT_MS,
        evidence_root=plugin_root,
        request_schema=zero_tool.REQUEST_SCHEMA_V1,
    )


def _run_transport_qualification(
    packet: Mapping[str, Any],
    *,
    opencodex_root: str | Path | None,
    plugin_root: str | Path | None,
) -> dict[str, Any] | None:
    if opencodex_root is None:
        return None
    root = Path(__file__).resolve().parents[3]
    try:
        if plugin_root is not None:
            supplied_root = Path(plugin_root)
            if (
                not supplied_root.is_absolute()
                or supplied_root.is_symlink()
                or supplied_root.resolve(strict=True) != root
            ):
                return None
        request = _transport_qualification_request(packet, plugin_root=root)
        return zero_tool_qualification.qualify_zero_tool_transport(
            request,
            zero_tool_qualification.TransportRuntime(
                plugin_root=root,
                opencodex_root=Path(opencodex_root),
            ),
        )
    except Exception:  # The authority boundary must fail closed without detail.
        return None


def build_v8_qualified_successor_packet(
    evidence_manifest: Any,
    transport_identity: Any,
    *,
    terminal_predecessor_root: str | Path,
    opencodex_root: str | Path,
    plugin_root: str | Path | None = None,
    campaign_label: str,
    prepared_at: str,
) -> dict[str, Any]:
    """Build packet v3 only after a fresh installed-runtime qualification."""

    predecessor = build_v8_successor_packet(
        evidence_manifest,
        transport_identity,
        terminal_predecessor_root=terminal_predecessor_root,
        campaign_label=campaign_label,
        prepared_at=prepared_at,
    )
    if predecessor.get("status") != "PASS":
        return _qualified_successor_packet_refusal(
            list(predecessor.get("issues", []))
        )
    qualification = _run_transport_qualification(
        predecessor,
        opencodex_root=opencodex_root,
        plugin_root=plugin_root,
    )
    qualification_validation = (
        zero_tool_qualification.validate_zero_tool_transport_qualification(
            qualification
        )
        if qualification is not None
        else {"status": "FAIL"}
    )
    if (
        qualification_validation.get("status") != "PASS"
        or qualification.get("status") != "PASS"
        or qualification.get("qualified") is not True
    ):
        return _qualified_successor_packet_refusal(
            ["packet:transport_qualification_failed"],
            transport_qualification=qualification,
        )
    core = {
        key: deepcopy(item)
        for key, item in predecessor.items()
        if key != "packet_sha256"
    }
    core["schema"] = QUALIFIED_SUCCESSOR_PACKET_SCHEMA
    core["transport_qualification"] = deepcopy(qualification)
    core["authority_status"] = "STANDING_AUTHORITY_READY"
    core["authority_note"] = _STANDING_AUTHORITY_NOTE
    return {**core, "packet_sha256": _sha256(core)}


def validate_v8_recovery_packet(value: Any) -> dict[str, Any]:
    """Recompute the packet seal and every authority/limit invariant."""

    issues: list[str] = []
    if (
        not isinstance(value, Mapping)
        or set(value) != _PACKET_FIELDS
        or value.get("schema") != PACKET_SCHEMA
    ):
        issues.append("packet:shape_invalid")
        if not isinstance(value, Mapping):
            value = {}
    if value.get("status") != "PASS" or value.get("issues") != []:
        issues.append("packet:not_passing")
    supplied = value.get("packet_sha256")
    core = {
        key: deepcopy(item)
        for key, item in value.items()
        if key != "packet_sha256"
    }
    expected = _sha256(core)
    if not _is_sha(supplied) or supplied != expected:
        issues.append("packet:seal_mismatch")

    campaign_label = value.get("campaign_label")
    prepared_at = value.get("prepared_at")
    campaign_wrapper = value.get("campaign")
    campaign = (
        campaign_wrapper.get("sealed")
        if isinstance(campaign_wrapper, Mapping)
        else None
    )
    verified = campaign_contract.verify_campaign(campaign)
    expected_campaign = (
        _build_recovery_campaign(campaign_label)
        if isinstance(campaign_label, str)
        and _LABEL.fullmatch(campaign_label) is not None
        else None
    )
    if (
        verified.get("status") != "PASS"
        or not isinstance(campaign_wrapper, Mapping)
        or set(campaign_wrapper) != _CAMPAIGN_WRAPPER_FIELDS
        or expected_campaign is None
        or campaign != expected_campaign
        or campaign_wrapper.get("campaign_sha256")
        != (campaign or {}).get("campaign_sha256")
        or campaign_wrapper.get("cell_count") != 1
        or campaign_wrapper.get("lane_counts") != [2]
        or campaign_wrapper.get("seeds") != [11_101]
        or campaign_wrapper.get("task_families") != ["evidence_extraction"]
        or campaign_wrapper.get("purpose")
        != "structural_zero_tool_transport_recovery_only"
    ):
        issues.append("packet:campaign_invalid")
    if (
        not isinstance(prepared_at, str)
        or _TIMESTAMP.fullmatch(prepared_at) is None
    ):
        issues.append("packet:prepared_at_invalid")

    terms = value.get("grant_terms")
    if (
        not isinstance(terms, Mapping)
        or set(terms) != _GRANT_TERM_FIELDS
        or any(
        terms.get(key) != item for key, item in _FIXED_GRANT_TERMS.items()
        )
    ):
        issues.append("packet:grant_terms_invalid")
    basis = terms.get("reservation_basis") if isinstance(terms, Mapping) else None
    total_distribution = (
        basis.get("observed_total_tokens")
        if isinstance(basis, Mapping)
        else None
    )
    output_distribution = (
        basis.get("observed_output_tokens")
        if isinstance(basis, Mapping)
        else None
    )
    distributions_valid = all(
        _distribution_summary_valid(distribution)
        for distribution in (total_distribution, output_distribution)
    )
    if (
        not isinstance(basis, Mapping)
        or set(basis) != _RESERVATION_BASIS_FIELDS
        or basis.get("population") != "compliant_single_response_n2_lanes"
        or type(basis.get("eligible_lane_sessions")) is not int
        or basis.get("eligible_lane_sessions", 0) < 1
        or basis.get("contaminated_continuation_excluded") is not True
        or basis.get("unknown_unsettled_usage_excluded") is not True
        or not distributions_valid
        or (
            isinstance(terms, Mapping)
            and isinstance(total_distribution, Mapping)
            and total_distribution.get("maximum", PER_LANE_TOTAL_TOKENS + 1)
            > terms.get("per_lane_total_tokens", 0)
        )
        or (
            isinstance(terms, Mapping)
            and isinstance(output_distribution, Mapping)
            and output_distribution.get("maximum", PER_LANE_OUTPUT_TOKENS + 1)
            > terms.get("per_lane_output_tokens", 0)
        )
    ):
        issues.append("packet:reservation_basis_invalid")
    if not _transport_valid(value.get("transport")):
        issues.append("packet:transport_identity_invalid")
    failure_basis = value.get("failure_aware_basis")
    if (
        not isinstance(failure_basis, Mapping)
        or set(failure_basis) != _FAILURE_BASIS_FIELDS
        or type(failure_basis.get("scored_lane_sessions")) is not int
        or type(failure_basis.get("malformed_lane_sessions")) is not int
        or type(failure_basis.get("evidence_failed_lane_slots")) is not int
        or failure_basis.get("evidence_failed_usage_status") != "UNKNOWN"
        or type(failure_basis.get("unstarted_reserved_lane_slots")) is not int
        or type(
            failure_basis.get(
                "compliant_single_response_lane_sessions_all_lane_counts"
            )
        )
        is not int
        or not isinstance(failure_basis.get("v7_compliant_lane"), Mapping)
        or set(failure_basis.get("v7_compliant_lane", {}))
        != _COMPLIANT_LANE_FIELDS
        or failure_basis["v7_compliant_lane"].get("tool_calls") != 0
        or not isinstance(
            failure_basis.get("v7_transport_contaminated_lane"), Mapping
        )
        or set(failure_basis.get("v7_transport_contaminated_lane", {}))
        != _CONTAMINATED_LANE_FIELDS
        or failure_basis["v7_transport_contaminated_lane"].get("tool_calls")
        != 1
        or failure_basis["v7_transport_contaminated_lane"].get(
            "response_count"
        )
        != 2
    ):
        issues.append("packet:failure_basis_invalid")
    terminal_rule = value.get("terminal_rule")
    if (
        not isinstance(terminal_rule, Mapping)
        or set(terminal_rule) != _TERMINAL_RULE_FIELDS
        or dict(terminal_rule) != _TERMINAL_RULE
    ):
        issues.append("packet:terminal_rule_invalid")
    if (
        value.get("authorized") is not False
        or value.get("grants_authority") is not False
        or value.get("authority_status") != "OWNER_APPROVAL_REQUIRED"
        or value.get("authority_note") != _LEGACY_AUTHORITY_NOTE
        or not _is_sha(value.get("evidence_manifest_sha256"))
        or not _is_sha(value.get("predecessor_failure_record_sha256"))
        or value.get("provider_free") is not True
        or value.get("model_calls") != 0
        or value.get("hosted_calls") != 0
    ):
        issues.append("packet:authority_boundary_invalid")

    report_core = {
        "schema": PACKET_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": sorted(set(issues)),
        "packet_sha256": supplied if _is_sha(supplied) else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**report_core, "report_sha256": _sha256(report_core)}


def validate_v8_successor_packet(
    value: Any,
    *,
    terminal_predecessor_root: str | Path | None,
) -> dict[str, Any]:
    """Validate v2 terms and re-read the exact immediate predecessor root."""

    issues: list[str] = []
    if (
        not isinstance(value, Mapping)
        or set(value) != _SUCCESSOR_PACKET_FIELDS
        or value.get("schema") != SUCCESSOR_PACKET_SCHEMA
    ):
        issues.append("packet:shape_invalid")
        if not isinstance(value, Mapping):
            value = {}
    supplied = value.get("packet_sha256")
    core = {
        key: deepcopy(item)
        for key, item in value.items()
        if key != "packet_sha256"
    }
    if not _is_sha(supplied) or supplied != _sha256(core):
        issues.append("packet:seal_mismatch")
    terminal_predecessor = value.get("terminal_predecessor")
    if not _terminal_predecessor_capsule_valid(terminal_predecessor):
        issues.append("packet:terminal_predecessor_invalid")

    legacy_core = {
        key: deepcopy(item)
        for key, item in value.items()
        if key not in {"packet_sha256", "terminal_predecessor"}
    }
    legacy_core["schema"] = PACKET_SCHEMA
    legacy = {**legacy_core, "packet_sha256": _sha256(legacy_core)}
    legacy_validation = validate_v8_recovery_packet(legacy)
    if legacy_validation.get("status") != "PASS":
        issues.extend(legacy_validation.get("issues", []))

    runtime_revalidated = False
    if terminal_predecessor_root is None:
        issues.append("packet:terminal_predecessor_runtime_required")
    else:
        observed = derive_terminal_predecessor_capsule(
            terminal_predecessor_root
        )
        if not _terminal_predecessor_capsule_valid(observed):
            issues.append("packet:terminal_predecessor_runtime_invalid")
        elif observed != terminal_predecessor:
            issues.append("packet:terminal_predecessor_mismatch")
        else:
            runtime_revalidated = True

    report_core = {
        "schema": SUCCESSOR_PACKET_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": sorted(set(issues)),
        "packet_sha256": supplied if _is_sha(supplied) else None,
        "terminal_predecessor_sha256": (
            terminal_predecessor.get("capsule_sha256")
            if isinstance(terminal_predecessor, Mapping)
            and _is_sha(terminal_predecessor.get("capsule_sha256"))
            else None
        ),
        "terminal_predecessor_runtime_revalidated": runtime_revalidated,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**report_core, "report_sha256": _sha256(report_core)}


def validate_v8_qualified_successor_packet(
    value: Any,
    *,
    terminal_predecessor_root: str | Path | None,
    opencodex_root: str | Path | None,
    plugin_root: str | Path | None = None,
) -> dict[str, Any]:
    """Re-run packet v3's exact predecessor and transport qualifications."""

    issues: list[str] = []
    if (
        not isinstance(value, Mapping)
        or set(value) != _QUALIFIED_SUCCESSOR_PACKET_FIELDS
        or value.get("schema") != QUALIFIED_SUCCESSOR_PACKET_SCHEMA
    ):
        issues.append("packet:shape_invalid")
        if not isinstance(value, Mapping):
            value = {}
    supplied = value.get("packet_sha256")
    core = {
        key: deepcopy(item)
        for key, item in value.items()
        if key != "packet_sha256"
    }
    if not _is_sha(supplied) or supplied != _sha256(core):
        issues.append("packet:seal_mismatch")

    predecessor_core = {
        key: deepcopy(item)
        for key, item in value.items()
        if key not in {"packet_sha256", "transport_qualification"}
    }
    predecessor_core["schema"] = SUCCESSOR_PACKET_SCHEMA
    predecessor_core["authority_status"] = "OWNER_APPROVAL_REQUIRED"
    predecessor_core["authority_note"] = _LEGACY_AUTHORITY_NOTE
    predecessor = {
        **predecessor_core,
        "packet_sha256": _sha256(predecessor_core),
    }
    predecessor_validation = validate_v8_successor_packet(
        predecessor,
        terminal_predecessor_root=terminal_predecessor_root,
    )
    if predecessor_validation.get("status") != "PASS":
        issues.extend(predecessor_validation.get("issues", []))
    if value.get("authority_status") != "STANDING_AUTHORITY_READY":
        issues.append("packet:standing_authority_status_invalid")
    if value.get("authority_note") != _STANDING_AUTHORITY_NOTE:
        issues.append("packet:standing_authority_note_invalid")

    stored = value.get("transport_qualification")
    stored_validation = (
        zero_tool_qualification.validate_zero_tool_transport_qualification(
            stored
        )
    )
    if (
        stored_validation.get("status") != "PASS"
        or not isinstance(stored, Mapping)
        or stored.get("status") != "PASS"
        or stored.get("qualified") is not True
    ):
        issues.append("packet:transport_qualification_invalid")

    transport_runtime_revalidated = False
    if opencodex_root is None:
        issues.append("packet:transport_qualification_runtime_required")
    elif predecessor_validation.get("status") == "PASS":
        observed = _run_transport_qualification(
            predecessor,
            opencodex_root=opencodex_root,
            plugin_root=plugin_root,
        )
        observed_validation = (
            zero_tool_qualification.validate_zero_tool_transport_qualification(
                observed
            )
            if observed is not None
            else {"status": "FAIL"}
        )
        if (
            observed_validation.get("status") != "PASS"
            or observed.get("status") != "PASS"
            or observed.get("qualified") is not True
        ):
            issues.append("packet:transport_qualification_failed")
        elif observed != stored:
            issues.append("packet:transport_qualification_mismatch")
        else:
            transport_runtime_revalidated = True

    terminal_predecessor = value.get("terminal_predecessor")
    report_core = {
        "schema": QUALIFIED_SUCCESSOR_PACKET_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "valid": not issues,
        "issues": sorted(set(issues)),
        "packet_sha256": supplied if _is_sha(supplied) else None,
        "terminal_predecessor_sha256": (
            terminal_predecessor.get("capsule_sha256")
            if isinstance(terminal_predecessor, Mapping)
            and _is_sha(terminal_predecessor.get("capsule_sha256"))
            else None
        ),
        "terminal_predecessor_runtime_revalidated": (
            predecessor_validation.get(
                "terminal_predecessor_runtime_revalidated", False
            )
            is True
        ),
        "transport_qualification_sha256": (
            stored.get("qualification_sha256")
            if isinstance(stored, Mapping)
            and _is_sha(stored.get("qualification_sha256"))
            else None
        ),
        "transport_runtime_revalidated": transport_runtime_revalidated,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**report_core, "report_sha256": _sha256(report_core)}


def _is_successor_packet(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("schema") == SUCCESSOR_PACKET_SCHEMA
    )


def _is_qualified_successor_packet(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("schema") == QUALIFIED_SUCCESSOR_PACKET_SCHEMA
    )


def _validate_packet_at_boundary(
    value: Any,
    terminal_predecessor_root: str | Path | None,
    *,
    opencodex_root: str | Path | None = None,
    plugin_root: str | Path | None = None,
) -> dict[str, Any]:
    """Dispatch validation without weakening fresh per-boundary re-reads.

    Do not cache this result across public operations. Each successor build,
    scope, grant, audit-sheet, and bundle boundary independently reopens the
    owner-private terminal root by contract.
    """

    if _is_qualified_successor_packet(value):
        return validate_v8_qualified_successor_packet(
            value,
            terminal_predecessor_root=terminal_predecessor_root,
            opencodex_root=opencodex_root,
            plugin_root=plugin_root,
        )
    if _is_successor_packet(value):
        return validate_v8_successor_packet(
            value,
            terminal_predecessor_root=terminal_predecessor_root,
        )
    return validate_v8_recovery_packet(value)


def v8_authority_scope_sha256(
    value: Any,
    *,
    terminal_predecessor_root: str | Path | None = None,
    opencodex_root: str | Path | None = None,
    plugin_root: str | Path | None = None,
) -> str | None:
    """Hash qualified execution terms eligible for one authority binding."""

    if not _is_qualified_successor_packet(value):
        return None
    if (
        _validate_packet_at_boundary(
            value,
            terminal_predecessor_root,
            opencodex_root=opencodex_root,
            plugin_root=plugin_root,
        )["status"]
        != "PASS"
    ):
        return None
    return _qualified_authority_scope_sha256(value)


def _qualified_authority_scope_sha256(value: Mapping[str, Any]) -> str:
    """Hash a packet v3 already freshly validated at its public boundary."""

    transport = {
        key: deepcopy(item)
        for key, item in value["transport"].items()
        if key != "plugin_version"
    }
    return _sha256(
        {
            "schema": QUALIFIED_SUCCESSOR_AUTHORITY_SCOPE_SCHEMA,
            "campaign_sha256": value["campaign"]["campaign_sha256"],
            "grant_terms": value["grant_terms"],
            "transport": transport,
            "failure_aware_basis": value["failure_aware_basis"],
            "terminal_rule": value["terminal_rule"],
            "evidence_manifest_sha256": value["evidence_manifest_sha256"],
            "predecessor_failure_record_sha256": value[
                "predecessor_failure_record_sha256"
            ],
            "terminal_predecessor_sha256": value["terminal_predecessor"][
                "capsule_sha256"
            ],
            "transport_qualification_sha256": value[
                "transport_qualification"
            ]["qualification_sha256"],
        }
    )


def replay_v8_authority_scope_sha256(value: Any) -> str | None:
    """Reproduce historical v1/v2 scope digests without making them active."""

    successor = _is_successor_packet(value)
    validation = (
        validate_v8_successor_packet(
            value,
            terminal_predecessor_root=None,
        )
        if successor
        else validate_v8_recovery_packet(value)
    )
    if successor:
        replay_issues = set(validation.get("issues", []))
        if replay_issues != {"packet:terminal_predecessor_runtime_required"}:
            return None
    elif validation.get("status") != "PASS":
        return None
    transport = {
        key: deepcopy(item)
        for key, item in value["transport"].items()
        if key != "plugin_version"
    }
    core = {
        "schema": (
            SUCCESSOR_AUTHORITY_SCOPE_SCHEMA
            if successor
            else AUTHORITY_SCOPE_SCHEMA
        ),
        "campaign_sha256": value["campaign"]["campaign_sha256"],
        "grant_terms": value["grant_terms"],
        "transport": transport,
        "failure_aware_basis": value["failure_aware_basis"],
        "terminal_rule": value["terminal_rule"],
        "evidence_manifest_sha256": value["evidence_manifest_sha256"],
        "predecessor_failure_record_sha256": value[
            "predecessor_failure_record_sha256"
        ],
    }
    if successor:
        core["terminal_predecessor_sha256"] = value[
            "terminal_predecessor"
        ]["capsule_sha256"]
    return _sha256(core)


def grant_from_v8_packet(
    value: Any,
    *,
    authority_source_sha256: Any = _AUTOMATIC_AUTHORITY,
    approved_authority_scope_sha256: Any = _AUTOMATIC_AUTHORITY,
    terminal_predecessor_root: str | Path | None = None,
    opencodex_root: str | Path | None = None,
    plugin_root: str | Path | None = None,
) -> dict[str, Any]:
    """Create a registrable grant from explicit or standing bounded authority."""

    successor = _is_successor_packet(value) or _is_qualified_successor_packet(
        value
    )
    qualified = _is_qualified_successor_packet(value)
    validation = _validate_packet_at_boundary(
        value,
        terminal_predecessor_root,
        opencodex_root=opencodex_root,
        plugin_root=plugin_root,
    )
    issues = list(validation["issues"])
    if not successor:
        issues.append("packet:terminal_predecessor_required")
    if not qualified:
        issues.append("packet:transport_qualification_required")
    authority_scope_sha256 = (
        _qualified_authority_scope_sha256(value)
        if qualified and validation.get("status") == "PASS"
        else None
    )
    automatic_authority = (
        authority_source_sha256 is _AUTOMATIC_AUTHORITY
        and approved_authority_scope_sha256 is _AUTOMATIC_AUTHORITY
    )
    standing_binding = None
    if automatic_authority and authority_scope_sha256 is not None:
        standing = standing_authority.bind_standing_owner_authority(
            authority_class=(
                standing_authority.QUALIFIED_RECOVERY_AUTHORITY_CLASS
            ),
            authority_scope_sha256=authority_scope_sha256,
        )
        if standing.get("status") == "PASS":
            authority_source_sha256 = standing["authority_source_sha256"]
            approved_authority_scope_sha256 = authority_scope_sha256
            standing_binding = standing
        else:
            issues.extend(standing.get("issues", []))
    if authority_source_sha256 is _AUTOMATIC_AUTHORITY:
        authority_source_sha256 = None
    if approved_authority_scope_sha256 is _AUTOMATIC_AUTHORITY:
        approved_authority_scope_sha256 = None
    if not _is_sha(authority_source_sha256):
        issues.append("packet:authority_required")
    if not _is_sha(approved_authority_scope_sha256):
        issues.append("packet:authority_scope_required")
    elif approved_authority_scope_sha256 != authority_scope_sha256:
        issues.append("packet:authority_scope_mismatch")
    if issues:
        return {
            "status": "FAIL",
            "issues": sorted(set(issues)),
            "campaign": None,
            "grant": None,
            "authority_binding": None,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }

    campaign = value["campaign"]["sealed"]
    terms = value["grant_terms"]
    try:
        grant = live_sweep.build_parameterized_live_grant(
            campaign,
            max_tokens=terms["aggregate_total_tokens"],
            max_wall_time_ms=terms["max_wall_time_ms"],
            reserved_tokens_per_lane_session=terms["per_lane_total_tokens"],
            authority_source_sha256=authority_source_sha256,
            grant_id=value["campaign_label"] + "-grant",
            attempt_id=value["campaign_label"] + "-attempt",
            standing_authority_binding=standing_binding,
        )
    except (TypeError, ValueError):
        return {
            "status": "FAIL",
            "issues": ["packet:grant_terms_invalid"],
            "campaign": None,
            "grant": None,
            "authority_binding": None,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    binding_core = {
        "schema": AUTHORITY_BINDING_SCHEMA,
        "packet_sha256": value["packet_sha256"],
        "authority_scope_sha256": authority_scope_sha256,
        "terminal_predecessor_sha256": value["terminal_predecessor"][
            "capsule_sha256"
        ],
        "transport_qualification_sha256": value[
            "transport_qualification"
        ]["qualification_sha256"],
        "authority_source_sha256": authority_source_sha256,
        "campaign_sha256": campaign["campaign_sha256"],
        "grant_sha256": grant["grant_sha256"],
        "authorized": True,
        "grants_campaign_registration": True,
        "live_calls_made": 0,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    authority_binding = {
        **binding_core,
        "binding_sha256": _sha256(binding_core),
    }
    return {
        "status": "PASS",
        "issues": [],
        "campaign": campaign,
        "grant": grant,
        "authority_binding": authority_binding,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def render_v8_decision_sheet(
    value: Any,
    *,
    terminal_predecessor_root: str | Path | None = None,
    opencodex_root: str | Path | None = None,
    plugin_root: str | Path | None = None,
) -> str:
    """Render the exact failure-aware terms and standing-authority binding."""

    qualified = _is_qualified_successor_packet(value)
    if not qualified:
        return (
            "Legacy v1/v2 recovery packet is replay-only. "
            "No authorization decision is available."
        )
    validation = _validate_packet_at_boundary(
        value,
        terminal_predecessor_root,
        opencodex_root=opencodex_root,
        plugin_root=plugin_root,
    )
    if validation["status"] != "PASS":
        return (
            "V8 N=2 recovery packet cannot be rendered: packet validation "
            "failed. No authorization decision is available."
        )
    return _render_v8_decision_sheet_validated(value)


def _render_v8_decision_sheet_validated(value: Mapping[str, Any]) -> str:
    """Render a packet v3 already revalidated at the calling boundary."""

    terms = value["grant_terms"]
    basis = terms["reservation_basis"]
    failure = value["failure_aware_basis"]
    contaminated = failure["v7_transport_contaminated_lane"]
    compliant = failure["v7_compliant_lane"]
    authority_scope_sha256 = _qualified_authority_scope_sha256(value)
    policy = standing_authority.standing_owner_policy()
    standing = standing_authority.bind_standing_owner_authority(
        authority_class=(
            standing_authority.QUALIFIED_RECOVERY_AUTHORITY_CLASS
        ),
        authority_scope_sha256=authority_scope_sha256,
    )
    predecessor = value["terminal_predecessor"]
    predecessor_lines = [
        "",
        "IMMEDIATE TERMINAL PREDECESSOR",
        "  Closed tranche: " + predecessor["predecessor"]["attempt_id"],
        "  Terminal state: " + predecessor["predecessor"]["state"],
        "  Consumed authority: yes; continuing authority: no.",
        "  Attempted usage remains UNKNOWN; lane 2 was not dispatched.",
        "  Terminal summary digest: "
        + predecessor["authority"]["terminal_summary_sha256"],
        "  Authority-consumption digest: "
        + predecessor["authority"]["consumption_record_sha256"],
        "  Predecessor capsule digest: " + predecessor["capsule_sha256"],
        "  Transport qualification digest: "
        + value["transport_qualification"]["qualification_sha256"],
    ]
    return "\n".join(
        [
            "ISSUE 111 V8 N=2 RECOVERY AUTHORITY AUDIT SHEET",
            "Campaign: " + value["campaign_label"],
            "Prepared: " + value["prepared_at"],
            "",
            "WHAT WOULD RUN",
            "  1 N=2 cell: 2 fresh lane sessions, one cell in flight.",
            "  The same evidence-extraction/high/acceptance-unit fixture and seed 11101.",
            "  Structural transport: tools [], tool_choice none, one response, no continuation.",
            "",
            "EXACT LIMITS",
            "  {:,} total tokens per lane; {:,} aggregate tokens.".format(
                terms["per_lane_total_tokens"],
                terms["aggregate_total_tokens"],
            ),
            "  {:,} output tokens per lane, {:,} response bytes, {:,} ms lane timeout.".format(
                terms["per_lane_output_tokens"],
                terms["max_response_bytes"],
                terms["lane_timeout_ms"],
            ),
            "  {:,} ms campaign wall backstop; zero retries, fallbacks, replacements, and hosted calls.".format(
                terms["max_wall_time_ms"]
            ),
            "  Zero preparation or review sessions.",
            "",
            "FAILURE-AWARE TOKEN BASIS",
            "  {} compliant single-response lanes across all observed lane counts; {} match N=2.".format(
                failure[
                    "compliant_single_response_lane_sessions_all_lane_counts"
                ],
                basis["eligible_lane_sessions"],
            ),
            "  {} compliant single-response N=2 lanes: observed maximum {:,}, p95 {:,}.".format(
                basis["eligible_lane_sessions"],
                basis["observed_total_tokens"]["maximum"],
                basis["observed_total_tokens"]["p95_nearest_rank"],
            ),
            "  The v7 tool-free companion used {:,} tokens and remains measurement evidence.".format(
                compliant["total_tokens"]
            ),
            "  The {:,}-token tool-call continuation is transport-contaminated failure evidence, not a normal budget sample.".format(
                contaminated["total_tokens"]
            ),
            "  V6 unsettled usage remains UNKNOWN and is excluded rather than reconstructed.",
            "  {} reserved lane slot was terminal-ledger-proven unstarted and is not a lane session.".format(
                failure["unstarted_reserved_lane_slots"]
            ),
            *predecessor_lines,
            "",
            "TERMINAL RULE",
            "  PASS requires both strict tool-free single responses, exact route/source/authority bindings,",
            "  per-lane and aggregate limits, and ordinary governed settlement.",
            "  Any mismatch drains and terminally stops without retry, repair, fallback, replacement, or extrapolation.",
            "  Either terminal result authorizes nothing further; derive a new successor packet.",
            "",
            "AUTHORIZATION",
            "  This packet carries no authority by itself. Fresh boundary revalidation",
            "  makes it eligible for one one-use grant under standing Owner authority;",
            "  no per-run Owner approval message is required.",
            "  Malformed or wrong-scope explicit recovery authority never falls back.",
            "  Standing policy digest: " + policy["policy_sha256"],
            "  Standing authority source digest: "
            + str(standing["authority_source_sha256"]),
            "  Authority scope digest: " + str(authority_scope_sha256),
            "  Packet digest (provenance only): " + value["packet_sha256"],
        ]
    )


def _bundle_report(
    *,
    status: str,
    issues: list[str],
    output_name: str | None,
    evidence_manifest_sha256: str | None,
    packet_sha256: str | None,
    authority_scope_sha256: str | None,
    terminal_predecessor_sha256: str | None = None,
    transport_qualification_sha256: str | None = None,
    files: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    core = {
        "schema": BUNDLE_RECEIPT_SCHEMA,
        "status": status,
        "issues": sorted(set(issues)),
        "output_name": output_name,
        "evidence_manifest_sha256": evidence_manifest_sha256,
        "packet_sha256": packet_sha256,
        "authority_scope_sha256": authority_scope_sha256,
        "terminal_predecessor_sha256": terminal_predecessor_sha256,
        "transport_qualification_sha256": (
            transport_qualification_sha256
        ),
        "files": dict(files or {}),
        "authorized": False,
        "grants_authority": False,
        "authority_status": (
            "STANDING_AUTHORITY_READY" if status == "PASS" else "UNAVAILABLE"
        ),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "receipt_sha256": _sha256(core)}


def _write_create_only(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def write_v8_recovery_bundle(
    output_directory: str | Path,
    evidence_manifest: Any,
    packet: Any,
    *,
    terminal_predecessor_root: str | Path | None = None,
    opencodex_root: str | Path | None = None,
    plugin_root: str | Path | None = None,
) -> dict[str, Any]:
    """Persist one immutable, path-hiding authority-audit artifact bundle."""

    successor = _is_successor_packet(packet) or _is_qualified_successor_packet(
        packet
    )
    qualified = _is_qualified_successor_packet(packet)
    validation = _validate_packet_at_boundary(
        packet,
        terminal_predecessor_root,
        opencodex_root=opencodex_root,
        plugin_root=plugin_root,
    )
    issues: list[str] = []
    if not successor:
        issues.append("artifact:terminal_predecessor_required")
    if not qualified:
        issues.append("artifact:transport_qualification_required")
    if not _manifest_valid(evidence_manifest):
        issues.append("artifact:evidence_manifest_invalid")
    if validation.get("status") != "PASS":
        issues.append("artifact:packet_invalid")
    manifest_sha = (
        evidence_manifest.get("manifest_sha256")
        if isinstance(evidence_manifest, Mapping)
        and _is_sha(evidence_manifest.get("manifest_sha256"))
        else None
    )
    packet_sha = (
        packet.get("packet_sha256")
        if isinstance(packet, Mapping) and _is_sha(packet.get("packet_sha256"))
        else None
    )
    authority_scope_sha = (
        _qualified_authority_scope_sha256(packet)
        if qualified and validation.get("status") == "PASS"
        else None
    )
    terminal_predecessor_sha = (
        packet.get("terminal_predecessor", {}).get("capsule_sha256")
        if successor
        and isinstance(packet.get("terminal_predecessor"), Mapping)
        and _is_sha(packet["terminal_predecessor"].get("capsule_sha256"))
        else None
    )
    transport_qualification_sha = (
        packet.get("transport_qualification", {}).get(
            "qualification_sha256"
        )
        if qualified
        and isinstance(packet.get("transport_qualification"), Mapping)
        and _is_sha(
            packet["transport_qualification"].get("qualification_sha256")
        )
        else None
    )
    if (
        not issues
        and packet.get("evidence_manifest_sha256") != manifest_sha
    ):
        issues.append("artifact:evidence_binding_mismatch")
    output = Path(output_directory)
    output_name = output.name if _safe_segment(output.name) else None
    try:
        parent = output.parent
        if (
            not output.is_absolute()
            or output_name is None
            or parent.is_symlink()
            or parent.resolve(strict=True) != parent
            or not parent.is_dir()
        ):
            raise OSError
    except OSError:
        issues.append("artifact:path_invalid")
    if os.path.lexists(output):
        issues.append("artifact:output_exists")
    if issues:
        return _bundle_report(
            status="FAIL",
            issues=issues,
            output_name=output_name,
            evidence_manifest_sha256=manifest_sha,
            packet_sha256=packet_sha,
            authority_scope_sha256=authority_scope_sha,
            terminal_predecessor_sha256=terminal_predecessor_sha,
            transport_qualification_sha256=(
                transport_qualification_sha
            ),
        )

    sheet = _render_v8_decision_sheet_validated(packet)
    payloads = {
        "evidence-manifest.json": _canonical_bytes(evidence_manifest) + b"\n",
        "predecessor-terminal-capsule.json": _canonical_bytes(
            packet["terminal_predecessor"]
        )
        + b"\n",
        "dispatch-packet.json": _canonical_bytes(packet) + b"\n",
        "AUTHORITY_AUDIT_SHEET.txt": (sheet + "\n").encode("utf-8"),
    }
    files = {
        name: {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
        for name, payload in sorted(payloads.items())
    }
    receipt = _bundle_report(
        status="PASS",
        issues=[],
        output_name=output_name,
        evidence_manifest_sha256=manifest_sha,
        packet_sha256=packet_sha,
        authority_scope_sha256=authority_scope_sha,
        terminal_predecessor_sha256=terminal_predecessor_sha,
        transport_qualification_sha256=transport_qualification_sha,
        files=files,
    )
    try:
        os.mkdir(output, 0o700)
        for name, payload in sorted(payloads.items()):
            _write_create_only(output / name, payload)
        _write_create_only(
            output / "bundle-receipt.json",
            _canonical_bytes(receipt) + b"\n",
        )
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        directory_descriptor = os.open(output, flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except (OSError, UnicodeError):
        return _bundle_report(
            status="FAIL",
            issues=["artifact:write_failed"],
            output_name=output_name,
            evidence_manifest_sha256=manifest_sha,
            packet_sha256=packet_sha,
            authority_scope_sha256=authority_scope_sha,
            terminal_predecessor_sha256=terminal_predecessor_sha,
            transport_qualification_sha256=(
                transport_qualification_sha
            ),
            files=files,
        )
    return receipt


__all__ = [
    "EVIDENCE_MANIFEST_SCHEMA",
    "HISTORY_SPEC_SCHEMA",
    "PACKET_SCHEMA",
    "SUCCESSOR_PACKET_SCHEMA",
    "QUALIFIED_SUCCESSOR_PACKET_SCHEMA",
    "PACKET_VALIDATION_SCHEMA",
    "SUCCESSOR_PACKET_VALIDATION_SCHEMA",
    "QUALIFIED_SUCCESSOR_PACKET_VALIDATION_SCHEMA",
    "TERMINAL_PREDECESSOR_CAPSULE_SCHEMA",
    "TRANSPORT_IDENTITY_SCHEMA",
    "RUNTIME_CLOSURE_SCHEMA",
    "AUTHORITY_SCOPE_RUNTIME_FILES",
    "AUTHORITY_SCOPE_SCHEMA",
    "SUCCESSOR_AUTHORITY_SCOPE_SCHEMA",
    "QUALIFIED_SUCCESSOR_AUTHORITY_SCOPE_SCHEMA",
    "AUTHORITY_BINDING_SCHEMA",
    "BUNDLE_RECEIPT_SCHEMA",
    "PER_LANE_TOTAL_TOKENS",
    "PER_LANE_OUTPUT_TOKENS",
    "AGGREGATE_TOTAL_TOKENS",
    "MAX_RESPONSE_BYTES",
    "LANE_TIMEOUT_MS",
    "MAX_WALL_TIME_MS",
    "MAX_CELLS_IN_FLIGHT",
    "MAX_LIVE_LANE_SESSIONS",
    "MAX_PREDECESSOR_ARTIFACT_BYTES",
    "derive_v8_evidence_manifest",
    "issue111_v8_history_spec",
    "derive_issue111_v8_evidence",
    "derive_terminal_predecessor_capsule",
    "derive_structural_transport_identity",
    "build_v8_recovery_packet",
    "build_v8_successor_packet",
    "build_v8_qualified_successor_packet",
    "validate_v8_recovery_packet",
    "validate_v8_successor_packet",
    "validate_v8_qualified_successor_packet",
    "v8_authority_scope_sha256",
    "replay_v8_authority_scope_sha256",
    "grant_from_v8_packet",
    "render_v8_decision_sheet",
    "write_v8_recovery_bundle",
]
