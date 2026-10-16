#!/usr/bin/env python3
"""Ledger-first controller for bounded live sweep campaign grants.

This optional adapter owns only provider-free campaign state transitions.  It
validates and records an explicit or standing grant, creates independently
appendable family shards, reserves cells before dispatch, validates observed runtime
evidence, and derives reports from the append-only ledgers.  It never contacts
a model, creates a worker, retries work, or changes a product default.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ImportError:  # pragma: no cover - isolated direct-file loading.
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules.setdefault(name, module)
        spec.loader.exec_module(module)
        return module


campaign_contract = _load_sibling("orch_dork_experiment_campaign")
hostile = _load_sibling("orch_dork_hostile_input")
sweep = _load_sibling("orch_dork_sweep_harness")
trace = _load_sibling("orch_dork_trace")
routing = _load_sibling("orch_dork_routing_verify")
record_replay = _load_sibling("orch_dork_record_replay")
refusal_tiers = _load_sibling("orch_dork_refusal_tiers")
standing_authority = _load_sibling("orch_dork_standing_authority")
PROFILE = hostile.PROFILE


LIVE_GRANT_SCHEMA_V1 = "orch-dork/live-sweep-grant/v1"
LIVE_GRANT_SCHEMA_V2 = "orch-dork/live-sweep-grant/v2"
LIVE_GRANT_SCHEMA_V3 = "orch-dork/live-sweep-grant/v3"
LIVE_GRANT_SCHEMA_V4 = "orch-dork/live-sweep-grant/v4"
LIVE_GRANT_SCHEMA_V5 = "orch-dork/live-sweep-grant/v5"
# Historical callers imported LIVE_GRANT_SCHEMA before successor authority
# existed.  Keep that name pinned to v1; new work must opt into the v2 builder.
LIVE_GRANT_SCHEMA = LIVE_GRANT_SCHEMA_V1
LIVE_CAMPAIGN_RECORD_SCHEMA = "orch-dork/live-sweep-campaign-record/v1"
LIVE_START_RECORD_SCHEMA = "orch-dork/live-sweep-start-record/v1"
LIVE_SHARD_HEADER_SCHEMA = "orch-dork/live-sweep-shard-header/v1"
LIVE_REPLICATE_REQUEST_SCHEMA = "orch-dork/live-sweep-replicate-request/v1"
LIVE_REPLICATE_REQUEST_SCHEMA_V2 = "orch-dork/live-sweep-replicate-request/v2"
LIVE_RESERVATION_RECORD_SCHEMA = "orch-dork/live-sweep-reservation-record/v1"
LIVE_LANE_ASSIGNMENT_SCHEMA = "orch-dork/live-sweep-lane-assignment/v1"
LIVE_LANE_RESULT_SCHEMA = "orch-dork/live-sweep-lane-result/v1"
LIVE_GOVERNED_EVIDENCE_SCHEMA = "orch-dork/live-sweep-governed-evidence/v1"
LIVE_COMPLETION_DRAFT_SCHEMA = "orch-dork/live-sweep-completion-draft/v1"
LIVE_COMPLETION_DRAFT_SCHEMA_V2 = "orch-dork/live-sweep-completion-draft/v2"
LIVE_COMPLETION_RECORD_SCHEMA = "orch-dork/live-sweep-completion-record/v1"
LIVE_COMPLETION_RECORD_SCHEMA_V2 = "orch-dork/live-sweep-completion-record/v2"
LIVE_EVIDENCE_FAILURE_DRAFT_SCHEMA = (
    "orch-dork/live-sweep-evidence-failure-draft/v1"
)
LIVE_EVIDENCE_FAILURE_DRAFT_SCHEMA_V2 = (
    "orch-dork/live-sweep-evidence-failure-draft/v2"
)
LIVE_EVIDENCE_FAILURE_DRAFT_SCHEMA_V3 = (
    "orch-dork/live-sweep-evidence-failure-draft/v3"
)
LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA = (
    "orch-dork/live-sweep-evidence-failure-record/v1"
)
LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA_V2 = (
    "orch-dork/live-sweep-evidence-failure-record/v2"
)
LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA_V3 = (
    "orch-dork/live-sweep-evidence-failure-record/v3"
)
LIVE_ABORT_DRAFT_SCHEMA = "orch-dork/live-sweep-abort-draft/v1"
LIVE_ABORT_RECORD_SCHEMA = "orch-dork/live-sweep-abort-record/v1"
LIVE_OWNER_TERMINATION_DRAFT_SCHEMA = (
    "orch-dork/live-sweep-owner-termination-draft/v1"
)
LIVE_OWNER_TERMINATION_RECORD_SCHEMA = (
    "orch-dork/live-sweep-owner-termination-record/v1"
)
LIVE_STOP_DRAFT_SCHEMA = "orch-dork/live-sweep-stop-draft/v1"
LIVE_STOP_RECORD_SCHEMA = "orch-dork/live-sweep-stop-record/v1"
LIVE_STOP_RECORD_SCHEMA_V2 = "orch-dork/live-sweep-stop-record/v2"
LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA = (
    "orch-dork/live-sweep-canonical-replicate-record/v1"
)
LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA_V2 = (
    "orch-dork/live-sweep-canonical-replicate-record/v2"
)
LIVE_FAMILY_SUMMARY_RECORD_SCHEMA = "orch-dork/live-sweep-family-summary-record/v1"
LIVE_FAMILY_SUMMARY_RECORD_SCHEMA_V2 = (
    "orch-dork/live-sweep-family-summary-record/v2"
)
LIVE_FAMILY_SUMMARY_RECORD_SCHEMA_V3 = (
    "orch-dork/live-sweep-family-summary-record/v3"
)
LIVE_JOIN_RECORD_SCHEMA = "orch-dork/live-sweep-join-record/v1"
LIVE_JOIN_RECORD_SCHEMA_V2 = "orch-dork/live-sweep-join-record/v2"
LIVE_JOIN_RECORD_SCHEMA_V3 = "orch-dork/live-sweep-join-record/v3"
LIVE_REPORT_SCHEMA = "orch-dork/live-sweep-report/v1"
LIVE_SHARD_REPORT_SCHEMA = "orch-dork/live-sweep-shard-report/v1"
LIVE_RESIDUAL_PROJECTION_SCHEMA = (
    "orch-dork/live-sweep-residual-projection/v2"
)
LIVE_SHARD_REPORT_SCHEMA_V2 = "orch-dork/live-sweep-shard-report/v2"

_LIVE_STOP_RECORD_SCHEMAS = frozenset(
    {LIVE_STOP_RECORD_SCHEMA, LIVE_STOP_RECORD_SCHEMA_V2}
)
_LIVE_FAMILY_SUMMARY_RECORD_SCHEMAS = frozenset(
    {
        LIVE_FAMILY_SUMMARY_RECORD_SCHEMA,
        LIVE_FAMILY_SUMMARY_RECORD_SCHEMA_V2,
        LIVE_FAMILY_SUMMARY_RECORD_SCHEMA_V3,
    }
)
_LIVE_JOIN_RECORD_SCHEMAS = frozenset(
    {
        LIVE_JOIN_RECORD_SCHEMA,
        LIVE_JOIN_RECORD_SCHEMA_V2,
        LIVE_JOIN_RECORD_SCHEMA_V3,
    }
)

ISSUE111_TASK_FAMILIES = (
    "evidence_extraction",
    "contract_audit",
    "dependency_graph",
)
ISSUE111_CUT_STRATEGIES = ("acceptance_unit", "dependency_region")
ISSUE111_LANE_COUNTS = (2, 4)
CAMPAIGN_AXES_SCHEMA = "orch-dork/live-sweep-campaign-axes/v1"
LANE_COUNT_FLOOR = 1
LANE_COUNT_CEILING = 32
WORKLOAD_ITEM_FLOOR = 4
WORKLOAD_ITEM_CEILING = 64
COUPLING_DENSITY_FLOOR_BPS = 0
COUPLING_DENSITY_CEILING_BPS = 10_000
_AXES_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "question",
        "task_families",
        "lane_counts",
        "cut_strategies",
        "workload_buckets",
        "seeds",
        "decision_rule",
    }
)
_WORKLOAD_BUCKET_FIELDS = frozenset({"item_count", "coupling_density_bps"})
ISSUE111_SEEDS = (11101, 11102, 11103)
ISSUE111_MAX_RUNS = 36
ISSUE111_MAX_TOKENS = 1_500_000
ISSUE111_MAX_WALL_TIME_MS = 14_400_000
ISSUE111_RESERVED_TOKENS_PER_RUN = 40_000
ISSUE111_FAMILY_RUNS = 12
ISSUE111_FAMILY_TOKENS = 480_000
ISSUE111_SUCCESSOR_MAX_TOKENS = 3_000_000
ISSUE111_SUCCESSOR_RESERVED_TOKENS_PER_LANE_SESSION = 27_000
ISSUE111_SUCCESSOR_FAMILY_TOKENS = 972_000
ISSUE111_PREDECESSOR_ATTRIBUTABLE_TOKENS = 2_442_060
ISSUE111_PREDECESSOR_OVERAGE_TOKENS = 942_060
ISSUE111_SUCCESSOR_GRANT_ID = "issue111-successor-human-grant-20260823"
ISSUE111_SUCCESSOR_ATTEMPT_ID = "issue111-live-qwen-successor-20260823"
ISSUE111_MEASUREMENT_SUCCESSOR_MAX_WALL_TIME_MS = 5_400_000
ISSUE111_MEASUREMENT_SUCCESSOR_GRANT_ID = (
    "issue111-measurement-successor-human-grant-20260824"
)
ISSUE111_MEASUREMENT_SUCCESSOR_ATTEMPT_ID = (
    "issue111-live-qwen-measurement-successor-20260824"
)

_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_GRANT_FIELDS_V1 = frozenset(
    {
        "schema",
        "grant_id",
        "campaign_sha256",
        "max_runs",
        "max_tokens",
        "max_wall_time_ms",
        "reserved_tokens_per_run",
        "family_allocations",
        "automatic_retries",
        "automatic_fallbacks",
        "automatic_replacements",
        "local_runtime",
        "authority_source_sha256",
        "grant_sha256",
    }
)
_GRANT_FIELDS_V2 = frozenset(
    {
        "schema",
        "grant_id",
        "attempt_id",
        "campaign_sha256",
        "max_runs",
        "max_tokens",
        "max_wall_time_ms",
        "reserved_tokens_per_lane_session",
        "family_allocations",
        "automatic_retries",
        "automatic_fallbacks",
        "automatic_replacements",
        "hosted_calls",
        "local_runtime",
        "execution_environment",
        "attribution",
        "risk",
        "recovery",
        "predecessor",
        "authority_source_sha256",
        "grant_sha256",
    }
)
_GRANT_FIELDS_V3 = _GRANT_FIELDS_V2 | frozenset({"finalization"})
_GRANT_FIELDS_V4 = frozenset(
    {
        "schema",
        "grant_id",
        "attempt_id",
        "campaign_sha256",
        "max_runs",
        "max_tokens",
        "max_wall_time_ms",
        "reserved_tokens_per_lane_session",
        "family_allocations",
        "automatic_retries",
        "automatic_fallbacks",
        "automatic_replacements",
        "hosted_calls",
        "local_runtime",
        "execution_environment",
        "attribution",
        "risk",
        "recovery",
        "finalization",
        "authority_source_sha256",
        "grant_sha256",
    }
)
_GRANT_FIELDS_V5 = _GRANT_FIELDS_V4 | frozenset({"standing_authority"})
_GRANT_FIELDS = _GRANT_FIELDS_V1
_ALLOCATION_FIELDS = frozenset({"task_family", "max_runs", "max_tokens"})
_PREDECESSOR_FIELDS = frozenset(
    {
        "state",
        "campaign_sha256",
        "grant_sha256",
        "registration_record_sha256",
        "replay_plan_sha256",
        "replay_plan_record_sha256",
        "abort_record_sha256",
        "ledger_sha256",
        "ledger_path_sha256",
        "attributable_tokens",
        "overage_tokens",
        "campaign_cells_reserved",
        "campaign_started",
    }
)
_TERMINATED_PREDECESSOR_FIELDS = frozenset(
    {
        "state",
        "campaign_sha256",
        "grant_sha256",
        "registration_record_sha256",
        "replay_plan_sha256",
        "replay_plan_record_sha256",
        "start_record_sha256",
        "termination_record_sha256",
        "termination_report_sha256",
        "ledger_sha256",
        "ledger_path_sha256",
        "shard_sha256s",
        "shard_path_sha256s",
        "counts",
        "observed_tokens",
        "live_model_calls",
    }
)
_EXECUTION_ENVIRONMENT_FIELDS = frozenset(
    {
        "host_id",
        "runtime",
        "model",
        "effort",
        "context_policy",
        "inherited_history",
        "wall_time_origin",
    }
)
_ATTRIBUTION_FIELDS = frozenset(
    {
        "scope",
        "additional_tokens_only",
        "preparation_sessions",
        "review_sessions",
    }
)
_RISK_FIELDS = frozenset({"primary", "mitigation"})
_RECOVERY_FIELDS = frozenset({"rollback", "on_failure"})
_FINALIZATION_FIELDS = frozenset(
    {
        "wall_time_role",
        "calendar_wait_required",
        "completion_proof",
        "early_stop",
    }
)
_REGISTRATION_FIELDS = frozenset(
    {
        "schema",
        "campaign",
        "campaign_sha256",
        "grant",
        "grant_sha256",
        "registered_at_ms",
        "adapter_contract",
        "record_sha256",
    }
)
_START_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "grant_sha256",
        "registration_record_sha256",
        "started_at_ms",
        "deadline_at_ms",
        "family_shards",
        "record_sha256",
    }
)
_SHARD_ROW_FIELDS = frozenset({"task_family", "shard_id", "path_sha256"})
_SHARD_HEADER_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "grant_sha256",
        "registration_record_sha256",
        "start_record_sha256",
        "task_family",
        "allocation",
        "started_at_ms",
        "deadline_at_ms",
        "record_sha256",
    }
)
_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "campaign_sha256",
        "configuration_id",
        "configuration_sha256",
        "task_family",
        "lane_count",
        "cut_strategy",
        "capability_profile",
        "replicate_index",
        "seed",
        "metric",
        "governed_entrypoint",
        "governed_program_schema",
        "reserved_tokens",
        "started_at_ms",
        "deadline_at_ms",
        "request_sha256",
    }
)
_REQUEST_FIELDS_V2 = _REQUEST_FIELDS | frozenset(
    {"workload_bucket", "item_count", "coupling_density_bps"}
)
_RESERVATION_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "grant_sha256",
        "shard_header_sha256",
        "request",
        "request_sha256",
        "reserved_at_ms",
        "reserved_tokens",
        "permanently_charged",
        "record_sha256",
    }
)
_ASSIGNMENT_FIELDS = frozenset(
    {
        "schema",
        "lane_id",
        "request_sha256",
        "task_family",
        "cut_strategy",
        "task",
        "output_schema",
        "assignment_sha256",
    }
)
_LANE_RESULT_FIELDS = frozenset(
    {
        "schema",
        "lane_id",
        "request_sha256",
        "assignment_sha256",
        "findings",
        "unknowns",
    }
)
_RUNTIME_PROJECTION_FIELDS = frozenset(
    {
        "lane_id",
        "session_id",
        "model",
        "effort",
        "source_sha256",
        "terminal_json_sha256",
        "usage",
        "runtime_observation_sha256",
    }
)
_USAGE_FIELDS = frozenset(
    {
        "status",
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
        "tool_calls",
    }
)
_AGGREGATE_USAGE_FIELDS = _USAGE_FIELDS - frozenset({"status"})
_TIMING_FIELDS = frozenset(
    {"reserved_at_ms", "completed_at_ms", "wall_time_ms"}
)
_GOVERNED_FIELDS = frozenset(
    {
        "schema",
        "entrypoint",
        "program_schema",
        "status",
        "governance_mode",
        "admission_report_sha256",
        "plan_report_sha256",
        "spawn_wave_report_sha256",
        "custody_report_sha256",
        "custody_coverage",
        "trace_report_sha256",
        "evidence_tier",
        "terminally_qualified",
    }
)
_COMPLETION_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "request_sha256",
        "reservation_record_sha256",
        "governed_evidence",
        "lane_results",
        "runtime_observations",
    }
)
_COMPLETION_DRAFT_FIELDS_V2 = _COMPLETION_DRAFT_FIELDS | frozenset(
    {"malformed_lanes"}
)
_MALFORMED_LANE_FIELDS = frozenset(
    {"lane_id", "terminal_json", "runtime_observation"}
)
_COMPLETION_RECORD_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "grant_sha256",
        "task_family",
        "request",
        "request_sha256",
        "reservation_record_sha256",
        "governed_evidence",
        "governed_evidence_sha256",
        "lane_results",
        "runtime_projections",
        "outcome",
        "metric",
        "usage",
        "timing",
        "model_calls",
        "hosted_calls",
        "automatic_retries",
        "automatic_fallbacks",
        "automatic_replacements",
        "record_sha256",
    }
)
_COMPLETION_RECORD_FIELDS_V2 = _COMPLETION_RECORD_FIELDS | frozenset(
    {"evidence_class", "malformed_projections"}
)
_EVIDENCE_FAILURE_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "request_sha256",
        "reservation_record_sha256",
        "failure_cause",
        "lane_observations",
    }
)
_EVIDENCE_FAILURE_DRAFT_FIELDS_V2 = _EVIDENCE_FAILURE_DRAFT_FIELDS | frozenset(
    {"stability_derivation"}
)
# v3 adds no draft field: a usage settlement needs only the ordinary
# lane observations, whose sealed usage.status already says "unknown".
_EVIDENCE_FAILURE_DRAFT_FIELDS_V3 = _EVIDENCE_FAILURE_DRAFT_FIELDS
_EVIDENCE_FAILURE_AUX_FIELD = "aux_process_samples"
_AUX_SAMPLE_FIELDS = frozenset(
    {
        "schema",
        "telemetry",
        "pgid",
        "process_count",
        "cpu_seconds_total",
        "rss_bytes_total",
        "auxiliary_only",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "sample_sha256",
    }
)
# Kept in sync with orch_dork_evidence_rate.AUX_SAMPLE_SCHEMA; the schema-
# pinning regression test asserts both modules agree so drift fails loudly.
AUX_PROCESS_SAMPLE_SCHEMA = "orch-dork/aux-process-sample/v1"
_EVIDENCE_FAILURE_LANE_FIELDS = frozenset(
    {"lane_id", "runtime_observation"}
)
_EVIDENCE_FAILURE_STABILITY_FIELDS = frozenset(
    {
        "first_source_sha256",
        "second_source_sha256",
        "first_report_sha256",
        "second_report_sha256",
        "first_observed_at_ms",
        "second_observed_at_ms",
        "interval_ms",
        "grace_floor_ms",
        "derivation_sha256",
    }
)
_EVIDENCE_FAILURE_PROJECTION_FIELDS = frozenset(
    {
        "lane_id",
        "session_id",
        "model",
        "effort",
        "source_sha256",
        "terminal_json_sha256",
        "usage",
        "runtime_observation_sha256",
        "observation_issues",
    }
)
_EVIDENCE_FAILURE_RECORD_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "grant_sha256",
        "task_family",
        "request",
        "request_sha256",
        "reservation_record_sha256",
        "failure_cause",
        "evidence_class",
        "score_available",
        "outcome_available",
        "runtime_projections",
        "usage",
        "timing",
        "model_calls",
        "hosted_calls",
        "automatic_retries",
        "automatic_fallbacks",
        "automatic_replacements",
        "record_sha256",
    }
)
_EVIDENCE_FAILURE_RECORD_FIELDS_V2 = _EVIDENCE_FAILURE_RECORD_FIELDS | frozenset(
    {"stability"}
)
# v3 replaces the aggregate usage mapping with the UNKNOWN sentinel and
# states availability explicitly, so no reader can mistake an unread
# accounting for a zero-cost cell.
_EVIDENCE_FAILURE_RECORD_FIELDS_V3 = _EVIDENCE_FAILURE_RECORD_FIELDS | frozenset(
    {"usage_available"}
)


def _validate_aux_process_samples(value: Any, issues: list[str]) -> list[dict[str, Any]] | None:
    """Validate the optional closed auxiliary sample pair.

    Auxiliary only: shape and seal are checked; the values never feed
    classification, scoring, or settlement decisions.
    """

    if not isinstance(value, list) or len(value) != 2:
        _issue(issues, "evidence_failure:aux_samples_invalid")
        return None
    normalized: list[dict[str, Any]] = []
    for row in value:
        sample = _closed(
            row, _AUX_SAMPLE_FIELDS, "evidence_failure.aux_sample", issues
        )
        if (
            sample.get("schema") != AUX_PROCESS_SAMPLE_SCHEMA
            or sample.get("auxiliary_only") is not True
            or sample.get("provider_free") is not True
            or sample.get("model_calls") != 0
            or sample.get("hosted_calls") != 0
            or sample.get("telemetry") not in ("observed", "unknown")
            or not _seal_valid(sample, "sample_sha256")
        ):
            _issue(issues, "evidence_failure:aux_samples_invalid")
            return None
        if sample["telemetry"] == "observed":
            if (
                type(sample.get("process_count")) is not int
                or sample["process_count"] < 0
                or type(sample.get("cpu_seconds_total")) is not float
                or sample["cpu_seconds_total"] < 0.0
                or type(sample.get("rss_bytes_total")) is not int
                or sample["rss_bytes_total"] < 0
                or type(sample.get("pgid")) is not int
                or sample["pgid"] < 1
            ):
                _issue(issues, "evidence_failure:aux_samples_invalid")
                return None
        elif any(
            sample.get(field) is not None
            for field in ("process_count", "cpu_seconds_total", "rss_bytes_total")
        ):
            _issue(issues, "evidence_failure:aux_samples_invalid")
            return None
        normalized.append(sample)
    return normalized
_CONTINUABLE_TERMINAL_FAILURE_CAUSES = frozenset(
    {
        "terminal:json_missing",
        "terminal:not_closed_json_object",
        "terminal:conflicting_records",
    }
)
STABLE_TERMINAL_FAILURE_CAUSE = "terminal:json_missing_stable"
_SETTLEABLE_TERMINAL_FAILURE_CAUSES = _CONTINUABLE_TERMINAL_FAILURE_CAUSES | {
    STABLE_TERMINAL_FAILURE_CAUSE
}

# Issue 123: a usage failure leaves route, session, observer, and
# terminal evidence intact and independently observed -- only the token
# accounting is unreadable -- so the cell can settle unscored with usage
# named UNKNOWN.  The observer/runtime issues stay non-continuable
# because they mean the observation itself cannot be trusted, and there
# is then nothing honest to settle against.
SETTLEABLE_USAGE_FAILURE_CAUSES = frozenset(
    {
        "usage:exact_record_missing",
        "usage:exact_record_invalid",
    }
)
UNKNOWN_USAGE = "UNKNOWN"

# Every cause that settles a cell without scoring it. Projections bucket
# each cause separately; this union is only for "may this appear in a
# settlement projection at all".
SETTLEABLE_EVIDENCE_FAILURE_CAUSES = (
    _SETTLEABLE_TERMINAL_FAILURE_CAUSES | SETTLEABLE_USAGE_FAILURE_CAUSES
)


def settled_usage_tokens(record: Any, field: str = "total_tokens") -> int:
    """Read one settled record's observed tokens, or zero when UNKNOWN.

    A v3 usage-unknown settlement seals ``UNKNOWN`` in place of the
    aggregate mapping (Issue 123), so every sum over settled records must
    treat it as contributing nothing observed.  That is not a zero-fill of
    the underlying spend: the cell is separately counted as a
    usage-unknown settlement, which forces the residual projection to
    report an upper bound rather than an exact total.
    """

    if not isinstance(record, Mapping):
        return 0
    usage = record.get("usage")
    if not isinstance(usage, Mapping):
        return 0
    value = usage.get(field)
    return int(value) if type(value) is int else 0


def usage_is_unknown(record: Any) -> bool:
    """True when a settled record sealed UNKNOWN in place of its usage."""

    return (
        isinstance(record, Mapping) and record.get("usage") == UNKNOWN_USAGE
    )


def _observed_failure_cause(cause: Any) -> Any:
    """The observation-level issue a settlement cause is grounded in."""

    if cause == STABLE_TERMINAL_FAILURE_CAUSE:
        return "terminal:json_missing"
    return cause


_EVIDENCE_FAILURE_RECORD_SCHEMAS = frozenset(
    {
        LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA,
        LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA_V2,
        LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA_V3,
    }
)
# Public aggregate of every sealed evidence-failure schema. Downstream
# readers need "is this record a settlement" as one question; exporting it
# keeps a future v4 in one place instead of in every caller.
EVIDENCE_FAILURE_RECORD_SCHEMAS = _EVIDENCE_FAILURE_RECORD_SCHEMAS
_RUNTIME_OBSERVATION_FIELDS = frozenset(
    {
        "schema",
        "status",
        "issues",
        "observer_id",
        "source_pointer",
        "source_sha256",
        "route",
        "terminal_schema",
        "terminal_json_sha256",
        "terminal_record",
        "usage",
        "usage_record",
        "skipped_lines",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "evidence_tier",
        "report_sha256",
    }
)
_RUNTIME_ROUTE_FIELDS = frozenset(
    {"session_id", "model", "effort", "context_policy", "inherited_history"}
)
_RUNTIME_POINTER_RECORD_FIELDS = frozenset({"line", "sha256"})
_ABORT_DRAFT_FIELDS = frozenset(
    {"schema", "reason_code", "authority_disposition", "observed_sessions"}
)
_ABORT_SESSION_FIELDS = frozenset(
    {
        "session_id",
        "model",
        "effort",
        "total_tokens",
        "tool_calls",
        "source_sha256",
        "runtime_report_sha256",
        "terminally_qualified",
    }
)
_ABORT_RECORD_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "grant_sha256",
        "registration_record_sha256",
        "reason_code",
        "authority_disposition",
        "observed_sessions",
        "attributable_sessions",
        "attributable_tokens",
        "grant_max_tokens",
        "overage_tokens",
        "campaign_cells_reserved",
        "campaign_started",
        "aborted_at_ms",
        "record_sha256",
    }
)
_OWNER_TERMINATION_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "authority_id",
        "authority_source_sha256",
        "reason_code",
        "environment",
        "limits",
        "material_risk",
        "recovery",
        "expected_canonical_ledger_sha256",
        "expected_shard_sha256s",
        "quarantined_completion",
    }
)
_OWNER_TERMINATION_ENVIRONMENT_FIELDS = frozenset(
    {"host_id", "runtime", "provider_free"}
)
_OWNER_TERMINATION_LIMIT_FIELDS = frozenset(
    {
        "qwen_calls",
        "model_calls",
        "hosted_calls",
        "additional_tokens",
        "new_reservations",
        "retries",
        "fallbacks",
        "replacements",
        "finalizer_invocations",
    }
)
_QUARANTINED_COMPLETION_FIELDS = frozenset(
    {
        "task_family",
        "configuration_id",
        "replicate_index",
        "seed",
        "request_sha256",
        "reservation_record_sha256",
        "completion_record_sha256",
        "bound_first_finisher_session_id",
        "observed_first_finisher_session_id",
        "observed_precedence_ms",
        "bound_custody_report_sha256",
        "corrected_custody_report_sha256",
        "bound_trace_report_sha256",
        "corrected_trace_report_sha256",
        "evidence_class",
    }
)
_OWNER_TERMINATION_COUNT_FIELDS = frozenset(
    {
        "expected_runs",
        "reserved_runs",
        "completed_runs",
        "failed_runs",
        "evidence_failure_runs",
        "quarantined_runs",
        "never_dispatched_runs",
        "missing_runs",
        "extrapolated_runs",
    }
)
_OWNER_TERMINATION_RECORD_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "grant_sha256",
        "start_record_sha256",
        "authority_id",
        "authority_source_sha256",
        "reason_code",
        "environment",
        "limits",
        "material_risk",
        "recovery",
        "canonical_ledger_sha256_before_termination",
        "shard_sha256s",
        "quarantined_completion",
        "original_deadline_at_ms",
        "terminated_at_ms",
        "early_termination",
        "state",
        "counts",
        "observed_tokens",
        "live_model_calls",
        "hosted_calls",
        "reportable",
        "training_eligible",
        "replay_decidable",
        "live_required",
        "record_sha256",
    }
)
_STOP_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "authority_id",
        "authority_source_sha256",
        "reason_code",
        "environment",
        "limits",
        "drain_evidence",
        "material_risk",
        "recovery",
        "expected_canonical_ledger_sha256",
        "expected_shard_sha256s",
    }
)
_STOP_LIMIT_FIELDS = frozenset(
    {
        "qwen_calls",
        "model_calls",
        "hosted_calls",
        "additional_tokens",
        "new_reservations",
        "retries",
        "fallbacks",
        "replacements",
        "stop_invocations",
    }
)
_STOP_DRAIN_FIELDS = frozenset(
    {
        "observed_at_ms",
        "campaign_worker_processes",
        "dispatcher_processes",
        "result_writer_processes",
        "codex_exec_processes",
        "qwen_running",
        "qwen_waiting",
        "qwen_capacity_blocked",
        "qwen_deferred",
        "active_worker_sessions",
        "pending_deliveries",
    }
)
_STOP_COUNT_FIELDS = frozenset(
    {
        "expected_runs",
        "reserved_runs",
        "completed_runs",
        "failed_runs",
        "never_dispatched_runs",
        "missing_runs",
        "extrapolated_runs",
    }
)
_STOP_COUNT_FIELDS_V2 = _STOP_COUNT_FIELDS | frozenset(
    {"settled_runs", "evidence_failure_runs", "malformed_runs"}
)
_STOP_RECORD_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "grant_sha256",
        "start_record_sha256",
        "authority_id",
        "authority_source_sha256",
        "reason_code",
        "environment",
        "limits",
        "drain_evidence",
        "material_risk",
        "recovery",
        "canonical_ledger_sha256_before_stop",
        "shard_sha256s",
        "original_deadline_at_ms",
        "stopped_at_ms",
        "calendar_wait_required",
        "state",
        "counts",
        "observed_tokens",
        "live_model_calls",
        "hosted_calls",
        "reportable",
        "training_eligible",
        "replay_decidable",
        "live_required",
        "record_sha256",
    }
)
_STOP_RECORD_FIELDS_V2 = _STOP_RECORD_FIELDS | frozenset(
    {
        "evidence_failure_record_sha256s",
        "evidence_failure_observed_tokens",
        "evidence_failure_lane_sessions",
        "evidence_failure_cause_counts",
        "well_formed_observed_tokens",
    }
)
_CANONICAL_REPLICATE_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "grant_sha256",
        "start_record_sha256",
        "task_family",
        "configuration_id",
        "configuration_sha256",
        "replicate_index",
        "seed",
        "live_request_sha256",
        "reservation_record_sha256",
        "completion_record_sha256",
        "outcome",
        "metric",
        "governed_report_sha256",
        "usage",
        "timing",
        "live_model_calls",
        "hosted_calls",
        "replay_model_call_record_sha256",
        "replay_decidable",
        "live_required",
        "record_sha256",
    }
)
_CANONICAL_REPLICATE_FIELDS_V2 = _CANONICAL_REPLICATE_FIELDS | frozenset(
    {"evidence_class"}
)
_FAMILY_SUMMARY_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "grant_sha256",
        "start_record_sha256",
        "task_family",
        "state",
        "counts",
        "configuration_results",
        "observed_tokens",
        "live_model_calls",
        "hosted_calls",
        "replay_decidable",
        "live_required",
        "joined_at_ms",
        "record_sha256",
    }
)
_FAMILY_SUMMARY_FIELDS_V2 = _FAMILY_SUMMARY_FIELDS | frozenset(
    {"well_formed_observed_tokens"}
)
_FAMILY_SUMMARY_FIELDS_V3 = _FAMILY_SUMMARY_FIELDS_V2 | frozenset(
    {
        "evidence_failure_record_sha256s",
        "evidence_failure_observed_tokens",
        "evidence_failure_lane_sessions",
        "evidence_failure_cause_counts",
        "reportable",
        "training_eligible",
    }
)
_JOIN_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "grant_sha256",
        "start_record_sha256",
        "state",
        "counts",
        "family_summary_record_sha256s",
        "canonical_replicate_record_sha256s",
        "replay_model_call_record_sha256s",
        "observed_tokens",
        "live_model_calls",
        "hosted_calls",
        "replay_decidable",
        "live_required",
        "joined_at_ms",
        "record_sha256",
    }
)
_JOIN_FIELDS_V2 = _JOIN_FIELDS | frozenset(
    {"well_formed_observed_tokens"}
)
_JOIN_FIELDS_V3 = _JOIN_FIELDS_V2 | frozenset(
    {
        "evidence_failure_record_sha256s",
        "evidence_failure_observed_tokens",
        "evidence_failure_lane_sessions",
        "evidence_failure_cause_counts",
        "reportable",
        "training_eligible",
    }
)

_REPLAY_DECIDABLE = ("verified_success_bps", "outcome")
_LIVE_REQUIRED = ("custody", "route", "timing", "token_usage")


def _canonical(value: Any) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hostile.canonicalize_bounded_json(raw, profile=PROFILE, batch=False)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _seal(core: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(core)
    return {**value, "record_sha256": _sha256(value)}


def _seal_valid(value: Any, field: str = "record_sha256") -> bool:
    if not isinstance(value, Mapping):
        return False
    core = dict(value)
    recorded = core.pop(field, None)
    try:
        return _sha_valid(recorded) and recorded == _sha256(core)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return False


def _sha_valid(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _integer(value: Any, *, minimum: int = 0) -> bool:
    return type(value) is int and value >= minimum


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _closed(
    value: Any, fields: frozenset[str], label: str, issues: list[str]
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, f"{label}:type_invalid")
        return {}
    result = dict(value)
    for field in sorted(fields - set(result)):
        _issue(issues, f"{label}:missing_field:{field}")
    for field in sorted(set(result) - fields):
        _issue(issues, f"{label}:unknown_field:{field}")
    return result


def _parameter_map(configuration: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    parameters = configuration.get("parameters")
    if not isinstance(parameters, list):
        return result
    for row in parameters:
        if isinstance(row, Mapping) and isinstance(row.get("name"), str):
            result[str(row["name"])] = row.get("value")
    return result


def build_issue111_campaign_draft() -> dict[str, Any]:
    """Return the fixed first-live-campaign preregistration material."""

    grid: list[dict[str, Any]] = []
    for family in ISSUE111_TASK_FAMILIES:
        for lane_count in ISSUE111_LANE_COUNTS:
            for cut_strategy in ISSUE111_CUT_STRATEGIES:
                configuration_id = f"{family}-n{lane_count}-{cut_strategy}"
                grid.append(
                    {
                        "configuration_id": configuration_id,
                        "parameters": [
                            {"name": "data_partition", "value": "training"},
                            {"name": "task_family", "value": family},
                            {
                                "name": "difficulty_bucket",
                                "value": "medium",
                            },
                            {"name": "lane_count", "value": lane_count},
                            {"name": "cut_strategy", "value": cut_strategy},
                            {"name": "capability_profile", "value": "qwen_smart"},
                            {"name": "stopping_margin_bps", "value": 0},
                        ],
                    }
                )
    return {
        "schema": campaign_contract.CAMPAIGN_DRAFT_SCHEMA,
        "campaign_id": "issue111-first-live-qwen-v1",
        "question": {
            "question_id": "issue111-wave-cut-family",
            "statement": (
                "How do first-wave lane count and cut strategy affect verified "
                "success across three Orch Dork task families?"
            ),
            "primary_metric": "verified_success_bps",
            "population": "sealed-local-qwen-orchestration-fixtures",
            "null_hypothesis": (
                "No preregistered configuration reaches the verified-success threshold."
            ),
        },
        "configuration_grid": grid,
        "replicate_count": 3,
        "seeds": list(ISSUE111_SEEDS),
        "decision_rule": {
            "metric": "verified_success_bps",
            "operator": "greater_than_or_equal",
            "threshold": {"numerator": 8_000, "denominator": 10_000},
            "minimum_complete_replicates": 3,
            "pass_disposition": "retain_default",
            "fail_disposition": "retain_default",
            "incomplete_disposition": "inconclusive",
        },
    }


def _workload_difficulty_bucket(
    bucket_name: str, buckets: Mapping[str, Mapping[str, Any]]
) -> str:
    """Map a workload bucket onto the closed low/medium/high difficulty set."""

    ordered = sorted(
        buckets, key=lambda name: int(buckets[name]["item_count"])
    )
    if len(ordered) == 1:
        return "medium"
    position = ordered.index(bucket_name)
    if position == 0:
        return "low"
    if position == len(ordered) - 1:
        return "high"
    return "medium"


def build_live_campaign_draft(axes: Any) -> dict[str, Any]:
    """Build a sealed-ready draft from explicit preregistration axes."""

    issues: list[str] = []
    value = _closed(axes, _AXES_FIELDS, "axes", issues)
    if value.get("schema") != CAMPAIGN_AXES_SCHEMA:
        _issue(issues, "axes:schema_invalid")
    if not _identifier(value.get("campaign_id")):
        _issue(issues, "axes:campaign_id_invalid")
    families = value.get("task_families")
    if (
        not isinstance(families, list)
        or not families
        or len(set(families)) != len(families)
        or any(family not in ISSUE111_TASK_FAMILIES for family in families)
    ):
        _issue(issues, "axes:task_families_invalid")
        families = []
    lane_counts = value.get("lane_counts")
    if (
        not isinstance(lane_counts, list)
        or not lane_counts
        or len(set(lane_counts)) != len(lane_counts)
        or any(
            type(count) is not int
            or count < LANE_COUNT_FLOOR
            or count > LANE_COUNT_CEILING
            for count in lane_counts
        )
    ):
        _issue(issues, "axes:lane_counts_invalid")
        lane_counts = []
    cut_strategies = value.get("cut_strategies")
    if (
        not isinstance(cut_strategies, list)
        or not cut_strategies
        or len(set(cut_strategies)) != len(cut_strategies)
        or any(cut not in ISSUE111_CUT_STRATEGIES for cut in cut_strategies)
    ):
        _issue(issues, "axes:cut_strategies_invalid")
        cut_strategies = []
    buckets = value.get("workload_buckets")
    normalized_buckets: dict[str, dict[str, int]] = {}
    if not isinstance(buckets, Mapping) or not buckets:
        _issue(issues, "axes:workload_buckets_invalid")
    else:
        for name in sorted(buckets):
            bucket = _closed(
                buckets[name],
                _WORKLOAD_BUCKET_FIELDS,
                f"axes.workload_buckets.{name}",
                issues,
            )
            item_count = bucket.get("item_count")
            density = bucket.get("coupling_density_bps")
            if (
                not _identifier(name)
                or type(item_count) is not int
                or item_count < WORKLOAD_ITEM_FLOOR
                or item_count > WORKLOAD_ITEM_CEILING
                or type(density) is not int
                or density < COUPLING_DENSITY_FLOOR_BPS
                or density > COUPLING_DENSITY_CEILING_BPS
            ):
                _issue(issues, f"axes.workload_buckets.{name}:invalid")
                continue
            normalized_buckets[str(name)] = {
                "item_count": item_count,
                "coupling_density_bps": density,
            }
        if not normalized_buckets:
            _issue(issues, "axes:workload_buckets_invalid")
    seeds = value.get("seeds")
    if (
        not isinstance(seeds, list)
        or not seeds
        or len(set(seeds)) != len(seeds)
        or any(type(seed) is not int or seed < 0 for seed in seeds)
    ):
        _issue(issues, "axes:seeds_invalid")
        seeds = []
    if issues:
        raise ValueError("invalid campaign axes: " + ",".join(sorted(set(issues))))
    grid: list[dict[str, Any]] = []
    for family in families:
        for bucket_name in sorted(normalized_buckets):
            bucket = normalized_buckets[bucket_name]
            for lane_count in lane_counts:
                cuts = (
                    [cut_strategies[0]] if lane_count == 1 else cut_strategies
                )
                for cut_strategy in cuts:
                    configuration_id = (
                        f"{family}-w{bucket_name}-n{lane_count}-{cut_strategy}"
                    )
                    grid.append(
                        {
                            "configuration_id": configuration_id,
                            "parameters": [
                                {"name": "data_partition", "value": "training"},
                                {"name": "task_family", "value": family},
                                {
                                    "name": "difficulty_bucket",
                                    "value": _workload_difficulty_bucket(
                                        bucket_name, normalized_buckets
                                    ),
                                },
                                {
                                    "name": "workload_bucket",
                                    "value": bucket_name,
                                },
                                {
                                    "name": "item_count",
                                    "value": bucket["item_count"],
                                },
                                {
                                    "name": "coupling_density_bps",
                                    "value": bucket["coupling_density_bps"],
                                },
                                {"name": "lane_count", "value": lane_count},
                                {"name": "cut_strategy", "value": cut_strategy},
                                {
                                    "name": "capability_profile",
                                    "value": "qwen_smart",
                                },
                                {"name": "stopping_margin_bps", "value": 0},
                            ],
                        }
                    )
    return {
        "schema": campaign_contract.CAMPAIGN_DRAFT_SCHEMA,
        "campaign_id": value["campaign_id"],
        "question": dict(value["question"]),
        "configuration_grid": grid,
        "replicate_count": len(seeds),
        "seeds": list(seeds),
        "decision_rule": dict(value["decision_rule"]),
    }


def expected_run_count(campaign: Mapping[str, Any]) -> int:
    grid = campaign.get("configuration_grid")
    seeds = campaign.get("seeds")
    if not isinstance(grid, list) or not isinstance(seeds, list):
        return 0
    return len(grid) * len(seeds)


def _campaign_families(campaign: Mapping[str, Any]) -> tuple[str, ...]:
    """Families actually present in the sealed grid, in canonical order."""

    present = {
        str(_parameter_map(row).get("task_family"))
        for row in campaign.get("configuration_grid", [])
        if isinstance(row, Mapping)
    }
    return tuple(
        family for family in ISSUE111_TASK_FAMILIES if family in present
    )


def _expected_families(
    campaign: Mapping[str, Any], issues: list[str]
) -> tuple[str, ...]:
    """Exact campaign families; an empty derivation is an issue, not a default."""

    families = _campaign_families(campaign)
    if not families:
        _issue(issues, "campaign:families_underivable")
    return families


def build_issue111_grant(
    campaign_sha256: str,
    *,
    authority_source_sha256: str,
) -> dict[str, Any]:
    """Build the exact human-approved Issue 111 grant and seal its identity."""

    core = {
        "schema": LIVE_GRANT_SCHEMA,
        "grant_id": "issue111-human-grant-20260823",
        "campaign_sha256": campaign_sha256,
        "max_runs": ISSUE111_MAX_RUNS,
        "max_tokens": ISSUE111_MAX_TOKENS,
        "max_wall_time_ms": ISSUE111_MAX_WALL_TIME_MS,
        "reserved_tokens_per_run": ISSUE111_RESERVED_TOKENS_PER_RUN,
        "family_allocations": [
            {
                "task_family": family,
                "max_runs": ISSUE111_FAMILY_RUNS,
                "max_tokens": ISSUE111_FAMILY_TOKENS,
            }
            for family in ISSUE111_TASK_FAMILIES
        ],
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "automatic_replacements": 0,
        "local_runtime": "qwen-local",
        "authority_source_sha256": authority_source_sha256,
    }
    return {**core, "grant_sha256": _sha256(core)}


def build_parameterized_live_grant(
    campaign: Any,
    *,
    max_tokens: int,
    max_wall_time_ms: int,
    reserved_tokens_per_lane_session: int,
    authority_source_sha256: str,
    grant_id: str = "issue113-parameterized-live-grant",
    attempt_id: str = "issue113-parameterized-live-attempt",
    standing_authority_binding: Any = None,
) -> dict[str, Any]:
    """Derive an explicit v4 or standing-authority v5 bounded grant."""

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        raise ValueError("invalid campaign")
    if not _sha_valid(authority_source_sha256):
        raise ValueError("invalid authority source digest")
    standing_binding = None
    if standing_authority_binding is not None:
        standing_binding = standing_authority.standing_owner_binding_material(
            standing_authority_binding
        )
        if (
            standing_binding is None
            or standing_binding["authority_source_sha256"]
            != authority_source_sha256
        ):
            raise ValueError("invalid standing authority binding")
    if not _integer(max_tokens, minimum=1) or not _integer(
        max_wall_time_ms, minimum=1
    ) or not _integer(reserved_tokens_per_lane_session, minimum=1):
        raise ValueError("invalid grant bounds")
    seed_count = len(campaign.get("seeds", []))
    family_runs: dict[str, int] = {}
    family_tokens: dict[str, int] = {}
    for configuration in campaign.get("configuration_grid", []):
        parameters = _parameter_map(configuration)
        family = str(parameters.get("task_family"))
        lane_count = parameters.get("lane_count")
        if type(lane_count) is not int:
            raise ValueError("invalid campaign lane count")
        family_runs[family] = family_runs.get(family, 0) + seed_count
        family_tokens[family] = (
            family_tokens.get(family, 0)
            + seed_count * lane_count * reserved_tokens_per_lane_session
        )
    families = list(_campaign_families(campaign)) or sorted(family_runs)
    core = {
        "schema": (
            LIVE_GRANT_SCHEMA_V5
            if standing_binding is not None
            else LIVE_GRANT_SCHEMA_V4
        ),
        "grant_id": grant_id,
        "attempt_id": attempt_id,
        "campaign_sha256": campaign["campaign_sha256"],
        "max_runs": expected_run_count(campaign),
        "max_tokens": max_tokens,
        "max_wall_time_ms": max_wall_time_ms,
        "reserved_tokens_per_lane_session": reserved_tokens_per_lane_session,
        "family_allocations": [
            {
                "task_family": family,
                "max_runs": family_runs[family],
                "max_tokens": family_tokens[family],
            }
            for family in families
        ],
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "automatic_replacements": 0,
        "hosted_calls": 0,
        "local_runtime": "qwen-local",
        "execution_environment": _issue111_successor_execution_environment(),
        "attribution": _issue111_measurement_successor_attribution(),
        "risk": _issue111_successor_risk(),
        "recovery": _issue111_measurement_successor_recovery(),
        "finalization": _issue111_measurement_successor_finalization(),
        "authority_source_sha256": authority_source_sha256,
    }
    if standing_binding is not None:
        core["standing_authority"] = standing_binding
    return {**core, "grant_sha256": _sha256(core)}


def _issue111_successor_execution_environment() -> dict[str, Any]:
    return {
        "host_id": "jwj-lab",
        "runtime": "qwen-local",
        "model": "qwen-local/qwen-smart",
        "effort": "xhigh",
        "context_policy": "none",
        "inherited_history": False,
        "wall_time_origin": "first_reserved_dispatch",
    }


def _issue111_successor_attribution() -> dict[str, Any]:
    return {
        "scope": "successor_campaign_execution_only",
        "additional_tokens_only": True,
        "preparation_sessions": 0,
        "review_sessions": 0,
    }


def _issue111_successor_risk() -> dict[str, str]:
    return {
        "primary": "local_qwen_token_or_wall_limit_exhaustion_before_36_cells",
        "mitigation": "permanent_lane_weighted_reservation_and_fail_closed_stop",
    }


def _issue111_successor_recovery() -> dict[str, str]:
    return {
        "rollback": "not_applicable_append_only_authority",
        "on_failure": "stop_preserve_partial_ledger_and_require_new_authority",
    }


def _issue111_measurement_successor_attribution() -> dict[str, Any]:
    return {
        "scope": "fresh_measurement_successor_campaign_execution_only",
        "additional_tokens_only": True,
        "preparation_sessions": 0,
        "review_sessions": 0,
    }


def _issue111_measurement_successor_recovery() -> dict[str, str]:
    return {
        "rollback": "not_applicable_append_only_authority",
        "on_failure": "immediate_terminal_stop_after_drain_no_calendar_wait",
    }


def _issue111_measurement_successor_finalization() -> dict[str, Any]:
    return {
        "wall_time_role": "execution_ceiling_only",
        "calendar_wait_required": False,
        "completion_proof": "terminal_ledger_and_drained_producers",
        "early_stop": "immediate_after_drain",
    }


def build_issue111_successor_grant(
    campaign: Any,
    predecessor_ledger_path: str | Path,
    *,
    authority_source_sha256: str,
) -> dict[str, Any]:
    """Build the exact renewed grant from one validated aborted predecessor."""

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        raise ValueError("invalid Issue 111 campaign")
    issues: list[str] = []
    predecessor = _predecessor_binding(campaign, predecessor_ledger_path, issues)
    if issues or predecessor is None:
        raise ValueError("invalid Issue 111 predecessor: " + ",".join(issues))
    if not _sha_valid(authority_source_sha256):
        raise ValueError("invalid authority source digest")
    core = {
        "schema": LIVE_GRANT_SCHEMA_V2,
        "grant_id": ISSUE111_SUCCESSOR_GRANT_ID,
        "attempt_id": ISSUE111_SUCCESSOR_ATTEMPT_ID,
        "campaign_sha256": campaign["campaign_sha256"],
        "max_runs": ISSUE111_MAX_RUNS,
        "max_tokens": ISSUE111_SUCCESSOR_MAX_TOKENS,
        "max_wall_time_ms": ISSUE111_MAX_WALL_TIME_MS,
        "reserved_tokens_per_lane_session": (
            ISSUE111_SUCCESSOR_RESERVED_TOKENS_PER_LANE_SESSION
        ),
        "family_allocations": [
            {
                "task_family": family,
                "max_runs": ISSUE111_FAMILY_RUNS,
                "max_tokens": ISSUE111_SUCCESSOR_FAMILY_TOKENS,
            }
            for family in ISSUE111_TASK_FAMILIES
        ],
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "automatic_replacements": 0,
        "hosted_calls": 0,
        "local_runtime": "qwen-local",
        "execution_environment": _issue111_successor_execution_environment(),
        "attribution": _issue111_successor_attribution(),
        "risk": _issue111_successor_risk(),
        "recovery": _issue111_successor_recovery(),
        "predecessor": predecessor,
        "authority_source_sha256": authority_source_sha256,
    }
    return {**core, "grant_sha256": _sha256(core)}


def build_issue111_measurement_successor_grant(
    campaign: Any,
    predecessor_ledger_path: str | Path,
    predecessor_shard_paths: Mapping[str, str | Path],
    *,
    authority_source_sha256: str,
) -> dict[str, Any]:
    """Build the exact 90-minute grant from the terminated v2 attempt."""

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        raise ValueError("invalid Issue 111 campaign")
    issues: list[str] = []
    predecessor = _terminated_successor_binding(
        campaign,
        predecessor_ledger_path,
        predecessor_shard_paths,
        issues,
    )
    if issues or predecessor is None:
        raise ValueError("invalid terminated Issue 111 predecessor: " + ",".join(issues))
    if not _sha_valid(authority_source_sha256):
        raise ValueError("invalid authority source digest")
    core = {
        "schema": LIVE_GRANT_SCHEMA_V3,
        "grant_id": ISSUE111_MEASUREMENT_SUCCESSOR_GRANT_ID,
        "attempt_id": ISSUE111_MEASUREMENT_SUCCESSOR_ATTEMPT_ID,
        "campaign_sha256": campaign["campaign_sha256"],
        "max_runs": ISSUE111_MAX_RUNS,
        "max_tokens": ISSUE111_SUCCESSOR_MAX_TOKENS,
        "max_wall_time_ms": ISSUE111_MEASUREMENT_SUCCESSOR_MAX_WALL_TIME_MS,
        "reserved_tokens_per_lane_session": (
            ISSUE111_SUCCESSOR_RESERVED_TOKENS_PER_LANE_SESSION
        ),
        "family_allocations": [
            {
                "task_family": family,
                "max_runs": ISSUE111_FAMILY_RUNS,
                "max_tokens": ISSUE111_SUCCESSOR_FAMILY_TOKENS,
            }
            for family in ISSUE111_TASK_FAMILIES
        ],
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "automatic_replacements": 0,
        "hosted_calls": 0,
        "local_runtime": "qwen-local",
        "execution_environment": _issue111_successor_execution_environment(),
        "attribution": _issue111_measurement_successor_attribution(),
        "risk": _issue111_successor_risk(),
        "recovery": _issue111_measurement_successor_recovery(),
        "finalization": _issue111_measurement_successor_finalization(),
        "predecessor": predecessor,
        "authority_source_sha256": authority_source_sha256,
    }
    return {**core, "grant_sha256": _sha256(core)}


def build_issue111_replay_plan(campaign: Any) -> dict[str, Any]:
    """Seal the exact pre-call replay policy for aggregate campaign cells."""

    policy_report = record_replay.seal_score_policy(
        {
            "schema": record_replay.SCORE_POLICY_DRAFT_SCHEMA,
            "policy_id": "issue111-verified-success",
            "terms": [
                {
                    "path": ["score"],
                    "weight": {"numerator": 1, "denominator": 1},
                }
            ],
            "intercept": {"numerator": 0, "denominator": 1},
        }
    )
    if policy_report.get("status") != "PASS":
        raise ValueError("could not seal Issue 111 replay score policy")
    plan_report = record_replay.seal_replay_plan(
        campaign,
        {
            "schema": record_replay.REPLAY_PLAN_DRAFT_SCHEMA,
            "plan_id": "issue111-first-live-replay-plan",
            "campaign_sha256": (
                campaign.get("campaign_sha256")
                if isinstance(campaign, Mapping)
                else None
            ),
            "baseline_policy": policy_report["score_policy"],
            "holdout_tolerance": {"numerator": 1, "denominator": 20},
        },
    )
    if plan_report.get("status") != "PASS":
        raise ValueError("could not seal Issue 111 replay plan")
    return plan_report["replay_plan"]


def _reservation_tokens_for_lane_count(
    grant: Mapping[str, Any], lane_count: Any
) -> int | None:
    if grant.get("schema") == LIVE_GRANT_SCHEMA_V1:
        value = grant.get("reserved_tokens_per_run")
        return value if _integer(value, minimum=1) else None
    if grant.get("schema") in {
        LIVE_GRANT_SCHEMA_V2,
        LIVE_GRANT_SCHEMA_V3,
        LIVE_GRANT_SCHEMA_V4,
        LIVE_GRANT_SCHEMA_V5,
    }:
        per_lane = grant.get("reserved_tokens_per_lane_session")
        if _integer(per_lane, minimum=1) and _integer(lane_count, minimum=1):
            return int(per_lane) * int(lane_count)
    return None


def _campaign_reservation_totals(
    campaign: Mapping[str, Any], grant: Mapping[str, Any]
) -> tuple[int, dict[str, int], dict[str, int]]:
    totals_issues: list[str] = []
    families = _expected_families(campaign, totals_issues)
    family_tokens = {family: 0 for family in families}
    family_runs = {family: 0 for family in families}
    total = 0
    seed_count = len(campaign.get("seeds", []))
    for configuration in campaign.get("configuration_grid", []):
        parameters = _parameter_map(configuration)
        family = parameters.get("task_family")
        reserved = _reservation_tokens_for_lane_count(
            grant, parameters.get("lane_count")
        )
        if family not in family_tokens or reserved is None:
            continue
        charged = reserved * seed_count
        family_tokens[str(family)] += charged
        family_runs[str(family)] += seed_count
        total += charged
    return total, family_tokens, family_runs


def _validate_successor_nested_fields(
    campaign: Mapping[str, Any], grant: Mapping[str, Any], issues: list[str]
) -> None:
    if grant.get("schema") in {LIVE_GRANT_SCHEMA_V4, LIVE_GRANT_SCHEMA_V5}:
        return
    measurement_successor = grant.get("schema") == LIVE_GRANT_SCHEMA_V3
    predecessor = _closed(
        grant.get("predecessor"),
        (
            _TERMINATED_PREDECESSOR_FIELDS
            if measurement_successor
            else _PREDECESSOR_FIELDS
        ),
        "grant.predecessor",
        issues,
    )
    expected_state = (
        "INCOMPLETE_EVIDENCE_FAILURE" if measurement_successor else "ABORTED"
    )
    if predecessor.get("state") != expected_state:
        _issue(issues, "grant.predecessor:state_invalid")
    if predecessor.get("campaign_sha256") != campaign.get("campaign_sha256"):
        _issue(issues, "grant.predecessor:campaign_mismatch")
    digest_fields = (
        (
            "grant_sha256",
            "registration_record_sha256",
            "replay_plan_sha256",
            "replay_plan_record_sha256",
            "start_record_sha256",
            "termination_record_sha256",
            "termination_report_sha256",
            "ledger_sha256",
            "ledger_path_sha256",
        )
        if measurement_successor
        else (
            "grant_sha256",
            "registration_record_sha256",
            "replay_plan_sha256",
            "replay_plan_record_sha256",
            "abort_record_sha256",
            "ledger_sha256",
            "ledger_path_sha256",
        )
    )
    for field in digest_fields:
        if not _sha_valid(predecessor.get(field)):
            _issue(issues, f"grant.predecessor:{field}_invalid")
    if measurement_successor:
        for field in ("shard_sha256s", "shard_path_sha256s"):
            values = predecessor.get(field)
            if (
                not isinstance(values, Mapping)
                or set(values) != set(ISSUE111_TASK_FAMILIES)
                or any(not _sha_valid(value) for value in values.values())
            ):
                _issue(issues, f"grant.predecessor:{field}_invalid")
        if predecessor.get("counts") != {
            "expected_runs": 36,
            "reserved_runs": 1,
            "completed_runs": 0,
            "failed_runs": 0,
            "evidence_failure_runs": 1,
            "quarantined_runs": 1,
            "never_dispatched_runs": 35,
            "missing_runs": 36,
            "extrapolated_runs": 0,
        }:
            _issue(issues, "grant.predecessor:counts_invalid")
        if not _integer(predecessor.get("observed_tokens"), minimum=0):
            _issue(issues, "grant.predecessor:observed_tokens_invalid")
        if predecessor.get("live_model_calls") != 2:
            _issue(issues, "grant.predecessor:live_model_calls_invalid")
    else:
        if (
            predecessor.get("attributable_tokens")
            != ISSUE111_PREDECESSOR_ATTRIBUTABLE_TOKENS
        ):
            _issue(issues, "grant.predecessor:attributable_tokens_invalid")
        if predecessor.get("overage_tokens") != ISSUE111_PREDECESSOR_OVERAGE_TOKENS:
            _issue(issues, "grant.predecessor:overage_tokens_invalid")
        if predecessor.get("campaign_cells_reserved") != 0:
            _issue(issues, "grant.predecessor:reserved_cells_invalid")
        if predecessor.get("campaign_started") is not False:
            _issue(issues, "grant.predecessor:campaign_started_invalid")
    nested = (
        (
            "execution_environment",
            _EXECUTION_ENVIRONMENT_FIELDS,
            _issue111_successor_execution_environment(),
        ),
        (
            "attribution",
            _ATTRIBUTION_FIELDS,
            (
                _issue111_measurement_successor_attribution()
                if measurement_successor
                else _issue111_successor_attribution()
            ),
        ),
        ("risk", _RISK_FIELDS, _issue111_successor_risk()),
        (
            "recovery",
            _RECOVERY_FIELDS,
            (
                _issue111_measurement_successor_recovery()
                if measurement_successor
                else _issue111_successor_recovery()
            ),
        ),
    )
    for name, fields, expected in nested:
        normalized = _closed(grant.get(name), fields, f"grant.{name}", issues)
        if normalized != expected:
            _issue(issues, f"grant:{name}_invalid")
    if measurement_successor:
        finalization = _closed(
            grant.get("finalization"),
            _FINALIZATION_FIELDS,
            "grant.finalization",
            issues,
        )
        if finalization != _issue111_measurement_successor_finalization():
            _issue(issues, "grant:finalization_invalid")


def _validate_parameterized_nested_fields(
    grant: Mapping[str, Any], issues: list[str]
) -> None:
    environment = _closed(
        grant.get("execution_environment"),
        frozenset(
            {
                "host_id",
                "runtime",
                "model",
                "effort",
                "context_policy",
                "inherited_history",
                "wall_time_origin",
            }
        ),
        "grant.execution_environment",
        issues,
    )
    if environment != _issue111_successor_execution_environment():
        _issue(issues, "grant.execution_environment:invalid")
    if grant.get("attribution") != _issue111_measurement_successor_attribution():
        _issue(issues, "grant.attribution:invalid")
    if grant.get("risk") != _issue111_successor_risk():
        _issue(issues, "grant.risk:invalid")
    if grant.get("recovery") != _issue111_measurement_successor_recovery():
        _issue(issues, "grant.recovery:invalid")
    if grant.get("finalization") != _issue111_measurement_successor_finalization():
        _issue(issues, "grant.finalization:invalid")


def _grant_material(
    campaign: Mapping[str, Any], value: Any, issues: list[str]
) -> dict[str, Any]:
    raw_schema = value.get("schema") if isinstance(value, Mapping) else None
    fields = (
        _GRANT_FIELDS_V5
        if raw_schema == LIVE_GRANT_SCHEMA_V5
        else _GRANT_FIELDS_V4
        if raw_schema == LIVE_GRANT_SCHEMA_V4
        else _GRANT_FIELDS_V3
        if raw_schema == LIVE_GRANT_SCHEMA_V3
        else _GRANT_FIELDS_V2
        if raw_schema == LIVE_GRANT_SCHEMA_V2
        else _GRANT_FIELDS_V1
    )
    grant = _closed(value, fields, "grant", issues)
    if grant.get("schema") not in {
        LIVE_GRANT_SCHEMA_V1,
        LIVE_GRANT_SCHEMA_V2,
        LIVE_GRANT_SCHEMA_V3,
        LIVE_GRANT_SCHEMA_V4,
        LIVE_GRANT_SCHEMA_V5,
    }:
        _issue(issues, "grant:schema_invalid")
    successor = grant.get("schema") in {
        LIVE_GRANT_SCHEMA_V2,
        LIVE_GRANT_SCHEMA_V3,
        LIVE_GRANT_SCHEMA_V4,
        LIVE_GRANT_SCHEMA_V5,
    }
    measurement_successor = grant.get("schema") == LIVE_GRANT_SCHEMA_V3
    parameterized = grant.get("schema") in {
        LIVE_GRANT_SCHEMA_V4,
        LIVE_GRANT_SCHEMA_V5,
    }
    if not _identifier(grant.get("grant_id")):
        _issue(issues, "grant:grant_id_invalid")
    if successor and not _identifier(grant.get("attempt_id")):
        _issue(issues, "grant:attempt_id_invalid")
    if grant.get("campaign_sha256") != campaign.get("campaign_sha256"):
        _issue(issues, "grant:campaign_mismatch")
    reservation_field = (
        "reserved_tokens_per_lane_session"
        if successor
        else "reserved_tokens_per_run"
    )
    for field in (
        "max_runs",
        "max_tokens",
        "max_wall_time_ms",
        reservation_field,
    ):
        if not _integer(grant.get(field), minimum=1):
            _issue(issues, f"grant:{field}_invalid")
    run_count = expected_run_count(campaign)
    if _integer(grant.get("max_runs"), minimum=1) and grant["max_runs"] < run_count:
        _issue(issues, "grant:run_limit_below_campaign")
    total_reserved, family_tokens, family_runs = _campaign_reservation_totals(
        campaign, grant
    )
    if (
        _integer(grant.get("max_tokens"), minimum=1)
        and total_reserved > grant["max_tokens"]
    ):
        _issue(issues, "grant:token_reservation_exceeds_limit")
    for field in (
        "automatic_retries",
        "automatic_fallbacks",
        "automatic_replacements",
    ):
        if grant.get(field) != 0 or type(grant.get(field)) is not int:
            _issue(issues, f"grant:{field}_must_be_zero")
    if successor and (grant.get("hosted_calls") != 0 or type(grant.get("hosted_calls")) is not int):
        _issue(issues, "grant:hosted_calls_must_be_zero")
    if grant.get("local_runtime") != "qwen-local":
        _issue(issues, "grant:runtime_invalid")
    if not _sha_valid(grant.get("authority_source_sha256")):
        _issue(issues, "grant:authority_source_sha256_invalid")
    if grant.get("schema") == LIVE_GRANT_SCHEMA_V5:
        standing_binding = standing_authority.standing_owner_binding_material(
            grant.get("standing_authority")
        )
        if standing_binding is None:
            _issue(issues, "grant:standing_authority_invalid")
        elif (
            standing_binding["authority_source_sha256"]
            != grant.get("authority_source_sha256")
        ):
            _issue(issues, "grant:standing_authority_source_mismatch")
    allocations = grant.get("family_allocations")
    campaign_families = _expected_families(campaign, issues)
    if not isinstance(allocations, list) or len(allocations) != len(
        campaign_families
    ):
        _issue(issues, "grant:family_allocations_invalid")
        allocations = []
    normalized_allocations: list[dict[str, Any]] = []
    for index, raw in enumerate(allocations):
        allocation = _closed(
            raw, _ALLOCATION_FIELDS, f"grant.family_allocations[{index}]", issues
        )
        family = allocation.get("task_family")
        if family not in campaign_families:
            _issue(issues, f"grant.family_allocations[{index}]:family_invalid")
        for field in ("max_runs", "max_tokens"):
            if not _integer(allocation.get(field), minimum=1):
                _issue(issues, f"grant.family_allocations[{index}]:{field}_invalid")
        normalized_allocations.append(dict(allocation))
    if [row.get("task_family") for row in normalized_allocations] != list(
        campaign_families
    ):
        _issue(issues, "grant:family_allocation_order_invalid")
    for allocation in normalized_allocations:
        family = allocation.get("task_family")
        if (
            family in family_runs
            and type(allocation.get("max_runs")) is int
            and allocation["max_runs"] < family_runs[family]
        ):
            _issue(issues, f"grant:family_run_limit_below_campaign:{family}")
        if (
            family in family_tokens
            and type(allocation.get("max_tokens")) is int
            and allocation["max_tokens"] < family_tokens[family]
        ):
            _issue(issues, f"grant:family_token_limit_below_campaign:{family}")
    if parameterized:
        _validate_parameterized_nested_fields(grant, issues)
        run_total = expected_run_count(campaign)
        if grant.get("max_runs") != run_total:
            _issue(issues, "grant:run_limit_not_exact")
        expected_allocations = [
            {
                "task_family": family,
                "max_runs": family_runs.get(family, 0),
                "max_tokens": family_tokens.get(family, 0),
            }
            for family in campaign_families
        ]
        if normalized_allocations != expected_allocations:
            _issue(issues, "grant:family_allocations_not_exact")
        exact_authority = {}
        issue = "grant:parameterized_authority_invalid"
    elif successor:
        _validate_successor_nested_fields(campaign, grant, issues)
        exact_authority = {
            "grant_id": ISSUE111_SUCCESSOR_GRANT_ID,
            "attempt_id": ISSUE111_SUCCESSOR_ATTEMPT_ID,
            "max_runs": ISSUE111_MAX_RUNS,
            "max_tokens": ISSUE111_SUCCESSOR_MAX_TOKENS,
            "max_wall_time_ms": ISSUE111_MAX_WALL_TIME_MS,
            "reserved_tokens_per_lane_session": (
                ISSUE111_SUCCESSOR_RESERVED_TOKENS_PER_LANE_SESSION
            ),
            "family_allocations": [
                {
                    "task_family": family,
                    "max_runs": ISSUE111_FAMILY_RUNS,
                    "max_tokens": ISSUE111_SUCCESSOR_FAMILY_TOKENS,
                }
                for family in ISSUE111_TASK_FAMILIES
            ],
            "automatic_retries": 0,
            "automatic_fallbacks": 0,
            "automatic_replacements": 0,
            "hosted_calls": 0,
            "local_runtime": "qwen-local",
        }
        issue = "grant:not_exact_issue111_successor_authority"
        if measurement_successor:
            exact_authority.update(
                {
                    "grant_id": ISSUE111_MEASUREMENT_SUCCESSOR_GRANT_ID,
                    "attempt_id": ISSUE111_MEASUREMENT_SUCCESSOR_ATTEMPT_ID,
                    "max_wall_time_ms": (
                        ISSUE111_MEASUREMENT_SUCCESSOR_MAX_WALL_TIME_MS
                    ),
                }
            )
            issue = "grant:not_exact_issue111_measurement_successor_authority"
    else:
        exact_authority = {
            "grant_id": "issue111-human-grant-20260823",
            "max_runs": ISSUE111_MAX_RUNS,
            "max_tokens": ISSUE111_MAX_TOKENS,
            "max_wall_time_ms": ISSUE111_MAX_WALL_TIME_MS,
            "reserved_tokens_per_run": ISSUE111_RESERVED_TOKENS_PER_RUN,
            "family_allocations": [
                {
                    "task_family": family,
                    "max_runs": ISSUE111_FAMILY_RUNS,
                    "max_tokens": ISSUE111_FAMILY_TOKENS,
                }
                for family in ISSUE111_TASK_FAMILIES
            ],
            "automatic_retries": 0,
            "automatic_fallbacks": 0,
            "automatic_replacements": 0,
            "local_runtime": "qwen-local",
        }
        issue = "grant:not_exact_issue111_authority"
    if any(grant.get(field) != expected for field, expected in exact_authority.items()):
        _issue(issues, issue)
    recorded = grant.get("grant_sha256")
    core = {key: grant.get(key) for key in fields if key != "grant_sha256"}
    if not _sha_valid(recorded) or recorded != _sha256(core):
        _issue(issues, "grant:seal_mismatch")
    return dict(grant)


def _append(path: str | Path, record: Mapping[str, Any]) -> dict[str, Any] | None:
    try:
        receipt = trace.append_trace_record(path, record)
    except (OSError, TypeError, ValueError):
        return None
    return receipt if receipt.get("status") == "PASS" else None


def _entries(path: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    return sweep.read_experiment_ledger(path)


def _base_report(
    *,
    status: str,
    state: str,
    issues: list[str],
    campaign_sha256: str | None,
    **extra: Any,
) -> dict[str, Any]:
    core = {
        "schema": LIVE_REPORT_SCHEMA,
        "status": status,
        "state": state,
        "issues": sorted(set(issues)),
        "campaign_sha256": campaign_sha256,
        **extra,
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "automatic_replacements": 0,
        "provider_free_operation": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "default_changed": False,
    }
    if status == "FAIL":
        # C10: report-only refusal-tier annotation on refusals.  PASS
        # reports and every stored ledger record never carry it, so
        # historical projections stay byte-identical.
        core["refusal_tiers"] = refusal_tiers.annotate_refusal_tiers(
            core["issues"]
        )
    return {**core, "report_sha256": _sha256(core)}


def _campaign_registration(
    entries: list[Mapping[str, Any]], campaign_sha256: str
) -> Mapping[str, Any] | None:
    rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema") == LIVE_CAMPAIGN_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == campaign_sha256
    ]
    return rows[0] if len(rows) == 1 else None


def _campaign_start(
    entries: list[Mapping[str, Any]], campaign_sha256: str
) -> Mapping[str, Any] | None:
    rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema") == LIVE_START_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == campaign_sha256
    ]
    return rows[0] if len(rows) == 1 else None


def _campaign_abort(
    entries: list[Mapping[str, Any]], campaign_sha256: str
) -> Mapping[str, Any] | None:
    rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema") == LIVE_ABORT_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == campaign_sha256
    ]
    return rows[0] if len(rows) == 1 else None


def _campaign_owner_termination(
    entries: list[Mapping[str, Any]], campaign_sha256: str
) -> Mapping[str, Any] | None:
    rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema")
        == LIVE_OWNER_TERMINATION_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == campaign_sha256
    ]
    return rows[0] if len(rows) == 1 else None


def _campaign_stop(
    entries: list[Mapping[str, Any]], campaign_sha256: str
) -> Mapping[str, Any] | None:
    rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema")
        in _LIVE_STOP_RECORD_SCHEMAS
        and row.get("record", {}).get("campaign_sha256") == campaign_sha256
    ]
    return rows[0] if len(rows) == 1 else None


def _consult_campaign_fences(
    entries: list[Mapping[str, Any]],
    campaign_sha256: str,
    issues: list[str],
    *,
    stop_code: str | None = None,
    termination_code: str | None = None,
    join_code: str | None = None,
) -> None:
    """Consult the campaign-terminal fences under one shared refusal seam.

    Fences are one-way: the settled stop, owner-termination, and join
    records are themselves the fences, and clearance only comes from fresh
    admission under a new grant.  Each caller names the exact stable code
    it already refuses under.  A None code preserves a seam's historical
    contract exactly (owner termination never consulted the stop fence),
    never a new exemption.
    """

    if join_code is not None and any(
        row.get("record", {}).get("schema") in _LIVE_JOIN_RECORD_SCHEMAS
        and row.get("record", {}).get("campaign_sha256") == campaign_sha256
        for row in entries
    ):
        _issue(issues, join_code)
    if (
        termination_code is not None
        and _campaign_owner_termination(entries, campaign_sha256) is not None
    ):
        _issue(issues, termination_code)
    if stop_code is not None and _campaign_stop(entries, campaign_sha256) is not None:
        _issue(issues, stop_code)


def _read_ledger_bytes(path: str | Path) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError:
        return b""


def _verify_head_expectations(
    canonical_ledger_path: str | Path,
    shard_path: str | Path,
    expected_canonical_ledger_sha256: Any,
    expected_shard_sha256: Any,
    label: str,
    issues: list[str],
) -> dict[str, str]:
    """Re-observe the two settlement ledger heads against caller expectations.

    Optional by construction: omitted expectations perform no read and
    leave every existing report byte-identical.  A supplied expectation is
    re-observed from the live bytes at this seam and a stale head refuses
    fail-closed under the caller's stable code family.
    """

    facts: dict[str, str] = {}
    for expected, path, key, code in (
        (
            expected_canonical_ledger_sha256,
            canonical_ledger_path,
            "canonical_ledger_sha256",
            f"{label}:canonical_head_mismatch",
        ),
        (
            expected_shard_sha256,
            shard_path,
            "shard_sha256",
            f"{label}:shard_head_mismatch",
        ),
    ):
        if expected is None:
            continue
        if not _sha_valid(expected):
            _issue(issues, f"{label}:head_expectation_invalid")
            continue
        observed = hashlib.sha256(_read_ledger_bytes(path)).hexdigest()
        if observed != expected:
            _issue(issues, code)
        else:
            facts[key] = observed
    return facts


def derive_campaign_fences(
    ledger_path: str | Path, campaign_sha256: str
) -> dict[str, Any]:
    """Project one campaign's terminal fences from the canonical ledger alone.

    Report-only: reads the same records the settlement seams consult and
    returns closed fence facts (kind, record digest, timestamp, reason
    code where the record carries one) with the observed ledger head.  It
    appends nothing and grants nothing.
    """

    canonical_sha256 = hashlib.sha256(_read_ledger_bytes(ledger_path)).hexdigest()
    entries, issues = _entries(ledger_path)
    if not _sha_valid(campaign_sha256):
        _issue(issues, "fences:campaign_sha256_invalid")
    if issues:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=(
                campaign_sha256 if _sha_valid(campaign_sha256) else None
            ),
        )
    fences: list[dict[str, Any]] = []
    for row in entries:
        record = row.get("record", {})
        if record.get("campaign_sha256") != campaign_sha256:
            continue
        schema = record.get("schema")
        if schema == LIVE_ABORT_RECORD_SCHEMA:
            kind, timestamp_field = "abort", "aborted_at_ms"
        elif schema == LIVE_OWNER_TERMINATION_RECORD_SCHEMA:
            kind, timestamp_field = "owner_termination", "terminated_at_ms"
        elif schema in _LIVE_STOP_RECORD_SCHEMAS:
            kind, timestamp_field = "stop", "stopped_at_ms"
        elif schema in _LIVE_JOIN_RECORD_SCHEMAS:
            kind, timestamp_field = "join", "joined_at_ms"
        else:
            continue
        fences.append(
            {
                "kind": kind,
                "record_sha256": record.get("record_sha256"),
                "fenced_at_ms": record.get(timestamp_field),
                "reason_code": record.get("reason_code"),
            }
        )
    return _base_report(
        status="PASS",
        state="FENCED" if fences else "OPEN",
        issues=[],
        campaign_sha256=campaign_sha256,
        fenced=bool(fences),
        fences=fences,
        canonical_ledger_sha256=canonical_sha256,
    )


LIVE_GRANT_SHAPE_SCHEMA = "orch-dork/live-grant-shape/v1"


def derive_grant_shape(campaign: Any, grant: Any) -> dict[str, Any]:
    """Seal the exact closed authority tuple one campaign grant carries (C5).

    A shape is a closed derived record over an already-validated
    grant/campaign pair: sealed limits, derived reservation totals,
    unreserved headroom, the campaign risk facts, and the zeroed
    retry/fallback/replacement/hosted posture.  It grants nothing itself
    (anything not in the shape stays impossible) and no grant schema
    widening of v1-v4 occurs; standing authority uses additive v5.
    """

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        issues = [
            str(item)
            if str(item).startswith("campaign:")
            else "campaign:" + str(item)
            for item in verified.get("issues", [])
        ] or ["campaign:invalid"]
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=(
                campaign.get("campaign_sha256")
                if isinstance(campaign, Mapping)
                else None
            ),
        )
    issues: list[str] = []
    grant_value = _grant_material(campaign, grant, issues)
    if issues:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=str(campaign.get("campaign_sha256")),
        )
    successor = grant_value.get("schema") in {
        LIVE_GRANT_SCHEMA_V2,
        LIVE_GRANT_SCHEMA_V3,
        LIVE_GRANT_SCHEMA_V4,
        LIVE_GRANT_SCHEMA_V5,
    }
    reservation_field = (
        "reserved_tokens_per_lane_session"
        if successor
        else "reserved_tokens_per_run"
    )
    total_reserved, family_tokens, family_runs = _campaign_reservation_totals(
        campaign, grant_value
    )
    families = _campaign_families(campaign)
    core = {
        "schema": LIVE_GRANT_SHAPE_SCHEMA,
        "campaign_sha256": campaign["campaign_sha256"],
        "grant_sha256": grant_value["grant_sha256"],
        "grant_schema": grant_value["schema"],
        "grant_id": grant_value["grant_id"],
        "task_families": list(families),
        "seed_count": len(campaign.get("seeds", [])),
        "configuration_count": len(campaign.get("configuration_grid", [])),
        "expected_runs": expected_run_count(campaign),
        "max_runs": grant_value["max_runs"],
        "max_tokens": grant_value["max_tokens"],
        "max_wall_time_ms": grant_value["max_wall_time_ms"],
        "reservation_field": reservation_field,
        "reservation_tokens": grant_value[reservation_field],
        "reserved_token_total": total_reserved,
        "unreserved_tokens": grant_value["max_tokens"] - total_reserved,
        "family_allocations": [
            {
                "task_family": family,
                "max_runs": family_runs.get(family, 0),
                "max_tokens": family_tokens.get(family, 0),
            }
            for family in families
        ],
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "automatic_replacements": 0,
        "hosted_calls": 0,
        "local_runtime": grant_value["local_runtime"],
        "authority_source_sha256": grant_value["authority_source_sha256"],
        "budget_model": "permanent_reservation",
        "grants_authority": False,
    }
    shape = {**core, "shape_sha256": _sha256(core)}
    return _base_report(
        status="PASS",
        state="SHAPED",
        issues=[],
        campaign_sha256=str(campaign["campaign_sha256"]),
        shape=shape,
        shape_sha256=shape["shape_sha256"],
    )


def validate_grant_shape(
    campaign: Any, grant: Any, shape: Any
) -> dict[str, Any]:
    """Refuse any drift between a claimed shape and the sealed pair (C5)."""

    derived = derive_grant_shape(campaign, grant)
    if derived.get("status") != "PASS":
        return derived
    issues: list[str] = []
    if not isinstance(shape, Mapping):
        _issue(issues, "shape:type_invalid")
    elif dict(shape) != derived["shape"]:
        expected = derived["shape"]
        for field in sorted(set(expected) | set(shape)):
            if field not in expected:
                _issue(issues, f"shape:unknown_field:{field}")
            elif field not in shape:
                _issue(issues, f"shape:missing_field:{field}")
            elif shape[field] != expected[field]:
                _issue(issues, f"shape:field_drift:{field}")
    if issues:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=derived.get("campaign_sha256"),
        )
    return _base_report(
        status="PASS",
        state="VALIDATED",
        issues=[],
        campaign_sha256=derived.get("campaign_sha256"),
        shape_sha256=derived["shape_sha256"],
    )


def _configuration(
    campaign: Mapping[str, Any], configuration_id: str
) -> Mapping[str, Any] | None:
    rows = [
        row
        for row in campaign.get("configuration_grid", [])
        if isinstance(row, Mapping) and row.get("configuration_id") == configuration_id
    ]
    return rows[0] if len(rows) == 1 else None


def _request_core(
    campaign: Mapping[str, Any],
    configuration: Mapping[str, Any],
    replicate_index: int,
    seed: int,
    *,
    reserved_tokens: int,
    started_at_ms: int,
    deadline_at_ms: int,
) -> dict[str, Any]:
    parameters = _parameter_map(configuration)
    core: dict[str, Any] = {
        "schema": LIVE_REPLICATE_REQUEST_SCHEMA,
        "campaign_id": campaign.get("campaign_id"),
        "campaign_sha256": campaign.get("campaign_sha256"),
        "configuration_id": configuration.get("configuration_id"),
        "configuration_sha256": _sha256(configuration),
        "task_family": parameters.get("task_family"),
        "lane_count": parameters.get("lane_count"),
        "cut_strategy": parameters.get("cut_strategy"),
        "capability_profile": parameters.get("capability_profile"),
        "replicate_index": replicate_index,
        "seed": seed,
        "metric": campaign.get("question", {}).get("primary_metric"),
        "governed_entrypoint": sweep.GOVERNED_ENTRYPOINT,
        "governed_program_schema": sweep.GOVERNED_PROGRAM_SCHEMA,
        "reserved_tokens": reserved_tokens,
        "started_at_ms": started_at_ms,
        "deadline_at_ms": deadline_at_ms,
    }
    if "workload_bucket" in parameters:
        core["schema"] = LIVE_REPLICATE_REQUEST_SCHEMA_V2
        core["workload_bucket"] = parameters.get("workload_bucket")
        core["item_count"] = parameters.get("item_count")
        core["coupling_density_bps"] = parameters.get("coupling_density_bps")
    return core


def _request(
    campaign: Mapping[str, Any],
    configuration: Mapping[str, Any],
    replicate_index: int,
    seed: int,
    *,
    reserved_tokens: int,
    started_at_ms: int,
    deadline_at_ms: int,
) -> dict[str, Any]:
    core = _request_core(
        campaign,
        configuration,
        replicate_index,
        seed,
        reserved_tokens=reserved_tokens,
        started_at_ms=started_at_ms,
        deadline_at_ms=deadline_at_ms,
    )
    return {**core, "request_sha256": _sha256(core)}


def _validate_request(value: Any, issues: list[str]) -> Mapping[str, Any]:
    raw_schema = value.get("schema") if isinstance(value, Mapping) else None
    fields = (
        _REQUEST_FIELDS_V2
        if raw_schema == LIVE_REPLICATE_REQUEST_SCHEMA_V2
        else _REQUEST_FIELDS
    )
    request = _closed(value, fields, "request", issues)
    if request.get("schema") not in {
        LIVE_REPLICATE_REQUEST_SCHEMA,
        LIVE_REPLICATE_REQUEST_SCHEMA_V2,
    }:
        _issue(issues, "request:schema_invalid")
    core = {key: request.get(key) for key in fields if key != "request_sha256"}
    if not _sha_valid(request.get("request_sha256")) or request.get(
        "request_sha256"
    ) != _sha256(core):
        _issue(issues, "request:seal_mismatch")
    if request.get("task_family") not in ISSUE111_TASK_FAMILIES:
        _issue(issues, "request:task_family_invalid")
    if request.get("schema") == LIVE_REPLICATE_REQUEST_SCHEMA_V2:
        lane_count = request.get("lane_count")
        if (
            type(lane_count) is not int
            or lane_count < LANE_COUNT_FLOOR
            or lane_count > LANE_COUNT_CEILING
        ):
            _issue(issues, "request:lane_count_invalid")
        item_count = request.get("item_count")
        density = request.get("coupling_density_bps")
        if (
            not _identifier(request.get("workload_bucket"))
            or type(item_count) is not int
            or item_count < WORKLOAD_ITEM_FLOOR
            or item_count > WORKLOAD_ITEM_CEILING
            or type(density) is not int
            or density < COUPLING_DENSITY_FLOOR_BPS
            or density > COUPLING_DENSITY_CEILING_BPS
        ):
            _issue(issues, "request:workload_invalid")
    elif request.get("lane_count") not in ISSUE111_LANE_COUNTS:
        _issue(issues, "request:lane_count_invalid")
    if request.get("cut_strategy") not in ISSUE111_CUT_STRATEGIES:
        _issue(issues, "request:cut_strategy_invalid")
    if request.get("capability_profile") != "qwen_smart":
        _issue(issues, "request:capability_profile_invalid")
    return request


def _task_items(task_family: str, seed: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if task_family == "evidence_extraction":
        rules = {
            "finding_rule": "Return an item id only when severity is at least 7 and verified is true."
        }
        items = [
            {
                "id": f"evidence-{index:02d}",
                "severity": (seed + index * 7) % 10,
                "verified": ((seed // 10) + index) % 3 != 0,
            }
            for index in range(12)
        ]
        return rules, items
    if task_family == "contract_audit":
        rules = {
            "finding_rule": (
                "Return a contract id when either request_fields or response_fields "
                "omits one of required_fields."
            )
        }
        items = []
        for index in range(12):
            required = ["id", "status"]
            request_fields = ["id"] + (
                ["status"] if (seed + index) % 4 != 0 else []
            )
            response_fields = ["id"] + (
                ["status"] if (seed * 3 + index) % 5 != 0 else []
            )
            items.append(
                {
                    "id": f"contract-{index:02d}",
                    "required_fields": required,
                    "request_fields": request_fields,
                    "response_fields": response_fields,
                }
            )
        return rules, items
    if task_family == "dependency_graph":
        rules = {
            "finding_rule": "Return a component id exactly when its directed edges contain a cycle."
        }
        items = []
        for index in range(12):
            prefix = f"d{index}"
            edges = [[prefix + "a", prefix + "b"], [prefix + "b", prefix + "c"]]
            if (seed + index * 5) % 7 in {0, 1}:
                edges.append([prefix + "c", prefix + "a"])
            items.append({"id": f"dependency-{index:02d}", "edges": edges})
        return rules, items
    raise ValueError("unknown task family")


def _item_is_finding(task_family: str, item: Mapping[str, Any]) -> bool:
    if task_family == "evidence_extraction":
        return type(item.get("severity")) is int and item["severity"] >= 7 and item.get("verified") is True
    if task_family == "contract_audit":
        required = set(item.get("required_fields", []))
        return not required.issubset(set(item.get("request_fields", []))) or not required.issubset(
            set(item.get("response_fields", []))
        )
    if task_family == "dependency_graph":
        edges = item.get("edges", [])
        graph: dict[str, list[str]] = {}
        for edge in edges:
            if isinstance(edge, list) and len(edge) == 2:
                graph.setdefault(str(edge[0]), []).append(str(edge[1]))
                graph.setdefault(str(edge[1]), [])
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> bool:
            if node in visiting:
                return True
            if node in visited:
                return False
            visiting.add(node)
            if any(visit(child) for child in graph.get(node, [])):
                return True
            visiting.remove(node)
            visited.add(node)
            return False

        return any(visit(node) for node in list(graph) if node not in visited)
    return False


def _coupling_positions(
    item_count: int, coupling_density_bps: int, seed: int
) -> list[int]:
    """Deterministic first-members of adjacent coupled pairs."""

    pair_count = (item_count * coupling_density_bps) // 20_000
    if pair_count <= 0:
        return []
    stride = max(2, item_count // pair_count)
    positions: list[int] = []
    cursor = (seed + item_count) % max(1, stride)
    while len(positions) < pair_count and cursor + 1 < item_count:
        positions.append(cursor)
        cursor += stride
    return positions


def _coupled_task_items(
    task_family: str,
    seed: int,
    *,
    item_count: int,
    coupling_density_bps: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[list[str]]]:
    """Workload-sized items where selected findings span adjacent items."""

    positions = set(_coupling_positions(item_count, coupling_density_bps, seed))
    groups: list[list[str]] = []
    if task_family == "evidence_extraction":
        rules = {
            "finding_rule": (
                "Return an item id when severity is at least 7 and verified is "
                "true, or when the item names a corroborates id whose severity "
                "is at least 7 and verified is true."
            )
        }
        items: list[dict[str, Any]] = [
            {
                "id": f"evidence-{index:02d}",
                "severity": (seed + index * 7) % 10,
                "verified": ((seed // 10) + index) % 3 != 0,
                "corroborates": None,
            }
            for index in range(item_count)
        ]
        for position in sorted(positions):
            anchor = items[position]
            witness = items[position + 1]
            anchor["severity"] = 9
            anchor["verified"] = True
            witness["severity"] = (seed + position) % 6
            witness["verified"] = False
            witness["corroborates"] = anchor["id"]
            groups.append([anchor["id"], witness["id"]])
        return rules, items, groups
    if task_family == "contract_audit":
        rules = {
            "finding_rule": (
                "Return a contract id when either request_fields or "
                "response_fields omits one of required_fields, or when the "
                "contract names an upstream id whose response_fields omit one "
                "of that upstream contract's required_fields."
            )
        }
        items = []
        for index in range(item_count):
            request_fields = ["id"] + (
                ["status"] if (seed + index) % 4 != 0 else []
            )
            response_fields = ["id"] + (
                ["status"] if (seed * 3 + index) % 5 != 0 else []
            )
            items.append(
                {
                    "id": f"contract-{index:02d}",
                    "required_fields": ["id", "status"],
                    "request_fields": request_fields,
                    "response_fields": response_fields,
                    "upstream": None,
                }
            )
        for position in sorted(positions):
            anchor = items[position]
            consumer = items[position + 1]
            anchor["response_fields"] = ["id"]
            consumer["request_fields"] = ["id", "status"]
            consumer["response_fields"] = ["id", "status"]
            consumer["upstream"] = anchor["id"]
            groups.append([anchor["id"], consumer["id"]])
        return rules, items, groups
    if task_family == "dependency_graph":
        rules = {
            "finding_rule": (
                "Return a component id exactly when any directed cycle in the "
                "combined edge set touches one of that component's nodes."
            )
        }
        items = []
        for index in range(item_count):
            prefix = f"d{index}"
            edges = [[prefix + "a", prefix + "b"], [prefix + "b", prefix + "c"]]
            if (seed + index * 5) % 7 in {0, 1}:
                edges.append([prefix + "c", prefix + "a"])
            items.append({"id": f"dependency-{index:02d}", "edges": edges})
        for position in sorted(positions):
            anchor = items[position]
            partner = items[position + 1]
            anchor_prefix = f"d{position}"
            partner_prefix = f"d{position + 1}"
            anchor["edges"] = [
                [anchor_prefix + "a", anchor_prefix + "b"],
                [anchor_prefix + "b", partner_prefix + "a"],
            ]
            partner["edges"] = [
                [partner_prefix + "a", partner_prefix + "b"],
                [partner_prefix + "b", anchor_prefix + "a"],
            ]
            groups.append([anchor["id"], partner["id"]])
        return rules, items, groups
    raise ValueError("unknown task family")


def coupled_item_groups(
    task_family: str,
    seed: int,
    *,
    item_count: int,
    coupling_density_bps: int,
) -> list[list[str]]:
    """Item-id groups whose finding truth spans more than one item."""

    _rules, _items, groups = _coupled_task_items(
        task_family,
        seed,
        item_count=item_count,
        coupling_density_bps=coupling_density_bps,
    )
    return groups


def _graph_cycle_nodes(items: list[Mapping[str, Any]]) -> set[str]:
    graph: dict[str, list[str]] = {}
    for member in items:
        for edge in member.get("edges", []):
            if isinstance(edge, list) and len(edge) == 2:
                graph.setdefault(str(edge[0]), []).append(str(edge[1]))
                graph.setdefault(str(edge[1]), [])
    visiting: list[str] = []
    visited: set[str] = set()
    members: set[str] = set()

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            members.update(visiting[visiting.index(node):])
            return
        visiting.append(node)
        for child in graph.get(node, []):
            visit(child)
        visiting.pop()
        visited.add(node)

    for node in list(graph):
        visit(node)
    return members


def _coupled_item_is_finding(
    task_family: str,
    item: Mapping[str, Any],
    items: list[Mapping[str, Any]],
) -> bool:
    items_by_id = {str(row.get("id")): row for row in items}
    if task_family == "evidence_extraction":
        if _item_is_finding(task_family, item):
            return True
        anchor = items_by_id.get(str(item.get("corroborates")))
        return anchor is not None and _item_is_finding(task_family, anchor)
    if task_family == "contract_audit":
        if _item_is_finding(task_family, item):
            return True
        upstream = items_by_id.get(str(item.get("upstream")))
        if upstream is None:
            return False
        required = set(upstream.get("required_fields", []))
        return not required.issubset(set(upstream.get("response_fields", [])))
    if task_family == "dependency_graph":
        own_nodes = {
            str(node)
            for edge in item.get("edges", [])
            if isinstance(edge, list) and len(edge) == 2
            for node in edge
        }
        return bool(own_nodes & _graph_cycle_nodes(items))
    return False


def _request_workload(request: Mapping[str, Any]) -> tuple[int, int] | None:
    item_count = request.get("item_count")
    density = request.get("coupling_density_bps")
    if type(item_count) is int and type(density) is int:
        return item_count, density
    return None


def _request_items(
    request: Mapping[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    family = str(request["task_family"])
    seed = int(request["seed"])
    workload = _request_workload(request)
    if workload is None:
        return _task_items(family, seed)
    rules, items, _groups = _coupled_task_items(
        family, seed, item_count=workload[0], coupling_density_bps=workload[1]
    )
    return rules, items


def _request_item_is_finding(
    request: Mapping[str, Any],
    item: Mapping[str, Any],
    items: list[Mapping[str, Any]],
) -> bool:
    family = str(request["task_family"])
    if _request_workload(request) is None:
        return _item_is_finding(family, item)
    return _coupled_item_is_finding(family, item, items)


def _partition_items(items: list[dict[str, Any]], lane_count: int, cut_strategy: str) -> list[list[dict[str, Any]]]:
    if cut_strategy == "acceptance_unit":
        return [items[index::lane_count] for index in range(lane_count)]
    quotient, remainder = divmod(len(items), lane_count)
    result: list[list[dict[str, Any]]] = []
    cursor = 0
    for index in range(lane_count):
        width = quotient + (1 if index < remainder else 0)
        result.append(items[cursor : cursor + width])
        cursor += width
    return result


def build_live_lane_assignments(request: Any) -> list[dict[str, Any]]:
    """Build deterministic answer-hidden lane briefs for one reserved cell."""

    issues: list[str] = []
    value = _validate_request(request, issues)
    if issues:
        raise ValueError("invalid live request")
    family = str(value["task_family"])
    rules, items = _request_items(value)
    partitions = _partition_items(
        items, int(value["lane_count"]), str(value["cut_strategy"])
    )
    assignments: list[dict[str, Any]] = []
    for index, lane_items in enumerate(partitions, start=1):
        core = {
            "schema": LIVE_LANE_ASSIGNMENT_SCHEMA,
            "lane_id": f"{value['configuration_id']}-r{value['replicate_index']}-lane-{index}",
            "request_sha256": value["request_sha256"],
            "task_family": family,
            "cut_strategy": value["cut_strategy"],
            "task": {"rules": rules, "items": lane_items},
            "output_schema": LIVE_LANE_RESULT_SCHEMA,
        }
        assignments.append({**core, "assignment_sha256": _sha256(core)})
    return assignments


def expected_live_lane_findings(request: Any, lane_id: str) -> list[str]:
    assignments = build_live_lane_assignments(request)
    matches = [row for row in assignments if row["lane_id"] == lane_id]
    if len(matches) != 1:
        raise ValueError("unknown live lane")
    assignment = matches[0]
    issues: list[str] = []
    value = _validate_request(request, issues)
    if issues:
        raise ValueError("invalid live request")
    _rules, all_items = _request_items(value)
    return sorted(
        str(item["id"])
        for item in assignment["task"]["items"]
        if _request_item_is_finding(value, item, all_items)
    )


def expected_locally_decidable_findings(request: Any) -> list[str]:
    """Findings a lane can prove from its own assignment alone."""

    issues: list[str] = []
    value = _validate_request(request, issues)
    if issues:
        raise ValueError("invalid live request")
    result: list[str] = []
    for assignment in build_live_lane_assignments(value):
        lane_items = list(assignment["task"]["items"])
        for item in lane_items:
            if _request_item_is_finding(value, item, lane_items):
                result.append(str(item["id"]))
    return sorted(result)


def expected_live_findings(request: Any) -> list[str]:
    return sorted(
        finding
        for assignment in build_live_lane_assignments(request)
        for finding in expected_live_lane_findings(request, assignment["lane_id"])
    )


def render_live_lane_prompt(assignment: Any) -> str:
    issues: list[str] = []
    value = _closed(assignment, _ASSIGNMENT_FIELDS, "assignment", issues)
    core = {key: value.get(key) for key in _ASSIGNMENT_FIELDS if key != "assignment_sha256"}
    if value.get("schema") != LIVE_LANE_ASSIGNMENT_SCHEMA or value.get(
        "assignment_sha256"
    ) != _sha256(core):
        _issue(issues, "assignment:seal_mismatch")
    if issues:
        raise ValueError("invalid live lane assignment")
    example = {
        "schema": LIVE_LANE_RESULT_SCHEMA,
        "lane_id": value["lane_id"],
        "request_sha256": value["request_sha256"],
        "assignment_sha256": value["assignment_sha256"],
        "findings": ["item-00"],
        "unknowns": ["item-01"],
    }
    return (
        "Return exactly one JSON object and make no tool calls. "
        f"The object schema is {LIVE_LANE_RESULT_SCHEMA}, and the schema "
        "field is mandatory. Copy lane_id, "
        "request_sha256, and assignment_sha256 exactly; findings is the sorted "
        "list of item ids satisfying task.rules.finding_rule and unknowns is a "
        "sorted list of item ids you cannot decide from this assignment alone. "
        "Shape example (values illustrative): "
        + _canonical(example).decode("utf-8")
        + " No prose. Assignment: "
        + _canonical(value).decode("utf-8")
    )


def _revalidate_standing_registration(
    campaign: Mapping[str, Any],
    grant: Mapping[str, Any],
    context: Any,
    issues: list[str],
) -> None:
    binding = standing_authority.standing_owner_binding_material(
        grant.get("standing_authority")
    )
    if binding is None:
        _issue(issues, "grant:standing_authority_revalidation_failed")
        return
    if not isinstance(context, Mapping):
        _issue(issues, "grant:standing_authority_revalidation_required")
        return
    authority_class = binding["authority_class"]
    try:
        if authority_class == standing_authority.TRANCHE_DISPATCH_AUTHORITY_CLASS:
            if set(context) != {"packet", "plugin_root"}:
                raise ValueError
            packet_module = _load_sibling("orch_dork_dispatch_packet")
            reproduced = packet_module.grant_from_packet(
                context.get("packet"), plugin_root=context.get("plugin_root")
            )
        elif authority_class == standing_authority.QUALIFIED_RECOVERY_AUTHORITY_CLASS:
            if set(context) != {
                "packet",
                "terminal_predecessor_root",
                "opencodex_root",
                "plugin_root",
            }:
                raise ValueError
            recovery_module = _load_sibling("orch_dork_live_recovery")
            reproduced = recovery_module.grant_from_v8_packet(
                context.get("packet"),
                terminal_predecessor_root=context.get(
                    "terminal_predecessor_root"
                ),
                opencodex_root=context.get("opencodex_root"),
                plugin_root=context.get("plugin_root"),
            )
        else:  # The binder already rejects this; retain a closed final branch.
            raise ValueError
    except (ImportError, KeyError, OSError, TypeError, ValueError):
        _issue(issues, "grant:standing_authority_revalidation_failed")
        return
    if reproduced.get("status") != "PASS":
        _issue(issues, "grant:standing_authority_revalidation_failed")
    elif (
        reproduced.get("campaign") != campaign
        or reproduced.get("grant") != grant
    ):
        _issue(issues, "grant:standing_authority_revalidation_mismatch")


def register_live_campaign(
    campaign: Any,
    grant: Any,
    ledger_path: str | Path,
    *,
    registered_at_ms: int,
    predecessor_ledger_path: str | Path | None = None,
    predecessor_shard_paths: Mapping[str, str | Path] | None = None,
    standing_authority_context: Any = None,
) -> dict[str, Any]:
    """Append a sealed campaign after validating and claiming its grant."""

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        issues = [
            str(item) if str(item).startswith("campaign:") else "campaign:" + str(item)
            for item in verified.get("issues", [])
        ] or ["campaign:invalid"]
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=(campaign.get("campaign_sha256") if isinstance(campaign, Mapping) else None),
        )
    issues: list[str] = []
    grant_value = _grant_material(campaign, grant, issues)
    if grant_value.get("schema") == LIVE_GRANT_SCHEMA_V5:
        _revalidate_standing_registration(
            campaign, grant_value, standing_authority_context, issues
        )
    if grant_value.get("schema") == LIVE_GRANT_SCHEMA_V2:
        if predecessor_ledger_path is None:
            _issue(issues, "predecessor:ledger_required")
        else:
            predecessor = _predecessor_binding(
                campaign, predecessor_ledger_path, issues
            )
            if predecessor is not None and predecessor != grant_value.get(
                "predecessor"
            ):
                _issue(issues, "predecessor:binding_mismatch")
    elif grant_value.get("schema") == LIVE_GRANT_SCHEMA_V3:
        if predecessor_ledger_path is None:
            _issue(issues, "predecessor:ledger_required")
        elif predecessor_shard_paths is None:
            _issue(issues, "predecessor:family_shards_required")
        else:
            predecessor = _terminated_successor_binding(
                campaign,
                predecessor_ledger_path,
                predecessor_shard_paths,
                issues,
            )
            if predecessor is not None and predecessor != grant_value.get(
                "predecessor"
            ):
                _issue(issues, "predecessor:binding_mismatch")
    try:
        replay_plan = build_issue111_replay_plan(campaign)
    except ValueError:
        replay_plan = {}
        _issue(issues, "replay_plan:seal_failed")
    if not _integer(registered_at_ms, minimum=0):
        _issue(issues, "campaign:registered_at_ms_invalid")
    entries, chain_issues = _entries(ledger_path)
    issues.extend(chain_issues)
    digest = str(campaign.get("campaign_sha256"))
    if any(
        row.get("record", {}).get("campaign_sha256") == digest
        and row.get("record", {}).get("schema")
        in {LIVE_CAMPAIGN_RECORD_SCHEMA, LIVE_START_RECORD_SCHEMA}
        for row in entries
    ):
        _issue(issues, "campaign:already_registered")
    authority_source_sha256 = grant_value.get("authority_source_sha256")
    if any(
        row.get("record", {}).get("schema") == LIVE_CAMPAIGN_RECORD_SCHEMA
        and row.get("record", {}).get("grant", {}).get(
            "authority_source_sha256"
        )
        == authority_source_sha256
        for row in entries
    ):
        _issue(issues, "grant:authority_source_already_registered")
    standing_claim = None
    if not issues and grant_value.get("schema") == LIVE_GRANT_SCHEMA_V5:
        standing_claim = standing_authority.claim_standing_owner_registration(
            grant_value.get("standing_authority"),
            campaign_sha256=digest,
            grant_sha256=grant_value.get("grant_sha256"),
            registered_at_ms=registered_at_ms,
        )
        if standing_claim.get("status") != "PASS":
            claim_issues = set(standing_claim.get("issues", []))
            _issue(
                issues,
                (
                    "grant:authority_source_already_registered"
                    if "standing_authority:already_registered" in claim_issues
                    else "grant:standing_authority_claim_failed"
                ),
            )
    if issues:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=digest,
        )
    adapter_contract = {
        "kind": "external_governed_live_adapter",
        "governed_entrypoint": sweep.GOVERNED_ENTRYPOINT,
        "governed_program_schema": sweep.GOVERNED_PROGRAM_SCHEMA,
        "attempts_per_replicate": 1,
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "automatic_replacements": 0,
        "model_dispatch_owned": False,
    }
    record = _seal(
        {
            "schema": LIVE_CAMPAIGN_RECORD_SCHEMA,
            "campaign": dict(campaign),
            "campaign_sha256": digest,
            "grant": grant_value,
            "grant_sha256": grant_value["grant_sha256"],
            "registered_at_ms": registered_at_ms,
            "adapter_contract": adapter_contract,
        }
    )
    receipt = _append(ledger_path, record)
    if receipt is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["ledger:append_failed"],
            campaign_sha256=digest,
        )
    replay_registration = record_replay.register_replay_plan(
        campaign, ledger_path, replay_plan
    )
    if replay_registration.get("status") != "PASS":
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["replay_plan:registration_failed"],
            campaign_sha256=digest,
            registration_record_sha256=record["record_sha256"],
        )
    return _base_report(
        status="PASS",
        state="REGISTERED",
        issues=[],
        campaign_sha256=digest,
        expected_runs=expected_run_count(campaign),
        grant=grant_value,
        registration_record_sha256=record["record_sha256"],
        replay_plan_sha256=replay_plan["plan_sha256"],
        replay_plan_record_sha256=replay_registration["record_sha256"],
        standing_authority_claim_sha256=(
            standing_claim.get("claim_sha256")
            if standing_claim is not None
            else None
        ),
        chain_receipt=receipt,
    )


def register_successor_live_campaign(
    campaign: Any,
    grant: Any,
    ledger_path: str | Path,
    predecessor_ledger_path: str | Path,
    *,
    registered_at_ms: int,
) -> dict[str, Any]:
    """Register v2 only after re-reading its exact aborted predecessor."""

    if not isinstance(grant, Mapping) or grant.get("schema") != LIVE_GRANT_SCHEMA_V2:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["grant:successor_schema_required"],
            campaign_sha256=(
                campaign.get("campaign_sha256")
                if isinstance(campaign, Mapping)
                else None
            ),
        )
    return register_live_campaign(
        campaign,
        grant,
        ledger_path,
        registered_at_ms=registered_at_ms,
        predecessor_ledger_path=predecessor_ledger_path,
    )


def register_measurement_successor_live_campaign(
    campaign: Any,
    grant: Any,
    ledger_path: str | Path,
    predecessor_ledger_path: str | Path,
    predecessor_shard_paths: Mapping[str, str | Path],
    *,
    registered_at_ms: int,
) -> dict[str, Any]:
    """Register v3 only after exact terminal-ledger and shard re-derivation."""

    if not isinstance(grant, Mapping) or grant.get("schema") != LIVE_GRANT_SCHEMA_V3:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["grant:measurement_successor_schema_required"],
            campaign_sha256=(
                campaign.get("campaign_sha256")
                if isinstance(campaign, Mapping)
                else None
            ),
        )
    return register_live_campaign(
        campaign,
        grant,
        ledger_path,
        registered_at_ms=registered_at_ms,
        predecessor_ledger_path=predecessor_ledger_path,
        predecessor_shard_paths=predecessor_shard_paths,
    )


def _validate_registration(
    record: Any, campaign_sha256: str, issues: list[str]
) -> Mapping[str, Any]:
    value = _closed(record, _REGISTRATION_FIELDS, "registration", issues)
    if value.get("schema") != LIVE_CAMPAIGN_RECORD_SCHEMA:
        _issue(issues, "registration:schema_invalid")
    if value.get("campaign_sha256") != campaign_sha256:
        _issue(issues, "registration:campaign_mismatch")
    if not _seal_valid(value):
        _issue(issues, "registration:seal_mismatch")
    campaign = value.get("campaign")
    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS":
        _issue(issues, "registration:campaign_invalid")
    if isinstance(campaign, Mapping):
        _grant_material(campaign, value.get("grant"), issues)
    if value.get("grant_sha256") != value.get("grant", {}).get("grant_sha256"):
        _issue(issues, "registration:grant_binding_mismatch")
    return value


def _predecessor_binding(
    campaign: Mapping[str, Any],
    predecessor_ledger_path: str | Path,
    issues: list[str],
) -> dict[str, Any] | None:
    """Re-derive the exact immutable binding for the exhausted v1 ledger."""

    path = Path(predecessor_ledger_path)
    try:
        ledger_bytes = path.read_bytes()
    except OSError:
        _issue(issues, "predecessor:ledger_unreadable")
        return None
    entries, chain_issues = _entries(path)
    for issue in chain_issues:
        _issue(issues, f"predecessor:{issue}")
    digest = str(campaign.get("campaign_sha256"))
    registration = _campaign_registration(entries, digest)
    if registration is None:
        _issue(issues, "predecessor:registration_missing")
        return None
    local_issues: list[str] = []
    registration = _validate_registration(registration, digest, local_issues)
    for issue in local_issues:
        _issue(issues, f"predecessor:{issue}")
    if registration.get("grant", {}).get("schema") != LIVE_GRANT_SCHEMA_V1:
        _issue(issues, "predecessor:grant_schema_invalid")
    if _campaign_start(entries, digest) is not None:
        _issue(issues, "predecessor:start_record_present")
    abort = _campaign_abort(entries, digest)
    if abort is None:
        _issue(issues, "predecessor:abort_missing")
        return None
    abort = _closed(abort, _ABORT_RECORD_FIELDS, "predecessor.abort", issues)
    if (
        not _seal_valid(abort)
        or abort.get("authority_disposition") != "EXHAUSTED"
        or abort.get("campaign_started") is not False
        or abort.get("campaign_cells_reserved") != 0
        or abort.get("attributable_tokens")
        != ISSUE111_PREDECESSOR_ATTRIBUTABLE_TOKENS
        or abort.get("overage_tokens") != ISSUE111_PREDECESSOR_OVERAGE_TOKENS
        or abort.get("grant_sha256") != registration.get("grant_sha256")
        or abort.get("registration_record_sha256")
        != registration.get("record_sha256")
    ):
        _issue(issues, "predecessor:abort_invalid")
    replay_rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema")
        == record_replay.REPLAY_PLAN_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == digest
    ]
    if len(replay_rows) != 1:
        _issue(issues, "predecessor:replay_plan_invalid")
        return None
    replay = replay_rows[0]
    if (
        not _seal_valid(replay)
        or record_replay.validate_replay_plan(
            campaign, replay.get("replay_plan")
        ).get("status")
        != "PASS"
        or replay.get("plan_sha256")
        != replay.get("replay_plan", {}).get("plan_sha256")
    ):
        _issue(issues, "predecessor:replay_plan_invalid")
    summary = summarize_live_campaign(path, digest)
    if (
        summary.get("status") != "PASS"
        or summary.get("state") != "ABORTED"
        or summary.get("attributable_tokens")
        != ISSUE111_PREDECESSOR_ATTRIBUTABLE_TOKENS
        or summary.get("overage_tokens") != ISSUE111_PREDECESSOR_OVERAGE_TOKENS
        or summary.get("counts", {}).get("reserved_runs") != 0
        or summary.get("abort_record_sha256") != abort.get("record_sha256")
    ):
        _issue(issues, "predecessor:summary_invalid")
    if issues:
        return None
    return {
        "state": "ABORTED",
        "campaign_sha256": digest,
        "grant_sha256": registration["grant_sha256"],
        "registration_record_sha256": registration["record_sha256"],
        "replay_plan_sha256": replay["plan_sha256"],
        "replay_plan_record_sha256": replay["record_sha256"],
        "abort_record_sha256": abort["record_sha256"],
        "ledger_sha256": hashlib.sha256(ledger_bytes).hexdigest(),
        "ledger_path_sha256": hashlib.sha256(
            str(path.resolve(strict=False)).encode("utf-8")
        ).hexdigest(),
        "attributable_tokens": ISSUE111_PREDECESSOR_ATTRIBUTABLE_TOKENS,
        "overage_tokens": ISSUE111_PREDECESSOR_OVERAGE_TOKENS,
        "campaign_cells_reserved": 0,
        "campaign_started": False,
    }


def _terminated_successor_binding(
    campaign: Mapping[str, Any],
    predecessor_ledger_path: str | Path,
    predecessor_shard_paths: Mapping[str, str | Path],
    issues: list[str],
) -> dict[str, Any] | None:
    """Re-derive the exact terminal v2 ledger and every bound family shard."""

    path = Path(predecessor_ledger_path)
    try:
        ledger_bytes = path.read_bytes()
    except OSError:
        _issue(issues, "predecessor:ledger_unreadable")
        return None
    entries, chain_issues = _entries(path)
    for issue in chain_issues:
        _issue(issues, f"predecessor:{issue}")
    digest = str(campaign.get("campaign_sha256"))
    registration = _campaign_registration(entries, digest)
    start = _campaign_start(entries, digest)
    termination = _campaign_owner_termination(entries, digest)
    if registration is None:
        _issue(issues, "predecessor:registration_missing")
        return None
    local_issues: list[str] = []
    registration = _validate_registration(registration, digest, local_issues)
    for issue in local_issues:
        _issue(issues, f"predecessor:{issue}")
    if registration.get("grant", {}).get("schema") != LIVE_GRANT_SCHEMA_V2:
        _issue(issues, "predecessor:grant_schema_invalid")
    if start is None or not _seal_valid(start):
        _issue(issues, "predecessor:start_invalid")
        return None
    if termination is None or not _seal_valid(termination):
        _issue(issues, "predecessor:termination_invalid")
        return None
    if (
        not entries
        or entries[-1].get("record", {}).get("record_sha256")
        != termination.get("record_sha256")
    ):
        _issue(issues, "predecessor:termination_not_terminal")
    replay_rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema")
        == record_replay.REPLAY_PLAN_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == digest
    ]
    if len(replay_rows) != 1 or not _seal_valid(replay_rows[0]):
        _issue(issues, "predecessor:replay_plan_invalid")
        return None
    replay = replay_rows[0]
    if not isinstance(predecessor_shard_paths, Mapping) or set(
        predecessor_shard_paths
    ) != set(ISSUE111_TASK_FAMILIES):
        _issue(issues, "predecessor:family_shards_invalid")
        return None
    shard_sha256s: dict[str, str] = {}
    shard_path_sha256s: dict[str, str] = {}
    for family in ISSUE111_TASK_FAMILIES:
        shard_path = Path(predecessor_shard_paths[family])
        try:
            shard_bytes = shard_path.read_bytes()
        except OSError:
            _issue(issues, f"predecessor:shard_unreadable:{family}")
            continue
        shard_sha256s[family] = hashlib.sha256(shard_bytes).hexdigest()
        shard_path_sha256s[family] = hashlib.sha256(
            str(shard_path.resolve(strict=False)).encode("utf-8")
        ).hexdigest()
    if shard_sha256s != termination.get("shard_sha256s"):
        _issue(issues, "predecessor:shard_binding_mismatch")
    start_paths = {
        row.get("task_family"): row.get("path_sha256")
        for row in start.get("family_shards", [])
        if isinstance(row, Mapping)
    }
    if shard_path_sha256s != start_paths:
        _issue(issues, "predecessor:shard_path_binding_mismatch")
    summary = summarize_live_campaign(path, digest)
    expected_counts = {
        "expected_runs": 36,
        "reserved_runs": 1,
        "completed_runs": 0,
        "failed_runs": 0,
        "evidence_failure_runs": 1,
        "quarantined_runs": 1,
        "never_dispatched_runs": 35,
        "missing_runs": 36,
        "extrapolated_runs": 0,
    }
    if (
        summary.get("status") != "PASS"
        or summary.get("state") != "INCOMPLETE_EVIDENCE_FAILURE"
        or summary.get("counts") != expected_counts
        or summary.get("termination_record_sha256")
        != termination.get("record_sha256")
        or summary.get("reportable") is not False
        or summary.get("training_eligible") is not False
    ):
        _issue(issues, "predecessor:summary_invalid")
    if issues:
        return None
    return {
        "state": "INCOMPLETE_EVIDENCE_FAILURE",
        "campaign_sha256": digest,
        "grant_sha256": registration["grant_sha256"],
        "registration_record_sha256": registration["record_sha256"],
        "replay_plan_sha256": replay["plan_sha256"],
        "replay_plan_record_sha256": replay["record_sha256"],
        "start_record_sha256": start["record_sha256"],
        "termination_record_sha256": termination["record_sha256"],
        "termination_report_sha256": summary["report_sha256"],
        "ledger_sha256": hashlib.sha256(ledger_bytes).hexdigest(),
        "ledger_path_sha256": hashlib.sha256(
            str(path.resolve(strict=False)).encode("utf-8")
        ).hexdigest(),
        "shard_sha256s": shard_sha256s,
        "shard_path_sha256s": shard_path_sha256s,
        "counts": expected_counts,
        "observed_tokens": summary["observed_tokens"],
        "live_model_calls": summary["live_model_calls"],
    }


def abort_live_campaign(
    campaign: Any,
    ledger_path: str | Path,
    incident: Any,
    *,
    aborted_at_ms: int,
) -> dict[str, Any]:
    """Seal a pre-start attributable-token overage and exhaust the grant."""

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["campaign:invalid"],
            campaign_sha256=(
                campaign.get("campaign_sha256")
                if isinstance(campaign, Mapping)
                else None
            ),
        )
    digest = str(campaign["campaign_sha256"])
    entries, issues = _entries(ledger_path)
    registration = _campaign_registration(entries, digest)
    if registration is None:
        _issue(issues, "campaign:registration_missing")
    else:
        registration = _validate_registration(registration, digest, issues)
    if _campaign_start(entries, digest) is not None:
        _issue(issues, "abort:campaign_already_started")
    if _campaign_abort(entries, digest) is not None:
        _issue(issues, "abort:already_recorded")
    draft = _closed(incident, _ABORT_DRAFT_FIELDS, "abort", issues)
    if draft.get("schema") != LIVE_ABORT_DRAFT_SCHEMA:
        _issue(issues, "abort:schema_invalid")
    if (
        draft.get("reason_code")
        != "attributable_token_limit_exceeded_before_campaign_start"
    ):
        _issue(issues, "abort:reason_code_invalid")
    if draft.get("authority_disposition") != "EXHAUSTED":
        _issue(issues, "abort:authority_disposition_invalid")
    raw_sessions = draft.get("observed_sessions")
    if (
        not isinstance(raw_sessions, list)
        or not raw_sessions
        or len(raw_sessions) > 16
    ):
        _issue(issues, "abort:observed_sessions_invalid")
        raw_sessions = []
    sessions: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_sessions):
        row = _closed(
            raw, _ABORT_SESSION_FIELDS, f"abort.session[{index}]", issues
        )
        if not _identifier(row.get("session_id")):
            _issue(issues, f"abort.session[{index}]:session_id_invalid")
        if row.get("model") != "qwen-local/qwen-smart":
            _issue(issues, f"abort.session[{index}]:model_invalid")
        if row.get("effort") != "xhigh":
            _issue(issues, f"abort.session[{index}]:effort_invalid")
        if not _integer(row.get("total_tokens"), minimum=1):
            _issue(issues, f"abort.session[{index}]:total_tokens_invalid")
        if not _integer(row.get("tool_calls"), minimum=0):
            _issue(issues, f"abort.session[{index}]:tool_calls_invalid")
        for field in ("source_sha256", "runtime_report_sha256"):
            if not _sha_valid(row.get(field)):
                _issue(issues, f"abort.session[{index}]:{field}_invalid")
        if row.get("terminally_qualified") is not False:
            _issue(issues, f"abort.session[{index}]:terminal_status_invalid")
        sessions.append(row)
    identities = [row.get("session_id") for row in sessions]
    if len(identities) != len(set(identities)):
        _issue(issues, "abort:session_duplicate")
    if not _integer(aborted_at_ms, minimum=0):
        _issue(issues, "abort:aborted_at_ms_invalid")
    attributable_tokens = sum(
        int(row.get("total_tokens", 0))
        for row in sessions
        if type(row.get("total_tokens")) is int
    )
    grant_max_tokens = (
        registration.get("grant", {}).get("max_tokens")
        if isinstance(registration, Mapping)
        else None
    )
    if type(grant_max_tokens) is not int or attributable_tokens <= grant_max_tokens:
        _issue(issues, "abort:token_limit_not_exceeded")
    if issues or registration is None or type(grant_max_tokens) is not int:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=digest,
        )
    record = _seal(
        {
            "schema": LIVE_ABORT_RECORD_SCHEMA,
            "campaign_sha256": digest,
            "grant_sha256": registration["grant_sha256"],
            "registration_record_sha256": registration["record_sha256"],
            "reason_code": draft["reason_code"],
            "authority_disposition": "EXHAUSTED",
            "observed_sessions": sessions,
            "attributable_sessions": len(sessions),
            "attributable_tokens": attributable_tokens,
            "grant_max_tokens": grant_max_tokens,
            "overage_tokens": attributable_tokens - grant_max_tokens,
            "campaign_cells_reserved": 0,
            "campaign_started": False,
            "aborted_at_ms": aborted_at_ms,
        }
    )
    receipt = _append(ledger_path, record)
    if receipt is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["ledger:abort_append_failed"],
            campaign_sha256=digest,
        )
    return _base_report(
        status="PASS",
        state="ABORTED",
        issues=[],
        campaign_sha256=digest,
        attributable_sessions=len(sessions),
        attributable_tokens=attributable_tokens,
        grant_max_tokens=grant_max_tokens,
        overage_tokens=attributable_tokens - grant_max_tokens,
        campaign_cells_reserved=0,
        session_observation_sha256s=[_sha256(row) for row in sessions],
        abort_record_sha256=record["record_sha256"],
        chain_receipt=receipt,
    )


def start_live_campaign(
    campaign: Any,
    ledger_path: str | Path,
    shard_paths: Mapping[str, str | Path],
    *,
    started_at_ms: int,
) -> dict[str, Any]:
    """Fix one conservative global clock and create inert family shards."""

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["campaign:invalid"],
            campaign_sha256=(campaign.get("campaign_sha256") if isinstance(campaign, Mapping) else None),
        )
    digest = str(campaign.get("campaign_sha256"))
    entries, issues = _entries(ledger_path)
    registration = _campaign_registration(entries, digest)
    if _campaign_abort(entries, digest) is not None:
        _issue(issues, "campaign:aborted")
    if registration is None:
        _issue(issues, "campaign:registration_missing")
    else:
        _validate_registration(registration, digest, issues)
    replay_plan_rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema")
        == record_replay.REPLAY_PLAN_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == digest
    ]
    if len(replay_plan_rows) != 1:
        _issue(
            issues,
            "replay_plan:missing" if not replay_plan_rows else "replay_plan:duplicate",
        )
    else:
        replay_plan_record = replay_plan_rows[0]
        if not _seal_valid(replay_plan_record):
            _issue(issues, "replay_plan:record_seal_mismatch")
        replay_plan_report = record_replay.validate_replay_plan(
            campaign, replay_plan_record.get("replay_plan")
        )
        if replay_plan_report.get("status") != "PASS":
            _issue(issues, "replay_plan:invalid")
        if replay_plan_record.get("plan_sha256") != replay_plan_record.get(
            "replay_plan", {}
        ).get("plan_sha256"):
            _issue(issues, "replay_plan:binding_mismatch")
    if _campaign_start(entries, digest) is not None:
        _issue(issues, "campaign:already_started")
    if not _integer(started_at_ms, minimum=0):
        _issue(issues, "campaign:started_at_ms_invalid")
    campaign_families = _expected_families(campaign, issues)
    if not isinstance(shard_paths, Mapping) or set(shard_paths) != set(
        campaign_families
    ):
        _issue(issues, "campaign:family_shards_invalid")
    else:
        resolved = [Path(path) for path in shard_paths.values()]
        if len({str(path.resolve(strict=False)) for path in resolved}) != len(resolved):
            _issue(issues, "campaign:family_shards_duplicate")
        if any(path.exists() for path in resolved):
            _issue(issues, "campaign:family_shard_exists")
    if issues or registration is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=digest,
        )
    grant = registration["grant"]
    deadline_at_ms = started_at_ms + int(grant["max_wall_time_ms"])
    shard_rows = []
    for family in campaign_families:
        path = Path(shard_paths[family])
        shard_rows.append(
            {
                "task_family": family,
                "shard_id": f"{campaign['campaign_id']}:{family}",
                "path_sha256": hashlib.sha256(
                    str(path.resolve(strict=False)).encode("utf-8")
                ).hexdigest(),
            }
        )
    start_core = {
        "schema": LIVE_START_RECORD_SCHEMA,
        "campaign_sha256": digest,
        "grant_sha256": grant["grant_sha256"],
        "registration_record_sha256": registration["record_sha256"],
        "started_at_ms": started_at_ms,
        "deadline_at_ms": deadline_at_ms,
        "family_shards": shard_rows,
    }
    start_record = _seal(start_core)
    allocations = {
        row["task_family"]: row for row in grant["family_allocations"]
    }
    # Shard headers are inert until the canonical start record is appended.
    # Writing them first ensures a failed final append cannot authorize work.
    for family in campaign_families:
        header = _seal(
            {
                "schema": LIVE_SHARD_HEADER_SCHEMA,
                "campaign_sha256": digest,
                "grant_sha256": grant["grant_sha256"],
                "registration_record_sha256": registration["record_sha256"],
                "start_record_sha256": start_record["record_sha256"],
                "task_family": family,
                "allocation": dict(allocations[family]),
                "started_at_ms": started_at_ms,
                "deadline_at_ms": deadline_at_ms,
            }
        )
        if _append(shard_paths[family], header) is None:
            return _base_report(
                status="FAIL",
                state="REFUSED",
                issues=["ledger:shard_header_append_failed"],
                campaign_sha256=digest,
            )
    receipt = _append(ledger_path, start_record)
    if receipt is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["ledger:start_append_failed"],
            campaign_sha256=digest,
        )
    return _base_report(
        status="PASS",
        state="RUNNING",
        issues=[],
        campaign_sha256=digest,
        started_at_ms=started_at_ms,
        deadline_at_ms=deadline_at_ms,
        family_shards={row["task_family"]: row["shard_id"] for row in shard_rows},
        start_record_sha256=start_record["record_sha256"],
        chain_receipt=receipt,
    )


def _shard_expected_runs(campaign: Mapping[str, Any], family: str) -> int:
    return sum(
        len(campaign.get("seeds", []))
        for row in campaign.get("configuration_grid", [])
        if _parameter_map(row).get("task_family") == family
    )


def _evidence_failure_aggregate(
    records: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Derive the shared sealed-record projection without trusting a caller."""

    rows = list(records)
    cause_counts: dict[str, int] = {}
    for row in rows:
        cause = str(row.get("failure_cause"))
        cause_counts[cause] = cause_counts.get(cause, 0) + 1
    return {
        "evidence_failure_record_sha256s": [
            row.get("record_sha256") for row in rows
        ],
        "evidence_failure_observed_tokens": sum(
            settled_usage_tokens(row) for row in rows
        ),
        "evidence_failure_lane_sessions": sum(
            int(row.get("model_calls", 0)) for row in rows
        ),
        "evidence_failure_cause_counts": cause_counts,
    }


def summarize_live_shard(
    ledger_path: str | Path, campaign_sha256: str, task_family: str
) -> dict[str, Any]:
    entries, issues = _entries(ledger_path)
    headers = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema") == LIVE_SHARD_HEADER_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == campaign_sha256
    ]
    if len(headers) != 1:
        _issue(issues, "shard:header_missing" if not headers else "shard:header_duplicate")
        header: Mapping[str, Any] = {}
    else:
        header = _closed(headers[0], _SHARD_HEADER_FIELDS, "shard.header", issues)
        if not _seal_valid(header):
            _issue(issues, "shard:header_seal_mismatch")
        if header.get("task_family") != task_family:
            _issue(issues, "shard:task_family_mismatch")
    allocation = header.get("allocation") if isinstance(header, Mapping) else {}
    reservations: list[Mapping[str, Any]] = []
    for row in entries:
        record = row.get("record")
        if not isinstance(record, Mapping) or record.get("schema") != LIVE_RESERVATION_RECORD_SCHEMA:
            continue
        value = _closed(record, _RESERVATION_FIELDS, "shard.reservation", issues)
        if not _seal_valid(value):
            _issue(issues, "shard:reservation_seal_mismatch")
        raw_request = value.get("request")
        request_fields = (
            _REQUEST_FIELDS_V2
            if isinstance(raw_request, Mapping)
            and raw_request.get("schema") == LIVE_REPLICATE_REQUEST_SCHEMA_V2
            else _REQUEST_FIELDS
        )
        request = _closed(raw_request, request_fields, "shard.request", issues)
        request_core = {key: request.get(key) for key in request_fields if key != "request_sha256"}
        if (
            not _sha_valid(request.get("request_sha256"))
            or request.get("request_sha256") != _sha256(request_core)
            or value.get("request_sha256") != request.get("request_sha256")
        ):
            _issue(issues, "shard:request_seal_mismatch")
        if request.get("task_family") != task_family:
            _issue(issues, "shard:reservation_family_mismatch")
        if value.get("permanently_charged") is not True:
            _issue(issues, "shard:reservation_not_charged")
        reservations.append(value)
    reservation_keys = [
        (
            row.get("request", {}).get("configuration_id"),
            row.get("request", {}).get("replicate_index"),
            row.get("request", {}).get("seed"),
        )
        for row in reservations
    ]
    if len(reservation_keys) != len(set(reservation_keys)):
        _issue(issues, "shard:duplicate_reservation")
    reserved_tokens = sum(
        int(row.get("reserved_tokens", 0))
        for row in reservations
        if type(row.get("reserved_tokens")) is int
    )
    if isinstance(allocation, Mapping):
        if len(reservations) > int(allocation.get("max_runs", 0)):
            _issue(issues, "shard:run_budget_exceeded")
        if reserved_tokens > int(allocation.get("max_tokens", 0)):
            _issue(issues, "shard:token_budget_exceeded")
    completions: list[Mapping[str, Any]] = []
    reservation_hashes = {row.get("record_sha256") for row in reservations}
    for row in entries:
        record = row.get("record")
        if not isinstance(record, Mapping) or record.get("schema") not in {
            LIVE_COMPLETION_RECORD_SCHEMA,
            LIVE_COMPLETION_RECORD_SCHEMA_V2,
        }:
            continue
        value = _closed(
            record,
            (
                _COMPLETION_RECORD_FIELDS_V2
                if record.get("schema") == LIVE_COMPLETION_RECORD_SCHEMA_V2
                else _COMPLETION_RECORD_FIELDS
            ),
            "shard.completion",
            issues,
        )
        if not _seal_valid(value):
            _issue(issues, "shard:completion_seal_mismatch")
        if value.get("reservation_record_sha256") not in reservation_hashes:
            _issue(issues, "shard:completion_reservation_missing")
        if value.get("task_family") != task_family:
            _issue(issues, "shard:completion_family_mismatch")
        completions.append(value)
    completion_requests = [row.get("request_sha256") for row in completions]
    if len(completion_requests) != len(set(completion_requests)):
        _issue(issues, "shard:duplicate_completion")
    evidence_failures: list[Mapping[str, Any]] = []
    reservations_by_sha = {
        str(row.get("record_sha256")): row for row in reservations
    }
    for row in entries:
        record = row.get("record")
        if (
            not isinstance(record, Mapping)
            or record.get("schema") not in _EVIDENCE_FAILURE_RECORD_SCHEMAS
        ):
            continue
        evidence_failures.append(
            _validate_stored_evidence_failure(
                record,
                reservations_by_sha,
                task_family,
                issues,
                label="shard.evidence_failure",
            )
        )
    evidence_failure_requests = [
        row.get("request_sha256") for row in evidence_failures
    ]
    if len(evidence_failure_requests) != len(set(evidence_failure_requests)):
        _issue(issues, "shard:duplicate_evidence_failure")
    if set(completion_requests) & set(evidence_failure_requests):
        _issue(issues, "shard:duplicate_cell_settlement")
    evidence_aggregate = _evidence_failure_aggregate(evidence_failures)
    completion_observed_tokens = sum(
        int(row.get("usage", {}).get("total_tokens", 0))
        for row in completions
        if type(row.get("usage", {}).get("total_tokens")) is int
    )
    evidence_failure_observed_tokens = evidence_aggregate[
        "evidence_failure_observed_tokens"
    ]
    observed_tokens = (
        completion_observed_tokens + evidence_failure_observed_tokens
    )
    completion_model_calls = sum(
        int(row.get("model_calls", 0))
        for row in completions
        if type(row.get("model_calls")) is int
    )
    evidence_failure_model_calls = evidence_aggregate[
        "evidence_failure_lane_sessions"
    ]
    model_calls = completion_model_calls + evidence_failure_model_calls
    completed = len(completions)
    evidence_failed = len(evidence_failures)
    settled = completed + evidence_failed
    failed = sum(row.get("outcome") == "failed" for row in completions)
    malformed = sum(
        row.get("evidence_class") == "malformed_terminal" for row in completions
    )
    completion_lane_sessions = sum(
        len(row.get("runtime_projections", []))
        + len(row.get("malformed_projections", []))
        for row in completions
    )
    evidence_failure_lane_sessions = evidence_aggregate[
        "evidence_failure_lane_sessions"
    ]
    lane_sessions = completion_lane_sessions + evidence_failure_lane_sessions
    malformed_lane_sessions = sum(
        len(row.get("malformed_projections", [])) for row in completions
    )
    well_formed_observed_tokens = sum(
        int(projection.get("usage", {}).get("total_tokens", 0))
        for row in completions
        for projection in row.get("runtime_projections", [])
        if type(projection.get("usage", {}).get("total_tokens")) is int
    )
    has_evidence_failures = bool(evidence_failures)
    core = {
        "schema": (
            LIVE_SHARD_REPORT_SCHEMA_V2
            if has_evidence_failures
            else LIVE_SHARD_REPORT_SCHEMA
        ),
        "status": "FAIL" if issues else "PASS",
        "state": (
            "UNKNOWN"
            if issues
            else "COMPLETE"
            if isinstance(allocation, Mapping)
            and completed == allocation.get("max_runs")
            else "INCOMPLETE"
            if isinstance(allocation, Mapping)
            and settled == allocation.get("max_runs")
            else "RUNNING"
        ),
        "issues": sorted(set(issues)),
        "campaign_sha256": campaign_sha256,
        "task_family": task_family,
        "counts": {
            "expected_runs": allocation.get("max_runs") if isinstance(allocation, Mapping) else None,
            "reserved_runs": len(reservations),
            "completed_runs": completed,
            "failed_runs": failed,
            "malformed_runs": malformed,
        },
        "token_budget": allocation.get("max_tokens") if isinstance(allocation, Mapping) else None,
        "reserved_tokens": reserved_tokens,
        "observed_tokens": observed_tokens,
        "well_formed_observed_tokens": well_formed_observed_tokens,
        "lane_sessions": lane_sessions,
        "malformed_lane_sessions": malformed_lane_sessions,
        "model_calls": model_calls,
        "hosted_calls": 0,
    }
    if has_evidence_failures:
        core["counts"] = {
            **core["counts"],
            "settled_runs": settled,
            "evidence_failure_runs": evidence_failed,
        }
        core.update(
            {
                "evidence_failure_observed_tokens": (
                    evidence_failure_observed_tokens
                ),
                "evidence_failure_lane_sessions": (
                    evidence_failure_lane_sessions
                ),
                "evidence_failure_cause_counts": evidence_aggregate[
                    "evidence_failure_cause_counts"
                ],
            }
        )
    return {**core, "report_sha256": _sha256(core)}


def summarize_live_campaign(
    ledger_path: str | Path, campaign_sha256: str
) -> dict[str, Any]:
    entries, issues = _entries(ledger_path)
    registration = _campaign_registration(entries, campaign_sha256)
    if registration is None:
        _issue(issues, "campaign:registration_missing")
        campaign: Mapping[str, Any] = {}
        grant: Mapping[str, Any] = {}
    else:
        _validate_registration(registration, campaign_sha256, issues)
        campaign = registration.get("campaign", {})
        grant = registration.get("grant", {})
    abort = _campaign_abort(entries, campaign_sha256)
    abort_value: Mapping[str, Any] | None = None
    start = _campaign_start(entries, campaign_sha256)
    if abort is not None:
        abort_value = _closed(abort, _ABORT_RECORD_FIELDS, "abort", issues)
        sessions = abort_value.get("observed_sessions")
        if not isinstance(sessions, list):
            sessions = []
            _issue(issues, "abort:observed_sessions_invalid")
        normalized_sessions = [
            _closed(row, _ABORT_SESSION_FIELDS, "abort.session", issues)
            for row in sessions
        ]
        attributable_tokens = sum(
            int(row.get("total_tokens", 0))
            for row in normalized_sessions
            if type(row.get("total_tokens")) is int
        )
        if (
            not _seal_valid(abort_value)
            or registration is None
            or abort_value.get("grant_sha256") != registration.get("grant_sha256")
            or abort_value.get("registration_record_sha256")
            != registration.get("record_sha256")
            or abort_value.get("authority_disposition") != "EXHAUSTED"
            or abort_value.get("campaign_started") is not False
            or abort_value.get("campaign_cells_reserved") != 0
            or abort_value.get("attributable_sessions")
            != len(normalized_sessions)
            or abort_value.get("attributable_tokens") != attributable_tokens
            or abort_value.get("grant_max_tokens")
            != registration.get("grant", {}).get("max_tokens")
            or abort_value.get("overage_tokens")
            != attributable_tokens
            - registration.get("grant", {}).get("max_tokens", 0)
            or attributable_tokens
            <= registration.get("grant", {}).get("max_tokens", 0)
        ):
            _issue(issues, "abort:record_invalid")
        if start is not None:
            _issue(issues, "abort:start_record_present")
        state = "ABORTED"
        started_at_ms = None
        deadline_at_ms = None
    elif start is not None:
        value = _closed(start, _START_FIELDS, "start", issues)
        if not _seal_valid(value):
            _issue(issues, "start:seal_mismatch")
        state = "RUNNING"
        started_at_ms = value.get("started_at_ms")
        deadline_at_ms = value.get("deadline_at_ms")
    else:
        state = "REGISTERED" if registration is not None else "UNKNOWN"
        started_at_ms = None
        deadline_at_ms = None
    terminations = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema")
        == LIVE_OWNER_TERMINATION_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == campaign_sha256
    ]
    if len(terminations) > 1:
        _issue(issues, "termination:duplicate")
    termination_value: Mapping[str, Any] | None = None
    if len(terminations) == 1:
        termination_value = _closed(
            terminations[0],
            _OWNER_TERMINATION_RECORD_FIELDS,
            "termination",
            issues,
        )
        termination_environment = _closed(
            termination_value.get("environment"),
            _OWNER_TERMINATION_ENVIRONMENT_FIELDS,
            "termination.environment",
            issues,
        )
        termination_limits = _closed(
            termination_value.get("limits"),
            _OWNER_TERMINATION_LIMIT_FIELDS,
            "termination.limits",
            issues,
        )
        quarantined = _closed(
            termination_value.get("quarantined_completion"),
            _QUARANTINED_COMPLETION_FIELDS,
            "termination.quarantined_completion",
            issues,
        )
        counts = _closed(
            termination_value.get("counts"),
            _OWNER_TERMINATION_COUNT_FIELDS,
            "termination.counts",
            issues,
        )
        shard_sha256s = termination_value.get("shard_sha256s")
        if (
            not isinstance(shard_sha256s, Mapping)
            or set(shard_sha256s) != set(ISSUE111_TASK_FAMILIES)
            or any(not _sha_valid(value) for value in shard_sha256s.values())
        ):
            _issue(issues, "termination:shard_sha256s_invalid")
        try:
            physical_lines = Path(ledger_path).read_bytes().splitlines(keepends=True)
            termination_entry = next(
                row
                for row in entries
                if row.get("record", {}).get("record_sha256")
                == termination_value.get("record_sha256")
            )
            prefix_bytes = b"".join(
                physical_lines[: int(termination_entry.get("seq", 0)) - 1]
            )
            if hashlib.sha256(prefix_bytes).hexdigest() != termination_value.get(
                "canonical_ledger_sha256_before_termination"
            ):
                _issue(issues, "termination:canonical_prefix_sha256_mismatch")
        except (OSError, StopIteration, TypeError, ValueError):
            _issue(issues, "termination:canonical_prefix_unverifiable")
        forbidden_after_termination = {
            LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA,
            LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA_V2,
            *_LIVE_FAMILY_SUMMARY_RECORD_SCHEMAS,
            *_LIVE_JOIN_RECORD_SCHEMAS,
            record_replay.MODEL_CALL_RECORD_SCHEMA,
        }
        if any(
            row.get("record", {}).get("schema") in forbidden_after_termination
            for row in entries
        ):
            _issue(issues, "termination:reportable_record_present")
        if (
            not _seal_valid(termination_value)
            or registration is None
            or start is None
            or abort is not None
            or termination_value.get("grant_sha256")
            != registration.get("grant_sha256")
            or termination_value.get("start_record_sha256")
            != start.get("record_sha256")
            or termination_value.get("original_deadline_at_ms")
            != start.get("deadline_at_ms")
            or termination_value.get("early_termination") is not True
            or not _integer(termination_value.get("terminated_at_ms"), minimum=0)
            or termination_value.get("terminated_at_ms", 0)
            >= start.get("deadline_at_ms", -1)
            or termination_value.get("state")
            != "INCOMPLETE_EVIDENCE_FAILURE"
            or termination_value.get("reportable") is not False
            or termination_value.get("training_eligible") is not False
            or termination_value.get("replay_decidable") != []
            or termination_value.get("live_required") != []
            or termination_value.get("hosted_calls") != 0
            or termination_environment
            != {
                "host_id": "jwj-lab",
                "runtime": "python3 -B",
                "provider_free": True,
            }
            or not _identifier(termination_value.get("authority_id"))
            or not _sha_valid(termination_value.get("authority_source_sha256"))
            or not isinstance(termination_value.get("material_risk"), str)
            or not termination_value.get("material_risk", "").strip()
            or not isinstance(termination_value.get("recovery"), str)
            or not termination_value.get("recovery", "").strip()
            or any(
                termination_limits.get(field) != 0
                for field in (
                    "qwen_calls",
                    "model_calls",
                    "hosted_calls",
                    "additional_tokens",
                    "new_reservations",
                    "retries",
                    "fallbacks",
                    "replacements",
                )
            )
            or termination_limits.get("finalizer_invocations") != 1
            or quarantined.get("evidence_class") != "contradictory"
            or counts.get("expected_runs") != expected_run_count(campaign)
            or counts.get("reserved_runs") != 1
            or counts.get("completed_runs") != 0
            or counts.get("evidence_failure_runs") != 1
            or counts.get("quarantined_runs") != 1
            or counts.get("never_dispatched_runs")
            != expected_run_count(campaign) - 1
            or counts.get("missing_runs") != expected_run_count(campaign)
            or counts.get("extrapolated_runs") != 0
        ):
            _issue(issues, "termination:record_invalid")
        state = "INCOMPLETE_EVIDENCE_FAILURE"
    stops = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema")
        in _LIVE_STOP_RECORD_SCHEMAS
        and row.get("record", {}).get("campaign_sha256") == campaign_sha256
    ]
    if len(stops) > 1:
        _issue(issues, "stop:duplicate")
    stop_value: Mapping[str, Any] | None = None
    if len(stops) == 1:
        stop_v2 = stops[0].get("schema") == LIVE_STOP_RECORD_SCHEMA_V2
        stop_value = _closed(
            stops[0],
            _STOP_RECORD_FIELDS_V2 if stop_v2 else _STOP_RECORD_FIELDS,
            "stop",
            issues,
        )
        stop_environment = _closed(
            stop_value.get("environment"),
            _OWNER_TERMINATION_ENVIRONMENT_FIELDS,
            "stop.environment",
            issues,
        )
        stop_limits = _closed(
            stop_value.get("limits"), _STOP_LIMIT_FIELDS, "stop.limits", issues
        )
        drain = _closed(
            stop_value.get("drain_evidence"),
            _STOP_DRAIN_FIELDS,
            "stop.drain_evidence",
            issues,
        )
        stop_counts = _closed(
            stop_value.get("counts"),
            _STOP_COUNT_FIELDS_V2 if stop_v2 else _STOP_COUNT_FIELDS,
            "stop.counts",
            issues,
        )
        stop_v2_invalid = False
        if stop_v2:
            evidence_hashes = stop_value.get(
                "evidence_failure_record_sha256s"
            )
            cause_counts = stop_value.get("evidence_failure_cause_counts")
            stop_v2_invalid = (
                not isinstance(evidence_hashes, list)
                or not evidence_hashes
                or len(evidence_hashes) != len(set(evidence_hashes))
                or any(not _sha_valid(value) for value in evidence_hashes)
                or len(evidence_hashes)
                != stop_counts.get("evidence_failure_runs")
                or any(
                    not _integer(stop_counts.get(field), minimum=0)
                    for field in _STOP_COUNT_FIELDS_V2
                )
                or not isinstance(cause_counts, Mapping)
                or set(cause_counts) - SETTLEABLE_EVIDENCE_FAILURE_CAUSES
                or any(
                    not _integer(value, minimum=1)
                    for value in (
                        cause_counts.values()
                        if isinstance(cause_counts, Mapping)
                        else []
                    )
                )
                or sum(cause_counts.values())
                != stop_counts.get("evidence_failure_runs")
                or stop_counts.get("settled_runs")
                != stop_counts.get("completed_runs", 0)
                + stop_counts.get("evidence_failure_runs", 0)
                or stop_counts.get("reserved_runs", -1)
                < stop_counts.get("settled_runs", 0)
                or not _integer(
                    stop_value.get("evidence_failure_observed_tokens"),
                    minimum=0,
                )
                or not _integer(
                    stop_value.get("evidence_failure_lane_sessions"),
                    minimum=1,
                )
                or not _integer(
                    stop_value.get("well_formed_observed_tokens"), minimum=0
                )
                or stop_value.get("observed_tokens", -1)
                < stop_value.get("evidence_failure_observed_tokens", 0)
                or stop_value.get("live_model_calls", -1)
                < stop_value.get("evidence_failure_lane_sessions", 0)
            )
        shard_sha256s = stop_value.get("shard_sha256s")
        if (
            not isinstance(shard_sha256s, Mapping)
            or set(shard_sha256s) != set(_expected_families(campaign, issues))
            or any(not _sha_valid(value) for value in shard_sha256s.values())
        ):
            _issue(issues, "stop:shard_sha256s_invalid")
        try:
            physical_lines = Path(ledger_path).read_bytes().splitlines(keepends=True)
            stop_entry = next(
                row
                for row in entries
                if row.get("record", {}).get("record_sha256")
                == stop_value.get("record_sha256")
            )
            prefix_bytes = b"".join(
                physical_lines[: int(stop_entry.get("seq", 0)) - 1]
            )
            if hashlib.sha256(prefix_bytes).hexdigest() != stop_value.get(
                "canonical_ledger_sha256_before_stop"
            ):
                _issue(issues, "stop:canonical_prefix_sha256_mismatch")
        except (OSError, StopIteration, TypeError, ValueError):
            _issue(issues, "stop:canonical_prefix_unverifiable")
        forbidden_after_stop = {
            LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA,
            LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA_V2,
            *_LIVE_FAMILY_SUMMARY_RECORD_SCHEMAS,
            *_LIVE_JOIN_RECORD_SCHEMAS,
            record_replay.MODEL_CALL_RECORD_SCHEMA,
        }
        if any(
            row.get("record", {}).get("schema") in forbidden_after_stop
            for row in entries
        ):
            _issue(issues, "stop:reportable_record_present")
        if (
            not entries
            or entries[-1].get("record", {}).get("record_sha256")
            != stop_value.get("record_sha256")
        ):
            _issue(issues, "stop:not_terminal")
        reason = stop_value.get("reason_code")
        expected_state = (
            "INCOMPLETE_OWNER_TERMINATED"
            if reason == "owner_directed"
            else "INCOMPLETE_FAILURE"
        )
        zero_drain_fields = _STOP_DRAIN_FIELDS - {"observed_at_ms"}
        if (
            not _seal_valid(stop_value)
            or stop_v2_invalid
            or registration is None
            or registration.get("grant", {}).get("schema")
            not in {
                LIVE_GRANT_SCHEMA_V3,
                LIVE_GRANT_SCHEMA_V4,
                LIVE_GRANT_SCHEMA_V5,
            }
            or start is None
            or abort is not None
            or termination_value is not None
            or stop_value.get("grant_sha256") != registration.get("grant_sha256")
            or stop_value.get("start_record_sha256") != start.get("record_sha256")
            or stop_value.get("original_deadline_at_ms")
            != start.get("deadline_at_ms")
            or stop_value.get("calendar_wait_required") is not False
            or not _integer(stop_value.get("stopped_at_ms"), minimum=0)
            or stop_value.get("stopped_at_ms", -1) < start.get("started_at_ms", 0)
            or stop_value.get("state") != expected_state
            or stop_value.get("reportable") is not False
            or stop_value.get("training_eligible") is not False
            or stop_value.get("replay_decidable") != []
            or stop_value.get("live_required") != []
            or stop_value.get("hosted_calls") != 0
            or stop_environment
            != {"host_id": "jwj-lab", "runtime": "python3 -B", "provider_free": True}
            or reason not in {"owner_directed", "execution_failure", "resource_limit", "evidence_failure"}
            or not _identifier(stop_value.get("authority_id"))
            or not _sha_valid(stop_value.get("authority_source_sha256"))
            or any(stop_limits.get(field) != 0 for field in _STOP_LIMIT_FIELDS - {"stop_invocations"})
            or stop_limits.get("stop_invocations") != 1
            or not _integer(drain.get("observed_at_ms"), minimum=0)
            or drain.get("observed_at_ms", -1) < start.get("started_at_ms", 0)
            or drain.get("observed_at_ms", -1) > stop_value.get("stopped_at_ms", -1)
            or any(drain.get(field) != 0 for field in zero_drain_fields)
            or any(
                not _integer(stop_counts.get(field), minimum=0)
                for field in _STOP_COUNT_FIELDS
            )
            or stop_counts.get("expected_runs") != expected_run_count(campaign)
            or stop_counts.get("reserved_runs", -1) < stop_counts.get("completed_runs", 0)
            or stop_counts.get("never_dispatched_runs")
            != expected_run_count(campaign) - stop_counts.get("reserved_runs", 0)
            or stop_counts.get("missing_runs")
            != expected_run_count(campaign) - stop_counts.get("completed_runs", 0)
            or stop_counts.get("extrapolated_runs") != 0
        ):
            _issue(issues, "stop:record_invalid")
        state = expected_state
    joins = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema")
        in _LIVE_JOIN_RECORD_SCHEMAS
        and row.get("record", {}).get("campaign_sha256") == campaign_sha256
    ]
    if len(joins) > 1:
        _issue(issues, "join:duplicate")
    if joins and termination_value is not None:
        _issue(issues, "termination:join_record_present")
    if joins and stop_value is not None:
        _issue(issues, "stop:join_record_present")
    join: Mapping[str, Any] | None = None
    families: list[dict[str, Any]] = []
    if len(joins) == 1 and termination_value is None and stop_value is None:
        join_v3 = joins[0].get("schema") == LIVE_JOIN_RECORD_SCHEMA_V3
        join = _closed(
            joins[0],
            (
                _JOIN_FIELDS_V3
                if joins[0].get("schema") == LIVE_JOIN_RECORD_SCHEMA_V3
                else _JOIN_FIELDS_V2
                if joins[0].get("schema") == LIVE_JOIN_RECORD_SCHEMA_V2
                else _JOIN_FIELDS
            ),
            "join",
            issues,
        )
        if not _seal_valid(join):
            _issue(issues, "join:seal_mismatch")
        if registration is not None and join.get("grant_sha256") != registration.get(
            "grant_sha256"
        ):
            _issue(issues, "join:grant_binding_mismatch")
        if start is not None and join.get("start_record_sha256") != start.get(
            "record_sha256"
        ):
            _issue(issues, "join:start_binding_mismatch")
        family_rows = [
            row["record"]
            for row in entries
            if row.get("record", {}).get("schema")
            in _LIVE_FAMILY_SUMMARY_RECORD_SCHEMAS
            and row.get("record", {}).get("campaign_sha256") == campaign_sha256
        ]
        summary_families = _expected_families(campaign, issues)
        if len(family_rows) != len(summary_families):
            _issue(issues, "join:family_summaries_incomplete")
        normalized_families: list[Mapping[str, Any]] = []
        for family, raw in zip(summary_families, family_rows):
            row = _closed(
                raw,
                (
                    _FAMILY_SUMMARY_FIELDS_V3
                    if raw.get("schema")
                    == LIVE_FAMILY_SUMMARY_RECORD_SCHEMA_V3
                    else _FAMILY_SUMMARY_FIELDS_V2
                    if raw.get("schema") == LIVE_FAMILY_SUMMARY_RECORD_SCHEMA_V2
                    else _FAMILY_SUMMARY_FIELDS
                ),
                "join.family",
                issues,
            )
            if not _seal_valid(row) or row.get("task_family") != family:
                _issue(issues, f"join:family_summary_invalid:{family}")
            normalized_families.append(row)
            counts = row.get("counts", {})
            family_projection = {
                "task_family": family,
                "state": row.get("state"),
                "expected_runs": counts.get("expected_runs"),
                "reserved_runs": counts.get("reserved_runs"),
                "completed_runs": counts.get("completed_runs"),
                "failed_runs": counts.get("failed_runs"),
                "missing_runs": counts.get("missing_runs"),
                "extrapolated_runs": counts.get("extrapolated_runs"),
                "configuration_results": row.get("configuration_results"),
                "observed_tokens": row.get("observed_tokens"),
                "live_model_calls": row.get("live_model_calls"),
                "hosted_calls": row.get("hosted_calls"),
            }
            if raw.get("schema") == LIVE_FAMILY_SUMMARY_RECORD_SCHEMA_V3:
                family_projection.update(
                    {
                    "well_formed_observed_tokens": row.get(
                        "well_formed_observed_tokens"
                    ),
                    "evidence_failure_observed_tokens": row.get(
                        "evidence_failure_observed_tokens"
                    ),
                    "evidence_failure_lane_sessions": row.get(
                        "evidence_failure_lane_sessions"
                    ),
                    "evidence_failure_cause_counts": row.get(
                        "evidence_failure_cause_counts"
                    ),
                    "reportable": row.get("reportable"),
                    "training_eligible": row.get("training_eligible"),
                    }
                )
            families.append(family_projection)
        if join.get("family_summary_record_sha256s") != [
            row.get("record_sha256") for row in normalized_families
        ]:
            _issue(issues, "join:family_summary_binding_mismatch")
        canonical_rows = [
            row["record"]
            for row in entries
            if row.get("record", {}).get("schema")
            in {
                LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA,
                LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA_V2,
            }
            and row.get("record", {}).get("campaign_sha256") == campaign_sha256
        ]
        normalized_canonical = [
            _closed(
                row,
                (
                    _CANONICAL_REPLICATE_FIELDS_V2
                    if row.get("schema")
                    == LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA_V2
                    else _CANONICAL_REPLICATE_FIELDS
                ),
                "join.replicate",
                issues,
            )
            for row in canonical_rows
        ]
        if any(not _seal_valid(row) for row in normalized_canonical):
            _issue(issues, "join:canonical_replicate_invalid")
        if join.get("canonical_replicate_record_sha256s") != [
            row.get("record_sha256") for row in normalized_canonical
        ]:
            _issue(issues, "join:canonical_replicate_binding_mismatch")
        replay_rows = {
            row["record"].get("record_sha256"): row["record"]
            for row in entries
            if row.get("record", {}).get("schema")
            == record_replay.MODEL_CALL_RECORD_SCHEMA
            and row.get("record", {}).get("campaign_sha256") == campaign_sha256
        }
        replay_hashes = join.get("replay_model_call_record_sha256s")
        if (
            not isinstance(replay_hashes, list)
            or any(value not in replay_rows for value in replay_hashes)
            or replay_hashes
            != [
                row.get("replay_model_call_record_sha256")
                for row in normalized_canonical
            ]
        ):
            _issue(issues, "join:replay_record_binding_mismatch")
        counts = join.get("counts", {})
        completed = len(normalized_canonical)
        failed = sum(row.get("outcome") == "failed" for row in normalized_canonical)
        if (
            not isinstance(counts, Mapping)
            or counts.get("expected_runs") != expected_run_count(campaign)
            or counts.get("completed_runs") != completed
            or counts.get("failed_runs") != failed
            or counts.get("missing_runs") != expected_run_count(campaign) - completed
            or sum(
                int(row.get("counts", {}).get("reserved_runs", 0))
                for row in normalized_families
            )
            != counts.get("reserved_runs")
        ):
            _issue(issues, "join:counts_mismatch")
        if join_v3:
            v3_count_fields = frozenset(
                {
                    "expected_runs",
                    "reserved_runs",
                    "completed_runs",
                    "failed_runs",
                    "missing_runs",
                    "settled_runs",
                    "evidence_failure_runs",
                    "malformed_runs",
                    "extrapolated_runs",
                }
            )
            if (
                not isinstance(counts, Mapping)
                or set(counts) != v3_count_fields
                or any(
                    not _integer(counts.get(field), minimum=0)
                    for field in v3_count_fields
                )
            ):
                _issue(issues, "join:v3_counts_invalid")
            else:
                if (
                    counts["evidence_failure_runs"] < 1
                    or counts["settled_runs"]
                    != counts["completed_runs"]
                    + counts["evidence_failure_runs"]
                    or counts["reserved_runs"] < counts["settled_runs"]
                    or counts["missing_runs"]
                    != counts["expected_runs"] - counts["completed_runs"]
                    or counts["extrapolated_runs"] != 0
                ):
                    _issue(issues, "join:v3_count_derivation_invalid")
            family_evidence_hashes: list[str] = []
            family_cause_counts: dict[str, int] = {}
            family_v3_invalid = False
            for row in normalized_families:
                row_counts = row.get("counts")
                row_hashes = row.get("evidence_failure_record_sha256s")
                row_causes = row.get("evidence_failure_cause_counts")
                if (
                    row.get("schema")
                    != LIVE_FAMILY_SUMMARY_RECORD_SCHEMA_V3
                    or not isinstance(row_counts, Mapping)
                    or set(row_counts) != v3_count_fields
                    or any(
                        not _integer(row_counts.get(field), minimum=0)
                        for field in v3_count_fields
                    )
                    or not isinstance(row_hashes, list)
                    or len(row_hashes) != len(set(row_hashes))
                    or any(not _sha_valid(value) for value in row_hashes)
                    or not isinstance(row_causes, Mapping)
                    or set(row_causes) - SETTLEABLE_EVIDENCE_FAILURE_CAUSES
                    or any(
                        not _integer(value, minimum=1)
                        for value in (
                            row_causes.values()
                            if isinstance(row_causes, Mapping)
                            else []
                        )
                    )
                    or row.get("reportable") is not False
                    or row.get("training_eligible") is not False
                    or not _integer(row.get("observed_tokens"), minimum=0)
                    or not _integer(
                        row.get("well_formed_observed_tokens"), minimum=0
                    )
                    or not _integer(
                        row.get("evidence_failure_observed_tokens"), minimum=0
                    )
                    or not _integer(
                        row.get("evidence_failure_lane_sessions"), minimum=0
                    )
                    or not _integer(row.get("live_model_calls"), minimum=0)
                ):
                    family_v3_invalid = True
                    continue
                if (
                    len(row_hashes) != row_counts["evidence_failure_runs"]
                    or sum(row_causes.values())
                    != row_counts["evidence_failure_runs"]
                    or row_counts["settled_runs"]
                    != row_counts["completed_runs"]
                    + row_counts["evidence_failure_runs"]
                    or row_counts["reserved_runs"] < row_counts["settled_runs"]
                    or row_counts["missing_runs"]
                    != row_counts["expected_runs"]
                    - row_counts["completed_runs"]
                    or row_counts["extrapolated_runs"] != 0
                    or row.get("state")
                    != (
                        "COMPLETE"
                        if row_counts["missing_runs"] == 0
                        else "INCOMPLETE"
                    )
                    or row.get("observed_tokens", 0)
                    < row.get("evidence_failure_observed_tokens", 0)
                    or row.get("live_model_calls", 0)
                    < row.get("evidence_failure_lane_sessions", 0)
                ):
                    family_v3_invalid = True
                family_evidence_hashes.extend(row_hashes)
                for cause, value in row_causes.items():
                    family_cause_counts[cause] = (
                        family_cause_counts.get(cause, 0) + value
                    )
            if family_v3_invalid:
                _issue(issues, "join:v3_family_summary_invalid")
            evidence_hashes = join.get("evidence_failure_record_sha256s")
            cause_counts = join.get("evidence_failure_cause_counts")
            if (
                not isinstance(evidence_hashes, list)
                or len(evidence_hashes) != len(set(evidence_hashes))
                or any(not _sha_valid(value) for value in evidence_hashes)
                or not isinstance(cause_counts, Mapping)
                or cause_counts != family_cause_counts
                or set(evidence_hashes) != set(family_evidence_hashes)
                or (
                    isinstance(counts, Mapping)
                    and len(evidence_hashes)
                    != counts.get("evidence_failure_runs")
                )
                or join.get("state") != "INCOMPLETE"
                or join.get("reportable") is not False
                or join.get("training_eligible") is not False
                or join.get("observed_tokens")
                != sum(
                    int(row.get("observed_tokens", 0))
                    for row in normalized_families
                )
                or join.get("well_formed_observed_tokens")
                != sum(
                    int(row.get("well_formed_observed_tokens", 0))
                    for row in normalized_families
                )
                or join.get("evidence_failure_observed_tokens")
                != sum(
                    int(row.get("evidence_failure_observed_tokens", 0))
                    for row in normalized_families
                )
                or join.get("evidence_failure_lane_sessions")
                != sum(
                    int(row.get("evidence_failure_lane_sessions", 0))
                    for row in normalized_families
                )
                or join.get("live_model_calls")
                != sum(
                    int(row.get("live_model_calls", 0))
                    for row in normalized_families
                )
            ):
                _issue(issues, "join:v3_projection_invalid")
        state = str(join.get("state"))
    terminal_value = stop_value if stop_value is not None else termination_value
    evidence_projection: dict[str, Any] = {}
    projection_source = (
        stop_value
        if stop_value is not None
        and stop_value.get("schema") == LIVE_STOP_RECORD_SCHEMA_V2
        else join
        if join is not None and join.get("schema") == LIVE_JOIN_RECORD_SCHEMA_V3
        else None
    )
    if projection_source is not None:
        evidence_projection = {
            "evidence_failure_record_sha256s": list(
                projection_source.get("evidence_failure_record_sha256s", [])
            ),
            "evidence_failure_observed_tokens": projection_source.get(
                "evidence_failure_observed_tokens"
            ),
            "evidence_failure_lane_sessions": projection_source.get(
                "evidence_failure_lane_sessions"
            ),
            "evidence_failure_cause_counts": dict(
                projection_source.get("evidence_failure_cause_counts", {})
            ),
        }
    return _base_report(
        status="FAIL" if issues else "PASS",
        state=state,
        issues=issues,
        campaign_sha256=campaign_sha256,
        expected_runs=expected_run_count(campaign),
        grant=dict(grant) if isinstance(grant, Mapping) else None,
        started_at_ms=started_at_ms,
        deadline_at_ms=deadline_at_ms,
        counts=(
            dict(terminal_value.get("counts", {}))
            if terminal_value is not None
            else dict(join.get("counts", {}))
            if join is not None
            else {
                "expected_runs": expected_run_count(campaign),
                "reserved_runs": 0,
                "completed_runs": 0,
                "failed_runs": 0,
                "missing_runs": expected_run_count(campaign),
            }
        ),
        families=families,
        observed_tokens=(
            terminal_value.get("observed_tokens")
            if terminal_value is not None
            else join.get("observed_tokens")
            if join is not None
            else 0
        ),
        well_formed_observed_tokens=(
            terminal_value.get("well_formed_observed_tokens")
            if terminal_value is not None
            and "well_formed_observed_tokens" in terminal_value
            else join.get("well_formed_observed_tokens")
            if join is not None
            else None
        ),
        live_model_calls=(
            terminal_value.get("live_model_calls")
            if terminal_value is not None
            else join.get("live_model_calls")
            if join is not None
            else 0
        ),
        replay_decidable=(
            list(terminal_value.get("replay_decidable", []))
            if terminal_value is not None
            else list(join.get("replay_decidable", []))
            if join is not None
            else []
        ),
        live_required=(
            list(terminal_value.get("live_required", []))
            if terminal_value is not None
            else list(join.get("live_required", []))
            if join is not None
            else []
        ),
        join_record_sha256=(join.get("record_sha256") if join is not None else None),
        termination_record_sha256=(
            termination_value.get("record_sha256")
            if termination_value is not None
            else None
        ),
        stop_record_sha256=(
            stop_value.get("record_sha256") if stop_value is not None else None
        ),
        terminated_at_ms=(
            termination_value.get("terminated_at_ms")
            if termination_value is not None
            else None
        ),
        stopped_at_ms=(
            stop_value.get("stopped_at_ms") if stop_value is not None else None
        ),
        calendar_wait_required=(
            stop_value.get("calendar_wait_required")
            if stop_value is not None
            else None
        ),
        early_termination=(
            termination_value.get("early_termination")
            if termination_value is not None
            else False
        ),
        reportable=(
            terminal_value.get("reportable")
            if terminal_value is not None
            else join.get("reportable")
            if join is not None
            else None
        ),
        training_eligible=(
            terminal_value.get("training_eligible")
            if terminal_value is not None
            else join.get("training_eligible")
            if join is not None
            else None
        ),
        termination_authority_id=(
            terminal_value.get("authority_id")
            if terminal_value is not None
            else None
        ),
        termination_authority_source_sha256=(
            terminal_value.get("authority_source_sha256")
            if terminal_value is not None
            else None
        ),
        termination_environment=(
            dict(terminal_value.get("environment", {}))
            if terminal_value is not None
            else None
        ),
        termination_limits=(
            dict(terminal_value.get("limits", {}))
            if terminal_value is not None
            else None
        ),
        material_risk=(
            terminal_value.get("material_risk")
            if terminal_value is not None
            else None
        ),
        recovery=(
            terminal_value.get("recovery")
            if terminal_value is not None
            else None
        ),
        quarantined_completion=(
            dict(termination_value.get("quarantined_completion", {}))
            if termination_value is not None
            else None
        ),
        attributable_sessions=(
            abort_value.get("attributable_sessions")
            if abort_value is not None
            else 0
        ),
        attributable_tokens=(
            abort_value.get("attributable_tokens") if abort_value is not None else 0
        ),
        overage_tokens=(
            abort_value.get("overage_tokens") if abort_value is not None else 0
        ),
        abort_record_sha256=(
            abort_value.get("record_sha256") if abort_value is not None else None
        ),
        **evidence_projection,
    )


def reserve_live_replicate(
    campaign: Any,
    canonical_ledger_path: str | Path,
    shard_path: str | Path,
    configuration_id: str,
    replicate_index: int,
    seed: int,
    *,
    reserved_at_ms: int,
    expected_canonical_ledger_sha256: str | None = None,
    expected_shard_sha256: str | None = None,
) -> dict[str, Any]:
    """Permanently charge one exact cell before its native creation calls."""

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["campaign:invalid"],
            campaign_sha256=(campaign.get("campaign_sha256") if isinstance(campaign, Mapping) else None),
        )
    digest = str(campaign.get("campaign_sha256"))
    canonical_entries, issues = _entries(canonical_ledger_path)
    head_facts = _verify_head_expectations(
        canonical_ledger_path,
        shard_path,
        expected_canonical_ledger_sha256,
        expected_shard_sha256,
        "reservation",
        issues,
    )
    registration = _campaign_registration(canonical_entries, digest)
    start = _campaign_start(canonical_entries, digest)
    if registration is None:
        _issue(issues, "campaign:registration_missing")
    if start is None:
        _issue(issues, "campaign:start_record_missing")
    elif not _seal_valid(start):
        _issue(issues, "campaign:start_record_invalid")
    _consult_campaign_fences(
        canonical_entries,
        digest,
        issues,
        stop_code="campaign:stopped",
        termination_code="campaign:owner_terminated",
        join_code="campaign:already_joined",
    )

    shard_entries, shard_issues = _entries(shard_path)
    issues.extend(shard_issues)
    headers = [
        row["record"]
        for row in shard_entries
        if row.get("record", {}).get("schema") == LIVE_SHARD_HEADER_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == digest
    ]
    if len(headers) != 1:
        _issue(issues, "shard:header_missing" if not headers else "shard:header_duplicate")
        header: Mapping[str, Any] = {}
    else:
        header = _closed(headers[0], _SHARD_HEADER_FIELDS, "shard.header", issues)
        if not _seal_valid(header):
            _issue(issues, "shard:header_invalid")
        if start is not None and header.get("start_record_sha256") != start.get("record_sha256"):
            _issue(issues, "shard:start_binding_mismatch")
        if registration is not None and header.get("registration_record_sha256") != registration.get("record_sha256"):
            _issue(issues, "shard:registration_binding_mismatch")

    configuration = _configuration(campaign, configuration_id)
    if configuration is None:
        _issue(issues, "reservation:configuration_unknown")
        parameters: dict[str, Any] = {}
    else:
        parameters = _parameter_map(configuration)
    if header and parameters.get("task_family") != header.get("task_family"):
        _issue(issues, "reservation:task_family_mismatch")
    seeds = campaign.get("seeds")
    if (
        type(replicate_index) is not int
        or replicate_index < 1
        or not isinstance(seeds, list)
        or replicate_index > len(seeds)
    ):
        _issue(issues, "reservation:replicate_index_invalid")
    elif seeds[replicate_index - 1] != seed:
        _issue(issues, "reservation:seed_index_mismatch")
    if not _integer(reserved_at_ms, minimum=0):
        _issue(issues, "reservation:reserved_at_ms_invalid")
    if (
        start is not None
        and type(start.get("started_at_ms")) is int
        and type(reserved_at_ms) is int
        and reserved_at_ms < start["started_at_ms"]
    ):
        _issue(issues, "reservation:time_regression")
    if (
        start is not None
        and type(start.get("deadline_at_ms")) is int
        and type(reserved_at_ms) is int
        and reserved_at_ms > start["deadline_at_ms"]
    ):
        _issue(issues, "grant:wall_time_exhausted")

    existing_reservations = [
        row["record"]
        for row in shard_entries
        if row.get("record", {}).get("schema") == LIVE_RESERVATION_RECORD_SCHEMA
    ]
    key = (configuration_id, replicate_index, seed)
    first_grid = campaign.get("configuration_grid", [])
    first_cell = (
        (
            first_grid[0].get("configuration_id"),
            1,
            campaign.get("seeds", [None])[0],
        )
        if first_grid and campaign.get("seeds")
        else None
    )
    if (
        registration is not None
        and registration.get("grant", {}).get("schema") == LIVE_GRANT_SCHEMA_V2
        and key == first_cell
        and start is not None
        and reserved_at_ms != start.get("started_at_ms")
    ):
        _issue(issues, "reservation:first_dispatch_clock_mismatch")
    settled_matches = [
        row
        for row in existing_reservations
        if (
            row.get("request", {}).get("configuration_id"),
            row.get("request", {}).get("replicate_index"),
            row.get("request", {}).get("seed"),
        )
        == key
    ]
    allocation = header.get("allocation") if isinstance(header, Mapping) else {}
    reserved_tokens = (
        _reservation_tokens_for_lane_count(
            registration.get("grant", {}), parameters.get("lane_count")
        )
        if isinstance(registration, Mapping)
        else None
    )
    if type(reserved_tokens) is not int or reserved_tokens <= 0:
        _issue(issues, "reservation:token_amount_invalid")
    if settled_matches:
        # C1: a byte-identical re-invocation replays to the settled record;
        # any difference keeps the fail-closed duplicate refusal.  Nothing
        # is re-dispatched or re-charged on replay.
        candidate = None
        replay_request: dict[str, Any] | None = None
        if (
            not issues
            and len(settled_matches) == 1
            and configuration is not None
            and start is not None
            and registration is not None
            and header
        ):
            replay_request = _request(
                campaign,
                configuration,
                replicate_index,
                seed,
                reserved_tokens=reserved_tokens,
                started_at_ms=int(start["started_at_ms"]),
                deadline_at_ms=int(start["deadline_at_ms"]),
            )
            candidate = _seal(
                {
                    "schema": LIVE_RESERVATION_RECORD_SCHEMA,
                    "campaign_sha256": digest,
                    "grant_sha256": registration["grant_sha256"],
                    "shard_header_sha256": header["record_sha256"],
                    "request": replay_request,
                    "request_sha256": replay_request["request_sha256"],
                    "reserved_at_ms": reserved_at_ms,
                    "reserved_tokens": reserved_tokens,
                    "permanently_charged": True,
                }
            )
        if candidate is not None and candidate == settled_matches[0]:
            return _base_report(
                status="PASS",
                state="REPLAYED",
                issues=[],
                campaign_sha256=digest,
                replayed=True,
                request=replay_request,
                reserved_tokens=reserved_tokens,
                reservation_record_sha256=candidate["record_sha256"],
                **({"verified_heads": head_facts} if head_facts else {}),
            )
        _issue(issues, "reservation:duplicate_cell")
    projected_runs = len(existing_reservations) + 1
    projected_tokens = sum(
        int(row.get("reserved_tokens", 0))
        for row in existing_reservations
        if type(row.get("reserved_tokens")) is int
    ) + (reserved_tokens if type(reserved_tokens) is int else 0)
    if isinstance(allocation, Mapping):
        if projected_runs > int(allocation.get("max_runs", 0)):
            _issue(issues, "grant:family_run_budget_exhausted")
        if projected_tokens > int(allocation.get("max_tokens", 0)):
            _issue(issues, "grant:family_token_budget_exhausted")
    if issues or configuration is None or start is None or registration is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=digest,
        )
    request = _request(
        campaign,
        configuration,
        replicate_index,
        seed,
        reserved_tokens=reserved_tokens,
        started_at_ms=int(start["started_at_ms"]),
        deadline_at_ms=int(start["deadline_at_ms"]),
    )
    record = _seal(
        {
            "schema": LIVE_RESERVATION_RECORD_SCHEMA,
            "campaign_sha256": digest,
            "grant_sha256": registration["grant_sha256"],
            "shard_header_sha256": header["record_sha256"],
            "request": request,
            "request_sha256": request["request_sha256"],
            "reserved_at_ms": reserved_at_ms,
            "reserved_tokens": reserved_tokens,
            "permanently_charged": True,
        }
    )
    receipt = _append(shard_path, record)
    if receipt is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["ledger:reservation_append_failed"],
            campaign_sha256=digest,
        )
    return _base_report(
        status="PASS",
        state="RESERVED",
        issues=[],
        campaign_sha256=digest,
        request=request,
        reserved_tokens=reserved_tokens,
        reservation_record_sha256=record["record_sha256"],
        chain_receipt=receipt,
        **({"verified_heads": head_facts} if head_facts else {}),
    )


def _governed_evidence(value: Any, issues: list[str]) -> Mapping[str, Any]:
    evidence = _closed(value, _GOVERNED_FIELDS, "governed", issues)
    if evidence.get("schema") != LIVE_GOVERNED_EVIDENCE_SCHEMA:
        _issue(issues, "governed:schema_invalid")
    if evidence.get("entrypoint") != sweep.GOVERNED_ENTRYPOINT:
        _issue(issues, "governed:entrypoint_invalid")
    if evidence.get("program_schema") != sweep.GOVERNED_PROGRAM_SCHEMA:
        _issue(issues, "governed:program_schema_invalid")
    if evidence.get("status") != "PASS":
        _issue(issues, "governed:not_passing")
    if evidence.get("governance_mode") != "governed":
        _issue(issues, "governed:mode_invalid")
    for field in (
        "admission_report_sha256",
        "plan_report_sha256",
        "spawn_wave_report_sha256",
        "custody_report_sha256",
        "trace_report_sha256",
    ):
        if not _sha_valid(evidence.get(field)):
            _issue(issues, f"governed:{field}_invalid")
    if evidence.get("custody_coverage") != "complete":
        _issue(issues, "governed:custody_incomplete")
    if evidence.get("evidence_tier") != "sealed-runtime":
        _issue(issues, "governed:evidence_tier_invalid")
    if evidence.get("terminally_qualified") is not True:
        _issue(issues, "governed:terminal_qualification_missing")
    return evidence


def _string_list(value: Any, label: str, issues: list[str]) -> list[str]:
    if not isinstance(value, list) or len(value) > PROFILE.max_array_items:
        _issue(issues, f"{label}:array_invalid")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not _identifier(item):
            _issue(issues, f"{label}[{index}]:invalid")
        else:
            result.append(str(item))
    if result != sorted(set(result)):
        _issue(issues, f"{label}:not_sorted_unique")
    return result


def _lane_result(
    request: Mapping[str, Any],
    assignments: Mapping[str, Mapping[str, Any]],
    value: Any,
    issues: list[str],
) -> Mapping[str, Any]:
    result = _closed(value, _LANE_RESULT_FIELDS, "lane_result", issues)
    if result.get("schema") != LIVE_LANE_RESULT_SCHEMA:
        _issue(issues, "lane_result:schema_invalid")
    lane_id = result.get("lane_id")
    assignment = assignments.get(str(lane_id))
    if assignment is None:
        _issue(issues, "lane_result:lane_unknown")
    else:
        if result.get("assignment_sha256") != assignment.get("assignment_sha256"):
            _issue(issues, "lane_result:assignment_mismatch")
    if result.get("request_sha256") != request.get("request_sha256"):
        _issue(issues, "lane_result:request_mismatch")
    findings = _string_list(result.get("findings"), "lane_result.findings", issues)
    unknowns = _string_list(result.get("unknowns"), "lane_result.unknowns", issues)
    if set(findings) & set(unknowns):
        _issue(issues, "lane_result:finding_unknown_overlap")
    if assignment is not None:
        item_ids = {
            str(item.get("id"))
            for item in assignment.get("task", {}).get("items", [])
            if isinstance(item, Mapping)
        }
        if not set(findings + unknowns).issubset(item_ids):
            _issue(issues, "lane_result:item_outside_assignment")
    return result


def _runtime_projection(
    result: Mapping[str, Any], value: Any, issues: list[str]
) -> Mapping[str, Any]:
    validation = routing.validate_session_runtime_observation(value)
    if validation.get("valid") is not True:
        _issue(issues, "runtime:observation_invalid")
        return {}
    observation = validation.get("normalized")
    if not isinstance(observation, Mapping):
        _issue(issues, "runtime:observation_invalid")
        return {}
    route = observation.get("route", {})
    if route.get("model") != "qwen-local/qwen-smart":
        _issue(issues, "runtime:model_mismatch")
    if route.get("effort") != "xhigh":
        _issue(issues, "runtime:effort_mismatch")
    if route.get("context_policy") != "none" or route.get("inherited_history") is not False:
        _issue(issues, "runtime:context_policy_mismatch")
    if observation.get("terminal_schema") != LIVE_LANE_RESULT_SCHEMA:
        _issue(issues, "runtime:terminal_schema_mismatch")
    if observation.get("terminal_json_sha256") != _sha256(result):
        _issue(issues, "runtime:terminal_result_mismatch")
    usage = observation.get("usage", {})
    if usage.get("status") != "observed":
        _issue(issues, "runtime:usage_unknown")
    if usage.get("tool_calls") != 0:
        _issue(issues, "runtime:tool_calls_forbidden")
    return {
        "lane_id": result.get("lane_id"),
        "session_id": route.get("session_id"),
        "model": route.get("model"),
        "effort": route.get("effort"),
        "source_sha256": observation.get("source_sha256"),
        "terminal_json_sha256": observation.get("terminal_json_sha256"),
        "usage": dict(usage) if isinstance(usage, Mapping) else {},
        "runtime_observation_sha256": observation.get("report_sha256"),
    }


def _score_live_results(
    request: Mapping[str, Any], lane_results: list[Mapping[str, Any]]
) -> tuple[dict[str, Any], str]:
    expected = set(expected_live_findings(request))
    observed = {
        str(finding)
        for result in lane_results
        for finding in result.get("findings", [])
    }
    if expected:
        earned = max(0, len(expected & observed) - len(observed - expected))
        numerator = (10_000 * earned) // len(expected)
    else:
        numerator = 10_000 if not observed else 0
    metric = {
        "name": request.get("metric"),
        "numerator": numerator,
        "denominator": 10_000,
    }
    return metric, "passed" if numerator >= 8_000 else "failed"


def _rederive_stored_completion(
    request: Mapping[str, Any],
    completion: Mapping[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    """Recompute score, usage, and projection bindings from a sealed record."""

    issues: list[str] = []
    scored_failure = (
        completion.get("schema") == LIVE_COMPLETION_RECORD_SCHEMA_V2
    )
    assignments_list = build_live_lane_assignments(request)
    assignments = {row["lane_id"]: row for row in assignments_list}
    malformed_rows = (
        completion.get("malformed_projections", []) if scored_failure else []
    )
    malformed_lane_ids = {
        str(row.get("lane_id"))
        for row in malformed_rows
        if isinstance(row, Mapping)
    }
    if scored_failure:
        if not malformed_rows or len(malformed_lane_ids) != len(malformed_rows):
            _issue(issues, "malformed_membership_invalid")
        if not malformed_lane_ids <= set(assignments):
            _issue(issues, "malformed_membership_invalid")
        for row in malformed_rows:
            if not isinstance(row, Mapping):
                _issue(issues, "malformed_projection_invalid")
                continue
            terminal = row.get("terminal_json")
            if not isinstance(terminal, Mapping) or (
                isinstance(terminal.get("schema"), str) and terminal.get("schema")
            ):
                _issue(issues, "malformed_projection_invalid")
            if row.get("terminal_json_sha256") != (
                _sha256(terminal) if isinstance(terminal, Mapping) else None
            ):
                _issue(issues, "malformed_projection_invalid")
            usage = row.get("usage")
            if not isinstance(usage, Mapping) or usage.get(
                "status"
            ) != "observed" or usage.get("tool_calls") != 0:
                _issue(issues, "malformed_projection_invalid")
            if row.get("observation_issues") != ["terminal:schema_missing"]:
                _issue(issues, "malformed_projection_invalid")
    scoring_assignments = {
        lane_id: assignment
        for lane_id, assignment in assignments.items()
        if lane_id not in malformed_lane_ids
    }
    raw_results = completion.get("lane_results")
    if not isinstance(raw_results, list) or len(raw_results) != len(
        scoring_assignments
    ):
        _issue(issues, "lane_results_membership_invalid")
        raw_results = []
    lane_results = [
        _lane_result(request, scoring_assignments, row, issues)
        for row in raw_results
    ]
    lane_ids = [row.get("lane_id") for row in lane_results]
    if set(lane_ids) != set(scoring_assignments) or len(lane_ids) != len(
        set(lane_ids)
    ):
        _issue(issues, "lane_results_membership_invalid")
    if scored_failure:
        derived_metric = {
            "name": request.get("metric"),
            "numerator": 0,
            "denominator": 10_000,
        }
        derived_outcome = "failed"
        if completion.get("evidence_class") != "malformed_terminal":
            _issue(issues, "malformed_projection_invalid")
    else:
        derived_metric, derived_outcome = _score_live_results(
            request, lane_results
        )
    score_valid = (
        completion.get("metric") == derived_metric
        and completion.get("outcome") == derived_outcome
    )
    if not score_valid:
        _issue(issues, "result_derivation_invalid")

    raw_projections = completion.get("runtime_projections")
    if not isinstance(raw_projections, list) or len(raw_projections) != len(
        lane_results
    ):
        _issue(issues, "runtime_membership_invalid")
        raw_projections = []
    results_by_lane = {str(row.get("lane_id")): row for row in lane_results}
    projections: list[dict[str, Any]] = []
    for raw in raw_projections:
        projection = _closed(
            raw, _RUNTIME_PROJECTION_FIELDS, "runtime_projection", issues
        )
        lane_id = str(projection.get("lane_id"))
        result = results_by_lane.get(lane_id)
        usage = _closed(projection.get("usage"), _USAGE_FIELDS, "usage", issues)
        numeric_fields = (
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "reasoning_tokens",
            "total_tokens",
            "tool_calls",
        )
        if (
            result is None
            or projection.get("model") != "qwen-local/qwen-smart"
            or projection.get("effort") != "xhigh"
            or not _identifier(projection.get("session_id"))
            or not _sha_valid(projection.get("source_sha256"))
            or not _sha_valid(projection.get("runtime_observation_sha256"))
            or projection.get("terminal_json_sha256")
            != (_sha256(result) if result is not None else None)
            or usage.get("status") != "observed"
            or any(
                type(usage.get(field)) is not int or usage.get(field, -1) < 0
                for field in numeric_fields
            )
        ):
            _issue(issues, "runtime_projection_invalid")
        elif (
            usage["cached_input_tokens"] > usage["input_tokens"]
            or usage["reasoning_tokens"] > usage["output_tokens"]
            or usage["total_tokens"]
            != usage["input_tokens"] + usage["output_tokens"]
            or usage["tool_calls"] != 0
        ):
            _issue(issues, "runtime_usage_invalid")
        projections.append(projection)
    projection_lane_ids = [row.get("lane_id") for row in projections]
    if set(projection_lane_ids) != set(scoring_assignments) or len(
        projection_lane_ids
    ) != len(set(projection_lane_ids)):
        _issue(issues, "runtime_membership_invalid")

    aggregate_fields = (
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
        "tool_calls",
    )
    derived_usage = {
        field: sum(
            int(row.get("usage", {}).get(field, 0))
            for row in (*projections, *malformed_rows)
            if isinstance(row, Mapping)
            and type(row.get("usage", {}).get(field)) is int
        )
        for field in aggregate_fields
    }
    if completion.get("usage") != derived_usage:
        _issue(issues, "usage_derivation_invalid")
    timing = _closed(completion.get("timing"), _TIMING_FIELDS, "timing", issues)
    if (
        type(timing.get("reserved_at_ms")) is not int
        or type(timing.get("completed_at_ms")) is not int
        or type(timing.get("wall_time_ms")) is not int
        or (
            type(timing.get("reserved_at_ms")) is int
            and type(timing.get("completed_at_ms")) is int
            and type(timing.get("wall_time_ms")) is int
            and timing["wall_time_ms"]
            != timing["completed_at_ms"] - timing["reserved_at_ms"]
        )
    ):
        _issue(issues, "timing_derivation_invalid")
    session_total = len(projections) + len(malformed_rows)
    if completion.get("model_calls") != session_total:
        _issue(issues, "model_call_count_invalid")
    return issues, {
        "metric": derived_metric,
        "outcome": derived_outcome,
        "usage": derived_usage,
        "model_calls": session_total,
    }


def _malformed_lane_projection(
    request: Mapping[str, Any],
    assignments: Mapping[str, Mapping[str, Any]],
    value: Any,
    issues: list[str],
) -> Mapping[str, Any]:
    """Validate one well-observed lane whose terminal omitted its schema."""

    row = _closed(value, _MALFORMED_LANE_FIELDS, "malformed", issues)
    lane_id = str(row.get("lane_id"))
    assignment = assignments.get(lane_id)
    if assignment is None:
        _issue(issues, "malformed:lane_unknown")
        return {}
    terminal = row.get("terminal_json")
    if not isinstance(terminal, Mapping):
        _issue(issues, "malformed:terminal_json_invalid")
        return {}
    if isinstance(terminal.get("schema"), str) and terminal.get("schema"):
        _issue(issues, "malformed:lane_actually_valid")
    observation = _closed(
        row.get("runtime_observation"),
        _RUNTIME_OBSERVATION_FIELDS,
        "malformed.observation",
        issues,
    )
    sealed = {
        key: observation.get(key)
        for key in _RUNTIME_OBSERVATION_FIELDS
        if key != "report_sha256"
    }
    if not _sha_valid(observation.get("report_sha256")) or observation.get(
        "report_sha256"
    ) != _sha256(sealed):
        _issue(issues, "malformed:observation_seal_mismatch")
    if observation.get("status") != "FAIL" or observation.get("issues") != [
        "terminal:schema_missing"
    ]:
        _issue(issues, "malformed:observation_not_schema_missing")
    if (
        observation.get("evidence_tier") != "runtime-observed"
        or observation.get("provider_free") is not True
        or observation.get("model_calls") != 0
        or observation.get("hosted_calls") != 0
        or observation.get("skipped_lines") != 0
    ):
        _issue(issues, "malformed:observation_boundary_invalid")
    route = observation.get("route")
    route_value = route if isinstance(route, Mapping) else {}
    if route_value.get("model") != "qwen-local/qwen-smart":
        _issue(issues, "malformed:model_mismatch")
    if route_value.get("effort") != "xhigh":
        _issue(issues, "malformed:effort_mismatch")
    if (
        route_value.get("context_policy") != "none"
        or route_value.get("inherited_history") is not False
    ):
        _issue(issues, "malformed:context_policy_mismatch")
    if observation.get("terminal_json_sha256") != _sha256(terminal):
        _issue(issues, "malformed:terminal_result_mismatch")
    usage = observation.get("usage")
    usage_value = usage if isinstance(usage, Mapping) else {}
    if usage_value.get("status") != "observed":
        _issue(issues, "malformed:usage_unknown")
    if usage_value.get("tool_calls") != 0:
        _issue(issues, "malformed:tool_calls_forbidden")
    return {
        "lane_id": lane_id,
        "session_id": route_value.get("session_id"),
        "model": route_value.get("model"),
        "effort": route_value.get("effort"),
        "source_sha256": observation.get("source_sha256"),
        "terminal_json_sha256": observation.get("terminal_json_sha256"),
        "terminal_json": dict(terminal),
        "usage": dict(usage_value),
        "runtime_observation_sha256": observation.get("report_sha256"),
        "observation_issues": list(observation.get("issues", [])),
    }


def _terminal_evidence_failure_projection(
    lane_id: str,
    value: Any,
    failure_cause: str,
    issues: list[str],
    *,
    usage_settlement: bool = False,
) -> Mapping[str, Any]:
    """Validate exact route/usage evidence without trusting terminal content."""

    observation = _closed(
        value,
        _RUNTIME_OBSERVATION_FIELDS,
        "evidence_failure.observation",
        issues,
    )
    sealed = {
        key: observation.get(key)
        for key in _RUNTIME_OBSERVATION_FIELDS
        if key != "report_sha256"
    }
    if not _sha_valid(observation.get("report_sha256")) or observation.get(
        "report_sha256"
    ) != _sha256(sealed):
        _issue(issues, "evidence_failure:observation_seal_mismatch")
    if observation.get("schema") != routing.SESSION_RUNTIME_OBSERVATION_SCHEMA:
        _issue(issues, "evidence_failure:observation_schema_invalid")
    observation_issues = observation.get("issues")
    if observation.get("status") == "PASS":
        if observation_issues != []:
            _issue(issues, "evidence_failure:passing_observation_has_issues")
        if observation.get("terminal_schema") != LIVE_LANE_RESULT_SCHEMA:
            _issue(issues, "evidence_failure:passing_terminal_schema_invalid")
        validation = routing.validate_session_runtime_observation(observation)
        if validation.get("status") != "PASS":
            _issue(issues, "evidence_failure:passing_observation_invalid")
    elif observation.get("status") == "FAIL":
        if observation_issues != [failure_cause]:
            _issue(issues, "evidence_failure:cause_mismatch")
    else:
        _issue(issues, "evidence_failure:observation_status_invalid")
    if (
        observation.get("evidence_tier") != "runtime-observed"
        or observation.get("provider_free") is not True
        or observation.get("model_calls") != 0
        or observation.get("hosted_calls") != 0
        or observation.get("skipped_lines") != 0
    ):
        _issue(issues, "evidence_failure:observation_boundary_invalid")
    route_value = _closed(
        observation.get("route"),
        _RUNTIME_ROUTE_FIELDS,
        "evidence_failure.route",
        issues,
    )
    if route_value.get("model") != "qwen-local/qwen-smart":
        _issue(issues, "evidence_failure:model_mismatch")
    if route_value.get("effort") != "xhigh":
        _issue(issues, "evidence_failure:effort_mismatch")
    if (
        route_value.get("context_policy") != "none"
        or route_value.get("inherited_history") is not False
    ):
        _issue(issues, "evidence_failure:context_policy_mismatch")
    if not _identifier(route_value.get("session_id")):
        _issue(issues, "evidence_failure:session_id_invalid")
    observer_id = observation.get("observer_id")
    if (
        not _identifier(observer_id)
        or observer_id == route_value.get("session_id")
    ):
        _issue(issues, "evidence_failure:observer_invalid")
    if observation.get("source_pointer") != (
        f"session://{route_value.get('session_id')}"
    ):
        _issue(issues, "evidence_failure:source_pointer_invalid")
    if not _sha_valid(observation.get("source_sha256")):
        _issue(issues, "evidence_failure:source_sha256_invalid")
    terminal_record = _closed(
        observation.get("terminal_record"),
        _RUNTIME_POINTER_RECORD_FIELDS,
        "evidence_failure.terminal_record",
        issues,
    )
    terminal_schema = observation.get("terminal_schema")
    terminal_sha256 = observation.get("terminal_json_sha256")
    terminal_line = terminal_record.get("line")
    terminal_record_sha256 = terminal_record.get("sha256")
    if (
        observation.get("status") == "FAIL"
        and failure_cause == "terminal:json_missing"
    ):
        if any(
            value is not None
            for value in (
                terminal_schema,
                terminal_sha256,
                terminal_line,
                terminal_record_sha256,
            )
        ):
            _issue(issues, "evidence_failure:missing_terminal_facts_invalid")
    elif (
        observation.get("status") == "FAIL"
        and failure_cause == "terminal:not_closed_json_object"
    ):
        if (
            terminal_schema is not None
            or terminal_sha256 is not None
            or not _integer(terminal_line, minimum=1)
            or not _sha_valid(terminal_record_sha256)
        ):
            _issue(issues, "evidence_failure:unclosed_terminal_facts_invalid")
    elif (
        observation.get("status") == "FAIL"
        and failure_cause == "terminal:conflicting_records"
    ):
        if (
            terminal_schema != LIVE_LANE_RESULT_SCHEMA
            or not _sha_valid(terminal_sha256)
            or not _integer(terminal_line, minimum=1)
            or not _sha_valid(terminal_record_sha256)
        ):
            _issue(issues, "evidence_failure:conflicting_terminal_facts_invalid")
    usage = observation.get("usage")
    usage_value = _closed(
        usage, _USAGE_FIELDS, "evidence_failure.usage", issues
    )
    numeric_usage = (
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
        "tool_calls",
    )
    if usage_settlement:
        # Issue 123: the settlement cause IS unreadable accounting, so the
        # lane that exhibits it must report unknown usage with every
        # numeric field absent.  A lane whose usage was in fact observed
        # cannot settle here -- the cause-observation check below refuses
        # it -- so this branch never widens what may settle.
        if usage_value.get("status") == "unknown":
            if any(
                usage_value.get(field) is not None
                for field in numeric_usage
            ):
                _issue(issues, "evidence_failure:unknown_usage_not_empty")
        elif usage_value.get("status") != "observed" or any(
            not _integer(usage_value.get(field), minimum=0)
            for field in numeric_usage
        ):
            _issue(issues, "evidence_failure:usage_unknown")
        elif usage_value.get("tool_calls") != 0:
            _issue(issues, "evidence_failure:tool_calls_forbidden")
    elif usage_value.get("status") != "observed" or any(
        not _integer(usage_value.get(field), minimum=0) for field in numeric_usage
    ):
        _issue(issues, "evidence_failure:usage_unknown")
    elif (
        usage_value["cached_input_tokens"] > usage_value["input_tokens"]
        or usage_value["reasoning_tokens"] > usage_value["output_tokens"]
        or usage_value["total_tokens"]
        != usage_value["input_tokens"] + usage_value["output_tokens"]
    ):
        _issue(issues, "evidence_failure:usage_arithmetic_invalid")
    if not usage_settlement and usage_value.get("tool_calls") != 0:
        _issue(issues, "evidence_failure:tool_calls_forbidden")
    usage_record = _closed(
        observation.get("usage_record"),
        _RUNTIME_POINTER_RECORD_FIELDS,
        "evidence_failure.usage_record",
        issues,
    )
    if usage_settlement and usage_value.get("status") == "unknown":
        # A missing accounting record is the observed condition itself.
        # ``usage:exact_record_missing`` leaves both pointer fields null;
        # ``usage:exact_record_invalid`` read a real record, so the pointer
        # is present and must still be a well-formed digest. Any other
        # shape refuses.
        line = usage_record.get("line")
        sha256 = usage_record.get("sha256")
        if line is None and sha256 is None:
            pass
        elif not _integer(line, minimum=1) or not _sha_valid(sha256):
            _issue(issues, "evidence_failure:usage_record_invalid")
    elif (
        not _integer(usage_record.get("line"), minimum=1)
        or not _sha_valid(usage_record.get("sha256"))
    ):
        _issue(issues, "evidence_failure:usage_record_invalid")
    return {
        "lane_id": lane_id,
        "session_id": route_value.get("session_id"),
        "model": route_value.get("model"),
        "effort": route_value.get("effort"),
        "source_sha256": observation.get("source_sha256"),
        "terminal_json_sha256": observation.get("terminal_json_sha256"),
        "usage": dict(usage_value),
        "runtime_observation_sha256": observation.get("report_sha256"),
        "observation_issues": list(observation_issues or []),
    }


def _validate_stored_evidence_failure(
    record: Any,
    reservations_by_sha: Mapping[str, Mapping[str, Any]],
    task_family: str,
    issues: list[str],
    *,
    label: str,
) -> Mapping[str, Any]:
    stored_schema = (
        record.get("schema") if isinstance(record, Mapping) else None
    )
    stable_record = stored_schema == LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA_V2
    usage_record_settlement = (
        stored_schema == LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA_V3
    )
    stored_aux = (
        stable_record
        and isinstance(record, Mapping)
        and _EVIDENCE_FAILURE_AUX_FIELD in record
    )
    value = _closed(
        record,
        (
            _EVIDENCE_FAILURE_RECORD_FIELDS_V2
            | {_EVIDENCE_FAILURE_AUX_FIELD}
            if stored_aux
            else _EVIDENCE_FAILURE_RECORD_FIELDS_V2
        )
        if stable_record
        else _EVIDENCE_FAILURE_RECORD_FIELDS_V3
        if usage_record_settlement
        else _EVIDENCE_FAILURE_RECORD_FIELDS,
        label,
        issues,
    )
    if stored_aux:
        _validate_aux_process_samples(
            value.get(_EVIDENCE_FAILURE_AUX_FIELD), issues
        )
    if not _seal_valid(value):
        _issue(issues, f"{label}:seal_mismatch")
    reservation = reservations_by_sha.get(
        str(value.get("reservation_record_sha256"))
    )
    if reservation is None:
        _issue(issues, f"{label}:reservation_missing")
        return value
    request = reservation.get("request", {})
    expected_cause_set = (
        {STABLE_TERMINAL_FAILURE_CAUSE}
        if stable_record
        else SETTLEABLE_USAGE_FAILURE_CAUSES
        if usage_record_settlement
        else _CONTINUABLE_TERMINAL_FAILURE_CAUSES
    )
    if (
        stored_schema not in _EVIDENCE_FAILURE_RECORD_SCHEMAS
        or value.get("campaign_sha256") != reservation.get("campaign_sha256")
        or value.get("grant_sha256") != reservation.get("grant_sha256")
        or value.get("task_family") != task_family
        or value.get("request") != request
        or value.get("request_sha256") != reservation.get("request_sha256")
        or value.get("failure_cause")
        not in expected_cause_set
        or value.get("evidence_class")
        != (
            "untrustworthy_usage"
            if usage_record_settlement
            else "untrustworthy_terminal"
        )
        or value.get("score_available") is not False
        or value.get("outcome_available") is not False
        or value.get("hosted_calls") != 0
        or value.get("automatic_retries") != 0
        or value.get("automatic_fallbacks") != 0
        or value.get("automatic_replacements") != 0
        or (
            usage_record_settlement
            and value.get("usage_available") is not False
        )
    ):
        _issue(issues, f"{label}:binding_invalid")
    if stable_record:
        stability = _closed(
            value.get("stability"),
            _EVIDENCE_FAILURE_STABILITY_FIELDS,
            f"{label}.stability",
            issues,
        )
        interval_ms = stability.get("interval_ms")
        if (
            not _sha_valid(stability.get("first_source_sha256"))
            or stability.get("first_source_sha256")
            != stability.get("second_source_sha256")
            or not _sha_valid(stability.get("first_report_sha256"))
            or not _sha_valid(stability.get("second_report_sha256"))
            or not _sha_valid(stability.get("derivation_sha256"))
            or not _integer(stability.get("first_observed_at_ms"), minimum=0)
            or not _integer(stability.get("second_observed_at_ms"), minimum=0)
            or not _integer(
                interval_ms, minimum=routing.TERMINAL_ABSENCE_GRACE_FLOOR_MS
            )
            or stability.get("grace_floor_ms")
            != routing.TERMINAL_ABSENCE_GRACE_FLOOR_MS
            or interval_ms
            != stability.get("second_observed_at_ms", 0)
            - stability.get("first_observed_at_ms", 0)
        ):
            _issue(issues, f"{label}:stability_facts_invalid")
    projections = value.get("runtime_projections")
    if not isinstance(projections, list):
        _issue(issues, f"{label}:runtime_projections_invalid")
        projections = []
    normalized = [
        _closed(
            row,
            _EVIDENCE_FAILURE_PROJECTION_FIELDS,
            f"{label}.projection",
            issues,
        )
        for row in projections
    ]
    expected_lane_ids = {
        row["lane_id"] for row in build_live_lane_assignments(request)
    }
    lane_ids = [row.get("lane_id") for row in normalized]
    session_ids = [row.get("session_id") for row in normalized]
    if (
        set(lane_ids) != expected_lane_ids
        or len(lane_ids) != len(set(lane_ids))
        or len(session_ids) != len(set(session_ids))
    ):
        _issue(issues, f"{label}:runtime_membership_invalid")
    cause = value.get("failure_cause")
    observed_cause = _observed_failure_cause(cause)
    if not any(
        row.get("observation_issues") == [observed_cause] for row in normalized
    ):
        _issue(issues, f"{label}:cause_observation_missing")
    if any(
        row.get("observation_issues") not in ([], [observed_cause])
        for row in normalized
    ):
        _issue(issues, f"{label}:projection_issue_invalid")
    projection_usage_fields = tuple(sorted(_USAGE_FIELDS - {"status"}))
    for row in normalized:
        projection_usage = _closed(
            row.get("usage"),
            _USAGE_FIELDS,
            f"{label}.projection.usage",
            issues,
        )
        if (
            row.get("model") != "qwen-local/qwen-smart"
            or row.get("effort") != "xhigh"
            or not _identifier(row.get("session_id"))
            or not _sha_valid(row.get("source_sha256"))
            or not _sha_valid(row.get("runtime_observation_sha256"))
        ):
            _issue(issues, f"{label}:projection_invalid")
        unknown_lane = (
            usage_record_settlement
            and projection_usage.get("status") == "unknown"
        )
        if unknown_lane:
            # The lane that exhibited the cause reports no accounting at
            # all; every numeric field must be absent rather than zeroed.
            if any(
                projection_usage.get(field) is not None
                for field in projection_usage_fields
            ):
                _issue(issues, f"{label}:unknown_usage_not_empty")
        elif projection_usage.get("status") != "observed" or any(
            not _integer(projection_usage.get(field), minimum=0)
            for field in projection_usage_fields
        ):
            _issue(issues, f"{label}:projection_invalid")
        elif (
            projection_usage["cached_input_tokens"]
            > projection_usage["input_tokens"]
            or projection_usage["reasoning_tokens"]
            > projection_usage["output_tokens"]
            or projection_usage["total_tokens"]
            != projection_usage["input_tokens"]
            + projection_usage["output_tokens"]
            or projection_usage["tool_calls"] != 0
        ):
            _issue(issues, f"{label}:projection_usage_invalid")
        projection_issues = row.get("observation_issues")
        terminal_sha256 = row.get("terminal_json_sha256")
        if projection_issues == [] and not _sha_valid(terminal_sha256):
            _issue(issues, f"{label}:passing_projection_terminal_invalid")
        if (
            not usage_record_settlement
            and projection_issues == [observed_cause]
        ) and (
            (
                observed_cause == "terminal:conflicting_records"
                and not _sha_valid(terminal_sha256)
            )
            or (
                observed_cause != "terminal:conflicting_records"
                and terminal_sha256 is not None
            )
        ):
            _issue(issues, f"{label}:failed_projection_terminal_invalid")
        if usage_record_settlement and not _sha_valid(terminal_sha256):
            # A usage settlement leaves the terminal intact by
            # definition, so every lane must still carry its digest.
            _issue(issues, f"{label}:usage_settlement_terminal_missing")
    usage = value.get("usage")
    if usage_record_settlement:
        # v3 seals the UNKNOWN sentinel in place of the aggregate: any
        # mapping here would assert an accounting the ledger never had.
        if usage != UNKNOWN_USAGE:
            _issue(issues, f"{label}:usage_not_unknown")
        usage_value = None
    else:
        usage_value = _closed(
            usage, _AGGREGATE_USAGE_FIELDS, f"{label}.usage", issues
        )
    usage_fields = tuple(sorted(_AGGREGATE_USAGE_FIELDS))
    derived_usage = {
        field: sum(
            int(row.get("usage", {}).get(field, 0))
            for row in normalized
            if type(row.get("usage", {}).get(field)) is int
        )
        for field in usage_fields
    }
    if value.get("model_calls") != len(normalized):
        _issue(issues, f"{label}:usage_mismatch")
    elif not usage_record_settlement and usage_value != derived_usage:
        _issue(issues, f"{label}:usage_mismatch")
    timing = value.get("timing")
    timing_value = _closed(
        timing,
        frozenset({"reserved_at_ms", "failed_at_ms", "wall_time_ms"}),
        f"{label}.timing",
        issues,
    )
    if (
        timing_value.get("reserved_at_ms") != reservation.get("reserved_at_ms")
        or not _integer(timing_value.get("failed_at_ms"), minimum=0)
        or timing_value.get("wall_time_ms")
        != timing_value.get("failed_at_ms", 0)
        - reservation.get("reserved_at_ms", 0)
        or timing_value.get("failed_at_ms", 0)
        > request.get("deadline_at_ms", -1)
        or derived_usage["total_tokens"] > reservation.get("reserved_tokens", -1)
    ):
        _issue(issues, f"{label}:timing_or_budget_invalid")
    return value


def record_live_evidence_failure(
    campaign: Any,
    canonical_ledger_path: str | Path,
    shard_path: str | Path,
    evidence_failure: Any,
    *,
    failed_at_ms: int,
    expected_canonical_ledger_sha256: str | None = None,
    expected_shard_sha256: str | None = None,
) -> dict[str, Any]:
    """Settle one exact reservation without score when terminal trust fails."""

    return _record_live_evidence_failure(
        campaign,
        canonical_ledger_path,
        shard_path,
        evidence_failure,
        failed_at_ms=failed_at_ms,
        expected_canonical_ledger_sha256=expected_canonical_ledger_sha256,
        expected_shard_sha256=expected_shard_sha256,
    )


def _validate_stability_derivation(
    derivation: Any,
    projections: list[Mapping[str, Any]],
    *,
    observed_cause: str,
    failed_at_ms: Any,
    issues: list[str],
) -> dict[str, Any] | None:
    """Bind a sealed two-sample stability derivation to the failing lane."""

    if (
        not isinstance(derivation, Mapping)
        or derivation.get("schema")
        != routing.TERMINAL_ABSENCE_STABILITY_SCHEMA
    ):
        _issue(issues, "evidence_failure:stability_derivation_invalid")
        return None
    if not _seal_valid(derivation, "report_sha256"):
        _issue(issues, "evidence_failure:stability_seal_invalid")
        return None
    if (
        derivation.get("status") != "PASS"
        or derivation.get("issues") != []
        or derivation.get("classification") != routing.STABLE_ABSENCE
        or derivation.get("provider_free") is not True
        or derivation.get("model_calls") != 0
        or derivation.get("hosted_calls") != 0
        or derivation.get("grace_floor_ms")
        != routing.TERMINAL_ABSENCE_GRACE_FLOOR_MS
    ):
        _issue(issues, "evidence_failure:stability_derivation_invalid")
        return None
    first = derivation.get("first")
    second = derivation.get("second")
    if not isinstance(first, Mapping) or not isinstance(second, Mapping):
        _issue(issues, "evidence_failure:stability_derivation_invalid")
        return None
    failing = [
        row
        for row in projections
        if row.get("observation_issues") == [observed_cause]
    ]
    bound = any(
        row.get("session_id") == derivation.get("session_id")
        and row.get("source_sha256") == first.get("source_sha256")
        and row.get("runtime_observation_sha256")
        == first.get("report_sha256")
        for row in failing
    )
    if not bound:
        _issue(issues, "evidence_failure:stability_binding_invalid")
        return None
    second_at = second.get("observed_at_ms")
    if (
        not _integer(second_at, minimum=0)
        or not _integer(failed_at_ms, minimum=0)
        or failed_at_ms < second_at
    ):
        _issue(issues, "evidence_failure:stability_time_invalid")
        return None
    return {
        "first_source_sha256": first.get("source_sha256"),
        "second_source_sha256": second.get("source_sha256"),
        "first_report_sha256": first.get("report_sha256"),
        "second_report_sha256": second.get("report_sha256"),
        "first_observed_at_ms": first.get("observed_at_ms"),
        "second_observed_at_ms": second_at,
        "interval_ms": derivation.get("interval_ms"),
        "grace_floor_ms": derivation.get("grace_floor_ms"),
        "derivation_sha256": derivation.get("report_sha256"),
    }


def _record_live_evidence_failure(
    campaign: Any,
    canonical_ledger_path: str | Path,
    shard_path: str | Path,
    evidence_failure: Any,
    *,
    failed_at_ms: int,
    expected_canonical_ledger_sha256: str | None = None,
    expected_shard_sha256: str | None = None,
) -> dict[str, Any]:
    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["campaign:invalid"],
            campaign_sha256=(
                campaign.get("campaign_sha256")
                if isinstance(campaign, Mapping)
                else None
            ),
        )
    digest = str(campaign.get("campaign_sha256"))
    issues: list[str] = []
    draft_schema = (
        evidence_failure.get("schema")
        if isinstance(evidence_failure, Mapping)
        else None
    )
    stable_draft = draft_schema == LIVE_EVIDENCE_FAILURE_DRAFT_SCHEMA_V2
    usage_draft = draft_schema == LIVE_EVIDENCE_FAILURE_DRAFT_SCHEMA_V3
    aux_supplied = (
        stable_draft
        and isinstance(evidence_failure, Mapping)
        and _EVIDENCE_FAILURE_AUX_FIELD in evidence_failure
    )
    draft = _closed(
        evidence_failure,
        (
            _EVIDENCE_FAILURE_DRAFT_FIELDS_V2 | {_EVIDENCE_FAILURE_AUX_FIELD}
            if aux_supplied
            else _EVIDENCE_FAILURE_DRAFT_FIELDS_V2
        )
        if stable_draft
        else _EVIDENCE_FAILURE_DRAFT_FIELDS_V3
        if usage_draft
        else _EVIDENCE_FAILURE_DRAFT_FIELDS,
        "evidence_failure",
        issues,
    )
    if draft_schema not in (
        LIVE_EVIDENCE_FAILURE_DRAFT_SCHEMA,
        LIVE_EVIDENCE_FAILURE_DRAFT_SCHEMA_V2,
        LIVE_EVIDENCE_FAILURE_DRAFT_SCHEMA_V3,
    ):
        _issue(issues, "evidence_failure:schema_invalid")
    cause = draft.get("failure_cause")
    if stable_draft:
        if cause != STABLE_TERMINAL_FAILURE_CAUSE:
            _issue(issues, "evidence_failure:v2_cause_invalid")
    elif usage_draft:
        if cause not in SETTLEABLE_USAGE_FAILURE_CAUSES:
            _issue(issues, "evidence_failure:v3_cause_invalid")
    elif cause not in _CONTINUABLE_TERMINAL_FAILURE_CAUSES:
        _issue(issues, "evidence_failure:cause_not_continuable")
    canonical_entries, canonical_issues = _entries(canonical_ledger_path)
    issues.extend(canonical_issues)
    head_facts = _verify_head_expectations(
        canonical_ledger_path,
        shard_path,
        expected_canonical_ledger_sha256,
        expected_shard_sha256,
        "evidence_failure",
        issues,
    )
    registration = _campaign_registration(canonical_entries, digest)
    start = _campaign_start(canonical_entries, digest)
    if registration is None:
        _issue(issues, "campaign:registration_missing")
    else:
        registration = _validate_registration(registration, digest, issues)
        if registration.get("grant", {}).get("schema") not in {
            LIVE_GRANT_SCHEMA_V4,
            LIVE_GRANT_SCHEMA_V5,
        }:
            _issue(issues, "evidence_failure:parameterized_grant_required")
    if start is None:
        _issue(issues, "campaign:start_record_missing")
    else:
        start = _closed(start, _START_FIELDS, "evidence_failure.start", issues)
        if (
            not _seal_valid(start)
            or start.get("campaign_sha256") != digest
            or registration is None
            or start.get("grant_sha256") != registration.get("grant_sha256")
            or start.get("registration_record_sha256")
            != registration.get("record_sha256")
        ):
            _issue(issues, "evidence_failure:start_record_invalid")
    _consult_campaign_fences(
        canonical_entries,
        digest,
        issues,
        stop_code="campaign:stopped",
        termination_code="campaign:owner_terminated",
        join_code="campaign:already_joined",
    )
    shard_entries, shard_issues = _entries(shard_path)
    issues.extend(shard_issues)
    headers = [
        row["record"]
        for row in shard_entries
        if row.get("record", {}).get("schema") == LIVE_SHARD_HEADER_SCHEMA
    ]
    if len(headers) != 1:
        _issue(issues, "evidence_failure:shard_header_invalid")
        header: Mapping[str, Any] = {}
    else:
        header = _closed(
            headers[0],
            _SHARD_HEADER_FIELDS,
            "evidence_failure.shard_header",
            issues,
        )
        if (
            not _seal_valid(header)
            or header.get("campaign_sha256") != digest
            or registration is None
            or header.get("grant_sha256") != registration.get("grant_sha256")
            or start is None
            or header.get("start_record_sha256") != start.get("record_sha256")
        ):
            _issue(issues, "evidence_failure:shard_header_binding_invalid")
    reservations = [
        row["record"]
        for row in shard_entries
        if row.get("record", {}).get("schema") == LIVE_RESERVATION_RECORD_SCHEMA
    ]
    matches = [
        row
        for row in reservations
        if row.get("record_sha256") == draft.get("reservation_record_sha256")
    ]
    if len(matches) != 1:
        _issue(issues, "evidence_failure:reservation_missing")
        reservation: Mapping[str, Any] = {}
        request: Mapping[str, Any] = {}
    else:
        reservation = matches[0]
        if not _seal_valid(reservation):
            _issue(issues, "evidence_failure:reservation_invalid")
        request = _validate_request(reservation.get("request"), issues)
        if draft.get("request_sha256") != request.get("request_sha256"):
            _issue(issues, "evidence_failure:request_mismatch")
        if (
            reservation.get("campaign_sha256") != digest
            or registration is None
            or reservation.get("grant_sha256")
            != registration.get("grant_sha256")
            or reservation.get("shard_header_sha256")
            != header.get("record_sha256")
            or request.get("task_family") != header.get("task_family")
            or reservation.get("reserved_tokens")
            != _reservation_tokens_for_lane_count(
                registration.get("grant", {}), request.get("lane_count")
            )
            or reservation.get("permanently_charged") is not True
        ):
            _issue(issues, "evidence_failure:reservation_binding_invalid")
    if any(
        row.get("record", {}).get("schema")
        in {LIVE_COMPLETION_RECORD_SCHEMA, LIVE_COMPLETION_RECORD_SCHEMA_V2}
        and row.get("record", {}).get("request_sha256")
        == draft.get("request_sha256")
        for row in shard_entries
    ):
        _issue(issues, "evidence_failure:duplicate_cell")
    settled_failures = [
        row["record"]
        for row in shard_entries
        if row.get("record", {}).get("schema")
        in _EVIDENCE_FAILURE_RECORD_SCHEMAS
        and row.get("record", {}).get("request_sha256")
        == draft.get("request_sha256")
    ]
    if len(settled_failures) > 1:
        _issue(issues, "evidence_failure:duplicate_cell")
    assignments = {
        row["lane_id"]: row for row in build_live_lane_assignments(request)
    } if request else {}
    raw_rows = draft.get("lane_observations")
    if not isinstance(raw_rows, list) or len(raw_rows) != len(assignments):
        _issue(issues, "evidence_failure:runtime_membership_invalid")
        raw_rows = []
    observed_cause = _observed_failure_cause(cause)
    projections: list[Mapping[str, Any]] = []
    for raw in raw_rows:
        row = _closed(
            raw,
            _EVIDENCE_FAILURE_LANE_FIELDS,
            "evidence_failure.lane",
            issues,
        )
        lane_id = str(row.get("lane_id"))
        if lane_id not in assignments:
            _issue(issues, "evidence_failure:lane_unknown")
        projections.append(
            _terminal_evidence_failure_projection(
                lane_id,
                row.get("runtime_observation"),
                str(observed_cause),
                issues,
                usage_settlement=usage_draft,
            )
        )
    lane_ids = [row.get("lane_id") for row in projections]
    session_ids = [row.get("session_id") for row in projections]
    if (
        set(lane_ids) != set(assignments)
        or len(lane_ids) != len(set(lane_ids))
        or len(session_ids) != len(set(session_ids))
    ):
        _issue(issues, "evidence_failure:runtime_membership_invalid")
    if not any(
        row.get("observation_issues") == [observed_cause]
        for row in projections
    ):
        _issue(issues, "evidence_failure:cause_observation_missing")
    stability_facts = None
    aux_samples = None
    if stable_draft:
        stability_facts = _validate_stability_derivation(
            draft.get("stability_derivation"),
            projections,
            observed_cause=str(observed_cause),
            failed_at_ms=failed_at_ms,
            issues=issues,
        )
        if aux_supplied:
            aux_samples = _validate_aux_process_samples(
                draft.get(_EVIDENCE_FAILURE_AUX_FIELD), issues
            )
    if not _integer(failed_at_ms, minimum=0):
        _issue(issues, "evidence_failure:failed_at_ms_invalid")
    else:
        if reservation and failed_at_ms < int(
            reservation.get("reserved_at_ms", 0)
        ):
            _issue(issues, "evidence_failure:time_regression")
        if start is not None and failed_at_ms > int(
            start.get("deadline_at_ms", -1)
        ):
            _issue(issues, "grant:wall_time_exhausted")
    usage_fields = tuple(sorted(_AGGREGATE_USAGE_FIELDS))
    usage = {
        field: sum(
            int(row.get("usage", {}).get(field, 0))
            for row in projections
            if type(row.get("usage", {}).get(field)) is int
        )
        for field in usage_fields
    }
    if usage_draft:
        # The aggregate is unknowable when any lane could not report its
        # accounting; a zero would understate real spend in exactly the
        # direction that flatters the campaign.
        usage = UNKNOWN_USAGE
    elif reservation and usage["total_tokens"] > int(
        reservation.get("reserved_tokens", 0)
    ):
        _issue(issues, "grant:cell_token_reservation_exhausted")
    if settled_failures and issues:
        _issue(issues, "evidence_failure:duplicate_cell")
    if issues or not request or registration is None or start is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=digest,
        )
    timing = {
        "reserved_at_ms": reservation["reserved_at_ms"],
        "failed_at_ms": failed_at_ms,
        "wall_time_ms": failed_at_ms - reservation["reserved_at_ms"],
    }
    core = {
        "schema": LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA_V2
        if stable_draft
        else LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA_V3
        if usage_draft
        else LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA,
        "campaign_sha256": digest,
        "grant_sha256": registration["grant_sha256"],
        "task_family": request["task_family"],
        "request": dict(request),
        "request_sha256": request["request_sha256"],
        "reservation_record_sha256": reservation["record_sha256"],
        "failure_cause": cause,
        "evidence_class": (
            "untrustworthy_usage" if usage_draft else "untrustworthy_terminal"
        ),
        "score_available": False,
        "outcome_available": False,
        "runtime_projections": [dict(row) for row in projections],
        "usage": usage,
        "timing": timing,
        "model_calls": len(projections),
        "hosted_calls": 0,
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "automatic_replacements": 0,
    }
    if usage_draft:
        core["usage_available"] = False
    if stable_draft:
        core["stability"] = dict(stability_facts or {})
        if aux_samples is not None:
            core[_EVIDENCE_FAILURE_AUX_FIELD] = [
                dict(row) for row in aux_samples
            ]
    record = _seal(core)
    if settled_failures:
        # C1: a byte-identical re-settlement replays to the accepted
        # original with provenance; any content difference is contradictory
        # and keeps the fail-closed duplicate refusal.  Nothing is
        # appended, re-charged, or re-dispatched on replay.
        if dict(settled_failures[0]) == record:
            same_cause_count = sum(
                row.get("record", {}).get("schema")
                in _EVIDENCE_FAILURE_RECORD_SCHEMAS
                and row.get("record", {}).get("failure_cause") == cause
                for row in shard_entries
            )
            return _base_report(
                status="PASS",
                state="REPLAYED",
                issues=[],
                campaign_sha256=digest,
                replayed=True,
                request_sha256=request["request_sha256"],
                failure_cause=cause,
                same_cause_count=same_cause_count,
                observed_tokens=(
                    UNKNOWN_USAGE if usage_draft else usage["total_tokens"]
                ),
                live_model_calls=len(projections),
                evidence_failure_record_sha256=record["record_sha256"],
                **({"verified_heads": head_facts} if head_facts else {}),
            )
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["evidence_failure:duplicate_cell"],
            campaign_sha256=digest,
        )
    receipt = _append(shard_path, record)
    if receipt is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["ledger:evidence_failure_append_failed"],
            campaign_sha256=digest,
        )
    same_cause_count = 1 + sum(
        row.get("record", {}).get("schema")
        in _EVIDENCE_FAILURE_RECORD_SCHEMAS
        and row.get("record", {}).get("failure_cause") == cause
        for row in shard_entries
    )
    return _base_report(
        status="PASS",
        state="EVIDENCE_FAILED",
        issues=[],
        campaign_sha256=digest,
        request_sha256=request["request_sha256"],
        failure_cause=cause,
        same_cause_count=same_cause_count,
        observed_tokens=(
            UNKNOWN_USAGE if usage_draft else usage["total_tokens"]
        ),
        live_model_calls=len(projections),
        evidence_failure_record_sha256=record["record_sha256"],
        chain_receipt=receipt,
        **({"verified_heads": head_facts} if head_facts else {}),
    )


def complete_live_replicate(
    campaign: Any,
    canonical_ledger_path: str | Path,
    shard_path: str | Path,
    completion: Any,
    *,
    completed_at_ms: int,
    expected_canonical_ledger_sha256: str | None = None,
    expected_shard_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate independently observed live evidence and append one result."""

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["campaign:invalid"],
            campaign_sha256=(campaign.get("campaign_sha256") if isinstance(campaign, Mapping) else None),
        )
    digest = str(campaign.get("campaign_sha256"))
    issues: list[str] = []
    raw_schema = (
        completion.get("schema") if isinstance(completion, Mapping) else None
    )
    scored_failures = raw_schema == LIVE_COMPLETION_DRAFT_SCHEMA_V2
    draft = _closed(
        completion,
        _COMPLETION_DRAFT_FIELDS_V2 if scored_failures else _COMPLETION_DRAFT_FIELDS,
        "completion",
        issues,
    )
    if draft.get("schema") not in {
        LIVE_COMPLETION_DRAFT_SCHEMA,
        LIVE_COMPLETION_DRAFT_SCHEMA_V2,
    }:
        _issue(issues, "completion:schema_invalid")
    canonical_entries, canonical_issues = _entries(canonical_ledger_path)
    issues.extend(canonical_issues)
    head_facts = _verify_head_expectations(
        canonical_ledger_path,
        shard_path,
        expected_canonical_ledger_sha256,
        expected_shard_sha256,
        "completion",
        issues,
    )
    registration = _campaign_registration(canonical_entries, digest)
    start = _campaign_start(canonical_entries, digest)
    if registration is None:
        _issue(issues, "campaign:registration_missing")
    if start is None:
        _issue(issues, "campaign:start_record_missing")
    _consult_campaign_fences(
        canonical_entries,
        digest,
        issues,
        stop_code="campaign:stopped",
        termination_code="campaign:owner_terminated",
        join_code="campaign:already_joined",
    )
    shard_entries, shard_issues = _entries(shard_path)
    issues.extend(shard_issues)
    reservations = [
        row["record"]
        for row in shard_entries
        if row.get("record", {}).get("schema") == LIVE_RESERVATION_RECORD_SCHEMA
    ]
    reservation_matches = [
        row
        for row in reservations
        if row.get("record_sha256") == draft.get("reservation_record_sha256")
    ]
    if len(reservation_matches) != 1:
        _issue(issues, "completion:reservation_missing")
        reservation: Mapping[str, Any] = {}
        request: Mapping[str, Any] = {}
    else:
        reservation = reservation_matches[0]
        if not _seal_valid(reservation):
            _issue(issues, "completion:reservation_invalid")
        request = _validate_request(reservation.get("request"), issues)
        if draft.get("request_sha256") != request.get("request_sha256"):
            _issue(issues, "completion:request_mismatch")
    settled_completions = [
        row["record"]
        for row in shard_entries
        if row.get("record", {}).get("schema")
        in {LIVE_COMPLETION_RECORD_SCHEMA, LIVE_COMPLETION_RECORD_SCHEMA_V2}
        and row.get("record", {}).get("request_sha256")
        == draft.get("request_sha256")
    ]
    if len(settled_completions) > 1:
        _issue(issues, "completion:duplicate_cell")
    if any(
        row.get("record", {}).get("schema")
        in _EVIDENCE_FAILURE_RECORD_SCHEMAS
        and row.get("record", {}).get("request_sha256")
        == draft.get("request_sha256")
        for row in shard_entries
    ):
        _issue(issues, "completion:evidence_failure_recorded")
    governed = _governed_evidence(draft.get("governed_evidence"), issues)
    assignments_list = build_live_lane_assignments(request) if request else []
    assignments = {row["lane_id"]: row for row in assignments_list}
    raw_malformed = draft.get("malformed_lanes") if scored_failures else []
    if scored_failures and (
        not isinstance(raw_malformed, list) or not raw_malformed
    ):
        _issue(issues, "completion:malformed_lanes_invalid")
        raw_malformed = []
    malformed_projections = [
        _malformed_lane_projection(request, assignments, row, issues)
        for row in (raw_malformed if isinstance(raw_malformed, list) else [])
    ]
    malformed_lane_ids = {
        str(row.get("lane_id")) for row in malformed_projections if row
    }
    if len(malformed_lane_ids) != len(malformed_projections):
        _issue(issues, "completion:malformed_membership_invalid")
    well_formed_assignments = {
        lane_id: assignment
        for lane_id, assignment in assignments.items()
        if lane_id not in malformed_lane_ids
    }
    raw_results = draft.get("lane_results")
    if not isinstance(raw_results, list) or len(raw_results) != len(
        well_formed_assignments
    ):
        _issue(issues, "completion:lane_results_membership_invalid")
        raw_results = []
    lane_results = [
        _lane_result(request, well_formed_assignments, row, issues)
        for row in raw_results
    ]
    lane_ids = [row.get("lane_id") for row in lane_results]
    if set(lane_ids) != set(well_formed_assignments) or len(lane_ids) != len(
        set(lane_ids)
    ):
        _issue(issues, "completion:lane_results_membership_invalid")
    raw_observations = draft.get("runtime_observations")
    if not isinstance(raw_observations, list) or len(raw_observations) != len(lane_results):
        _issue(issues, "completion:runtime_membership_invalid")
        raw_observations = []
    runtime_projections: list[Mapping[str, Any]] = []
    for result, observation in zip(lane_results, raw_observations):
        runtime_projections.append(_runtime_projection(result, observation, issues))
    runtime_lane_ids = [row.get("lane_id") for row in runtime_projections]
    if set(runtime_lane_ids) != set(well_formed_assignments) or len(
        runtime_lane_ids
    ) != len(set(runtime_lane_ids)):
        _issue(issues, "completion:runtime_membership_invalid")
    session_ids = [
        row.get("session_id")
        for row in (*runtime_projections, *malformed_projections)
        if row
    ]
    if len(session_ids) != len(set(session_ids)):
        _issue(issues, "completion:duplicate_session")
    if not _integer(completed_at_ms, minimum=0):
        _issue(issues, "completion:completed_at_ms_invalid")
    if start is not None and type(start.get("deadline_at_ms")) is int and completed_at_ms > start["deadline_at_ms"]:
        _issue(issues, "grant:wall_time_exhausted")
    if reservation and completed_at_ms < int(reservation.get("reserved_at_ms", 0)):
        _issue(issues, "completion:time_regression")
    usage_fields = (
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
        "tool_calls",
    )
    usage = {
        field: sum(
            int(row.get("usage", {}).get(field, 0))
            for row in (*runtime_projections, *malformed_projections)
            if type(row.get("usage", {}).get(field)) is int
        )
        for field in usage_fields
    }
    if reservation and usage["total_tokens"] > int(reservation.get("reserved_tokens", 0)):
        _issue(issues, "grant:cell_token_reservation_exhausted")
    if settled_completions and issues:
        _issue(issues, "completion:duplicate_cell")
    if issues or not request or registration is None or start is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=digest,
        )
    if scored_failures:
        metric = {
            "name": request.get("metric"),
            "numerator": 0,
            "denominator": 10_000,
        }
        outcome = "failed"
        evidence_class = "malformed_terminal"
    else:
        metric, outcome = _score_live_results(request, lane_results)
        evidence_class = "qualified"
    timing = {
        "reserved_at_ms": reservation["reserved_at_ms"],
        "completed_at_ms": completed_at_ms,
        "wall_time_ms": completed_at_ms - reservation["reserved_at_ms"],
    }
    governed_sha256 = _sha256(governed)
    record_core: dict[str, Any] = {
        "schema": (
            LIVE_COMPLETION_RECORD_SCHEMA_V2
            if scored_failures
            else LIVE_COMPLETION_RECORD_SCHEMA
        ),
        "campaign_sha256": digest,
        "grant_sha256": registration["grant_sha256"],
        "task_family": request["task_family"],
        "request": dict(request),
        "request_sha256": request["request_sha256"],
        "reservation_record_sha256": reservation["record_sha256"],
        "governed_evidence": dict(governed),
        "governed_evidence_sha256": governed_sha256,
        "lane_results": [dict(row) for row in lane_results],
        "runtime_projections": [dict(row) for row in runtime_projections],
        "outcome": outcome,
        "metric": metric,
        "usage": usage,
        "timing": timing,
        "model_calls": len(runtime_projections) + len(malformed_projections),
        "hosted_calls": 0,
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "automatic_replacements": 0,
    }
    if scored_failures:
        record_core["evidence_class"] = "malformed_terminal"
        record_core["malformed_projections"] = [
            dict(row) for row in malformed_projections
        ]
    record = _seal(record_core)
    if settled_completions:
        # C1: a byte-identical re-settlement replays to the accepted
        # original with provenance; any content difference is contradictory
        # and keeps the fail-closed duplicate refusal.  Nothing is
        # re-dispatched or appended on replay.
        if dict(settled_completions[0]) == record:
            return _base_report(
                status="PASS",
                state="REPLAYED",
                issues=[],
                campaign_sha256=digest,
                replayed=True,
                request_sha256=request["request_sha256"],
                outcome=outcome,
                metric=metric,
                evidence_class=evidence_class,
                observed_tokens=usage["total_tokens"],
                live_model_calls=len(runtime_projections)
                + len(malformed_projections),
                completion_record_sha256=record["record_sha256"],
                **({"verified_heads": head_facts} if head_facts else {}),
            )
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["completion:duplicate_cell"],
            campaign_sha256=digest,
        )
    receipt = _append(shard_path, record)
    if receipt is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["ledger:completion_append_failed"],
            campaign_sha256=digest,
        )
    return _base_report(
        status="PASS",
        state="COMPLETED",
        issues=[],
        campaign_sha256=digest,
        request_sha256=request["request_sha256"],
        outcome=outcome,
        metric=metric,
        evidence_class=evidence_class,
        observed_tokens=usage["total_tokens"],
        live_model_calls=len(runtime_projections) + len(malformed_projections),
        completion_record_sha256=record["record_sha256"],
        chain_receipt=receipt,
        **({"verified_heads": head_facts} if head_facts else {}),
    )


def _campaign_cell_order(
    campaign: Mapping[str, Any],
) -> list[tuple[str, int, int]]:
    return [
        (str(configuration.get("configuration_id")), replicate_index, int(seed))
        for configuration in campaign.get("configuration_grid", [])
        for replicate_index, seed in enumerate(campaign.get("seeds", []), start=1)
    ]


UNSETTLED_USAGE_UNKNOWN = "UNKNOWN"


def _finalize_residual_row(row: Mapping[str, int]) -> dict[str, Any]:
    """Close one residual row over its settled and unsettled halves.

    A reservation that never settled leaves its lane usage nowhere in the
    ledger, so the row reports that usage as UNKNOWN rather than zero and
    publishes the residual as an upper bound: unrecorded spend can only
    reduce it, never raise it.  A fully settled row keeps the exact
    residual and a zero unsettled block, where the zeroes are true
    counts of unsettled runs rather than an absence sentinel.

    A usage-unknown settlement (Issue 123) is incomplete for the same
    reason: the cell settled, but its accounting was never readable, so
    its real spend is missing from the settled total.
    """

    published = dict(row)
    unsettled_reserved = published.pop("unsettled_reserved_held", 0)
    reserved = published["reserved_tokens"]
    settled = published["settled_attributable_tokens"]
    # Both counters are required: a row missing either is malformed, and
    # defaulting one to zero would report an incomplete row as complete.
    for field in ("unsettled_runs", "usage_unknown_settlements"):
        if type(published.get(field)) is not int:
            raise ValueError("residual row is missing " + field)
    complete = (
        published["unsettled_runs"] == 0
        and published["usage_unknown_settlements"] == 0
    )
    closed: dict[str, Any] = {
        **published,
        "attributable_tokens_complete": complete,
        "unsettled_usage": {
            "unsettled_runs": published["unsettled_runs"],
            "reserved_tokens": unsettled_reserved,
            "observed_tokens": (
                # This block describes unsettled reservations only.  A
                # usage-unknown settlement is a settled cell and is
                # reported through usage_unknown_settlements instead, so a
                # zero here with an incomplete row is correct.
                0
                if published["unsettled_runs"] == 0
                else UNSETTLED_USAGE_UNKNOWN
            ),
        },
    }
    if complete:
        closed["residual_reserved_tokens"] = reserved - settled
    else:
        closed["residual_reserved_tokens_upper_bound"] = reserved - settled
    return closed


def project_campaign_residual(
    ledger_path: str | Path,
    shard_paths: Mapping[str, str | Path],
    campaign_sha256: str,
) -> dict[str, Any]:
    """Project reserved versus attributable versus residual tokens (C4).

    Report-only and digest-bound: the projection derives per-campaign,
    per-family, and per-configuration budget arithmetic from the ledgers
    alone and records the exact canonical and shard heads it observed
    (C8: the head travels with the counters).  Permanent reservation is
    the budget model; the residual is reserved-minus-attributable and is
    structurally unable to move a limit, charge a draw, or widen
    authority.

    Settled records are the only token source the ledger has, so the
    derived total is named ``settled_attributable_tokens``: a reservation
    whose lane sessions burned tokens and then failed to settle leaves
    that usage nowhere in the ledger (drain records carry process counts,
    never tokens).  Rather than fabricate or zero-fill it, an unsettled
    run is reported through ``unsettled_usage`` with ``observed_tokens``
    ``UNKNOWN``, ``attributable_tokens_complete`` goes false, and the
    residual is published as ``residual_reserved_tokens_upper_bound``
    because unrecorded spend can only reduce it.  TICKETS.md Issue 121
    records the campaign that exhibited this.
    """

    canonical_sha256 = hashlib.sha256(
        _read_ledger_bytes(ledger_path)
    ).hexdigest()
    entries, issues = _entries(ledger_path)
    if not _sha_valid(campaign_sha256):
        _issue(issues, "residual:campaign_sha256_invalid")
    registration = _campaign_registration(entries, campaign_sha256)
    if registration is None:
        _issue(issues, "campaign:registration_missing")
        grant: Mapping[str, Any] = {}
        campaign: Mapping[str, Any] = {}
    else:
        registration = _validate_registration(
            registration, campaign_sha256, issues
        )
        grant = registration.get("grant", {})
        campaign = registration.get("campaign", {})
    campaign_families = tuple(
        _campaign_families(campaign) if isinstance(campaign, Mapping) else ()
    )
    if not isinstance(shard_paths, Mapping) or set(shard_paths) != set(
        campaign_families
    ):
        _issue(issues, "residual:family_shards_invalid")
    if issues:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=(
                campaign_sha256 if _sha_valid(campaign_sha256) else None
            ),
        )
    shard_sha256s: dict[str, str] = {}
    families: dict[str, dict[str, int]] = {}
    configurations: dict[str, dict[str, int]] = {}
    totals = {
        "reserved_runs": 0,
        "completed_runs": 0,
        "evidence_failure_runs": 0,
        "unsettled_runs": 0,
        "reserved_tokens": 0,
        "settled_attributable_tokens": 0,
        "unsettled_reserved_held": 0,
        "usage_unknown_settlements": 0,
    }
    for family in campaign_families:
        path = shard_paths[family]
        shard_sha256s[family] = hashlib.sha256(
            _read_ledger_bytes(path)
        ).hexdigest()
        shard_entries, shard_issues = _entries(path)
        for item in shard_issues:
            _issue(issues, f"residual:{family}:{item}")
        family_row = {
            "reserved_runs": 0,
            "completed_runs": 0,
            "evidence_failure_runs": 0,
            "unsettled_runs": 0,
            "reserved_tokens": 0,
            "settled_attributable_tokens": 0,
            "unsettled_reserved_held": 0,
            "usage_unknown_settlements": 0,
        }
        settled_request_sha256s: set[str] = set()
        reservation_rows: list[Mapping[str, Any]] = []
        for outer in shard_entries:
            record = outer.get("record", {})
            schema = record.get("schema")
            if schema == LIVE_RESERVATION_RECORD_SCHEMA:
                reservation_rows.append(record)
                continue
            settled = schema in {
                LIVE_COMPLETION_RECORD_SCHEMA,
                LIVE_COMPLETION_RECORD_SCHEMA_V2,
            }
            failed = schema in _EVIDENCE_FAILURE_RECORD_SCHEMAS
            if not settled and not failed:
                continue
            request = record.get("request", {})
            configuration_id = str(request.get("configuration_id"))
            # Issue 123: a usage-unknown settlement seals UNKNOWN in place
            # of the aggregate mapping. Its real spend is unrecorded, so
            # it contributes nothing to the settled total and instead
            # makes the campaign total incomplete, exactly as an
            # unsettled reservation does (Issue 121).
            stored_usage = record.get("usage")
            usage_unknown = usage_is_unknown(record)
            observed = settled_usage_tokens(record)
            settled_request_sha256s.add(str(record.get("request_sha256")))
            row = configurations.setdefault(
                configuration_id,
                {
                    "reserved_runs": 0,
                    "completed_runs": 0,
                    "evidence_failure_runs": 0,
                    "unsettled_runs": 0,
                    "reserved_tokens": 0,
                    "settled_attributable_tokens": 0,
                    "unsettled_reserved_held": 0,
                    "usage_unknown_settlements": 0,
                },
            )
            key = "completed_runs" if settled else "evidence_failure_runs"
            row[key] += 1
            row["settled_attributable_tokens"] += observed
            family_row[key] += 1
            family_row["settled_attributable_tokens"] += observed
            totals[key] += 1
            totals["settled_attributable_tokens"] += observed
            if usage_unknown:
                row["usage_unknown_settlements"] += 1
                family_row["usage_unknown_settlements"] += 1
                totals["usage_unknown_settlements"] += 1
        for record in reservation_rows:
            request = record.get("request", {})
            configuration_id = str(request.get("configuration_id"))
            reserved = int(
                record.get("reserved_tokens", 0)
                if type(record.get("reserved_tokens")) is int
                else 0
            )
            row = configurations.setdefault(
                configuration_id,
                {
                    "reserved_runs": 0,
                    "completed_runs": 0,
                    "evidence_failure_runs": 0,
                    "unsettled_runs": 0,
                    "reserved_tokens": 0,
                    "settled_attributable_tokens": 0,
                    "unsettled_reserved_held": 0,
                    "usage_unknown_settlements": 0,
                },
            )
            row["reserved_runs"] += 1
            row["reserved_tokens"] += reserved
            family_row["reserved_runs"] += 1
            family_row["reserved_tokens"] += reserved
            totals["reserved_runs"] += 1
            totals["reserved_tokens"] += reserved
            if str(record.get("request_sha256")) not in settled_request_sha256s:
                row["unsettled_runs"] += 1
                row["unsettled_reserved_held"] += reserved
                family_row["unsettled_runs"] += 1
                family_row["unsettled_reserved_held"] += reserved
                totals["unsettled_runs"] += 1
                totals["unsettled_reserved_held"] += reserved
        families[family] = _finalize_residual_row(family_row)
    if issues:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=campaign_sha256,
        )
    configurations = {
        key: _finalize_residual_row(row)
        for key, row in configurations.items()
    }
    grant_max_tokens = int(grant.get("max_tokens", 0))
    projected_totals = {
        **_finalize_residual_row(dict(totals)),
        "grant_max_tokens": grant_max_tokens,
        "unreserved_tokens": grant_max_tokens - totals["reserved_tokens"],
        "expected_runs": expected_run_count(campaign),
    }
    return _base_report(
        status="PASS",
        state="PROJECTED",
        issues=[],
        campaign_sha256=campaign_sha256,
        projection_schema=LIVE_RESIDUAL_PROJECTION_SCHEMA,
        grant_sha256=registration.get("grant_sha256"),
        canonical_ledger_sha256=canonical_sha256,
        shard_sha256s=shard_sha256s,
        totals=projected_totals,
        families=families,
        configurations=configurations,
        budget_model="permanent_reservation",
        report_only=True,
    )


def _join_sources(
    campaign: Mapping[str, Any],
    registration: Mapping[str, Any],
    start: Mapping[str, Any],
    shard_paths: Mapping[str, str | Path],
    issues: list[str],
) -> tuple[
    dict[tuple[str, int, int], Mapping[str, Any]],
    dict[tuple[str, int, int], Mapping[str, Any]],
    dict[tuple[str, int, int], Mapping[str, Any]],
]:
    """Validate shard chains and return reservations, completions, failures."""

    digest = str(campaign.get("campaign_sha256"))
    campaign_families = _expected_families(campaign, issues)
    if not isinstance(shard_paths, Mapping) or set(shard_paths) != set(
        campaign_families
    ):
        _issue(issues, "join:family_shards_invalid")
        return {}, {}, {}
    start_rows = {
        row.get("task_family"): row for row in start.get("family_shards", [])
    }
    allocations = {
        row.get("task_family"): row
        for row in registration.get("grant", {}).get("family_allocations", [])
    }
    reservations: dict[tuple[str, int, int], Mapping[str, Any]] = {}
    completions: dict[tuple[str, int, int], Mapping[str, Any]] = {}
    evidence_failures: dict[tuple[str, int, int], Mapping[str, Any]] = {}
    expected = set(_campaign_cell_order(campaign))
    configuration_hashes = {
        str(row.get("configuration_id")): _sha256(row)
        for row in campaign.get("configuration_grid", [])
    }
    for family in campaign_families:
        path = Path(shard_paths[family])
        binding = start_rows.get(family)
        if not isinstance(binding, Mapping) or binding.get(
            "path_sha256"
        ) != hashlib.sha256(
            str(path.resolve(strict=False)).encode("utf-8")
        ).hexdigest():
            _issue(issues, f"join:shard_path_mismatch:{family}")
        entries, shard_issues = _entries(path)
        for item in shard_issues:
            _issue(issues, f"join:{family}:{item}")
        headers = [
            row["record"]
            for row in entries
            if row.get("record", {}).get("schema") == LIVE_SHARD_HEADER_SCHEMA
        ]
        if len(headers) != 1:
            _issue(issues, f"join:shard_header_invalid:{family}")
            continue
        header = _closed(
            headers[0], _SHARD_HEADER_FIELDS, f"join.{family}.header", issues
        )
        if (
            not _seal_valid(header)
            or header.get("campaign_sha256") != digest
            or header.get("grant_sha256") != registration.get("grant_sha256")
            or header.get("registration_record_sha256")
            != registration.get("record_sha256")
            or header.get("start_record_sha256") != start.get("record_sha256")
            or header.get("task_family") != family
            or header.get("started_at_ms") != start.get("started_at_ms")
            or header.get("deadline_at_ms") != start.get("deadline_at_ms")
            or header.get("allocation") != allocations.get(family)
        ):
            _issue(issues, f"join:shard_header_binding_invalid:{family}")
        family_reservations: dict[str, tuple[tuple[str, int, int], Mapping[str, Any]]] = {}
        for outer in entries:
            raw = outer.get("record")
            if not isinstance(raw, Mapping) or raw.get(
                "schema"
            ) != LIVE_RESERVATION_RECORD_SCHEMA:
                continue
            value = _closed(
                raw,
                _RESERVATION_FIELDS,
                f"join.{family}.reservation",
                issues,
            )
            request = _validate_request(value.get("request"), issues)
            key = (
                str(request.get("configuration_id")),
                request.get("replicate_index"),
                request.get("seed"),
            )
            if (
                not _seal_valid(value)
                or value.get("campaign_sha256") != digest
                or value.get("grant_sha256") != registration.get("grant_sha256")
                or value.get("shard_header_sha256") != header.get("record_sha256")
                or value.get("request_sha256") != request.get("request_sha256")
                or request.get("task_family") != family
                or request.get("configuration_sha256")
                != configuration_hashes.get(str(request.get("configuration_id")))
                or key not in expected
                or type(value.get("reserved_at_ms")) is not int
                or value.get("reserved_at_ms", -1) < start.get("started_at_ms", 0)
                or value.get("reserved_at_ms", 0) > start.get("deadline_at_ms", -1)
                or value.get("reserved_tokens")
                != _reservation_tokens_for_lane_count(
                    registration.get("grant", {}), request.get("lane_count")
                )
                or value.get("permanently_charged") is not True
            ):
                _issue(issues, f"join:reservation_invalid:{family}")
                continue
            if key in reservations or request.get("request_sha256") in family_reservations:
                _issue(issues, f"join:reservation_duplicate:{family}")
                continue
            reservations[key] = value
            family_reservations[str(request["request_sha256"])] = (key, value)
        for outer in entries:
            raw = outer.get("record")
            if not isinstance(raw, Mapping) or raw.get("schema") not in {
                LIVE_COMPLETION_RECORD_SCHEMA,
                LIVE_COMPLETION_RECORD_SCHEMA_V2,
            }:
                continue
            value = _closed(
                raw,
                (
                    _COMPLETION_RECORD_FIELDS_V2
                    if raw.get("schema") == LIVE_COMPLETION_RECORD_SCHEMA_V2
                    else _COMPLETION_RECORD_FIELDS
                ),
                f"join.{family}.completion",
                issues,
            )
            source = family_reservations.get(str(value.get("request_sha256")))
            if source is None:
                _issue(issues, f"join:completion_reservation_missing:{family}")
                continue
            key, reservation = source
            governed_issues: list[str] = []
            governed = _governed_evidence(
                value.get("governed_evidence"), governed_issues
            )
            for item in governed_issues:
                _issue(issues, f"join:{family}:{item}")
            derivation_issues, _derived = _rederive_stored_completion(
                reservation.get("request", {}), value
            )
            if "result_derivation_invalid" in derivation_issues:
                _issue(
                    issues,
                    f"join:completion_result_derivation_invalid:{family}",
                )
            if any(
                item != "result_derivation_invalid" for item in derivation_issues
            ):
                _issue(issues, f"join:completion_projection_invalid:{family}")
            metric = value.get("metric")
            usage = value.get("usage")
            timing = value.get("timing")
            if (
                not _seal_valid(value)
                or value.get("campaign_sha256") != digest
                or value.get("grant_sha256") != registration.get("grant_sha256")
                or value.get("task_family") != family
                or value.get("request") != reservation.get("request")
                or value.get("reservation_record_sha256")
                != reservation.get("record_sha256")
                or value.get("governed_evidence_sha256") != _sha256(governed)
                or value.get("outcome") not in {"passed", "failed"}
                or not isinstance(metric, Mapping)
                or metric.get("name")
                != campaign.get("question", {}).get("primary_metric")
                or type(metric.get("numerator")) is not int
                or metric.get("denominator") != 10_000
                or not isinstance(usage, Mapping)
                or type(usage.get("total_tokens")) is not int
                or usage.get("total_tokens", -1) < 0
                or usage.get("total_tokens", 0)
                > reservation.get("reserved_tokens", -1)
                or not isinstance(timing, Mapping)
                or timing.get("reserved_at_ms") != reservation.get("reserved_at_ms")
                or type(timing.get("completed_at_ms")) is not int
                or timing.get("completed_at_ms", 0) > start.get("deadline_at_ms", -1)
                or value.get("model_calls")
                != reservation.get("request", {}).get("lane_count")
                or value.get("hosted_calls") != 0
                or value.get("automatic_retries") != 0
                or value.get("automatic_fallbacks") != 0
                or value.get("automatic_replacements") != 0
            ):
                _issue(issues, f"join:completion_invalid:{family}")
                continue
            if key in completions:
                _issue(issues, f"join:completion_duplicate:{family}")
                continue
            completions[key] = value
        family_reservations_by_sha = {
            str(row[1].get("record_sha256")): row[1]
            for row in family_reservations.values()
        }
        for outer in entries:
            raw = outer.get("record")
            if (
                not isinstance(raw, Mapping)
                or raw.get("schema") not in _EVIDENCE_FAILURE_RECORD_SCHEMAS
            ):
                continue
            issue_count = len(issues)
            value = _validate_stored_evidence_failure(
                raw,
                family_reservations_by_sha,
                family,
                issues,
                label=f"join.{family}.evidence_failure",
            )
            source = family_reservations.get(str(value.get("request_sha256")))
            if source is None:
                _issue(
                    issues,
                    f"join:evidence_failure_reservation_missing:{family}",
                )
                continue
            key, _reservation = source
            if len(issues) != issue_count:
                continue
            if key in completions or key in evidence_failures:
                _issue(issues, f"join:cell_settlement_duplicate:{family}")
                continue
            evidence_failures[key] = value
        allocation = allocations.get(family, {})
        family_reservation_values = [row[1] for row in family_reservations.values()]
        family_reserved_tokens = sum(
            int(row.get("reserved_tokens", 0))
            for row in family_reservation_values
        )
        family_observed_tokens = sum(
            settled_usage_tokens(row)
            for row in (*completions.values(), *evidence_failures.values())
            if row.get("task_family") == family
        )
        if len(family_reservation_values) > int(allocation.get("max_runs", 0)):
            _issue(issues, f"join:family_run_budget_exceeded:{family}")
        if family_reserved_tokens > int(allocation.get("max_tokens", 0)):
            _issue(issues, f"join:family_reserved_token_budget_exceeded:{family}")
        if family_observed_tokens > int(allocation.get("max_tokens", 0)):
            _issue(issues, f"join:family_observed_token_budget_exceeded:{family}")
    grant = registration.get("grant", {})
    reserved_tokens = sum(
        int(row.get("reserved_tokens", 0)) for row in reservations.values()
    )
    observed_tokens = sum(
        settled_usage_tokens(row)
        for row in (*completions.values(), *evidence_failures.values())
    )
    if len(reservations) > int(grant.get("max_runs", 0)):
        _issue(issues, "join:run_budget_exceeded")
    if reserved_tokens > int(grant.get("max_tokens", 0)):
        _issue(issues, "join:reserved_token_budget_exceeded")
    if observed_tokens > int(grant.get("max_tokens", 0)):
        _issue(issues, "join:observed_token_budget_exceeded")
    return reservations, completions, evidence_failures


def terminate_live_campaign(
    campaign: Any,
    ledger_path: str | Path,
    shard_paths: Mapping[str, str | Path],
    termination: Any,
    *,
    terminated_at_ms: int,
) -> dict[str, Any]:
    """Record one Owner-directed early stop and quarantine its invalid cell."""

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["campaign:invalid"],
            campaign_sha256=(
                campaign.get("campaign_sha256")
                if isinstance(campaign, Mapping)
                else None
            ),
        )
    digest = str(campaign["campaign_sha256"])
    entries, issues = _entries(ledger_path)
    registration = _campaign_registration(entries, digest)
    start = _campaign_start(entries, digest)
    if registration is None:
        _issue(issues, "campaign:registration_missing")
    else:
        _validate_registration(registration, digest, issues)
        if registration.get("grant", {}).get("schema") != LIVE_GRANT_SCHEMA_V2:
            _issue(issues, "termination:successor_grant_required")
    if start is None:
        _issue(issues, "campaign:start_record_missing")
    else:
        start = _closed(start, _START_FIELDS, "termination.start", issues)
        if not _seal_valid(start):
            _issue(issues, "termination:start_record_invalid")
    _consult_campaign_fences(
        entries,
        digest,
        issues,
        termination_code="campaign:already_owner_terminated",
        join_code="campaign:already_joined",
    )

    draft = _closed(
        termination,
        _OWNER_TERMINATION_DRAFT_FIELDS,
        "termination",
        issues,
    )
    if draft.get("schema") != LIVE_OWNER_TERMINATION_DRAFT_SCHEMA:
        _issue(issues, "termination:schema_invalid")
    if not _identifier(draft.get("authority_id")):
        _issue(issues, "termination:authority_id_invalid")
    if not _sha_valid(draft.get("authority_source_sha256")):
        _issue(issues, "termination:authority_source_sha256_invalid")
    if draft.get("reason_code") != (
        "owner_directed_early_termination_after_evidence_contradiction"
    ):
        _issue(issues, "termination:reason_code_invalid")
    environment = _closed(
        draft.get("environment"),
        _OWNER_TERMINATION_ENVIRONMENT_FIELDS,
        "termination.environment",
        issues,
    )
    if environment != {
        "host_id": "jwj-lab",
        "runtime": "python3 -B",
        "provider_free": True,
    }:
        _issue(issues, "termination:environment_invalid")
    limits = _closed(
        draft.get("limits"),
        _OWNER_TERMINATION_LIMIT_FIELDS,
        "termination.limits",
        issues,
    )
    expected_limits = {
        "qwen_calls": 0,
        "model_calls": 0,
        "hosted_calls": 0,
        "additional_tokens": 0,
        "new_reservations": 0,
        "retries": 0,
        "fallbacks": 0,
        "replacements": 0,
        "finalizer_invocations": 1,
    }
    if limits != expected_limits:
        _issue(issues, "termination:limits_invalid")
    for field in ("material_risk", "recovery"):
        if not isinstance(draft.get(field), str) or not draft[field].strip():
            _issue(issues, f"termination:{field}_invalid")
    if not _integer(terminated_at_ms, minimum=0):
        _issue(issues, "termination:terminated_at_ms_invalid")
    elif isinstance(start, Mapping):
        if terminated_at_ms < int(start.get("started_at_ms", terminated_at_ms + 1)):
            _issue(issues, "termination:time_regression")
        if terminated_at_ms >= int(start.get("deadline_at_ms", -1)):
            _issue(issues, "termination:not_early")

    try:
        canonical_bytes = Path(ledger_path).read_bytes()
    except OSError:
        canonical_bytes = b""
        _issue(issues, "termination:canonical_ledger_unreadable")
    canonical_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    if draft.get("expected_canonical_ledger_sha256") != canonical_sha256:
        _issue(issues, "termination:canonical_ledger_sha256_mismatch")
    expected_shard_sha256s = draft.get("expected_shard_sha256s")
    if not isinstance(expected_shard_sha256s, Mapping) or set(
        expected_shard_sha256s
    ) != set(ISSUE111_TASK_FAMILIES):
        _issue(issues, "termination:shard_sha256s_invalid")
        expected_shard_sha256s = {}
    shard_sha256s: dict[str, str] = {}
    if not isinstance(shard_paths, Mapping) or set(shard_paths) != set(
        ISSUE111_TASK_FAMILIES
    ):
        _issue(issues, "termination:family_shards_invalid")
    else:
        for family in ISSUE111_TASK_FAMILIES:
            try:
                value = hashlib.sha256(Path(shard_paths[family]).read_bytes()).hexdigest()
            except OSError:
                _issue(issues, f"termination:shard_unreadable:{family}")
                continue
            shard_sha256s[family] = value
            if expected_shard_sha256s.get(family) != value:
                _issue(issues, f"termination:shard_sha256_mismatch:{family}")

    reservations: dict[tuple[str, int, int], Mapping[str, Any]] = {}
    completions: dict[tuple[str, int, int], Mapping[str, Any]] = {}
    if registration is not None and start is not None:
        reservations, completions, _evidence_failures = _join_sources(
            campaign, registration, start, shard_paths, issues
        )
    quarantined = _closed(
        draft.get("quarantined_completion"),
        _QUARANTINED_COMPLETION_FIELDS,
        "termination.quarantined_completion",
        issues,
    )
    key = (
        quarantined.get("configuration_id"),
        quarantined.get("replicate_index"),
        quarantined.get("seed"),
    )
    completion = completions.get(key)
    reservation = reservations.get(key)
    if len(reservations) != 1 or len(completions) != 1:
        _issue(issues, "termination:exact_single_cell_incident_required")
    if completion is None or reservation is None:
        _issue(issues, "termination:quarantined_completion_missing")
    else:
        governed = completion.get("governed_evidence", {})
        if (
            quarantined.get("task_family") != completion.get("task_family")
            or quarantined.get("request_sha256")
            != completion.get("request_sha256")
            or quarantined.get("reservation_record_sha256")
            != reservation.get("record_sha256")
            or quarantined.get("completion_record_sha256")
            != completion.get("record_sha256")
            or quarantined.get("bound_custody_report_sha256")
            != governed.get("custody_report_sha256")
            or quarantined.get("bound_trace_report_sha256")
            != governed.get("trace_report_sha256")
        ):
            _issue(issues, "termination:quarantine_binding_mismatch")
    if quarantined.get("evidence_class") != "contradictory":
        _issue(issues, "termination:evidence_class_invalid")
    if (
        not _identifier(quarantined.get("bound_first_finisher_session_id"))
        or not _identifier(quarantined.get("observed_first_finisher_session_id"))
        or quarantined.get("bound_first_finisher_session_id")
        == quarantined.get("observed_first_finisher_session_id")
        or not _integer(quarantined.get("observed_precedence_ms"), minimum=1)
    ):
        _issue(issues, "termination:first_finisher_contradiction_invalid")
    for bound_field, corrected_field in (
        ("bound_custody_report_sha256", "corrected_custody_report_sha256"),
        ("bound_trace_report_sha256", "corrected_trace_report_sha256"),
    ):
        if (
            not _sha_valid(quarantined.get(bound_field))
            or not _sha_valid(quarantined.get(corrected_field))
            or quarantined.get(bound_field) == quarantined.get(corrected_field)
        ):
            _issue(issues, f"termination:contradiction_hash_invalid:{corrected_field}")
    if issues or registration is None or start is None or completion is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=digest,
        )

    counts = {
        "expected_runs": expected_run_count(campaign),
        "reserved_runs": len(reservations),
        "completed_runs": 0,
        "failed_runs": 0,
        "evidence_failure_runs": 1,
        "quarantined_runs": 1,
        "never_dispatched_runs": expected_run_count(campaign) - len(reservations),
        "missing_runs": expected_run_count(campaign),
        "extrapolated_runs": 0,
    }
    record = _seal(
        {
            "schema": LIVE_OWNER_TERMINATION_RECORD_SCHEMA,
            "campaign_sha256": digest,
            "grant_sha256": registration["grant_sha256"],
            "start_record_sha256": start["record_sha256"],
            "authority_id": draft["authority_id"],
            "authority_source_sha256": draft["authority_source_sha256"],
            "reason_code": draft["reason_code"],
            "environment": dict(environment),
            "limits": dict(limits),
            "material_risk": draft["material_risk"],
            "recovery": draft["recovery"],
            "canonical_ledger_sha256_before_termination": canonical_sha256,
            "shard_sha256s": shard_sha256s,
            "quarantined_completion": dict(quarantined),
            "original_deadline_at_ms": start["deadline_at_ms"],
            "terminated_at_ms": terminated_at_ms,
            "early_termination": True,
            "state": "INCOMPLETE_EVIDENCE_FAILURE",
            "counts": counts,
            "observed_tokens": int(completion["usage"]["total_tokens"]),
            "live_model_calls": int(completion["model_calls"]),
            "hosted_calls": 0,
            "reportable": False,
            "training_eligible": False,
            "replay_decidable": [],
            "live_required": [],
        }
    )
    try:
        if hashlib.sha256(Path(ledger_path).read_bytes()).hexdigest() != canonical_sha256:
            return _base_report(
                status="FAIL",
                state="REFUSED",
                issues=["termination:canonical_ledger_changed_before_append"],
                campaign_sha256=digest,
            )
    except OSError:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["termination:canonical_ledger_unreadable_before_append"],
            campaign_sha256=digest,
        )
    for family in ISSUE111_TASK_FAMILIES:
        try:
            current = hashlib.sha256(Path(shard_paths[family]).read_bytes()).hexdigest()
        except (KeyError, OSError, TypeError):
            current = None
        if current != shard_sha256s.get(family):
            return _base_report(
                status="FAIL",
                state="REFUSED",
                issues=[f"termination:shard_changed_before_append:{family}"],
                campaign_sha256=digest,
            )
    if _append(ledger_path, record) is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["ledger:owner_termination_append_failed"],
            campaign_sha256=digest,
        )
    return summarize_live_campaign(ledger_path, digest)


def stop_live_campaign(
    campaign: Any,
    ledger_path: str | Path,
    shard_paths: Mapping[str, str | Path],
    stop: Any,
    *,
    stopped_at_ms: int,
) -> dict[str, Any]:
    """Immediately fence one drained v3 attempt without a proof-date wait."""

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["campaign:invalid"],
            campaign_sha256=(
                campaign.get("campaign_sha256")
                if isinstance(campaign, Mapping)
                else None
            ),
        )
    digest = str(campaign["campaign_sha256"])
    entries, issues = _entries(ledger_path)
    registration = _campaign_registration(entries, digest)
    start = _campaign_start(entries, digest)
    if registration is None:
        _issue(issues, "campaign:registration_missing")
    else:
        registration = _validate_registration(registration, digest, issues)
        if registration.get("grant", {}).get("schema") not in {
            LIVE_GRANT_SCHEMA_V3,
            LIVE_GRANT_SCHEMA_V4,
            LIVE_GRANT_SCHEMA_V5,
        }:
            _issue(issues, "stop:measurement_successor_grant_required")
    if start is None:
        _issue(issues, "campaign:start_record_missing")
    else:
        start = _closed(start, _START_FIELDS, "stop.start", issues)
        if not _seal_valid(start):
            _issue(issues, "stop:start_record_invalid")
    _consult_campaign_fences(
        entries,
        digest,
        issues,
        stop_code="campaign:already_stopped",
        termination_code="campaign:already_owner_terminated",
        join_code="campaign:already_joined",
    )

    draft = _closed(stop, _STOP_DRAFT_FIELDS, "stop", issues)
    if draft.get("schema") != LIVE_STOP_DRAFT_SCHEMA:
        _issue(issues, "stop:schema_invalid")
    if draft.get("reason_code") not in {
        "owner_directed",
        "execution_failure",
        "resource_limit",
        "evidence_failure",
    }:
        _issue(issues, "stop:reason_code_invalid")
    if not _identifier(draft.get("authority_id")):
        _issue(issues, "stop:authority_id_invalid")
    if not _sha_valid(draft.get("authority_source_sha256")):
        _issue(issues, "stop:authority_source_sha256_invalid")
    environment = _closed(
        draft.get("environment"),
        _OWNER_TERMINATION_ENVIRONMENT_FIELDS,
        "stop.environment",
        issues,
    )
    if environment != {
        "host_id": "jwj-lab",
        "runtime": "python3 -B",
        "provider_free": True,
    }:
        _issue(issues, "stop:environment_invalid")
    limits = _closed(draft.get("limits"), _STOP_LIMIT_FIELDS, "stop.limits", issues)
    expected_limits = {
        "qwen_calls": 0,
        "model_calls": 0,
        "hosted_calls": 0,
        "additional_tokens": 0,
        "new_reservations": 0,
        "retries": 0,
        "fallbacks": 0,
        "replacements": 0,
        "stop_invocations": 1,
    }
    if limits != expected_limits:
        _issue(issues, "stop:limits_invalid")
    drain = _closed(
        draft.get("drain_evidence"),
        _STOP_DRAIN_FIELDS,
        "stop.drain_evidence",
        issues,
    )
    zero_drain_fields = _STOP_DRAIN_FIELDS - {"observed_at_ms"}
    if (
        not _integer(drain.get("observed_at_ms"), minimum=0)
        or any(drain.get(field) != 0 for field in zero_drain_fields)
    ):
        _issue(issues, "stop:producers_not_drained")
    for field in ("material_risk", "recovery"):
        if not isinstance(draft.get(field), str) or not draft[field].strip():
            _issue(issues, f"stop:{field}_invalid")
    if not _integer(stopped_at_ms, minimum=0):
        _issue(issues, "stop:stopped_at_ms_invalid")
    elif isinstance(start, Mapping):
        if stopped_at_ms < int(start.get("started_at_ms", stopped_at_ms + 1)):
            _issue(issues, "stop:time_regression")
        if (
            type(drain.get("observed_at_ms")) is int
            and (
                drain["observed_at_ms"] > stopped_at_ms
                or stopped_at_ms - drain["observed_at_ms"] > 60_000
            )
        ):
            _issue(issues, "stop:drain_evidence_not_fresh")

    try:
        canonical_bytes = Path(ledger_path).read_bytes()
    except OSError:
        canonical_bytes = b""
        _issue(issues, "stop:canonical_ledger_unreadable")
    canonical_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    if draft.get("expected_canonical_ledger_sha256") != canonical_sha256:
        _issue(issues, "stop:canonical_ledger_sha256_mismatch")
    stop_families = _expected_families(campaign, issues)
    expected_shard_sha256s = draft.get("expected_shard_sha256s")
    if not isinstance(expected_shard_sha256s, Mapping) or set(
        expected_shard_sha256s
    ) != set(stop_families):
        _issue(issues, "stop:shard_sha256s_invalid")
        expected_shard_sha256s = {}
    shard_sha256s: dict[str, str] = {}
    if not isinstance(shard_paths, Mapping) or set(shard_paths) != set(
        stop_families
    ):
        _issue(issues, "stop:family_shards_invalid")
    else:
        for family in stop_families:
            try:
                value = hashlib.sha256(Path(shard_paths[family]).read_bytes()).hexdigest()
            except OSError:
                _issue(issues, f"stop:shard_unreadable:{family}")
                continue
            shard_sha256s[family] = value
            if expected_shard_sha256s.get(family) != value:
                _issue(issues, f"stop:shard_sha256_mismatch:{family}")

    reservations: dict[tuple[str, int, int], Mapping[str, Any]] = {}
    completions: dict[tuple[str, int, int], Mapping[str, Any]] = {}
    evidence_failures: dict[tuple[str, int, int], Mapping[str, Any]] = {}
    if registration is not None and start is not None:
        reservations, completions, evidence_failures = _join_sources(
            campaign, registration, start, shard_paths, issues
        )
    if len(completions) == expected_run_count(campaign):
        _issue(issues, "stop:campaign_complete_use_join")
    if issues or registration is None or start is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=digest,
        )

    evidence_failure_rows = [
        evidence_failures[key]
        for key in _campaign_cell_order(campaign)
        if key in evidence_failures
    ]
    evidence_aggregate = _evidence_failure_aggregate(evidence_failure_rows)
    has_evidence_failures = bool(evidence_failure_rows)
    counts = {
        "expected_runs": expected_run_count(campaign),
        "reserved_runs": len(reservations),
        "completed_runs": len(completions),
        "failed_runs": sum(
            row.get("outcome") == "failed" for row in completions.values()
        ),
        "never_dispatched_runs": expected_run_count(campaign) - len(reservations),
        "missing_runs": expected_run_count(campaign) - len(completions),
        "extrapolated_runs": 0,
    }
    if has_evidence_failures:
        counts.update(
            {
                "settled_runs": len(completions) + len(evidence_failure_rows),
                "evidence_failure_runs": len(evidence_failure_rows),
                "malformed_runs": sum(
                    row.get("evidence_class") == "malformed_terminal"
                    for row in completions.values()
                ),
            }
        )
    state = (
        "INCOMPLETE_OWNER_TERMINATED"
        if draft["reason_code"] == "owner_directed"
        else "INCOMPLETE_FAILURE"
    )
    record_core: dict[str, Any] = {
        "schema": (
            LIVE_STOP_RECORD_SCHEMA_V2
            if has_evidence_failures
            else LIVE_STOP_RECORD_SCHEMA
        ),
        "campaign_sha256": digest,
        "grant_sha256": registration["grant_sha256"],
        "start_record_sha256": start["record_sha256"],
        "authority_id": draft["authority_id"],
        "authority_source_sha256": draft["authority_source_sha256"],
        "reason_code": draft["reason_code"],
        "environment": dict(environment),
        "limits": dict(limits),
        "drain_evidence": dict(drain),
        "material_risk": draft["material_risk"],
        "recovery": draft["recovery"],
        "canonical_ledger_sha256_before_stop": canonical_sha256,
        "shard_sha256s": shard_sha256s,
        "original_deadline_at_ms": start["deadline_at_ms"],
        "stopped_at_ms": stopped_at_ms,
        "calendar_wait_required": False,
        "state": state,
        "counts": counts,
        "observed_tokens": sum(
            int(row.get("usage", {}).get("total_tokens", 0))
            for row in completions.values()
        )
        + evidence_aggregate["evidence_failure_observed_tokens"],
        "live_model_calls": sum(
            int(row.get("model_calls", 0)) for row in completions.values()
        )
        + evidence_aggregate["evidence_failure_lane_sessions"],
        "hosted_calls": 0,
        "reportable": False,
        "training_eligible": False,
        "replay_decidable": [],
        "live_required": [],
    }
    if has_evidence_failures:
        record_core.update(
            {
                **evidence_aggregate,
                "well_formed_observed_tokens": sum(
                    int(projection.get("usage", {}).get("total_tokens", 0))
                    for row in completions.values()
                    for projection in row.get("runtime_projections", [])
                    if type(projection.get("usage", {}).get("total_tokens"))
                    is int
                ),
            }
        )
    record = _seal(record_core)
    try:
        if hashlib.sha256(Path(ledger_path).read_bytes()).hexdigest() != canonical_sha256:
            return _base_report(
                status="FAIL",
                state="REFUSED",
                issues=["stop:canonical_ledger_changed_before_append"],
                campaign_sha256=digest,
            )
    except OSError:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["stop:canonical_ledger_unreadable_before_append"],
            campaign_sha256=digest,
        )
    for family in stop_families:
        try:
            current = hashlib.sha256(Path(shard_paths[family]).read_bytes()).hexdigest()
        except (KeyError, OSError, TypeError):
            current = None
        if current != shard_sha256s.get(family):
            return _base_report(
                status="FAIL",
                state="REFUSED",
                issues=[f"stop:shard_changed_before_append:{family}"],
                campaign_sha256=digest,
            )
    if _append(ledger_path, record) is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["ledger:stop_append_failed"],
            campaign_sha256=digest,
        )
    return summarize_live_campaign(ledger_path, digest)


def _replay_evidence(
    campaign: Mapping[str, Any], completion: Mapping[str, Any]
) -> dict[str, Any]:
    request = completion["request"]
    metric = completion["metric"]
    return {
        "schema": record_replay.MODEL_CALL_EVIDENCE_SCHEMA,
        "campaign_sha256": campaign["campaign_sha256"],
        "configuration_id": request["configuration_id"],
        "replicate_index": request["replicate_index"],
        "seed": request["seed"],
        "request": {
            "schema": "orch-dork/live-sweep-replay-request/v1",
            "live_request": dict(request),
            "lane_assignments": build_live_lane_assignments(request),
        },
        "response": {
            "schema": "orch-dork/live-sweep-replay-response/v1",
            "lane_results": [dict(row) for row in completion["lane_results"]],
            "score": {
                "numerator": metric["numerator"],
                "denominator": metric["denominator"],
            },
            "outcome": completion["outcome"],
        },
        "governed_report_sha256": completion["governed_evidence_sha256"],
    }


def _configuration_results(
    campaign: Mapping[str, Any],
    family: str,
    completions: Mapping[tuple[str, int, int], Mapping[str, Any]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for configuration in campaign.get("configuration_grid", []):
        if _parameter_map(configuration).get("task_family") != family:
            continue
        configuration_id = str(configuration.get("configuration_id"))
        rows = [
            completions[key]
            for key in _campaign_cell_order(campaign)
            if key[0] == configuration_id and key in completions
        ]
        expected = len(campaign.get("seeds", []))
        complete = len(rows) == expected
        numerator = (
            sum(int(row["metric"]["numerator"]) for row in rows)
            if complete
            else None
        )
        results.append(
            {
                "configuration_id": configuration_id,
                "configuration_sha256": _sha256(configuration),
                "state": "COMPLETE" if complete else "INCOMPLETE",
                "expected_runs": expected,
                "completed_runs": len(rows),
                "passed_runs": sum(row.get("outcome") == "passed" for row in rows),
                "failed_runs": sum(row.get("outcome") == "failed" for row in rows),
                "missing_runs": expected - len(rows),
                "verified_success_mean": (
                    {
                        "numerator": numerator,
                        "denominator": expected * 10_000,
                    }
                    if numerator is not None
                    else None
                ),
                "extrapolated_runs": 0,
            }
        )
    return results


def _find_cell_record(
    entries: list[Mapping[str, Any]], schema: str, key: tuple[str, int, int]
) -> Mapping[str, Any] | None:
    rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema") == schema
        and (
            row.get("record", {}).get("configuration_id"),
            row.get("record", {}).get("replicate_index"),
            row.get("record", {}).get("seed"),
        )
        == key
    ]
    return rows[0] if len(rows) == 1 else None


def join_live_campaign(
    campaign: Any,
    ledger_path: str | Path,
    shard_paths: Mapping[str, str | Path],
    *,
    joined_at_ms: int,
) -> dict[str, Any]:
    """Deterministically join family shards without replaying missing cells."""

    verified = campaign_contract.verify_campaign(campaign)
    if verified.get("status") != "PASS" or not isinstance(campaign, Mapping):
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["campaign:invalid"],
            campaign_sha256=(
                campaign.get("campaign_sha256")
                if isinstance(campaign, Mapping)
                else None
            ),
        )
    digest = str(campaign["campaign_sha256"])
    entries, issues = _entries(ledger_path)
    termination_rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema")
        == LIVE_OWNER_TERMINATION_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == digest
    ]
    if len(termination_rows) == 1:
        return summarize_live_campaign(ledger_path, digest)
    if len(termination_rows) > 1:
        _issue(issues, "termination:duplicate")
    stop_rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema")
        in _LIVE_STOP_RECORD_SCHEMAS
        and row.get("record", {}).get("campaign_sha256") == digest
    ]
    if len(stop_rows) == 1:
        return summarize_live_campaign(ledger_path, digest)
    if len(stop_rows) > 1:
        _issue(issues, "stop:duplicate")
    registration = _campaign_registration(entries, digest)
    start = _campaign_start(entries, digest)
    if registration is None:
        _issue(issues, "campaign:registration_missing")
    else:
        _validate_registration(registration, digest, issues)
    if start is None:
        _issue(issues, "campaign:start_record_missing")
    else:
        start = _closed(start, _START_FIELDS, "join.start", issues)
        if not _seal_valid(start):
            _issue(issues, "join:start_record_invalid")
        elif registration is not None:
            if (
                start.get("campaign_sha256") != digest
                or start.get("grant_sha256") != registration.get("grant_sha256")
                or start.get("registration_record_sha256")
                != registration.get("record_sha256")
                or type(start.get("started_at_ms")) is not int
                or type(start.get("deadline_at_ms")) is not int
                or start.get("deadline_at_ms")
                != start.get("started_at_ms", 0)
                + registration.get("grant", {}).get("max_wall_time_ms", -1)
                or [
                    row.get("task_family")
                    for row in start.get("family_shards", [])
                    if isinstance(row, Mapping)
                ]
                != list(_expected_families(campaign, issues))
            ):
                _issue(issues, "join:start_record_binding_invalid")
    joins = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema")
        in _LIVE_JOIN_RECORD_SCHEMAS
        and row.get("record", {}).get("campaign_sha256") == digest
    ]
    if len(joins) == 1:
        return summarize_live_campaign(ledger_path, digest)
    if len(joins) > 1:
        _issue(issues, "join:duplicate")
    if not _integer(joined_at_ms, minimum=0):
        _issue(issues, "join:joined_at_ms_invalid")
    if issues or registration is None or start is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=digest,
        )
    reservations, completions, evidence_failures = _join_sources(
        campaign, registration, start, shard_paths, issues
    )
    expected_keys = _campaign_cell_order(campaign)
    settled_count = len(completions) + len(evidence_failures)
    if settled_count != len(expected_keys) and joined_at_ms < int(
        start["deadline_at_ms"]
    ):
        _issue(issues, "join:campaign_still_open")
    if issues:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=issues,
            campaign_sha256=digest,
        )

    v2_join = any(
        row.get("schema") == LIVE_COMPLETION_RECORD_SCHEMA_V2
        for row in completions.values()
    )
    v3_join = bool(evidence_failures)
    canonical_hashes: list[str] = []
    replay_hashes: list[str] = []
    for key in expected_keys:
        completion = completions.get(key)
        if completion is None:
            continue
        replay_evidence = _replay_evidence(campaign, completion)
        existing_call = _find_cell_record(
            entries, record_replay.MODEL_CALL_RECORD_SCHEMA, key
        )
        if existing_call is None:
            replay_report = record_replay.record_model_call(
                campaign, ledger_path, replay_evidence
            )
            if replay_report.get("status") != "PASS":
                return _base_report(
                    status="FAIL",
                    state="REFUSED",
                    issues=["join:replay_record_failed"],
                    campaign_sha256=digest,
                )
            replay_record_sha256 = str(
                replay_report["model_call_record_sha256"]
            )
            entries, chain_issues = _entries(ledger_path)
            if chain_issues:
                return _base_report(
                    status="FAIL",
                    state="REFUSED",
                    issues=chain_issues,
                    campaign_sha256=digest,
                )
        else:
            if (
                existing_call.get("request") != replay_evidence["request"]
                or existing_call.get("response") != replay_evidence["response"]
                or existing_call.get("governed_report_sha256")
                != replay_evidence["governed_report_sha256"]
                or not _seal_valid(existing_call)
            ):
                return _base_report(
                    status="FAIL",
                    state="REFUSED",
                    issues=["join:existing_replay_record_mismatch"],
                    campaign_sha256=digest,
                )
            replay_record_sha256 = str(existing_call["record_sha256"])
        replay_hashes.append(replay_record_sha256)
        request = completion["request"]
        canonical_core = {
            "schema": (
                LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA_V2
                if v2_join
                else LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA
            ),
            "campaign_sha256": digest,
            "grant_sha256": registration["grant_sha256"],
            "start_record_sha256": start["record_sha256"],
            "task_family": completion["task_family"],
            "configuration_id": request["configuration_id"],
            "configuration_sha256": request["configuration_sha256"],
            "replicate_index": request["replicate_index"],
            "seed": request["seed"],
            "live_request_sha256": request["request_sha256"],
            "reservation_record_sha256": completion[
                "reservation_record_sha256"
            ],
            "completion_record_sha256": completion["record_sha256"],
            "outcome": completion["outcome"],
            "metric": dict(completion["metric"]),
            "governed_report_sha256": completion["governed_evidence_sha256"],
            "usage": dict(completion["usage"]),
            "timing": dict(completion["timing"]),
            "live_model_calls": completion["model_calls"],
            "hosted_calls": completion["hosted_calls"],
            "replay_model_call_record_sha256": replay_record_sha256,
            "replay_decidable": list(_REPLAY_DECIDABLE),
            "live_required": list(_LIVE_REQUIRED),
        }
        if v2_join:
            canonical_core["evidence_class"] = completion.get(
                "evidence_class", "qualified"
            )
        canonical_record = _seal(canonical_core)
        existing_canonical = _find_cell_record(
            entries,
            (
                LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA_V2
                if v2_join
                else LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA
            ),
            key,
        )
        if existing_canonical is None:
            if _append(ledger_path, canonical_record) is None:
                return _base_report(
                    status="FAIL",
                    state="REFUSED",
                    issues=["ledger:canonical_replicate_append_failed"],
                    campaign_sha256=digest,
                )
            entries, chain_issues = _entries(ledger_path)
            if chain_issues:
                return _base_report(
                    status="FAIL",
                    state="REFUSED",
                    issues=chain_issues,
                    campaign_sha256=digest,
                )
        elif existing_canonical != canonical_record or not _seal_valid(
            existing_canonical
        ):
            return _base_report(
                status="FAIL",
                state="REFUSED",
                issues=["join:existing_canonical_record_mismatch"],
                campaign_sha256=digest,
            )
        canonical_hashes.append(canonical_record["record_sha256"])

    state = "COMPLETE" if len(completions) == len(expected_keys) else "INCOMPLETE"
    family_records: list[dict[str, Any]] = []
    for family in _campaign_families(campaign):
        family_expected = [
            key
            for key in expected_keys
            if _parameter_map(_configuration(campaign, key[0]) or {}).get(
                "task_family"
            )
            == family
        ]
        family_reserved = [key for key in family_expected if key in reservations]
        family_completed = [key for key in family_expected if key in completions]
        family_evidence_failed = [
            key for key in family_expected if key in evidence_failures
        ]
        family_evidence_rows = [
            evidence_failures[key] for key in family_evidence_failed
        ]
        family_evidence_aggregate = _evidence_failure_aggregate(
            family_evidence_rows
        )
        counts = {
            "expected_runs": len(family_expected),
            "reserved_runs": len(family_reserved),
            "completed_runs": len(family_completed),
            "failed_runs": sum(
                completions[key].get("outcome") == "failed"
                for key in family_completed
            ),
            "missing_runs": len(family_expected) - len(family_completed),
            "extrapolated_runs": 0,
        }
        if v2_join:
            counts["malformed_runs"] = sum(
                completions[key].get("evidence_class") == "malformed_terminal"
                for key in family_completed
            )
        if v3_join:
            counts.update(
                {
                    "settled_runs": (
                        len(family_completed) + len(family_evidence_failed)
                    ),
                    "evidence_failure_runs": len(family_evidence_failed),
                    "malformed_runs": sum(
                        completions[key].get("evidence_class")
                        == "malformed_terminal"
                        for key in family_completed
                    ),
                }
            )
        family_core = {
            "schema": (
                LIVE_FAMILY_SUMMARY_RECORD_SCHEMA_V3
                if v3_join
                else LIVE_FAMILY_SUMMARY_RECORD_SCHEMA_V2
                if v2_join
                else LIVE_FAMILY_SUMMARY_RECORD_SCHEMA
            ),
            "campaign_sha256": digest,
            "grant_sha256": registration["grant_sha256"],
            "start_record_sha256": start["record_sha256"],
            "task_family": family,
            "state": (
                "COMPLETE" if not counts["missing_runs"] else "INCOMPLETE"
            ),
            "counts": counts,
            "configuration_results": _configuration_results(
                campaign, family, completions
            ),
            "observed_tokens": sum(
                int(completions[key]["usage"]["total_tokens"])
                for key in family_completed
            )
            + family_evidence_aggregate["evidence_failure_observed_tokens"],
            "live_model_calls": sum(
                int(completions[key]["model_calls"])
                for key in family_completed
            )
            + family_evidence_aggregate["evidence_failure_lane_sessions"],
            "hosted_calls": 0,
            "replay_decidable": list(_REPLAY_DECIDABLE),
            "live_required": list(_LIVE_REQUIRED),
            "joined_at_ms": joined_at_ms,
        }
        if v2_join or v3_join:
            family_core["well_formed_observed_tokens"] = sum(
                int(projection.get("usage", {}).get("total_tokens", 0))
                for key in family_completed
                for projection in completions[key].get("runtime_projections", [])
                if type(projection.get("usage", {}).get("total_tokens")) is int
            )
        if v3_join:
            family_core.update(
                {
                    **family_evidence_aggregate,
                    "reportable": False,
                    "training_eligible": False,
                }
            )
        family_record = _seal(family_core)
        existing_family = [
            row["record"]
            for row in entries
            if row.get("record", {}).get("schema")
            in _LIVE_FAMILY_SUMMARY_RECORD_SCHEMAS
            and row.get("record", {}).get("campaign_sha256") == digest
            and row.get("record", {}).get("task_family") == family
        ]
        if not existing_family:
            if _append(ledger_path, family_record) is None:
                return _base_report(
                    status="FAIL",
                    state="REFUSED",
                    issues=["ledger:family_summary_append_failed"],
                    campaign_sha256=digest,
                )
            entries, chain_issues = _entries(ledger_path)
            if chain_issues:
                return _base_report(
                    status="FAIL",
                    state="REFUSED",
                    issues=chain_issues,
                    campaign_sha256=digest,
                )
        elif len(existing_family) != 1 or existing_family[0] != family_record:
            return _base_report(
                status="FAIL",
                state="REFUSED",
                issues=["join:existing_family_summary_mismatch"],
                campaign_sha256=digest,
            )
        family_records.append(family_record)

    counts = {
        "expected_runs": len(expected_keys),
        "reserved_runs": len(reservations),
        "completed_runs": len(completions),
        "failed_runs": sum(
            row.get("outcome") == "failed" for row in completions.values()
        ),
        "missing_runs": len(expected_keys) - len(completions),
    }
    if v2_join:
        counts["malformed_runs"] = sum(
            row.get("evidence_class") == "malformed_terminal"
            for row in completions.values()
        )
    if v3_join:
        counts.update(
            {
                "settled_runs": settled_count,
                "evidence_failure_runs": len(evidence_failures),
                "malformed_runs": sum(
                    row.get("evidence_class") == "malformed_terminal"
                    for row in completions.values()
                ),
                "extrapolated_runs": 0,
            }
        )
    evidence_failure_rows = [
        evidence_failures[key]
        for key in expected_keys
        if key in evidence_failures
    ]
    evidence_aggregate = _evidence_failure_aggregate(evidence_failure_rows)
    join_core: dict[str, Any] = {
        "schema": (
            LIVE_JOIN_RECORD_SCHEMA_V3
            if v3_join
            else LIVE_JOIN_RECORD_SCHEMA_V2
            if v2_join
            else LIVE_JOIN_RECORD_SCHEMA
        ),
        "campaign_sha256": digest,
        "grant_sha256": registration["grant_sha256"],
        "start_record_sha256": start["record_sha256"],
        "state": state,
        "counts": counts,
        "family_summary_record_sha256s": [
            row["record_sha256"] for row in family_records
        ],
        "canonical_replicate_record_sha256s": canonical_hashes,
        "replay_model_call_record_sha256s": replay_hashes,
        "observed_tokens": sum(
            int(row["usage"]["total_tokens"]) for row in completions.values()
        )
        + evidence_aggregate["evidence_failure_observed_tokens"],
        "live_model_calls": sum(
            int(row["model_calls"]) for row in completions.values()
        )
        + evidence_aggregate["evidence_failure_lane_sessions"],
        "hosted_calls": 0,
        "replay_decidable": list(_REPLAY_DECIDABLE),
        "live_required": list(_LIVE_REQUIRED),
        "joined_at_ms": joined_at_ms,
    }
    if v2_join or v3_join:
        join_core["well_formed_observed_tokens"] = sum(
            int(projection.get("usage", {}).get("total_tokens", 0))
            for row in completions.values()
            for projection in row.get("runtime_projections", [])
            if type(projection.get("usage", {}).get("total_tokens")) is int
        )
    if v3_join:
        join_core.update(
            {
                **evidence_aggregate,
                "reportable": False,
                "training_eligible": False,
            }
        )
    join_record = _seal(join_core)
    if _append(ledger_path, join_record) is None:
        return _base_report(
            status="FAIL",
            state="REFUSED",
            issues=["ledger:join_append_failed"],
            campaign_sha256=digest,
        )
    return summarize_live_campaign(ledger_path, digest)


__all__ = [
    "ISSUE111_CUT_STRATEGIES",
    "ISSUE111_TASK_FAMILIES",
    "LIVE_ABORT_DRAFT_SCHEMA",
    "LIVE_ABORT_RECORD_SCHEMA",
    "LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA",
    "LIVE_CAMPAIGN_RECORD_SCHEMA",
    "LIVE_COMPLETION_DRAFT_SCHEMA",
    "LIVE_COMPLETION_DRAFT_SCHEMA_V2",
    "LIVE_COMPLETION_RECORD_SCHEMA",
    "LIVE_COMPLETION_RECORD_SCHEMA_V2",
    "LIVE_EVIDENCE_FAILURE_DRAFT_SCHEMA",
    "LIVE_EVIDENCE_FAILURE_DRAFT_SCHEMA_V2",
    "LIVE_EVIDENCE_FAILURE_DRAFT_SCHEMA_V3",
    "LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA",
    "LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA_V2",
    "LIVE_EVIDENCE_FAILURE_RECORD_SCHEMA_V3",
    "EVIDENCE_FAILURE_RECORD_SCHEMAS",
    "SETTLEABLE_EVIDENCE_FAILURE_CAUSES",
    "SETTLEABLE_USAGE_FAILURE_CAUSES",
    "UNKNOWN_USAGE",
    "STABLE_TERMINAL_FAILURE_CAUSE",
    "LIVE_GOVERNED_EVIDENCE_SCHEMA",
    "LIVE_GRANT_SCHEMA",
    "LIVE_GRANT_SCHEMA_V1",
    "LIVE_GRANT_SCHEMA_V2",
    "LIVE_GRANT_SCHEMA_V3",
    "LIVE_GRANT_SCHEMA_V4",
    "LIVE_GRANT_SCHEMA_V5",
    "LIVE_GRANT_SHAPE_SCHEMA",
    "LIVE_FAMILY_SUMMARY_RECORD_SCHEMA",
    "LIVE_FAMILY_SUMMARY_RECORD_SCHEMA_V2",
    "LIVE_FAMILY_SUMMARY_RECORD_SCHEMA_V3",
    "LIVE_JOIN_RECORD_SCHEMA",
    "LIVE_JOIN_RECORD_SCHEMA_V2",
    "LIVE_JOIN_RECORD_SCHEMA_V3",
    "LIVE_LANE_ASSIGNMENT_SCHEMA",
    "LIVE_LANE_RESULT_SCHEMA",
    "LIVE_OWNER_TERMINATION_DRAFT_SCHEMA",
    "LIVE_OWNER_TERMINATION_RECORD_SCHEMA",
    "LIVE_REPORT_SCHEMA",
    "LIVE_REPLICATE_REQUEST_SCHEMA",
    "LIVE_RESERVATION_RECORD_SCHEMA",
    "LIVE_RESIDUAL_PROJECTION_SCHEMA",
    "LIVE_SHARD_HEADER_SCHEMA",
    "LIVE_SHARD_REPORT_SCHEMA",
    "LIVE_SHARD_REPORT_SCHEMA_V2",
    "LIVE_START_RECORD_SCHEMA",
    "LIVE_STOP_DRAFT_SCHEMA",
    "LIVE_STOP_RECORD_SCHEMA",
    "LIVE_STOP_RECORD_SCHEMA_V2",
    "build_issue111_campaign_draft",
    "build_issue111_grant",
    "build_issue111_replay_plan",
    "build_issue111_measurement_successor_grant",
    "build_issue111_successor_grant",
    "build_live_lane_assignments",
    "abort_live_campaign",
    "complete_live_replicate",
    "derive_campaign_fences",
    "derive_grant_shape",
    "expected_run_count",
    "expected_live_findings",
    "expected_live_lane_findings",
    "join_live_campaign",
    "project_campaign_residual",
    "register_live_campaign",
    "register_measurement_successor_live_campaign",
    "register_successor_live_campaign",
    "record_live_evidence_failure",
    "reserve_live_replicate",
    "render_live_lane_prompt",
    "settled_usage_tokens",
    "start_live_campaign",
    "stop_live_campaign",
    "summarize_live_campaign",
    "summarize_live_shard",
    "terminate_live_campaign",
    "usage_is_unknown",
    "validate_grant_shape",
]
