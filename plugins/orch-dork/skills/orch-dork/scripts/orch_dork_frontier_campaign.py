#!/usr/bin/env python3
"""Bounded end-to-end frontier qualification behind Control Tower v2.

The module is deliberately provider-free at its Issue 150 boundary.  It owns
campaign selection and the campaign event stream, while each configuration run
remains an independently verified RunEngine stream supplied through an injected
resolver.  It never contacts a model, executes a tool, or creates authority.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable, Mapping


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ImportError:
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        previous = sys.modules.get(name)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
            raise
        return module


run_store = _load_sibling("orch_dork_run_store")
run_engine = _load_sibling("orch_dork_run_engine")
topology_lab = _load_sibling("orch_dork_topology_lab")


PROGRAM_SCHEMA = "orch-dork/control-tower-program/v2"
REPORT_SCHEMA = "orch-dork/control-tower-report/v2"
PREPARE_SCHEMA = "orch-dork/frontier-campaign-prepare/v2"
PREPARATION_SCHEMA = "orch-dork/frontier-campaign-preparation/v2"
ADVANCE_SCHEMA = "orch-dork/frontier-campaign-advance/v2"
INSPECTION_QUERY_SCHEMA = "orch-dork/frontier-campaign-inspection-query/v2"
FIXTURE_SCHEMA = "orch-dork/frontier-fixture/v2"
CORPUS_DRAFT_SCHEMA = "orch-dork/frontier-corpus-draft/v2"
CORPUS_SCHEMA = "orch-dork/frontier-corpus/v2"
RUNTIME_CONTRACT_SCHEMA = "orch-dork/frontier-runtime-contract/v2"
AUTHORITY_CLASS = "frontier-qualification/v1"
CURSOR_SCHEMA = "orch-dork/frontier-campaign-cursor/v2"
DECISION_SCHEMA = "orch-dork/frontier-campaign-decision/v2"
INSPECTION_SCHEMA = "orch-dork/frontier-campaign-inspection/v2"
AUTHORITY_REGISTRATION_DRAFT_SCHEMA = (
    "orch-dork/frontier-authority-registration-draft/v2"
)
AUTHORITY_REGISTRATION_SCHEMA = "orch-dork/frontier-authority-registration/v2"
RUN_REF_SCHEMA = "orch-dork/frontier-run-ref/v2"
CONFIG_OBSERVATION_DRAFT_SCHEMA = (
    "orch-dork/frontier-config-observation-draft/v2"
)
CONFIG_OBSERVATION_SCHEMA = "orch-dork/frontier-config-observation/v2"
REVIEW_OBSERVATION_DRAFT_SCHEMA = (
    "orch-dork/sol-proxy-review-observation-draft/v2"
)
REVIEW_OBSERVATION_SCHEMA = "orch-dork/sol-proxy-review-observation/v2"

OPERATIONS = frozenset({"prepare", "advance", "inspect"})
PARTITIONS = ("frozen", "recent_failures", "adversarial", "holdout")
STRUCTURAL_FLOORS = (
    "correctness_bps",
    "verified_coverage_bps",
    "privacy_bps",
    "authority_bps",
    "safety_bps",
    "evidence_completeness_bps",
)
SELECTION_MINIMA = (
    "critical_path_ms",
    "tokens",
    "cost_micros",
    "integration_cost_micros",
    "repair_cost_micros",
)
REVIEW_DIMENSIONS = (
    "task_usefulness",
    "maintainability_locality",
    "integration_coherence",
    "operational_verification_readiness",
)
_CALIBRATION_ROTATION = (
    ("calibration-alpha", "A"),
    ("calibration-beta", "B"),
    ("calibration-gamma", "TIE"),
    ("calibration-delta", "A"),
    ("calibration-epsilon", "B"),
)

MAX_CANONICAL_BYTES = 262_144
MAX_NESTING = 32
MAX_COMPOSITE_NODES = 8192
MAX_CONTAINER_ITEMS = 512

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,127}\Z")
_PROGRAM_FIELDS = frozenset({"schema", "program_id", "operation", "payload"})
_PREPARE_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "archive",
        "corpus",
        "runtime_contract",
        "authority_scope_sha256",
        "prompt_bundle_sha256",
        "verification_policy_sha256",
        "cost_weights_sha256",
        "tool_policy_sha256",
        "prepared_at_ms",
    }
)
_CORPUS_DRAFT_FIELDS = frozenset(
    {"schema", "corpus_id", "holdout_group_id", "fixtures"}
)
_FIXTURE_FIELDS = frozenset(
    {
        "schema",
        "fixture_id",
        "fixture_sha256",
        "partition",
        "lineage_sha256",
        "rung",
        "task_input_sha256",
        "champion_task_brief_sha256",
        "challenger_task_brief_sha256",
        "snapshot_sha256",
        "public_checks_sha256",
        "hidden_checks_sha256",
        "privacy_class",
    }
)
_RUNTIME_FIELDS = frozenset(
    {
        "schema",
        "qwen_identity_sha256",
        "sol_identity_sha256",
        "qwen_provider",
        "sol_provider",
        "sol_model_id",
        "sol_runtime_id",
        "sol_retention",
        "sol_region",
        "sol_context_tokens",
        "sol_input_tokens",
        "sol_output_tokens",
        "sol_generations",
        "sol_tools",
        "provider_free",
    }
)
_PREPARATION_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "preparation_status",
        "archive_sha256",
        "champion",
        "challenger",
        "corpus_sha256",
        "corpus_id",
        "holdout_group_id",
        "fixtures",
        "runtime_contract",
        "runtime_contract_sha256",
        "authority_class",
        "authority_scope_sha256",
        "prompt_bundle_sha256",
        "verification_policy_sha256",
        "cost_weights_sha256",
        "tool_policy_sha256",
        "budget_contract",
        "deadline_contract",
        "review_contract",
        "prepared_at_ms",
        "terminal",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "preparation_sha256",
    }
)
_ADVANCE_FIELDS = frozenset(
    {"schema", "kind", "campaign_id", "prior_cursor", "request"}
)
_INSPECTION_QUERY_FIELDS = frozenset(
    {"schema", "campaign_id", "after_seq", "max_events"}
)
_CURSOR_FIELDS = frozenset(
    {"schema", "campaign_id", "seq", "event_hash", "stream_sha256"}
)
_AUTHORITY_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "class_id",
        "campaign_id",
        "authority_scope_sha256",
        "registration_id",
        "registered_at_ms",
        "provider_free",
    }
)
_AUTHORITY_FIELDS = _AUTHORITY_DRAFT_FIELDS | frozenset(
    {"registration_sha256"}
)
_RUN_REF_FIELDS = frozenset({"schema", "run_id", "stream_sha256"})
_OBJECTIVE_FIELDS = frozenset(
    {"safety", "privacy", "authority", "custody", "cleanup", "correctness"}
)
_USAGE_FIELDS = frozenset(
    {"exact", "tokens", "weighted_cost_micros", "critical_path_ms"}
)
_CONFIG_OBSERVATION_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "fixture_sha256",
        "role",
        "run_ref",
        "objective_checks",
        "usage",
        "artifact_sha256",
        "hidden_check_sha256",
        "evidence_sha256",
    }
)
_CONFIG_OBSERVATION_FIELDS = _CONFIG_OBSERVATION_DRAFT_FIELDS | frozenset(
    {"observation_sha256"}
)
_REVIEW_OBSERVATION_DRAFT_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "fixture_sha256",
        "review_status",
        "sol_identity_sha256",
        "blind_packet_sha256",
        "rubric_sha256",
        "option_a_scores",
        "option_b_scores",
        "winner",
        "evidence_refs",
        "calibration_pair_sha256",
        "calibration_disposition",
        "tokens",
        "review_evidence_sha256",
    }
)
_REVIEW_OBSERVATION_FIELDS = _REVIEW_OBSERVATION_DRAFT_FIELDS | frozenset(
    {"review_usefulness_bps", "observation_sha256"}
)


def _canonical(value: Any) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > MAX_CANONICAL_BYTES:
        raise ValueError("canonical_bytes_exceeded")
    return raw


def _shape_within_bounds(value: Any) -> bool:
    stack = [(value, 0)]
    composite = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, Mapping):
            composite += 1
            if (
                depth > MAX_NESTING
                or composite > MAX_COMPOSITE_NODES
                or len(current) > MAX_CONTAINER_ITEMS
            ):
                return False
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            composite += 1
            if (
                depth > MAX_NESTING
                or composite > MAX_COMPOSITE_NODES
                or len(current) > MAX_CONTAINER_ITEMS
            ):
                return False
            stack.extend((item, depth + 1) for item in current)
    return True


def json_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    result = deepcopy(dict(value))
    result.pop(field, None)
    result[field] = json_sha256(result)
    return result


def _sealed(value: Any, field: str) -> bool:
    if not isinstance(value, Mapping) or not _sha(value.get(field)):
        return False
    core = dict(value)
    digest = core.pop(field)
    try:
        return digest == json_sha256(core)
    except (TypeError, ValueError, OverflowError):
        return False


def _sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _closed(
    value: Any, fields: frozenset[str], label: str, issues: list[str]
) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) != fields:
        issues.append(label + ":contract_invalid")
        return None
    return deepcopy(dict(value))


def _fixture(value: Any, issues: list[str]) -> dict[str, Any] | None:
    fixture = _closed(value, _FIXTURE_FIELDS, "fixture", issues)
    if fixture is None:
        return None
    if fixture.get("schema") != FIXTURE_SCHEMA:
        issues.append("fixture:schema_invalid")
    if not _identifier(fixture.get("fixture_id")):
        issues.append("fixture:id_invalid")
    for field in _FIXTURE_FIELDS - {
        "schema",
        "fixture_id",
        "partition",
        "rung",
        "privacy_class",
    }:
        if not _sha(fixture.get(field)):
            issues.append("fixture:" + field + "_invalid")
    if fixture.get("partition") not in PARTITIONS:
        issues.append("fixture:partition_invalid")
    if type(fixture.get("rung")) is not int or not 1 <= fixture["rung"] <= 5:
        issues.append("fixture:rung_invalid")
    if fixture.get("privacy_class") != "hosted_restricted":
        issues.append("fixture:privacy_invalid")
    return fixture


def _corpus(value: Any) -> tuple[dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    draft = _closed(value, _CORPUS_DRAFT_FIELDS, "corpus", issues)
    if draft is None:
        return None, sorted(set(issues))
    if draft.get("schema") != CORPUS_DRAFT_SCHEMA:
        issues.append("corpus:schema_invalid")
    if not _identifier(draft.get("corpus_id")) or not _identifier(
        draft.get("holdout_group_id")
    ):
        issues.append("corpus:id_invalid")
    raw_fixtures = draft.get("fixtures")
    normalized: list[dict[str, Any]] = []
    if not isinstance(raw_fixtures, list) or len(raw_fixtures) != 20:
        issues.append("corpus:fixture_count_invalid")
    else:
        for raw in raw_fixtures:
            item = _fixture(raw, issues)
            if item is not None:
                normalized.append(item)
    identities = [item["fixture_sha256"] for item in normalized]
    ids = [item["fixture_id"] for item in normalized]
    if len(identities) != len(set(identities)) or len(ids) != len(set(ids)):
        issues.append("corpus:fixture_duplicate")
    for partition in PARTITIONS:
        if sum(item.get("partition") == partition for item in normalized) != 5:
            issues.append("corpus:partition_count_invalid")
    for rung in range(1, 6):
        seen = {
            item["partition"] for item in normalized if item.get("rung") == rung
        }
        if seen != set(PARTITIONS) or sum(
            item.get("rung") == rung for item in normalized
        ) != 4:
            issues.append("corpus:rung_partition_invalid")
    training = {
        item["lineage_sha256"]
        for item in normalized
        if item.get("partition") != "holdout"
    }
    holdout = {
        item["lineage_sha256"]
        for item in normalized
        if item.get("partition") == "holdout"
    }
    if training & holdout:
        issues.append("corpus:lineage_overlap")
    if issues:
        return None, sorted(set(issues))
    normalized.sort(
        key=lambda item: (item["rung"], PARTITIONS.index(item["partition"]))
    )
    core = {
        "schema": CORPUS_SCHEMA,
        "corpus_id": draft["corpus_id"],
        "holdout_group_id": draft["holdout_group_id"],
        "fixtures": normalized,
    }
    return _seal(core, "corpus_sha256"), []


def _runtime_contract(
    value: Any, issues: list[str]
) -> dict[str, Any] | None:
    contract = _closed(value, _RUNTIME_FIELDS, "runtime", issues)
    if contract is None:
        return None
    if contract.get("schema") != RUNTIME_CONTRACT_SCHEMA:
        issues.append("runtime:schema_invalid")
    for field in ("qwen_identity_sha256", "sol_identity_sha256"):
        if not _sha(contract.get(field)):
            issues.append("runtime:" + field + "_invalid")
    for field in (
        "qwen_provider",
        "sol_provider",
        "sol_model_id",
        "sol_runtime_id",
        "sol_retention",
        "sol_region",
    ):
        if not _identifier(contract.get(field)):
            issues.append("runtime:" + field + "_invalid")
    expected = {
        "sol_context_tokens": 12_000,
        "sol_input_tokens": 8_000,
        "sol_output_tokens": 2_000,
        "sol_generations": 1,
        "sol_tools": [],
        "provider_free": True,
    }
    for field, required in expected.items():
        if contract.get(field) != required:
            issues.append("runtime:" + field + "_invalid")
    return contract


def _candidate_eligible(
    entry: Mapping[str, Any], baseline: Mapping[str, Any]
) -> bool:
    candidate = entry.get("candidate")
    metrics = entry.get("metrics")
    genome = candidate.get("genome") if isinstance(candidate, Mapping) else None
    baseline_metrics = baseline.get("metrics")
    if not isinstance(genome, Mapping) or not isinstance(metrics, Mapping) or not isinstance(
        baseline_metrics, Mapping
    ):
        return False
    if (
        genome.get("profile_id") == "direct/v1"
        or type(genome.get("lane_count")) is not int
        or genome["lane_count"] > 2
        or type(genome.get("depth")) is not int
        or genome["depth"] > 2
    ):
        return False
    if any(metrics.get(field, -1) < baseline_metrics.get(field, 0) for field in STRUCTURAL_FLOORS):
        return False
    return True


def _select_challenger(archive: Mapping[str, Any]) -> dict[str, Any] | None:
    baseline = archive["direct_baseline"]
    eligible = [
        entry
        for entry in archive["frontier"]
        if _candidate_eligible(entry, baseline)
    ]
    if not eligible:
        return None
    selected = min(
        eligible,
        key=lambda entry: (
            *(entry["metrics"][field] for field in SELECTION_MINIMA),
            entry["candidate"]["candidate_sha256"],
        ),
    )
    return deepcopy(selected)


def _budget_contract() -> dict[str, Any]:
    return {
        "schema": "orch-dork/frontier-budget-contract/v2",
        "qwen_session_limit": 80,
        "champion_session_limit": 20,
        "challenger_session_limit": 60,
        "qwen_total_tokens_per_session": 27_000,
        "qwen_output_tokens_per_session": 4_096,
        "qwen_generations_per_session": 8,
        "qwen_tool_calls_per_session": 24,
        "sol_review_limit": 20,
        "sol_total_tokens_per_review": 12_000,
        "sol_output_tokens_per_review": 2_000,
        "sol_generations_per_review": 1,
        "sol_tool_calls_per_review": 0,
        "aggregate_reserved_tokens": 2_400_000,
        "max_active_fixture_pairs": 2,
        "max_concurrent_qwen_sessions": 4,
        "max_concurrent_sol_reviews": 2,
        "champion_sessions_per_fixture": 1,
        "challenger_sessions_per_fixture": 3,
        "max_weighted_cost_micros_per_fixture": 81_000,
    }


def _deadline_contract() -> dict[str, Any]:
    return {
        "schema": "orch-dork/frontier-deadline-contract/v2",
        "rung_ms": 7_200_000,
        "campaign_ms": 36_000_000,
        "cleanup_ms": 60_000,
    }


def _review_contract(runtime: Mapping[str, Any]) -> dict[str, Any]:
    core = {
        "schema": "orch-dork/sol-proxy-review-contract/v2",
        "sol_identity_sha256": runtime["sol_identity_sha256"],
        "dimensions": list(REVIEW_DIMENSIONS),
        "score_min": 0,
        "score_max": 4,
        "equal_weighted": True,
        "blind": True,
        "human_proxy": True,
        "human_authored": False,
        "tools": [],
        "calibration_required_per_rung": True,
        "retry_limit": 0,
    }
    return _seal(core, "review_contract_sha256")


def _terminal_no_candidate(
    campaign_id: str, archive_sha256: str, corpus_sha256: str
) -> dict[str, Any]:
    successor = _seal(
        {
            "schema": "orch-dork/frontier-successor/v2",
            "kind": "STOP",
            "campaign_id": campaign_id,
            "candidate_sha256": None,
            "rotated_holdout_required": True,
            "dispatch_permitted": False,
            "authority_granted": False,
        },
        "successor_sha256",
    )
    return _seal(
        {
            "schema": "orch-dork/frontier-terminal/v2",
            "outcome": "NO_ELIGIBLE_CHALLENGER",
            "reason": "frontier:no_eligible_challenger",
            "archive_sha256": archive_sha256,
            "corpus_sha256": corpus_sha256,
            "model_calls": 0,
            "hosted_calls": 0,
            "retries": 0,
            "fallbacks": 0,
            "replacements": 0,
            "successor": successor,
        },
        "terminal_sha256",
    )


def _prepare(value: Any) -> tuple[dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    request = _closed(value, _PREPARE_FIELDS, "prepare", issues)
    if request is None:
        return None, sorted(set(issues))
    if request.get("schema") != PREPARE_SCHEMA:
        issues.append("prepare:schema_invalid")
    if not _identifier(request.get("campaign_id")):
        issues.append("prepare:campaign_id_invalid")
    archive = request.get("archive")
    if topology_lab.validate_archive(archive).get("status") != "PASS":
        issues.append("prepare:archive_invalid")
    corpus, corpus_issues = _corpus(request.get("corpus"))
    issues.extend(corpus_issues)
    runtime = _runtime_contract(request.get("runtime_contract"), issues)
    for field in (
        "authority_scope_sha256",
        "prompt_bundle_sha256",
        "verification_policy_sha256",
        "cost_weights_sha256",
        "tool_policy_sha256",
    ):
        if not _sha(request.get(field)):
            issues.append("prepare:" + field + "_invalid")
    if type(request.get("prepared_at_ms")) is not int or request["prepared_at_ms"] < 0:
        issues.append("prepare:clock_invalid")
    if issues or corpus is None or runtime is None or not isinstance(archive, Mapping):
        return None, sorted(set(issues))
    selected = _select_challenger(archive)
    terminal = (
        _terminal_no_candidate(
            request["campaign_id"], archive["archive_sha256"], corpus["corpus_sha256"]
        )
        if selected is None
        else None
    )
    champion = {
        "profile_id": "direct/v1",
        "configuration_sha256": archive["direct_baseline"]["baseline_sha256"],
        "metrics": deepcopy(archive["direct_baseline"]["metrics"]),
    }
    core = {
        "schema": PREPARATION_SCHEMA,
        "campaign_id": request["campaign_id"],
        "preparation_status": "NO_ELIGIBLE_CHALLENGER" if selected is None else "READY",
        "archive_sha256": archive["archive_sha256"],
        "champion": champion,
        "challenger": None if selected is None else selected["candidate"],
        "corpus_sha256": corpus["corpus_sha256"],
        "corpus_id": corpus["corpus_id"],
        "holdout_group_id": corpus["holdout_group_id"],
        "fixtures": corpus["fixtures"],
        "runtime_contract": runtime,
        "runtime_contract_sha256": json_sha256(runtime),
        "authority_class": AUTHORITY_CLASS,
        "authority_scope_sha256": request["authority_scope_sha256"],
        "prompt_bundle_sha256": request["prompt_bundle_sha256"],
        "verification_policy_sha256": request["verification_policy_sha256"],
        "cost_weights_sha256": request["cost_weights_sha256"],
        "tool_policy_sha256": request["tool_policy_sha256"],
        "budget_contract": _budget_contract(),
        "deadline_contract": _deadline_contract(),
        "review_contract": _review_contract(runtime),
        "prepared_at_ms": request["prepared_at_ms"],
        "terminal": terminal,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return _seal(core, "preparation_sha256"), []


def validate_preparation(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    record = _closed(value, _PREPARATION_FIELDS, "preparation", issues)
    if record is not None:
        if record.get("schema") != PREPARATION_SCHEMA:
            issues.append("preparation:schema_invalid")
        if not _sealed(record, "preparation_sha256"):
            issues.append("preparation:seal_invalid")
        if not _identifier(record.get("campaign_id")):
            issues.append("preparation:campaign_id_invalid")
        if record.get("preparation_status") not in {
            "READY",
            "NO_ELIGIBLE_CHALLENGER",
        }:
            issues.append("preparation:status_invalid")
        if record.get("provider_free") is not True or record.get("model_calls") != 0 or record.get("hosted_calls") != 0:
            issues.append("preparation:provider_boundary_invalid")
        fixtures = record.get("fixtures")
        if not isinstance(fixtures, list) or len(fixtures) != 20:
            issues.append("preparation:fixtures_invalid")
        challenger = record.get("challenger")
        if record.get("preparation_status") == "READY":
            if topology_lab.validate_candidate(challenger).get("status") != "PASS":
                issues.append("preparation:challenger_invalid")
            elif challenger["genome"]["profile_id"] == "direct/v1" or challenger["genome"]["lane_count"] > 2 or challenger["genome"]["depth"] > 2:
                issues.append("preparation:challenger_ineligible")
            if record.get("terminal") is not None:
                issues.append("preparation:terminal_invalid")
        elif not isinstance(record.get("terminal"), Mapping):
            issues.append("preparation:terminal_missing")
    unique = sorted(set(issues))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


def genesis_cursor(campaign_id: str) -> dict[str, Any]:
    if not _identifier(campaign_id):
        raise ValueError("campaign_id_invalid")
    return {
        "schema": CURSOR_SCHEMA,
        "campaign_id": campaign_id,
        "seq": 0,
        "event_hash": run_store.GENESIS_PREV_HASH,
        "stream_sha256": run_store.GENESIS_PREV_HASH,
    }


def _stream_id(campaign_id: str) -> str:
    return "fc-" + hashlib.sha256(campaign_id.encode("utf-8")).hexdigest()[:24]


def _cursor(campaign_id: str, rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    if not rows:
        return genesis_cursor(campaign_id)
    stream_sha256 = json_sha256([row["event_hash"] for row in rows])
    return {
        "schema": CURSOR_SCHEMA,
        "campaign_id": campaign_id,
        "seq": rows[-1]["seq"],
        "event_hash": rows[-1]["event_hash"],
        "stream_sha256": stream_sha256,
    }


def _cursor_valid(value: Any, campaign_id: str) -> bool:
    if not isinstance(value, Mapping) or set(value) != _CURSOR_FIELDS:
        return False
    return (
        value.get("schema") == CURSOR_SCHEMA
        and value.get("campaign_id") == campaign_id
        and type(value.get("seq")) is int
        and value["seq"] >= 0
        and _sha(value.get("event_hash"))
        and _sha(value.get("stream_sha256"))
    )


def _authority_registration(
    value: Any, *, sealed: bool
) -> tuple[dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    fields = _AUTHORITY_FIELDS if sealed else _AUTHORITY_DRAFT_FIELDS
    record = _closed(value, fields, "authority_registration", issues)
    if record is None:
        return None, sorted(set(issues))
    expected_schema = (
        AUTHORITY_REGISTRATION_SCHEMA
        if sealed
        else AUTHORITY_REGISTRATION_DRAFT_SCHEMA
    )
    if record.get("schema") != expected_schema:
        issues.append("authority_registration:schema_invalid")
    if record.get("class_id") != AUTHORITY_CLASS:
        issues.append("authority_registration:class_invalid")
    for field in ("campaign_id", "registration_id"):
        if not _identifier(record.get(field)):
            issues.append("authority_registration:" + field + "_invalid")
    if not _sha(record.get("authority_scope_sha256")):
        issues.append("authority_registration:scope_invalid")
    if (
        type(record.get("registered_at_ms")) is not int
        or record["registered_at_ms"] < 0
    ):
        issues.append("authority_registration:clock_invalid")
    if record.get("provider_free") is not True:
        issues.append("authority_registration:provider_boundary_invalid")
    if sealed and not _sealed(record, "registration_sha256"):
        issues.append("authority_registration:seal_invalid")
    return record, sorted(set(issues))


def seal_authority_registration(value: Any) -> dict[str, Any]:
    draft, issues = _authority_registration(value, sealed=False)
    if issues or draft is None:
        raise ValueError(";".join(issues))
    draft["schema"] = AUTHORITY_REGISTRATION_SCHEMA
    return _seal(draft, "registration_sha256")


def _config_observation(
    value: Any, *, sealed: bool
) -> tuple[dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    fields = (
        _CONFIG_OBSERVATION_FIELDS
        if sealed
        else _CONFIG_OBSERVATION_DRAFT_FIELDS
    )
    record = _closed(value, fields, "config_observation", issues)
    if record is None:
        return None, sorted(set(issues))
    expected_schema = (
        CONFIG_OBSERVATION_SCHEMA
        if sealed
        else CONFIG_OBSERVATION_DRAFT_SCHEMA
    )
    if record.get("schema") != expected_schema:
        issues.append("config_observation:schema_invalid")
    if not _identifier(record.get("campaign_id")):
        issues.append("config_observation:campaign_id_invalid")
    if record.get("role") not in {"champion", "challenger"}:
        issues.append("config_observation:role_invalid")
    for field in (
        "fixture_sha256",
        "artifact_sha256",
        "hidden_check_sha256",
        "evidence_sha256",
    ):
        if not _sha(record.get(field)):
            issues.append("config_observation:" + field + "_invalid")
    run_ref = _closed(
        record.get("run_ref"), _RUN_REF_FIELDS, "config_observation:run_ref", issues
    )
    if run_ref is not None and (
        run_ref.get("schema") != RUN_REF_SCHEMA
        or not _identifier(run_ref.get("run_id"))
        or not _sha(run_ref.get("stream_sha256"))
    ):
        issues.append("config_observation:run_ref_invalid")
    objective = _closed(
        record.get("objective_checks"),
        _OBJECTIVE_FIELDS,
        "config_observation:objective",
        issues,
    )
    if objective is not None and any(
        objective.get(field) not in {"PASS", "FAIL", "UNKNOWN"}
        for field in _OBJECTIVE_FIELDS
    ):
        issues.append("config_observation:objective_invalid")
    usage = _closed(
        record.get("usage"), _USAGE_FIELDS, "config_observation:usage", issues
    )
    if usage is not None:
        exact = usage.get("exact")
        values = (
            usage.get("tokens"),
            usage.get("weighted_cost_micros"),
            usage.get("critical_path_ms"),
        )
        if exact is True:
            if any(type(item) is not int or item < 0 for item in values):
                issues.append("config_observation:usage_invalid")
        elif exact is False:
            if any(item is not None for item in values):
                issues.append("config_observation:usage_invalid")
        else:
            issues.append("config_observation:usage_invalid")
    if sealed and not _sealed(record, "observation_sha256"):
        issues.append("config_observation:seal_invalid")
    return record, sorted(set(issues))


def seal_config_observation(value: Any) -> dict[str, Any]:
    draft, issues = _config_observation(value, sealed=False)
    if issues or draft is None:
        raise ValueError(";".join(issues))
    draft["schema"] = CONFIG_OBSERVATION_SCHEMA
    return _seal(draft, "observation_sha256")


def _score_set(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == set(REVIEW_DIMENSIONS)
        and all(type(value[field]) is int and 0 <= value[field] <= 4 for field in REVIEW_DIMENSIONS)
    )


def _score_bps(scores: Mapping[str, int]) -> int:
    return sum(scores[field] for field in REVIEW_DIMENSIONS) * 10_000 // 16


def _blind_a_role(fixture_sha256: str) -> str:
    """Derive the private option order without storing an option map."""

    return "champion" if int(fixture_sha256[0], 16) % 2 == 0 else "challenger"


def _calibration_for_rung(campaign_id: str, rung: int) -> tuple[str, str]:
    calibration_id, expected_disposition = _CALIBRATION_ROTATION[rung - 1]
    pair_sha256 = json_sha256(
        {
            "campaign_id": campaign_id,
            "rung": rung,
            "calibration_id": calibration_id,
        }
    )
    return pair_sha256, expected_disposition


def _review_observation(
    value: Any, *, sealed: bool
) -> tuple[dict[str, Any] | None, list[str]]:
    issues: list[str] = []
    fields = (
        _REVIEW_OBSERVATION_FIELDS
        if sealed
        else _REVIEW_OBSERVATION_DRAFT_FIELDS
    )
    record = _closed(value, fields, "review_observation", issues)
    if record is None:
        return None, sorted(set(issues))
    expected_schema = (
        REVIEW_OBSERVATION_SCHEMA
        if sealed
        else REVIEW_OBSERVATION_DRAFT_SCHEMA
    )
    if record.get("schema") != expected_schema:
        issues.append("review_observation:schema_invalid")
    if not _identifier(record.get("campaign_id")):
        issues.append("review_observation:campaign_id_invalid")
    for field in (
        "fixture_sha256",
        "sol_identity_sha256",
        "blind_packet_sha256",
        "rubric_sha256",
        "review_evidence_sha256",
    ):
        if not _sha(record.get(field)):
            issues.append("review_observation:" + field + "_invalid")
    status = record.get("review_status")
    if status not in {
        "PASS",
        "ABSTAIN",
        "MALFORMED",
        "TRANSPORT_FAILURE",
        "UNKNOWN",
    }:
        issues.append("review_observation:status_invalid")
    scores_a = record.get("option_a_scores")
    scores_b = record.get("option_b_scores")
    evidence_refs = record.get("evidence_refs")
    if status == "PASS":
        if not _score_set(scores_a) or not _score_set(scores_b):
            issues.append("review_observation:scores_invalid")
        else:
            a_bps = _score_bps(scores_a)
            b_bps = _score_bps(scores_b)
            expected_winner = "A" if a_bps > b_bps else "B" if b_bps > a_bps else "TIE"
            if record.get("winner") != expected_winner:
                issues.append("review_observation:winner_invalid")
        if (
            not isinstance(evidence_refs, list)
            or not evidence_refs
            or len(evidence_refs) > 16
            or any(not _sha(item) for item in evidence_refs)
            or len(evidence_refs) != len(set(evidence_refs))
        ):
            issues.append("review_observation:evidence_invalid")
    elif (
        scores_a is not None
        or scores_b is not None
        or record.get("winner") is not None
        or evidence_refs not in ([], None)
    ):
        issues.append("review_observation:failure_payload_invalid")
    calibration = record.get("calibration_pair_sha256")
    if calibration is not None and not _sha(calibration):
        issues.append("review_observation:calibration_invalid")
    if record.get("calibration_disposition") not in {None, "A", "B", "TIE"}:
        issues.append("review_observation:calibration_invalid")
    if type(record.get("tokens")) is not int or not 0 <= record["tokens"] <= 12_000:
        issues.append("review_observation:tokens_invalid")
    if sealed:
        expected_usefulness = (
            {
                "option_a": _score_bps(scores_a),
                "option_b": _score_bps(scores_b),
            }
            if status == "PASS"
            and _score_set(scores_a)
            and _score_set(scores_b)
            else None
        )
        if record.get("review_usefulness_bps") != expected_usefulness:
            issues.append("review_observation:usefulness_invalid")
    if sealed and not _sealed(record, "observation_sha256"):
        issues.append("review_observation:seal_invalid")
    return record, sorted(set(issues))


def seal_review_observation(value: Any) -> dict[str, Any]:
    draft, issues = _review_observation(value, sealed=False)
    if issues or draft is None:
        raise ValueError(";".join(issues))
    draft["schema"] = REVIEW_OBSERVATION_SCHEMA
    draft["review_usefulness_bps"] = (
        {
            "option_a": _score_bps(draft["option_a_scores"]),
            "option_b": _score_bps(draft["option_b_scores"]),
        }
        if draft["review_status"] == "PASS"
        else None
    )
    return _seal(draft, "observation_sha256")


def _fixture_state(fixture: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "manifest": deepcopy(dict(fixture)),
        "reserved_at_ms": None,
        "dispatch_order": [],
        "configs": {
            "champion": {"dispatched": False, "sessions": 0, "observation": None},
            "challenger": {"dispatched": False, "sessions": 0, "observation": None},
        },
        "review_dispatch": None,
        "review_observation": None,
        "calibration_status": None,
    }


def _campaign_state(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    run_engine.verify_event_chain(rows)
    if not rows:
        raise ValueError("campaign_stream_empty")
    started = json.loads(rows[0]["payload"])
    origin = started["plan"]["origin"]["frontier_campaign"]
    preparation = origin["preparation"]
    fixtures = {
        item["fixture_id"]: _fixture_state(item) for item in preparation["fixtures"]
    }
    state = {
        "preparation": preparation,
        "started_at_ms": origin["started_at_ms"],
        "authority_registration": origin["authority_registration"],
        "fixtures": fixtures,
        "sealed_rungs": set(),
        "terminal_record": None,
    }
    for row in rows[1:]:
        facts = json.loads(row["payload"])
        if row["kind"] == run_engine.KIND_APPLIED:
            event = facts["frontier_event"]
            kind = event["kind"]
            if kind == "pair_reserved":
                fixtures[event["fixture_id"]]["reserved_at_ms"] = event["at_ms"]
            elif kind == "config_dispatched":
                target = fixtures[event["fixture_id"]]
                target["dispatch_order"].append(event["role"])
                target["configs"][event["role"]]["dispatched"] = True
                target["configs"][event["role"]]["sessions"] = event["sessions"]
            elif kind == "config_observed":
                fixtures[event["fixture_id"]]["configs"][event["role"]][
                    "observation"
                ] = event["observation"]
            elif kind == "review_dispatched":
                fixtures[event["fixture_id"]]["review_dispatch"] = event["intent"]
            elif kind == "review_observed":
                fixtures[event["fixture_id"]]["review_observation"] = event[
                    "observation"
                ]
                fixtures[event["fixture_id"]]["calibration_status"] = event[
                    "calibration_status"
                ]
            elif kind == "rung_committed":
                state["sealed_rungs"].add(event["rung"])
        elif row["kind"] in run_store.TERMINAL_KINDS:
            state["terminal_record"] = facts["frontier_terminal"]
    state["rows"] = rows
    return state


def _public_fixture_status(fixture: Mapping[str, Any]) -> str:
    if fixture["review_observation"] is not None:
        return (
            "COMPLETE"
            if fixture["review_observation"]["review_status"] == "PASS"
            and fixture["calibration_status"] != "FAIL"
            else "EVIDENCE_INCOMPLETE"
        )
    if fixture["review_dispatch"] is not None:
        return "REVIEWING"
    observations = [
        fixture["configs"][role]["observation"]
        for role in ("champion", "challenger")
    ]
    if all(item is not None for item in observations):
        return "AWAITING_REVIEW"
    if any(fixture["configs"][role]["dispatched"] for role in ("champion", "challenger")):
        return "RUNNING"
    if fixture["reserved_at_ms"] is not None:
        return "RESERVED"
    return "PENDING"


def _review_values(fixture: Mapping[str, Any]) -> tuple[int, int] | None:
    review = fixture["review_observation"]
    dispatch = fixture["review_dispatch"]
    if (
        review is None
        or dispatch is None
        or review["review_status"] != "PASS"
        or fixture["calibration_status"] == "FAIL"
    ):
        return None
    a_bps = review["review_usefulness_bps"]["option_a"]
    b_bps = review["review_usefulness_bps"]["option_b"]
    return (a_bps, b_bps) if dispatch["a_role"] == "champion" else (b_bps, a_bps)


def _usage(state: Mapping[str, Any]) -> dict[str, Any]:
    champion_sessions = 0
    challenger_sessions = 0
    sol_reviews = 0
    active_qwen = 0
    active_sol = 0
    exact = True
    tokens = {"champion": 0, "challenger": 0, "sol": 0}
    costs = {"champion": 0, "challenger": 0}
    latency = {"champion": 0, "challenger": 0}
    for fixture in state["fixtures"].values():
        for role in ("champion", "challenger"):
            config = fixture["configs"][role]
            if config["dispatched"]:
                if role == "champion":
                    champion_sessions += config["sessions"]
                else:
                    challenger_sessions += config["sessions"]
                if config["observation"] is None:
                    active_qwen += config["sessions"]
            observation = config["observation"]
            if observation is not None:
                observed_usage = observation["usage"]
                exact = exact and observed_usage["exact"]
                if observed_usage["exact"]:
                    tokens[role] += observed_usage["tokens"]
                    costs[role] += observed_usage["weighted_cost_micros"]
                    latency[role] += observed_usage["critical_path_ms"]
        if fixture["review_dispatch"] is not None:
            sol_reviews += 1
            if fixture["review_observation"] is None:
                active_sol += 1
        if fixture["review_observation"] is not None:
            tokens["sol"] += fixture["review_observation"]["tokens"]
    return {
        "exact": exact,
        "champion_qwen_sessions": champion_sessions,
        "challenger_qwen_sessions": challenger_sessions,
        "sol_reviews": sol_reviews,
        "active_qwen_sessions": active_qwen,
        "active_sol_reviews": active_sol,
        "tokens": tokens,
        "weighted_cost_micros": costs,
        "critical_path_ms": latency,
    }


def _gate_trajectory(state: Mapping[str, Any]) -> dict[str, Any]:
    champion_usefulness = 0
    challenger_usefulness = 0
    reviewed = 0
    for fixture in state["fixtures"].values():
        values = _review_values(fixture)
        if values is not None:
            reviewed += 1
            champion_usefulness += values[0]
            challenger_usefulness += values[1]
    usage = _usage(state)
    remaining = 20 - reviewed
    budget = state["preparation"]["budget_contract"]
    deadlines = state["preparation"]["deadline_contract"]
    usefulness_reachable = (
        challenger_usefulness + remaining * 10_000 >= champion_usefulness
    )
    cost_reachable = (
        usage["weighted_cost_micros"]["challenger"]
        <= usage["weighted_cost_micros"]["champion"]
        + remaining * budget["max_weighted_cost_micros_per_fixture"]
    )
    latency_reachable = (
        usage["critical_path_ms"]["challenger"]
        <= usage["critical_path_ms"]["champion"]
        + remaining * deadlines["rung_ms"]
    )
    return {
        "reviewed_fixtures": reviewed,
        "remaining_fixtures": remaining,
        "review_usefulness_bps_sum": {
            "champion": champion_usefulness,
            "challenger": challenger_usefulness,
        },
        "weighted_cost_micros": usage["weighted_cost_micros"],
        "critical_path_ms": usage["critical_path_ms"],
        "usefulness_reachable": usefulness_reachable,
        "cost_reachable": cost_reachable,
        "latency_reachable": latency_reachable,
        "final_gate_reachable": usefulness_reachable
        and cost_reachable
        and latency_reachable,
    }


def _pending_transition(state: Mapping[str, Any], now_ms: int) -> dict[str, Any] | None:
    if state["terminal_record"] is not None:
        return None
    preparation = state["preparation"]
    deadlines = preparation["deadline_contract"]
    if now_ms - state["started_at_ms"] > deadlines["campaign_ms"]:
        return {"kind": "SEAL_TERMINAL", "outcome": "TIMEOUT", "reason": "campaign:deadline_exceeded"}
    for fixture in state["fixtures"].values():
        manifest = fixture["manifest"]
        if fixture["reserved_at_ms"] is not None and manifest["rung"] not in state["sealed_rungs"] and now_ms - fixture["reserved_at_ms"] > deadlines["rung_ms"]:
            return {"kind": "SEAL_TERMINAL", "outcome": "TIMEOUT", "reason": "rung:deadline_exceeded"}
        champion = fixture["configs"]["champion"]["observation"]
        challenger = fixture["configs"]["challenger"]["observation"]
        if champion is not None:
            controls = champion["objective_checks"]
            if any(value != "PASS" for value in controls.values()) or not champion["usage"]["exact"]:
                return {"kind": "SEAL_TERMINAL", "outcome": "INCONCLUSIVE", "reason": "champion:evidence_not_passing"}
        if challenger is not None:
            controls = challenger["objective_checks"]
            if any(value == "FAIL" for value in controls.values()):
                return {"kind": "SEAL_TERMINAL", "outcome": "CHAMPION_RETAINED", "reason": "challenger:objective_regression"}
            if any(value == "UNKNOWN" for value in controls.values()) or not challenger["usage"]["exact"]:
                return {"kind": "SEAL_TERMINAL", "outcome": "INCONCLUSIVE", "reason": "challenger:evidence_unknown"}
        review = fixture["review_observation"]
        if fixture["calibration_status"] == "FAIL":
            return {
                "kind": "SEAL_TERMINAL",
                "outcome": "EVIDENCE_INCOMPLETE",
                "reason": "sol:calibration_failed",
            }
        if review is not None and review["review_status"] != "PASS":
            return {"kind": "SEAL_TERMINAL", "outcome": "EVIDENCE_INCOMPLETE", "reason": "sol:review_incomplete"}
    sealed = state["sealed_rungs"]
    if sealed and not _gate_trajectory(state)["final_gate_reachable"]:
        return {
            "kind": "SEAL_TERMINAL",
            "outcome": "CHAMPION_RETAINED",
            "reason": "gate:final_result_unreachable",
        }
    if len(sealed) == 5:
        trajectory = _gate_trajectory(state)
        retained = (
            trajectory["review_usefulness_bps_sum"]["challenger"]
            >= trajectory["review_usefulness_bps_sum"]["champion"]
            and trajectory["weighted_cost_micros"]["challenger"]
            <= trajectory["weighted_cost_micros"]["champion"]
            and trajectory["critical_path_ms"]["challenger"]
            <= trajectory["critical_path_ms"]["champion"]
        )
        return {
            "kind": "SEAL_TERMINAL",
            "outcome": "CHALLENGER_RETAINED" if retained else "CHAMPION_RETAINED",
            "reason": "gate:challenger_no_worse" if retained else "gate:challenger_worse",
        }
    current_rung = min(set(range(1, 6)) - sealed)
    rung_fixtures = [
        fixture
        for fixture in state["fixtures"].values()
        if fixture["manifest"]["rung"] == current_rung
    ]
    if all(
        fixture["review_observation"] is not None
        and fixture["review_observation"]["review_status"] == "PASS"
        for fixture in rung_fixtures
    ):
        return {"kind": "COMMIT_RUNG", "rung": current_rung}
    return None


def _successor(
    preparation: Mapping[str, Any], outcome: str
) -> dict[str, Any]:
    kind = {
        "CHALLENGER_RETAINED": "SHADOW_DESIGN",
        "CHAMPION_RETAINED": "NEXT_ELIGIBLE",
        "INCONCLUSIVE": "DIAGNOSIS",
        "EVIDENCE_INCOMPLETE": "DIAGNOSIS",
        "TIMEOUT": "DIAGNOSIS",
        "CANCELLED": "STOP",
    }[outcome]
    return _seal(
        {
            "schema": "orch-dork/frontier-successor/v2",
            "kind": kind,
            "campaign_id": preparation["campaign_id"],
            "candidate_sha256": preparation["challenger"]["candidate_sha256"],
            "rotated_holdout_required": kind in {"NEXT_ELIGIBLE", "STOP"},
            "dispatch_permitted": False,
            "authority_granted": False,
        },
        "successor_sha256",
    )


def _terminal_record(
    state: Mapping[str, Any], outcome: str, reason: str, at_ms: int
) -> dict[str, Any]:
    preparation = state["preparation"]
    usage = _usage(state)
    trajectory = _gate_trajectory(state)
    successor = _successor(preparation, outcome)
    return _seal(
        {
            "schema": "orch-dork/frontier-terminal/v2",
            "campaign_id": preparation["campaign_id"],
            "outcome": outcome,
            "reason": reason,
            "candidate_sha256": preparation["challenger"]["candidate_sha256"],
            "corpus_sha256": preparation["corpus_sha256"],
            "runtime_contract_sha256": preparation["runtime_contract_sha256"],
            "authority_scope_sha256": preparation["authority_scope_sha256"],
            "usage": usage,
            "gate_trajectory": trajectory,
            "sealed_rungs": len(state["sealed_rungs"]),
            "completed_fixtures": trajectory["reviewed_fixtures"],
            "authority_consumed": True,
            "continuing_authority": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
            "retries": 0,
            "fallbacks": 0,
            "replacements": 0,
            "terminal_at_ms": at_ms,
            "successor": successor,
            "empirical_overlay": _seal(
                {
                    "schema": "orch-dork/frontier-empirical-overlay/v2",
                    "effective_configuration_sha256": preparation["challenger"]["candidate_sha256"],
                    "corpus_sha256": preparation["corpus_sha256"],
                    "runtime_contract_sha256": preparation["runtime_contract_sha256"],
                    "campaign_id": preparation["campaign_id"],
                    "outcome": outcome,
                    "structural_archive_mutated": False,
                    "excluded_exact_configuration": outcome == "CHAMPION_RETAINED",
                },
                "overlay_sha256",
            ),
        },
        "terminal_sha256",
    )


class FrontierCampaignController:
    """Stateful provider-free v2 controller over one canonical event stream."""

    def __init__(
        self,
        *,
        store: Any = None,
        clock_ms: Callable[[], int] | None = None,
        run_resolver: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    ) -> None:
        self.store = store if store is not None else run_store.InMemoryRunStore()
        self.engine = run_engine.RunEngine(self.store)
        self.clock_ms = clock_ms if clock_ms is not None else (lambda: 0)
        self.run_resolver = run_resolver

    def _rows(self, campaign_id: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self.store.events(_stream_id(campaign_id), 0)]

    def _state(self, campaign_id: str) -> dict[str, Any]:
        rows = self._rows(campaign_id)
        if not rows:
            raise ValueError("campaign_not_found")
        return _campaign_state(rows)

    def _append(
        self,
        campaign_id: str,
        cursor: Mapping[str, Any],
        event: Mapping[str, Any],
    ) -> None:
        self.engine.append_event(
            _stream_id(campaign_id),
            run_engine.KIND_APPLIED,
            "controller",
            {"frontier_event": deepcopy(dict(event))},
            expected_seq=cursor["seq"],
            expected_prev_hash=cursor["event_hash"],
        )

    def _append_terminal(
        self,
        campaign_id: str,
        cursor: Mapping[str, Any],
        terminal: Mapping[str, Any],
        *,
        terminated: bool = False,
    ) -> None:
        self.engine.append_event(
            _stream_id(campaign_id),
            run_engine.KIND_TERMINATED if terminated else run_engine.KIND_COMPLETED,
            "controller",
            {"frontier_terminal": deepcopy(dict(terminal))},
            expected_seq=cursor["seq"],
            expected_prev_hash=cursor["event_hash"],
        )

    def _decision(
        self,
        *,
        campaign_id: str,
        prior_cursor: Mapping[str, Any],
        accepted_input: Mapping[str, Any],
        status: str,
        reasons: list[str],
        intents: list[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        rows = self._rows(campaign_id)
        state = _campaign_state(rows)
        now_ms = self.clock_ms()
        pending = _pending_transition(state, now_ms)
        terminal = state["terminal_record"]
        core = {
            "schema": DECISION_SCHEMA,
            "campaign_id": campaign_id,
            "decision_status": status,
            "prior_cursor": deepcopy(dict(prior_cursor)),
            "accepted_input_sha256": json_sha256(accepted_input),
            "cursor": _cursor(campaign_id, rows),
            "reason_codes": sorted(set(reasons)),
            "intents": [deepcopy(dict(item)) for item in (intents or [])],
            "next_action": (
                "TERMINAL"
                if terminal is not None
                else pending["kind"]
                if pending is not None
                else self._next_action(state)
            ),
            "terminal": terminal,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
            "retries": 0,
            "fallbacks": 0,
            "replacements": 0,
        }
        return _seal(core, "decision_sha256")

    @staticmethod
    def _current_rung(state: Mapping[str, Any]) -> int:
        remaining = set(range(1, 6)) - set(state["sealed_rungs"])
        return min(remaining) if remaining else 5

    def _next_action(self, state: Mapping[str, Any]) -> str:
        rung = self._current_rung(state)
        fixtures = sorted(
            (
                fixture
                for fixture in state["fixtures"].values()
                if fixture["manifest"]["rung"] == rung
            ),
            key=lambda item: PARTITIONS.index(item["manifest"]["partition"]),
        )
        for fixture in fixtures:
            if fixture["reserved_at_ms"] is None:
                return "RESERVE_PAIR"
            for role in ("champion", "challenger"):
                config = fixture["configs"][role]
                if config["dispatched"] and config["observation"] is None:
                    return "OBSERVE_CONFIG"
            if len(fixture["dispatch_order"]) < 2:
                return "DISPATCH_CONFIG"
            if fixture["review_dispatch"] is None:
                return "DISPATCH_REVIEW"
            if fixture["review_observation"] is None:
                return "OBSERVE_REVIEW"
        return "RECONCILE"

    @staticmethod
    def _fixture_by_id(
        state: Mapping[str, Any], fixture_id: Any
    ) -> dict[str, Any] | None:
        return state["fixtures"].get(fixture_id) if isinstance(fixture_id, str) else None

    def _start(
        self,
        payload: Mapping[str, Any],
        request: Any,
        prior_cursor: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        if not isinstance(request, Mapping) or set(request) != {
            "preparation",
            "authority_registration",
        }:
            return None, ["advance:start_request_invalid"]
        preparation = request.get("preparation")
        if validate_preparation(preparation)["status"] != "PASS" or preparation.get(
            "preparation_status"
        ) != "READY":
            return None, ["advance:preparation_invalid"]
        registration, issues = _authority_registration(
            request.get("authority_registration"), sealed=True
        )
        if issues or registration is None:
            return None, ["advance:authority_registration_invalid"]
        campaign_id = preparation["campaign_id"]
        if (
            registration["campaign_id"] != campaign_id
            or registration["authority_scope_sha256"]
            != preparation["authority_scope_sha256"]
        ):
            return None, ["advance:authority_registration_mismatch"]
        if prior_cursor != genesis_cursor(campaign_id):
            return None, ["advance:stale_cursor"]
        stream_id = _stream_id(campaign_id)
        if self.store.exists(stream_id):
            return None, ["advance:campaign_already_started"]
        now_ms = self.clock_ms()
        if type(now_ms) is not int or now_ms < 0:
            return None, ["advance:clock_invalid"]
        plan = run_engine.make_plan(
            run_id=stream_id,
            name="Frontier qualification " + campaign_id,
            expected_roles=("controller",),
            deliverable=True,
            actors=(
                run_engine.actor(
                    kind="observer",
                    model="deterministic-frontier-controller/v2",
                    actor_key="controller",
                    intent="control:frontier-qualification/v2",
                ),
            ),
            origin={
                "frontier_campaign": {
                    "preparation": deepcopy(dict(preparation)),
                    "authority_registration": registration,
                    "started_at_ms": now_ms,
                }
            },
        )
        try:
            self.engine.start(plan)
        except (run_engine.MalformedInputError, run_engine.ProtocolError):
            return None, ["advance:campaign_start_failed"]
        return (
            self._decision(
                campaign_id=campaign_id,
                prior_cursor=prior_cursor,
                accepted_input=payload,
                status="ADVANCED",
                reasons=["advance:campaign_started"],
            ),
            [],
        )

    def _reserve_pair(
        self,
        payload: Mapping[str, Any],
        state: Mapping[str, Any],
        request: Any,
        prior_cursor: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        if not isinstance(request, Mapping) or set(request) != {"fixture_id"}:
            return None, ["advance:reserve_request_invalid"]
        fixture = self._fixture_by_id(state, request.get("fixture_id"))
        if fixture is None:
            return None, ["advance:fixture_unknown"]
        if fixture["manifest"]["rung"] != self._current_rung(state):
            return None, ["advance:rung_not_released"]
        if fixture["reserved_at_ms"] is not None:
            return None, ["advance:fixture_already_reserved"]
        active_pairs = sum(
            item["reserved_at_ms"] is not None
            and item["review_observation"] is None
            for item in state["fixtures"].values()
        )
        if active_pairs >= state["preparation"]["budget_contract"][
            "max_active_fixture_pairs"
        ]:
            return None, ["advance:pair_concurrency_exceeded"]
        event = {
            "kind": "pair_reserved",
            "fixture_id": fixture["manifest"]["fixture_id"],
            "at_ms": self.clock_ms(),
        }
        self._append(state["preparation"]["campaign_id"], prior_cursor, event)
        return (
            self._decision(
                campaign_id=state["preparation"]["campaign_id"],
                prior_cursor=prior_cursor,
                accepted_input=payload,
                status="ADVANCED",
                reasons=["advance:pair_reserved"],
            ),
            [],
        )

    def _dispatch_config(
        self,
        payload: Mapping[str, Any],
        state: Mapping[str, Any],
        request: Any,
        prior_cursor: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        if not isinstance(request, Mapping) or set(request) != {"fixture_id", "role"}:
            return None, ["advance:dispatch_request_invalid"]
        fixture = self._fixture_by_id(state, request.get("fixture_id"))
        role = request.get("role")
        if fixture is None or role not in {"champion", "challenger"}:
            return None, ["advance:dispatch_request_invalid"]
        if fixture["reserved_at_ms"] is None:
            return None, ["advance:pair_not_reserved"]
        config = fixture["configs"][role]
        if config["dispatched"]:
            return None, ["advance:configuration_already_dispatched"]
        fixtures = state["preparation"]["fixtures"]
        index = next(
            i
            for i, item in enumerate(fixtures)
            if item["fixture_id"] == fixture["manifest"]["fixture_id"]
        )
        expected_first = "champion" if index % 2 == 0 else "challenger"
        if not fixture["dispatch_order"] and role != expected_first:
            return None, ["advance:dispatch_order_invalid"]
        budget = state["preparation"]["budget_contract"]
        sessions = budget[
            "champion_sessions_per_fixture"
            if role == "champion"
            else "challenger_sessions_per_fixture"
        ]
        usage = _usage(state)
        if (
            usage["active_qwen_sessions"] + sessions
            > budget["max_concurrent_qwen_sessions"]
        ):
            return None, ["advance:qwen_concurrency_exceeded"]
        if (
            role == "champion"
            and usage["champion_qwen_sessions"] + sessions
            > budget["champion_session_limit"]
        ):
            return None, ["advance:champion_session_budget_exceeded"]
        if (
            role == "challenger"
            and usage["challenger_qwen_sessions"] + sessions
            > budget["challenger_session_limit"]
        ):
            return None, ["advance:challenger_session_budget_exceeded"]
        event = {
            "kind": "config_dispatched",
            "fixture_id": fixture["manifest"]["fixture_id"],
            "role": role,
            "sessions": sessions,
            "at_ms": self.clock_ms(),
        }
        campaign_id = state["preparation"]["campaign_id"]
        self._append(campaign_id, prior_cursor, event)
        profile_id = (
            "direct/v1"
            if role == "champion"
            else state["preparation"]["challenger"]["genome"]["profile_id"]
        )
        intent = _seal(
            {
                "schema": "orch-dork/frontier-config-run-intent/v2",
                "campaign_id": campaign_id,
                "fixture_sha256": fixture["manifest"]["fixture_sha256"],
                "role": role,
                "profile_id": profile_id,
                "task_brief_sha256": fixture["manifest"][
                    role + "_task_brief_sha256"
                ],
                "session_count": sessions,
                "qwen_identity_sha256": state["preparation"]["runtime_contract"][
                    "qwen_identity_sha256"
                ],
                "tool_policy_sha256": state["preparation"]["tool_policy_sha256"],
                "retry_limit": 0,
                "fallback_limit": 0,
                "replacement_limit": 0,
            },
            "intent_sha256",
        )
        return (
            self._decision(
                campaign_id=campaign_id,
                prior_cursor=prior_cursor,
                accepted_input=payload,
                status="ADVANCED",
                reasons=["advance:configuration_dispatched"],
                intents=[intent],
            ),
            [],
        )

    def _observe_config(
        self,
        payload: Mapping[str, Any],
        state: Mapping[str, Any],
        request: Any,
        prior_cursor: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        if not isinstance(request, Mapping) or set(request) != {"observation"}:
            return None, ["advance:observation_request_invalid"]
        observation, issues = _config_observation(
            request.get("observation"), sealed=True
        )
        if issues or observation is None:
            return None, ["advance:config_observation_invalid"]
        campaign_id = state["preparation"]["campaign_id"]
        if observation["campaign_id"] != campaign_id:
            return None, ["advance:campaign_binding_mismatch"]
        fixture = next(
            (
                item
                for item in state["fixtures"].values()
                if item["manifest"]["fixture_sha256"]
                == observation["fixture_sha256"]
            ),
            None,
        )
        if fixture is None:
            return None, ["advance:fixture_unknown"]
        role = observation["role"]
        config = fixture["configs"][role]
        if not config["dispatched"] or config["observation"] is not None:
            return None, ["advance:configuration_observation_out_of_order"]
        if observation["hidden_check_sha256"] != fixture["manifest"]["hidden_checks_sha256"]:
            return None, ["advance:hidden_check_mismatch"]
        profile_id = (
            "direct/v1"
            if role == "champion"
            else state["preparation"]["challenger"]["genome"]["profile_id"]
        )
        if self.run_resolver is None:
            return None, ["advance:run_resolver_unavailable"]
        resolution = self.run_resolver(
            {
                "campaign_id": campaign_id,
                "fixture_sha256": fixture["manifest"]["fixture_sha256"],
                "role": role,
                "profile_id": profile_id,
                "task_brief_sha256": fixture["manifest"][
                    role + "_task_brief_sha256"
                ],
                "qwen_identity_sha256": state["preparation"]["runtime_contract"][
                    "qwen_identity_sha256"
                ],
                "tool_policy_sha256": state["preparation"][
                    "tool_policy_sha256"
                ],
                "run_ref": observation["run_ref"],
            }
        )
        if not isinstance(resolution, Mapping) or resolution.get("status") != "PASS":
            return None, ["advance:run_evidence_invalid"]
        event = {
            "kind": "config_observed",
            "fixture_id": fixture["manifest"]["fixture_id"],
            "role": role,
            "observation": observation,
            "run_resolution_sha256": json_sha256(resolution),
            "at_ms": self.clock_ms(),
        }
        self._append(campaign_id, prior_cursor, event)
        return (
            self._decision(
                campaign_id=campaign_id,
                prior_cursor=prior_cursor,
                accepted_input=payload,
                status="ADVANCED",
                reasons=["advance:configuration_observed"],
            ),
            [],
        )

    def _dispatch_review(
        self,
        payload: Mapping[str, Any],
        state: Mapping[str, Any],
        request: Any,
        prior_cursor: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        fields = {"fixture_id", "blind_packet_sha256", "input_tokens", "artifact_sha256s"}
        if not isinstance(request, Mapping) or set(request) != fields:
            return None, ["advance:review_dispatch_invalid"]
        fixture = self._fixture_by_id(state, request.get("fixture_id"))
        if fixture is None or fixture["review_dispatch"] is not None:
            return None, ["advance:review_dispatch_invalid"]
        if any(
            fixture["configs"][role]["observation"] is None
            for role in ("champion", "challenger")
        ):
            return None, ["advance:configurations_incomplete"]
        if not _sha(request.get("blind_packet_sha256")):
            return None, ["advance:blind_packet_invalid"]
        if type(request.get("input_tokens")) is not int or not 0 <= request["input_tokens"] <= 8_000:
            return None, ["advance:blind_packet_size_invalid"]
        artifacts = request.get("artifact_sha256s")
        expected_artifacts = sorted(
            fixture["configs"][role]["observation"]["artifact_sha256"]
            for role in ("champion", "challenger")
        )
        if not isinstance(artifacts, list) or sorted(artifacts) != expected_artifacts:
            return None, ["advance:review_artifact_mismatch"]
        usage = _usage(state)
        budget = state["preparation"]["budget_contract"]
        if (
            usage["active_sol_reviews"] >= budget["max_concurrent_sol_reviews"]
            or usage["sol_reviews"] >= budget["sol_review_limit"]
        ):
            return None, ["advance:sol_concurrency_or_budget_exceeded"]
        rung = fixture["manifest"]["rung"]
        prior_in_rung = sum(
            item["review_dispatch"] is not None
            for item in state["fixtures"].values()
            if item["manifest"]["rung"] == rung
        )
        calibration_required = prior_in_rung == 0
        if calibration_required:
            calibration_pair_sha256, expected_calibration_disposition = (
                _calibration_for_rung(
                    state["preparation"]["campaign_id"], rung
                )
            )
        else:
            calibration_pair_sha256 = None
            expected_calibration_disposition = None
        a_role = _blind_a_role(fixture["manifest"]["fixture_sha256"])
        private_intent = {
            "schema": "orch-dork/sol-proxy-review-intent/v2",
            "fixture_sha256": fixture["manifest"]["fixture_sha256"],
            "blind_packet_sha256": request["blind_packet_sha256"],
            "input_tokens": request["input_tokens"],
            "artifact_sha256s": sorted(artifacts),
            "rubric_sha256": state["preparation"]["review_contract"][
                "review_contract_sha256"
            ],
            "sol_identity_sha256": state["preparation"]["runtime_contract"][
                "sol_identity_sha256"
            ],
            "calibration_required": calibration_required,
            "calibration_pair_sha256": calibration_pair_sha256,
            "a_role": a_role,
            "expected_calibration_disposition": expected_calibration_disposition,
        }
        private_intent = _seal(private_intent, "intent_sha256")
        event = {
            "kind": "review_dispatched",
            "fixture_id": fixture["manifest"]["fixture_id"],
            "intent": private_intent,
            "at_ms": self.clock_ms(),
        }
        campaign_id = state["preparation"]["campaign_id"]
        self._append(campaign_id, prior_cursor, event)
        public_intent = {
            key: deepcopy(value)
            for key, value in private_intent.items()
            if key
            not in {
                "a_role",
                "expected_calibration_disposition",
                "intent_sha256",
            }
        }
        public_intent["schema"] = "orch-dork/sol-proxy-review-public-intent/v2"
        public_intent = _seal(public_intent, "intent_sha256")
        return (
            self._decision(
                campaign_id=campaign_id,
                prior_cursor=prior_cursor,
                accepted_input=payload,
                status="ADVANCED",
                reasons=["advance:sol_review_dispatched"],
                intents=[public_intent],
            ),
            [],
        )

    def _observe_review(
        self,
        payload: Mapping[str, Any],
        state: Mapping[str, Any],
        request: Any,
        prior_cursor: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        if not isinstance(request, Mapping) or set(request) != {"observation"}:
            return None, ["advance:review_observation_invalid"]
        observation, issues = _review_observation(
            request.get("observation"), sealed=True
        )
        if issues or observation is None:
            return None, ["advance:review_observation_invalid"]
        campaign_id = state["preparation"]["campaign_id"]
        if observation["campaign_id"] != campaign_id:
            return None, ["advance:campaign_binding_mismatch"]
        fixture = next(
            (
                item
                for item in state["fixtures"].values()
                if item["manifest"]["fixture_sha256"] == observation["fixture_sha256"]
            ),
            None,
        )
        if fixture is None or fixture["review_dispatch"] is None or fixture["review_observation"] is not None:
            return None, ["advance:review_observation_out_of_order"]
        intent = fixture["review_dispatch"]
        if (
            observation["sol_identity_sha256"] != intent["sol_identity_sha256"]
            or observation["blind_packet_sha256"] != intent["blind_packet_sha256"]
            or observation["rubric_sha256"] != intent["rubric_sha256"]
            or observation["calibration_pair_sha256"]
            != intent["calibration_pair_sha256"]
        ):
            return None, ["advance:review_binding_mismatch"]
        calibration_status = (
            "FAIL"
            if intent["calibration_required"]
            and observation["calibration_disposition"]
            != intent["expected_calibration_disposition"]
            else "PASS"
        )
        if not intent["calibration_required"] and observation[
            "calibration_disposition"
        ] is not None:
            return None, ["advance:calibration_unexpected"]
        event = {
            "kind": "review_observed",
            "fixture_id": fixture["manifest"]["fixture_id"],
            "observation": observation,
            "calibration_status": calibration_status,
            "at_ms": self.clock_ms(),
        }
        self._append(campaign_id, prior_cursor, event)
        return (
            self._decision(
                campaign_id=campaign_id,
                prior_cursor=prior_cursor,
                accepted_input=payload,
                status="ADVANCED",
                reasons=["advance:sol_review_observed"],
            ),
            [],
        )

    def _reconcile(
        self,
        payload: Mapping[str, Any],
        state: Mapping[str, Any],
        request: Any,
        prior_cursor: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        if request != {}:
            return None, ["advance:reconcile_request_invalid"]
        now_ms = self.clock_ms()
        pending = _pending_transition(state, now_ms)
        if pending is None:
            return None, ["advance:nothing_to_reconcile"]
        campaign_id = state["preparation"]["campaign_id"]
        if pending["kind"] == "COMMIT_RUNG":
            event = {
                "kind": "rung_committed",
                "rung": pending["rung"],
                "gate_trajectory": _gate_trajectory(state),
                "at_ms": now_ms,
            }
            self._append(campaign_id, prior_cursor, event)
            return (
                self._decision(
                    campaign_id=campaign_id,
                    prior_cursor=prior_cursor,
                    accepted_input=payload,
                    status="ADVANCED",
                    reasons=["advance:rung_committed"],
                ),
                [],
            )
        terminal = _terminal_record(
            state, pending["outcome"], pending["reason"], now_ms
        )
        self._append_terminal(campaign_id, prior_cursor, terminal)
        return (
            self._decision(
                campaign_id=campaign_id,
                prior_cursor=prior_cursor,
                accepted_input=payload,
                status="TERMINAL",
                reasons=["advance:campaign_terminal"],
            ),
            [],
        )

    def _cancel(
        self,
        payload: Mapping[str, Any],
        state: Mapping[str, Any],
        request: Any,
        prior_cursor: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, list[str]]:
        fields = {"reason", "cleanup_status", "owned_descendants", "cleanup_evidence_sha256", "elapsed_ms"}
        if not isinstance(request, Mapping) or set(request) != fields:
            return None, ["advance:cancel_request_invalid"]
        if not isinstance(request.get("reason"), str) or not request["reason"]:
            return None, ["advance:cancel_reason_invalid"]
        if request.get("cleanup_status") not in {"PASS", "FAIL", "UNKNOWN"}:
            return None, ["advance:cleanup_invalid"]
        if type(request.get("owned_descendants")) is not int or request["owned_descendants"] < 0 or not _sha(request.get("cleanup_evidence_sha256")) or type(request.get("elapsed_ms")) is not int or request["elapsed_ms"] < 0:
            return None, ["advance:cleanup_invalid"]
        if request["cleanup_status"] == "PASS" and (
            request["owned_descendants"] != 0 or request["elapsed_ms"] > 60_000
        ):
            return None, ["advance:cleanup_invalid"]
        campaign_id = state["preparation"]["campaign_id"]
        terminal = _terminal_record(
            state,
            "CANCELLED",
            "campaign:cancelled:" + request["cleanup_status"].lower(),
            self.clock_ms(),
        )
        core = dict(terminal)
        core.pop("terminal_sha256")
        core["cleanup"] = deepcopy(dict(request))
        terminal = _seal(core, "terminal_sha256")
        self._append_terminal(campaign_id, prior_cursor, terminal, terminated=True)
        return (
            self._decision(
                campaign_id=campaign_id,
                prior_cursor=prior_cursor,
                accepted_input=payload,
                status="TERMINAL",
                reasons=["advance:campaign_cancelled"],
            ),
            [],
        )

    def advance(self, payload: Any) -> tuple[dict[str, Any] | None, list[str]]:
        issues: list[str] = []
        value = _closed(payload, _ADVANCE_FIELDS, "advance", issues)
        if value is None:
            return None, sorted(set(issues))
        if value.get("schema") != ADVANCE_SCHEMA:
            return None, ["advance:schema_invalid"]
        kind = value.get("kind")
        if kind not in {
            "start",
            "reserve_pair",
            "dispatch_config",
            "observe_config",
            "dispatch_review",
            "observe_review",
            "reconcile",
            "cancel",
        }:
            return None, ["advance:kind_invalid"]
        campaign_id = value.get("campaign_id")
        if not _identifier(campaign_id) or not _cursor_valid(
            value.get("prior_cursor"), campaign_id
        ):
            return None, ["advance:cursor_invalid"]
        prior_cursor = value["prior_cursor"]
        if kind == "start":
            return self._start(value, value.get("request"), prior_cursor)
        if not self.store.exists(_stream_id(campaign_id)):
            return None, ["advance:campaign_not_found"]
        state = self._state(campaign_id)
        actual_cursor = _cursor(campaign_id, state["rows"])
        if prior_cursor != actual_cursor:
            return None, ["advance:stale_cursor"]
        if state["terminal_record"] is not None:
            return None, ["advance:post_terminal"]
        pending = _pending_transition(state, self.clock_ms())
        if pending is not None and kind not in {"reconcile", "cancel"}:
            return None, ["advance:reconciliation_required"]
        handler = {
            "reserve_pair": self._reserve_pair,
            "dispatch_config": self._dispatch_config,
            "observe_config": self._observe_config,
            "dispatch_review": self._dispatch_review,
            "observe_review": self._observe_review,
            "reconcile": self._reconcile,
            "cancel": self._cancel,
        }[kind]
        try:
            return handler(value, state, value.get("request"), prior_cursor)
        except (run_store.StaleSeqError, run_engine.RunKernelError):
            return None, ["advance:cas_conflict"]

    def inspect(self, payload: Any) -> tuple[dict[str, Any] | None, list[str]]:
        issues: list[str] = []
        query = _closed(payload, _INSPECTION_QUERY_FIELDS, "inspect", issues)
        if query is None:
            return None, sorted(set(issues))
        if query.get("schema") != INSPECTION_QUERY_SCHEMA:
            return None, ["inspect:schema_invalid"]
        campaign_id = query.get("campaign_id")
        if not _identifier(campaign_id) or not self.store.exists(_stream_id(campaign_id)):
            return None, ["inspect:campaign_not_found"]
        if type(query.get("after_seq")) is not int or query["after_seq"] < 0:
            return None, ["inspect:after_seq_invalid"]
        if type(query.get("max_events")) is not int or not 1 <= query["max_events"] <= 64:
            return None, ["inspect:max_events_invalid"]
        state = self._state(campaign_id)
        rows = state["rows"]
        selected = [row for row in rows if row["seq"] > query["after_seq"]][
            : query["max_events"]
        ]
        usage = _usage(state)
        preparation = state["preparation"]
        pending = _pending_transition(state, self.clock_ms())
        terminal = state["terminal_record"]
        fixture_states = []
        for fixture in sorted(
            state["fixtures"].values(),
            key=lambda item: (
                item["manifest"]["rung"],
                PARTITIONS.index(item["manifest"]["partition"]),
            ),
        ):
            fixture_states.append(
                {
                    "fixture_id": fixture["manifest"]["fixture_id"],
                    "fixture_sha256": fixture["manifest"]["fixture_sha256"],
                    "partition": fixture["manifest"]["partition"],
                    "rung": fixture["manifest"]["rung"],
                    "status": _public_fixture_status(fixture),
                }
            )
        budget = preparation["budget_contract"]
        core = {
            "schema": INSPECTION_SCHEMA,
            "campaign_id": campaign_id,
            "candidate_sha256": preparation["challenger"]["candidate_sha256"],
            "corpus_sha256": preparation["corpus_sha256"],
            "runtime_contract_sha256": preparation["runtime_contract_sha256"],
            "authority_scope_sha256": preparation["authority_scope_sha256"],
            "current_rung": self._current_rung(state),
            "sealed_rungs": len(state["sealed_rungs"]),
            "completed_fixtures": _gate_trajectory(state)["reviewed_fixtures"],
            "fixture_states": fixture_states,
            "usage": usage,
            "remaining_budget": {
                "champion_qwen_sessions": budget["champion_session_limit"]
                - usage["champion_qwen_sessions"],
                "challenger_qwen_sessions": budget["challenger_session_limit"]
                - usage["challenger_qwen_sessions"],
                "sol_reviews": budget["sol_review_limit"] - usage["sol_reviews"],
            },
            "gate_trajectory": _gate_trajectory(state),
            "next_action": (
                "TERMINAL"
                if terminal is not None
                else pending["kind"]
                if pending is not None
                else self._next_action(state)
            ),
            "terminal": terminal is not None,
            "terminal_outcome": None if terminal is None else terminal["outcome"],
            "terminal_reason": None if terminal is None else terminal["reason"],
            "successor": None if terminal is None else terminal["successor"],
            "cursor": _cursor(campaign_id, rows),
            "events": [
                {
                    "seq": row["seq"],
                    "kind": row["kind"],
                    "event_hash": row["event_hash"],
                    "prev_hash": row["prev_hash"],
                    "facts_sha256": hashlib.sha256(
                        row["payload"].encode("utf-8")
                    ).hexdigest(),
                }
                for row in selected
            ],
            "truncated": len(
                [row for row in rows if row["seq"] > query["after_seq"]]
            )
            > len(selected),
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
        return _seal(core, "inspection_sha256"), []

    def evaluate(self, program: Any) -> dict[str, Any]:
        issues: list[str] = []
        try:
            canonical = _canonical(program) if _shape_within_bounds(program) else None
        except (TypeError, ValueError, OverflowError, RecursionError):
            canonical = None
        value = _closed(program, _PROGRAM_FIELDS, "program", issues) if canonical is not None else None
        if canonical is None:
            issues.append("program:hostile_or_noncanonical")
        result = None
        operation = None
        program_id = None
        if value is not None:
            if value.get("schema") != PROGRAM_SCHEMA:
                issues.append("program:schema_invalid")
            if _identifier(value.get("program_id")):
                program_id = value["program_id"]
            else:
                issues.append("program:program_id_invalid")
            if value.get("operation") in OPERATIONS:
                operation = value["operation"]
            else:
                issues.append("program:operation_invalid")
            if not issues and operation == "prepare":
                result, found = _prepare(value.get("payload"))
                issues.extend(found)
            elif not issues and operation == "advance":
                result, found = self.advance(value.get("payload"))
                issues.extend(found)
            elif not issues and operation == "inspect":
                result, found = self.inspect(value.get("payload"))
                issues.extend(found)
        core = {
            "schema": REPORT_SCHEMA,
            "program_id": program_id,
            "operation": operation,
            "status": "PASS" if not issues else "FAIL",
            "issues": sorted(set(issues)),
            "result": result if not issues else None,
        }
        return _seal(core, "report_sha256")


__all__ = [
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "PREPARE_SCHEMA",
    "PREPARATION_SCHEMA",
    "ADVANCE_SCHEMA",
    "INSPECTION_QUERY_SCHEMA",
    "FIXTURE_SCHEMA",
    "CORPUS_DRAFT_SCHEMA",
    "CORPUS_SCHEMA",
    "RUNTIME_CONTRACT_SCHEMA",
    "AUTHORITY_CLASS",
    "CURSOR_SCHEMA",
    "DECISION_SCHEMA",
    "INSPECTION_SCHEMA",
    "AUTHORITY_REGISTRATION_DRAFT_SCHEMA",
    "AUTHORITY_REGISTRATION_SCHEMA",
    "RUN_REF_SCHEMA",
    "CONFIG_OBSERVATION_DRAFT_SCHEMA",
    "CONFIG_OBSERVATION_SCHEMA",
    "REVIEW_OBSERVATION_DRAFT_SCHEMA",
    "REVIEW_OBSERVATION_SCHEMA",
    "REVIEW_DIMENSIONS",
    "FrontierCampaignController",
    "genesis_cursor",
    "json_sha256",
    "seal_authority_registration",
    "seal_config_observation",
    "seal_review_observation",
    "validate_preparation",
]


if __name__ == "__main__":
    raise SystemExit("Import FrontierCampaignController; no CLI is provided.")
