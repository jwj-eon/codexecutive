#!/usr/bin/env python3
"""Ledger-derived learned sizing and stopping with evidence-gated promotion.

This module deliberately implements a small empirical lookup policy rather
than an opaque model.  Training examples are re-derived from sealed sweep
records and reportable blind dogfood chains.  The resulting policy maps a
declared task family and difficulty bucket to an advisory first-wave shape and
an advisory deepening margin; the ordinary split and deepening gates still
dispose.  Promotion is a separate append-only decision requiring a later
preregistered campaign, a promotion-eligible sealed result, fresh ledger
position, and lineage disjointness from every training example.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from fractions import Fraction
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
    except ImportError:  # pragma: no cover - direct-file loading.
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


campaigns = _load_sibling("orch_dork_experiment_campaign")
dogfood = _load_sibling("orch_dork_dogfood_corpus")
hostile = _load_sibling("orch_dork_hostile_input")
sweep = _load_sibling("orch_dork_sweep_harness")
trace = _load_sibling("orch_dork_trace")

PROFILE = hostile.PROFILE

TRAINING_REQUEST_SCHEMA = "orch-dork/learned-training-request/v1"
TRAINING_MANIFEST_SCHEMA = "orch-dork/learned-training-manifest/v1"
TRAINING_MANIFEST_REPORT_SCHEMA = "orch-dork/learned-training-manifest-report/v1"
TRAINING_MANIFEST_VALIDATION_SCHEMA = (
    "orch-dork/learned-training-manifest-validation/v1"
)
TRAINING_EXAMPLE_SCHEMA = "orch-dork/learned-training-example/v1"
FIT_PROGRAM_SCHEMA = "orch-dork/learned-policy-fit-program/v1"
FIT_REPORT_SCHEMA = "orch-dork/learned-policy-fit-report/v1"
LEARNED_POLICY_SCHEMA = "orch-dork/learned-sizing-stopping-policy/v1"
LEARNED_POLICY_VALIDATION_SCHEMA = "orch-dork/learned-policy-validation/v1"
INFERENCE_PROGRAM_SCHEMA = "orch-dork/learned-policy-inference-program/v1"
INFERENCE_REPORT_SCHEMA = "orch-dork/learned-policy-inference/v1"
PROMOTION_PROGRAM_SCHEMA = "orch-dork/learned-policy-promotion-program/v1"
PROMOTION_RECORD_SCHEMA = "orch-dork/learned-policy-promotion/v1"
PROMOTION_REPORT_SCHEMA = "orch-dork/learned-policy-promotion-report/v1"
PROMOTION_VALIDATION_SCHEMA = "orch-dork/learned-policy-promotion-validation/v1"
LIVE_CAMPAIGN_RECORD_SCHEMA = "orch-dork/live-sweep-campaign-record/v1"
LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA = (
    "orch-dork/live-sweep-canonical-replicate-record/v1"
)
LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA_V2 = (
    "orch-dork/live-sweep-canonical-replicate-record/v2"
)


def _load_live_sweep():
    """Load the downstream live adapter only for a declared live source."""

    return _load_sibling("orch_dork_live_sweep")

EXTRACTOR_VERSION = "difficulty-feature-extractor/v1"
FITTER_VERSION = "empirical-sizing-stopping/v1"
STANDING_DEFAULTS_ID = "standing-defaults/v1"

DIFFICULTY_BUCKETS = frozenset({"low", "medium", "high"})
PROMOTION_DISPOSITIONS = frozenset(
    {"PROMOTE_GLOBAL", "PROMOTE_PER_FAMILY", "BEATEN"}
)

_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")

_TRAINING_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "manifest_id",
        "experiment_ledger_checkpoint",
        "sweep_campaign_sha256s",
        "dogfood_corpora",
    }
)
_CHECKPOINT_FIELDS = frozenset({"length", "last_sha256"})
_DOGFOOD_SOURCE_FIELDS = frozenset({"host_id", "head_sha256"})
_TRAINING_PARAMETER_FIELDS = frozenset(
    {
        "data_partition",
        "task_family",
        "difficulty_bucket",
        "lane_count",
        "cut_strategy",
        "capability_profile",
        "stopping_margin_bps",
    }
)
_EXAMPLE_FIELDS = frozenset(
    {
        "schema",
        "source_kind",
        "source_schema",
        "source_record_sha256",
        "source_chain_head_sha256",
        "source_sequence",
        "lineage_sha256",
        "data_partition",
        "task_family",
        "difficulty_bucket",
        "sizer_target",
        "stopping_target",
        "score",
        "example_sha256",
    }
)
_SIZER_FIELDS = frozenset(
    {"lane_count", "cut_strategy", "capability_profile"}
)
_STOPPING_FIELDS = frozenset({"minimum_net_margin_bps"})
_RATIONAL_FIELDS = frozenset({"numerator", "denominator"})
_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "manifest_id",
        "extractor_version",
        "scoring_policy",
        "experiment_ledger_checkpoint",
        "sweep_campaign_sha256s",
        "dogfood_corpora",
        "examples",
        "source_counts",
        "task_families",
        "partition_proof",
        "manifest_sha256",
    }
)
_SOURCE_COUNT_FIELDS = frozenset(
    {"sweep", "blind_dogfood", "total"}
)
_PARTITION_PROOF_FIELDS = frozenset(
    {
        "allowed_partition",
        "evaluation_tasks_selected",
        "hidden_tests_selected",
        "control_outputs_selected",
    }
)
_FIT_FIELDS = frozenset({"schema", "candidate_id", "training_request"})
_RULE_FIELDS = frozenset(
    {
        "rule_id",
        "task_family",
        "difficulty_bucket",
        "training_example_sha256s",
        "sizer",
        "stopping",
        "mean_score",
    }
)
_POLICY_FIELDS = frozenset(
    {
        "schema",
        "candidate_id",
        "fitter_version",
        "training_manifest_sha256",
        "training_ledger_checkpoint",
        "rules",
        "family_classifier",
        "advisory_only",
        "split_gate_required",
        "deepening_gate_required",
        "workers_permitted",
        "authority_granted",
        "policy_sha256",
    }
)
_POLICY_CLASSIFIER_FIELDS = frozenset(
    {"feature", "known_families", "rule_ids_by_family", "unknown_family_fallback"}
)
_INFERENCE_FIELDS = frozenset({"schema", "policy", "task"})
_TASK_FIELDS = frozenset({"task_id", "task_family", "difficulty_bucket"})
_PROMOTION_FIELDS = frozenset(
    {
        "schema",
        "promotion_id",
        "training_request",
        "training_manifest",
        "candidate_policy",
        "evaluation_campaign",
        "campaign_result",
        "promotion_rule",
        "standing_defaults",
    }
)
_PROMOTION_RULE_FIELDS = frozenset({"direction", "minimum_improvement"})
_STANDING_DEFAULT_FIELDS = frozenset({"id", "sizer", "stopping"})
_EVALUATION_PARAMETER_FIELDS = frozenset(
    {"data_partition", "task_family", "policy_role", "policy_ref", "lineage_sha256"}
)
_FAMILY_RESULT_FIELDS = frozenset(
    {
        "task_family",
        "candidate_score",
        "standing_default_score",
        "improvement",
        "minimum_improvement",
        "candidate_beats_default",
    }
)
_PER_FAMILY_FIELDS = frozenset(
    {"task_family", "candidate_policy_sha256", "rule_ids"}
)
_PROMOTION_CLASSIFIER_FIELDS = frozenset(
    {"feature", "assignments", "unknown_family_fallback"}
)
_FRESHNESS_FIELDS = frozenset(
    {"training_checkpoint_length", "training_checkpoint_sha256", "evaluation_campaign_seq", "fresh"}
)
_LINEAGE_FIELDS = frozenset(
    {"training_lineage_sha256s", "evaluation_lineage_sha256s", "disjoint"}
)
_PROMOTION_RECORD_FIELDS = frozenset(
    {
        "schema",
        "promotion_id",
        "candidate_policy_sha256",
        "training_manifest_sha256",
        "evaluation_campaign_sha256",
        "campaign_result_sha256",
        "standing_defaults",
        "promotion_rule",
        "freshness",
        "lineage",
        "family_results",
        "disposition",
        "candidate_retained",
        "global_policy_retained",
        "per_family_policies",
        "family_classifier",
        "default_change_eligible",
        "default_changed",
        "provider_free",
        "model_calls",
        "hosted_calls",
        "record_sha256",
    }
)

_SWEEP_RECORD_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "configuration_id",
        "configuration_sha256",
        "replicate_index",
        "seed",
        "request_sha256",
        "validation_status",
        "failure_reason",
        "outcome",
        "metric",
        "governed_entrypoint",
        "governed_program_schema",
        "governed_report_sha256",
        "adapter_receipt_sha256",
        "provider_free_evidence",
        "model_calls",
        "hosted_calls",
        "record_sha256",
    }
)
_LIVE_SWEEP_RECORD_FIELDS = frozenset(
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

_SCORING_POLICY = {
    "sweep_metric": "exact_rational",
    "dogfood_plan_verdict": {
        "good": {"numerator": 1, "denominator": 1},
        "wrong_split": {"numerator": 0, "denominator": 1},
        "missed_coupling": {"numerator": 0, "denominator": 1},
        "over_split": {"numerator": 0, "denominator": 1},
    },
    "dogfood_outcome": {
        "shipped": {"numerator": 1, "denominator": 1},
        "needed_rework": {"numerator": 1, "denominator": 2},
        "abandoned": {"numerator": 0, "denominator": 1},
    },
    "dogfood_combination": "arithmetic_mean",
}


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


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _closed(
    value: Any, fields: frozenset[str], label: str, issues: list[str]
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":type_invalid")
        return {}
    result = dict(value)
    if set(result) != fields:
        _issue(issues, label + ":shape_invalid")
    return result


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _bounded_int(
    value: Any, *, minimum: int = 0, maximum: int | None = None
) -> bool:
    return (
        type(value) is int
        and value >= minimum
        and (maximum is None or value <= maximum)
    )


def _fraction(value: Any, label: str, issues: list[str]) -> Fraction:
    row = _closed(value, _RATIONAL_FIELDS, label, issues)
    numerator = row.get("numerator")
    denominator = row.get("denominator")
    if type(numerator) is not int or not _bounded_int(denominator, minimum=1):
        _issue(issues, label + ":invalid")
        return Fraction(0, 1)
    return Fraction(numerator, denominator)


def _rational(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}


def _sealed(core: Mapping[str, Any], field: str) -> dict[str, Any]:
    value = dict(core)
    return {**value, field: _sha256(value)}


def _seal_valid(value: Any, field: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    core = dict(value)
    recorded = core.pop(field, None)
    try:
        return _digest(recorded) and recorded == _sha256(core)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return False


def _parameter_map(configuration: Any) -> dict[str, Any]:
    if not isinstance(configuration, Mapping):
        return {}
    raw = configuration.get("parameters")
    if not isinstance(raw, list):
        return {}
    result: dict[str, Any] = {}
    for row in raw:
        if not isinstance(row, Mapping) or set(row) != {"name", "value"}:
            return {}
        name = row.get("name")
        if not isinstance(name, str) or name in result:
            return {}
        result[name] = row.get("value")
    return result


def _training_report(
    issues: Sequence[str], manifest: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "schema": TRAINING_MANIFEST_REPORT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(str(item) for item in issues)),
        "training_manifest": dict(manifest) if not issues and isinstance(manifest, Mapping) else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "default_changed": False,
    }


def _validate_training_request(value: Any, issues: list[str]) -> dict[str, Any]:
    request = _closed(value, _TRAINING_REQUEST_FIELDS, "training_request", issues)
    if request.get("schema") != TRAINING_REQUEST_SCHEMA:
        _issue(issues, "training_request:schema_invalid")
    if not _identifier(request.get("manifest_id")):
        _issue(issues, "training_request:manifest_id_invalid")
    checkpoint = _closed(
        request.get("experiment_ledger_checkpoint"),
        _CHECKPOINT_FIELDS,
        "training_request.experiment_ledger_checkpoint",
        issues,
    )
    if not _bounded_int(checkpoint.get("length"), minimum=1):
        _issue(issues, "training_request:checkpoint_length_invalid")
    if not _digest(checkpoint.get("last_sha256")):
        _issue(issues, "training_request:checkpoint_sha256_invalid")

    campaign_hashes = request.get("sweep_campaign_sha256s")
    if (
        not isinstance(campaign_hashes, list)
        or not campaign_hashes
        or len(campaign_hashes) > PROFILE.max_array_items
        or any(not _digest(item) for item in campaign_hashes)
        or len(campaign_hashes) != len(set(campaign_hashes))
    ):
        _issue(issues, "training_request:sweep_campaigns_invalid")
        campaign_hashes = []

    corpora = request.get("dogfood_corpora")
    normalized_corpora: list[dict[str, str]] = []
    if (
        not isinstance(corpora, list)
        or not corpora
        or len(corpora) > PROFILE.max_array_items
    ):
        _issue(issues, "training_request:dogfood_corpora_invalid")
        corpora = []
    for index, raw in enumerate(corpora):
        row = _closed(
            raw,
            _DOGFOOD_SOURCE_FIELDS,
            f"training_request.dogfood_corpora[{index}]",
            issues,
        )
        if not _identifier(row.get("host_id")) or not _digest(row.get("head_sha256")):
            _issue(issues, "training_request:dogfood_source_invalid")
        else:
            normalized_corpora.append(
                {"host_id": row["host_id"], "head_sha256": row["head_sha256"]}
            )
    hosts = [row["host_id"] for row in normalized_corpora]
    if len(hosts) != len(set(hosts)):
        _issue(issues, "training_request:dogfood_host_duplicate")
    return {
        "schema": TRAINING_REQUEST_SCHEMA,
        "manifest_id": request.get("manifest_id"),
        "experiment_ledger_checkpoint": {
            "length": checkpoint.get("length"),
            "last_sha256": checkpoint.get("last_sha256"),
        },
        "sweep_campaign_sha256s": list(campaign_hashes),
        "dogfood_corpora": sorted(normalized_corpora, key=lambda row: row["host_id"]),
    }


def _difficulty_from_dogfood(record: Mapping[str, Any]) -> str | None:
    observation = record.get("observation")
    if not isinstance(observation, Mapping):
        return None
    checks = observation.get("checks_count")
    if not _bounded_int(checks):
        return None
    if checks <= 2:
        return "low"
    if checks <= 5:
        return "medium"
    return "high"


def _dogfood_score(record: Mapping[str, Any]) -> Fraction | None:
    plan = _SCORING_POLICY["dogfood_plan_verdict"].get(record.get("plan_verdict"))
    outcome = _SCORING_POLICY["dogfood_outcome"].get(record.get("outcome"))
    if not isinstance(plan, Mapping) or not isinstance(outcome, Mapping):
        return None
    return (
        Fraction(plan["numerator"], plan["denominator"])
        + Fraction(outcome["numerator"], outcome["denominator"])
    ) / 2


def _example(core: Mapping[str, Any]) -> dict[str, Any]:
    return _sealed({**dict(core), "schema": TRAINING_EXAMPLE_SCHEMA}, "example_sha256")


def _sweep_examples(
    prefix: Sequence[Mapping[str, Any]],
    campaign_sha256: str,
    ledger_head: str,
    issues: list[str],
) -> list[dict[str, Any]]:
    campaign_rows = [
        row
        for row in prefix
        if row.get("record", {}).get("schema")
        in {sweep.CAMPAIGN_RECORD_SCHEMA, LIVE_CAMPAIGN_RECORD_SCHEMA}
        and row.get("record", {}).get("campaign_sha256") == campaign_sha256
    ]
    if len(campaign_rows) != 1:
        _issue(issues, "training_source:campaign_missing_or_duplicate")
        return []
    campaign_record = campaign_rows[0]["record"]
    live_source = (
        campaign_record.get("schema") == LIVE_CAMPAIGN_RECORD_SCHEMA
    )
    replicate_schemas = (
        {
            LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA,
            LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA_V2,
        }
        if live_source
        else {sweep.REPLICATE_RECORD_SCHEMA}
    )
    if not _seal_valid(campaign_record, "record_sha256"):
        _issue(issues, "training_source:campaign_record_seal_invalid")
        return []
    campaign = campaign_record.get("campaign")
    verification = campaigns.verify_campaign(campaign)
    if verification.get("status") != "PASS" or not isinstance(campaign, Mapping):
        _issue(issues, "training_source:campaign_invalid")
        return []

    configurations: dict[str, dict[str, Any]] = {}
    configuration_hashes: dict[str, str] = {}
    for configuration in campaign.get("configuration_grid", []):
        params = _parameter_map(configuration)
        if set(params) != _TRAINING_PARAMETER_FIELDS:
            _issue(issues, "training_source:configuration_shape_invalid")
            continue
        if params.get("data_partition") != "training":
            _issue(issues, "training_source:nontraining_partition")
            continue
        if (
            not _identifier(params.get("task_family"))
            or params.get("difficulty_bucket") not in DIFFICULTY_BUCKETS
            or not _bounded_int(params.get("lane_count"), minimum=1, maximum=32)
            or not _identifier(params.get("cut_strategy"))
            or not _identifier(params.get("capability_profile"))
            or not _bounded_int(params.get("stopping_margin_bps"), maximum=10_000)
        ):
            _issue(issues, "training_source:configuration_value_invalid")
            continue
        configurations[str(configuration.get("configuration_id"))] = params
        configuration_hashes[str(configuration.get("configuration_id"))] = _sha256(
            configuration
        )

    examples: list[dict[str, Any]] = []
    seen_cells: set[tuple[str, int, int]] = set()
    for outer in prefix:
        record = outer.get("record")
        if not isinstance(record, Mapping):
            continue
        if (
            record.get("schema") not in replicate_schemas
            or record.get("campaign_sha256") != campaign_sha256
        ):
            continue
        if live_source:
            record_fields = (
                _LIVE_SWEEP_RECORD_FIELDS | {"evidence_class"}
                if record.get("schema")
                == LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA_V2
                else _LIVE_SWEEP_RECORD_FIELDS
            )
        else:
            record_fields = _SWEEP_RECORD_FIELDS
        if set(record) != record_fields or not _seal_valid(
            record, "record_sha256"
        ):
            _issue(issues, "training_source:replicate_record_invalid")
            continue
        if record.get("schema") == LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA_V2 and record.get(
            "evidence_class"
        ) not in ("qualified", "malformed_terminal"):
            _issue(issues, "training_source:replicate_record_invalid")
            continue
        replicate_index = record.get("replicate_index")
        seed = record.get("seed")
        if not _bounded_int(replicate_index, minimum=1) or not _bounded_int(seed):
            _issue(issues, "training_source:replicate_record_invalid")
            continue
        cell = (
            str(record.get("configuration_id")),
            replicate_index,
            seed,
        )
        if cell in seen_cells:
            _issue(issues, "training_source:replicate_duplicate")
            continue
        seen_cells.add(cell)
        params = configurations.get(cell[0])
        metric = record.get("metric")
        validation_accepted = (
            True
            if live_source
            else record.get("validation_status") == "accepted"
        )
        live_binding_valid = (
            True
            if not live_source
            else (
                record.get("task_family") == (params or {}).get("task_family")
                and record.get("configuration_sha256")
                == configuration_hashes.get(cell[0])
                and _bounded_int(record.get("live_model_calls"), minimum=1)
                and record.get("hosted_calls") == 0
                and record.get("replay_decidable")
                == ["verified_success_bps", "outcome"]
                and record.get("live_required")
                == ["custody", "route", "timing", "token_usage"]
            )
        )
        if (
            params is None
            or not validation_accepted
            or not live_binding_valid
            or record.get("outcome") not in {"passed", "failed"}
            or not isinstance(metric, Mapping)
            or set(metric) != {"name", "numerator", "denominator"}
            or metric.get("name") != campaign.get("question", {}).get("primary_metric")
            or type(metric.get("numerator")) is not int
            or not _bounded_int(metric.get("denominator"), minimum=1)
            or not _digest(record.get("governed_report_sha256"))
        ):
            _issue(issues, "training_source:replicate_not_admissible")
            continue
        examples.append(
            _example(
                {
                    "source_kind": "sweep",
                    "source_schema": record.get("schema"),
                    "source_record_sha256": record["record_sha256"],
                    "source_chain_head_sha256": ledger_head,
                    "source_sequence": outer["seq"],
                    "lineage_sha256": record["governed_report_sha256"],
                    "data_partition": "training",
                    "task_family": params["task_family"],
                    "difficulty_bucket": params["difficulty_bucket"],
                    "sizer_target": {
                        "lane_count": params["lane_count"],
                        "cut_strategy": params["cut_strategy"],
                        "capability_profile": params["capability_profile"],
                    },
                    "stopping_target": {
                        "minimum_net_margin_bps": params["stopping_margin_bps"]
                    },
                    "score": {
                        "numerator": metric["numerator"],
                        "denominator": metric["denominator"],
                    },
                }
            )
        )
    expected = len(campaign.get("configuration_grid", [])) * int(
        campaign.get("replicate_count", 0)
    )
    if len(examples) != expected:
        _issue(issues, "training_source:sweep_incomplete")
    return examples


def _dogfood_examples(
    source: Mapping[str, str],
    path: str | Path | None,
    issues: list[str],
) -> list[dict[str, Any]]:
    if path is None:
        _issue(issues, "dogfood:source_unavailable")
        return []
    try:
        entries = dogfood.read_corpus(path)
    except (dogfood.DogfoodCorpusError, OSError, UnicodeError):
        _issue(issues, "dogfood:chain_invalid")
        return []
    matching = [
        index
        for index, entry in enumerate(entries)
        if entry.get("entry_sha256") == source["head_sha256"]
    ]
    if len(matching) != 1:
        _issue(issues, "dogfood:head_unavailable")
        return []
    prefix = entries[: matching[0] + 1]
    summary = dogfood.summarize_corpus(
        prefix, min_records=dogfood.DEFAULT_MIN_RECORDS
    )
    if summary.get("aggregate_reportable") is not True:
        _issue(issues, "dogfood:standing_corpus_rules_not_met")
        return []
    records = dogfood.effective_records(prefix)
    examples: list[dict[str, Any]] = []
    for record in records:
        if record.get("blind") is not True:
            continue
        observation = record.get("observation")
        lane_count = observation.get("lane_count") if isinstance(observation, Mapping) else None
        difficulty = _difficulty_from_dogfood(record)
        score = _dogfood_score(record)
        if (
            not _identifier(record.get("ticket_key"))
            or not _identifier(record.get("run_key"))
            or not _bounded_int(lane_count, minimum=1, maximum=32)
            or difficulty is None
            or score is None
            or not _digest(record.get("entry_sha256"))
        ):
            _issue(issues, "dogfood:record_not_admissible")
            continue
        examples.append(
            _example(
                {
                    "source_kind": "dogfood",
                    "source_schema": dogfood.RECORD_SCHEMA,
                    "source_record_sha256": record["entry_sha256"],
                    "source_chain_head_sha256": source["head_sha256"],
                    "source_sequence": record["sequence"],
                    "lineage_sha256": _sha256(
                        {"host_id": source["host_id"], "run_key": record["run_key"]}
                    ),
                    "data_partition": "training",
                    "task_family": record["ticket_key"],
                    "difficulty_bucket": difficulty,
                    "sizer_target": {
                        "lane_count": lane_count,
                        "cut_strategy": "observed_plan",
                        "capability_profile": "observed",
                    },
                    "stopping_target": None,
                    "score": _rational(score),
                }
            )
        )
    if len(examples) < dogfood.DEFAULT_MIN_RECORDS:
        _issue(issues, "dogfood:admissible_record_count_below_floor")
    return examples


def derive_training_manifest(
    request: Any,
    experiment_ledger_path: str | Path,
    dogfood_corpus_paths: Mapping[str, str | Path],
) -> dict[str, Any]:
    """Re-derive a sealed manifest from fixed append-only ledger prefixes."""

    issues: list[str] = []
    try:
        _canonical(request)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return _training_report(["training_request:hostile_or_noncanonical"])
    normalized = _validate_training_request(request, issues)
    if not isinstance(dogfood_corpus_paths, Mapping):
        _issue(issues, "dogfood:paths_invalid")
        dogfood_corpus_paths = {}
    entries, chain_issues = sweep.read_experiment_ledger(experiment_ledger_path)
    for item in chain_issues:
        _issue(issues, item)
    checkpoint = normalized["experiment_ledger_checkpoint"]
    length = checkpoint.get("length")
    if (
        type(length) is not int
        or length < 1
        or length > len(entries)
        or entries[length - 1].get("record_sha256") != checkpoint.get("last_sha256")
    ):
        _issue(issues, "training_request:checkpoint_mismatch")
        prefix: list[dict[str, Any]] = []
    else:
        prefix = entries[:length]
    if issues:
        return _training_report(issues)

    examples: list[dict[str, Any]] = []
    for campaign_sha256 in normalized["sweep_campaign_sha256s"]:
        is_live = any(
            row.get("record", {}).get("schema")
            == LIVE_CAMPAIGN_RECORD_SCHEMA
            and row.get("record", {}).get("campaign_sha256") == campaign_sha256
            for row in prefix
        )
        campaign_summary = (
            _load_live_sweep().summarize_live_campaign(
                experiment_ledger_path, campaign_sha256
            )
            if is_live
            else sweep.summarize_sweep_campaign(
                experiment_ledger_path, campaign_sha256
            )
        )
        if campaign_summary.get("status") != "PASS":
            _issue(issues, "training_source:sweep_campaign_invalid")
            continue
        if is_live and campaign_summary.get("state") != "COMPLETE":
            _issue(issues, "training_source:sweep_campaign_incomplete")
            continue
        examples.extend(
            _sweep_examples(
                prefix,
                campaign_sha256,
                checkpoint["last_sha256"],
                issues,
            )
        )
    for source in normalized["dogfood_corpora"]:
        examples.extend(
            _dogfood_examples(
                source,
                dogfood_corpus_paths.get(source["host_id"]),
                issues,
            )
        )
    if issues:
        return _training_report(issues)
    examples = sorted(
        examples,
        key=lambda row: (
            row["source_kind"],
            row["source_record_sha256"],
            row["example_sha256"],
        ),
    )
    sweep_count = sum(row["source_kind"] == "sweep" for row in examples)
    dogfood_count = sum(row["source_kind"] == "dogfood" for row in examples)
    core = {
        "schema": TRAINING_MANIFEST_SCHEMA,
        "manifest_id": normalized["manifest_id"],
        "extractor_version": EXTRACTOR_VERSION,
        "scoring_policy": _SCORING_POLICY,
        "experiment_ledger_checkpoint": checkpoint,
        "sweep_campaign_sha256s": normalized["sweep_campaign_sha256s"],
        "dogfood_corpora": normalized["dogfood_corpora"],
        "examples": examples,
        "source_counts": {
            "sweep": sweep_count,
            "blind_dogfood": dogfood_count,
            "total": len(examples),
        },
        "task_families": sorted({row["task_family"] for row in examples}),
        "partition_proof": {
            "allowed_partition": "training",
            "evaluation_tasks_selected": 0,
            "hidden_tests_selected": 0,
            "control_outputs_selected": 0,
        },
    }
    manifest = _sealed(core, "manifest_sha256")
    return _training_report([], manifest)


def _validate_example(value: Any, issues: list[str]) -> dict[str, Any]:
    row = _closed(value, _EXAMPLE_FIELDS, "training_example", issues)
    if row.get("schema") != TRAINING_EXAMPLE_SCHEMA:
        _issue(issues, "training_example:schema_invalid")
    if row.get("source_kind") not in {"sweep", "dogfood"}:
        _issue(issues, "training_example:source_kind_invalid")
    expected_schemas = {
        "sweep": {
            sweep.REPLICATE_RECORD_SCHEMA,
            LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA,
            LIVE_CANONICAL_REPLICATE_RECORD_SCHEMA_V2,
        },
        "dogfood": {dogfood.RECORD_SCHEMA},
    }.get(row.get("source_kind"), set())
    if row.get("source_schema") not in expected_schemas:
        _issue(issues, "training_example:source_schema_invalid")
    for field in (
        "source_record_sha256",
        "source_chain_head_sha256",
        "lineage_sha256",
        "example_sha256",
    ):
        if not _digest(row.get(field)):
            _issue(issues, "training_example:" + field + "_invalid")
    if not _bounded_int(row.get("source_sequence")):
        _issue(issues, "training_example:source_sequence_invalid")
    if row.get("data_partition") != "training":
        _issue(issues, "training_example:partition_invalid")
    if not _identifier(row.get("task_family")):
        _issue(issues, "training_example:task_family_invalid")
    if row.get("difficulty_bucket") not in DIFFICULTY_BUCKETS:
        _issue(issues, "training_example:difficulty_invalid")
    sizer = _closed(row.get("sizer_target"), _SIZER_FIELDS, "training_example.sizer", issues)
    if (
        not _bounded_int(sizer.get("lane_count"), minimum=1, maximum=32)
        or not _identifier(sizer.get("cut_strategy"))
        or not _identifier(sizer.get("capability_profile"))
    ):
        _issue(issues, "training_example:sizer_invalid")
    stopping = row.get("stopping_target")
    if stopping is not None:
        stopping = _closed(stopping, _STOPPING_FIELDS, "training_example.stopping", issues)
        if not _bounded_int(stopping.get("minimum_net_margin_bps"), maximum=10_000):
            _issue(issues, "training_example:stopping_invalid")
    _fraction(row.get("score"), "training_example.score", issues)
    if not _seal_valid(row, "example_sha256"):
        _issue(issues, "training_example:seal_mismatch")
    return row


def validate_training_manifest(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    try:
        _canonical(value)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        value = {}
        _issue(issues, "training_manifest:hostile_or_noncanonical")
    manifest = _closed(value, _MANIFEST_FIELDS, "training_manifest", issues)
    if manifest.get("schema") != TRAINING_MANIFEST_SCHEMA:
        _issue(issues, "training_manifest:schema_invalid")
    if not _identifier(manifest.get("manifest_id")):
        _issue(issues, "training_manifest:manifest_id_invalid")
    if manifest.get("extractor_version") != EXTRACTOR_VERSION:
        _issue(issues, "training_manifest:extractor_version_invalid")
    if manifest.get("scoring_policy") != _SCORING_POLICY:
        _issue(issues, "training_manifest:scoring_policy_invalid")
    checkpoint = _closed(
        manifest.get("experiment_ledger_checkpoint"),
        _CHECKPOINT_FIELDS,
        "training_manifest.checkpoint",
        issues,
    )
    if not _bounded_int(checkpoint.get("length"), minimum=1) or not _digest(
        checkpoint.get("last_sha256")
    ):
        _issue(issues, "training_manifest:checkpoint_invalid")
    campaign_hashes = manifest.get("sweep_campaign_sha256s")
    if (
        not isinstance(campaign_hashes, list)
        or not campaign_hashes
        or any(not _digest(item) for item in campaign_hashes)
        or len(campaign_hashes) != len(set(campaign_hashes))
    ):
        _issue(issues, "training_manifest:sweep_campaigns_invalid")
    corpora = manifest.get("dogfood_corpora")
    if not isinstance(corpora, list) or not corpora:
        _issue(issues, "training_manifest:dogfood_corpora_invalid")
        corpora = []
    for item in corpora:
        row = _closed(item, _DOGFOOD_SOURCE_FIELDS, "training_manifest.dogfood_source", issues)
        if not _identifier(row.get("host_id")) or not _digest(row.get("head_sha256")):
            _issue(issues, "training_manifest:dogfood_source_invalid")
    examples_raw = manifest.get("examples")
    examples: list[dict[str, Any]] = []
    if not isinstance(examples_raw, list) or not examples_raw:
        _issue(issues, "training_manifest:examples_invalid")
    else:
        for item in examples_raw:
            examples.append(_validate_example(item, issues))
    hashes = [row.get("example_sha256") for row in examples]
    if len(hashes) != len(set(hashes)):
        _issue(issues, "training_manifest:example_duplicate")
    counts = _closed(
        manifest.get("source_counts"), _SOURCE_COUNT_FIELDS, "training_manifest.source_counts", issues
    )
    expected_counts = {
        "sweep": sum(row.get("source_kind") == "sweep" for row in examples),
        "blind_dogfood": sum(row.get("source_kind") == "dogfood" for row in examples),
        "total": len(examples),
    }
    if counts != expected_counts or counts.get("blind_dogfood", 0) < dogfood.DEFAULT_MIN_RECORDS:
        _issue(issues, "training_manifest:source_counts_invalid")
    families = manifest.get("task_families")
    observed_families = sorted(
        {
            str(row.get("task_family"))
            for row in examples
            if _identifier(row.get("task_family"))
        }
    )
    if families != observed_families:
        _issue(issues, "training_manifest:task_families_invalid")
    proof = _closed(
        manifest.get("partition_proof"), _PARTITION_PROOF_FIELDS, "training_manifest.partition_proof", issues
    )
    if proof != {
        "allowed_partition": "training",
        "evaluation_tasks_selected": 0,
        "hidden_tests_selected": 0,
        "control_outputs_selected": 0,
    }:
        _issue(issues, "training_manifest:partition_proof_invalid")
    if not _seal_valid(manifest, "manifest_sha256"):
        _issue(issues, "training_manifest:seal_mismatch")
    return {
        "schema": TRAINING_MANIFEST_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "manifest_sha256": manifest.get("manifest_sha256") if not issues else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _mean(rows: Sequence[Mapping[str, Any]]) -> Fraction:
    return sum(
        (Fraction(row["score"]["numerator"], row["score"]["denominator"]) for row in rows),
        Fraction(0, 1),
    ) / len(rows)


def _fit_rules(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in manifest["examples"]:
        grouped[(row["task_family"], row["difficulty_bucket"])].append(row)
    rules: list[dict[str, Any]] = []
    for (family, difficulty), rows in sorted(grouped.items()):
        sweep_rows = [row for row in rows if row["source_kind"] == "sweep"]
        if not sweep_rows:
            continue
        sweep_lane_counts = {
            int(row["sizer_target"]["lane_count"]) for row in sweep_rows
        }
        lane_groups: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
        for row in rows:
            lane_count = int(row["sizer_target"]["lane_count"])
            if lane_count in sweep_lane_counts:
                lane_groups[lane_count].append(row)
        ranked_lanes = sorted(
            (
                (-_mean(lane_rows), lane_count)
                for lane_count, lane_rows in lane_groups.items()
            )
        )
        chosen_lane = ranked_lanes[0][1]
        candidates = [
            row for row in sweep_rows if row["sizer_target"]["lane_count"] == chosen_lane
        ]
        action_groups: dict[tuple[int, str, str, int], list[Mapping[str, Any]]] = defaultdict(list)
        for row in candidates:
            action = (
                int(row["sizer_target"]["lane_count"]),
                str(row["sizer_target"]["cut_strategy"]),
                str(row["sizer_target"]["capability_profile"]),
                int(row["stopping_target"]["minimum_net_margin_bps"]),
            )
            action_groups[action].append(row)
        ranked_actions = sorted(
            ((-_mean(action_rows), action) for action, action_rows in action_groups.items())
        )
        chosen_score = -ranked_actions[0][0]
        lane_count, cut, profile, margin = ranked_actions[0][1]
        source_hashes = sorted(row["example_sha256"] for row in rows)
        rule_id = "rule-" + _sha256(
            {"family": family, "difficulty": difficulty, "sources": source_hashes}
        )[:24]
        rules.append(
            {
                "rule_id": rule_id,
                "task_family": family,
                "difficulty_bucket": difficulty,
                "training_example_sha256s": source_hashes,
                "sizer": {
                    "lane_count": lane_count,
                    "cut_strategy": cut,
                    "capability_profile": profile,
                },
                "stopping": {"minimum_net_margin_bps": margin},
                "mean_score": _rational(chosen_score),
            }
        )
    return rules


def fit_learned_policy(
    program: Any,
    experiment_ledger_path: str | Path,
    dogfood_corpus_paths: Mapping[str, str | Path],
) -> dict[str, Any]:
    issues: list[str] = []
    try:
        _canonical(program)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return {
            "schema": FIT_REPORT_SCHEMA,
            "status": "FAIL",
            "issues": ["fit_program:hostile_or_noncanonical"],
            "training_manifest": None,
            "candidate_policy": None,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
            "default_changed": False,
        }
    value = _closed(program, _FIT_FIELDS, "fit_program", issues)
    if value.get("schema") != FIT_PROGRAM_SCHEMA:
        _issue(issues, "fit_program:schema_invalid")
    if not _identifier(value.get("candidate_id")):
        _issue(issues, "fit_program:candidate_id_invalid")
    manifest_report = derive_training_manifest(
        value.get("training_request"), experiment_ledger_path, dogfood_corpus_paths
    )
    if manifest_report.get("status") != "PASS":
        _issue(issues, "fit_program:training_manifest_invalid")
    manifest = manifest_report.get("training_manifest")
    rules = _fit_rules(manifest) if isinstance(manifest, Mapping) else []
    if not rules:
        _issue(issues, "fit_program:no_learnable_rules")
    if issues:
        return {
            "schema": FIT_REPORT_SCHEMA,
            "status": "FAIL",
            "issues": sorted(set(issues)),
            "training_manifest": None,
            "candidate_policy": None,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
            "default_changed": False,
        }
    assert isinstance(manifest, Mapping)
    families = sorted({row["task_family"] for row in rules})
    ids_by_family = {
        family: sorted(row["rule_id"] for row in rules if row["task_family"] == family)
        for family in families
    }
    core = {
        "schema": LEARNED_POLICY_SCHEMA,
        "candidate_id": value["candidate_id"],
        "fitter_version": FITTER_VERSION,
        "training_manifest_sha256": manifest["manifest_sha256"],
        "training_ledger_checkpoint": manifest["experiment_ledger_checkpoint"],
        "rules": rules,
        "family_classifier": {
            "feature": "task_family",
            "known_families": families,
            "rule_ids_by_family": ids_by_family,
            "unknown_family_fallback": STANDING_DEFAULTS_ID,
        },
        "advisory_only": True,
        "split_gate_required": True,
        "deepening_gate_required": True,
        "workers_permitted": False,
        "authority_granted": False,
    }
    policy = _sealed(core, "policy_sha256")
    return {
        "schema": FIT_REPORT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "training_manifest": dict(manifest),
        "candidate_policy": policy,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "default_changed": False,
    }


def validate_learned_policy(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    try:
        _canonical(value)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        value = {}
        _issue(issues, "learned_policy:hostile_or_noncanonical")
    policy = _closed(value, _POLICY_FIELDS, "learned_policy", issues)
    if policy.get("schema") != LEARNED_POLICY_SCHEMA:
        _issue(issues, "learned_policy:schema_invalid")
    if not _identifier(policy.get("candidate_id")) or policy.get("fitter_version") != FITTER_VERSION:
        _issue(issues, "learned_policy:identity_invalid")
    if not _digest(policy.get("training_manifest_sha256")):
        _issue(issues, "learned_policy:manifest_sha256_invalid")
    checkpoint = _closed(
        policy.get("training_ledger_checkpoint"), _CHECKPOINT_FIELDS, "learned_policy.checkpoint", issues
    )
    if not _bounded_int(checkpoint.get("length"), minimum=1) or not _digest(checkpoint.get("last_sha256")):
        _issue(issues, "learned_policy:checkpoint_invalid")
    rules = policy.get("rules")
    normalized_rules: list[dict[str, Any]] = []
    if not isinstance(rules, list) or not rules:
        _issue(issues, "learned_policy:rules_invalid")
        rules = []
    for raw in rules:
        rule = _closed(raw, _RULE_FIELDS, "learned_policy.rule", issues)
        if (
            not _identifier(rule.get("rule_id"))
            or not _identifier(rule.get("task_family"))
            or rule.get("difficulty_bucket") not in DIFFICULTY_BUCKETS
        ):
            _issue(issues, "learned_policy:rule_identity_invalid")
        hashes = rule.get("training_example_sha256s")
        if not isinstance(hashes, list) or not hashes or any(not _digest(item) for item in hashes):
            _issue(issues, "learned_policy:rule_sources_invalid")
        sizer = _closed(rule.get("sizer"), _SIZER_FIELDS, "learned_policy.rule.sizer", issues)
        if (
            not _bounded_int(sizer.get("lane_count"), minimum=1, maximum=32)
            or not _identifier(sizer.get("cut_strategy"))
            or not _identifier(sizer.get("capability_profile"))
        ):
            _issue(issues, "learned_policy:rule_sizer_invalid")
        stopping = _closed(
            rule.get("stopping"), _STOPPING_FIELDS, "learned_policy.rule.stopping", issues
        )
        if not _bounded_int(stopping.get("minimum_net_margin_bps"), maximum=10_000):
            _issue(issues, "learned_policy:rule_stopping_invalid")
        _fraction(rule.get("mean_score"), "learned_policy.rule.mean_score", issues)
        if _identifier(rule.get("task_family")) and _identifier(rule.get("rule_id")):
            normalized_rules.append(rule)
    identities = [(row.get("task_family"), row.get("difficulty_bucket")) for row in normalized_rules]
    if len(identities) != len(set(identities)):
        _issue(issues, "learned_policy:rule_identity_duplicate")
    classifier = _closed(
        policy.get("family_classifier"),
        _POLICY_CLASSIFIER_FIELDS,
        "learned_policy.family_classifier",
        issues,
    )
    families = sorted({str(row.get("task_family")) for row in normalized_rules})
    expected_map = {
        family: sorted(row.get("rule_id") for row in normalized_rules if row.get("task_family") == family)
        for family in families
    }
    if classifier != {
        "feature": "task_family",
        "known_families": families,
        "rule_ids_by_family": expected_map,
        "unknown_family_fallback": STANDING_DEFAULTS_ID,
    }:
        _issue(issues, "learned_policy:family_classifier_invalid")
    for field, expected in (
        ("advisory_only", True),
        ("split_gate_required", True),
        ("deepening_gate_required", True),
        ("workers_permitted", False),
        ("authority_granted", False),
    ):
        if policy.get(field) is not expected:
            _issue(issues, "learned_policy:" + field + "_invalid")
    if not _seal_valid(policy, "policy_sha256"):
        _issue(issues, "learned_policy:seal_mismatch")
    return {
        "schema": LEARNED_POLICY_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "policy_sha256": policy.get("policy_sha256") if not issues else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def evaluate_learned_policy(program: Any) -> dict[str, Any]:
    issues: list[str] = []
    try:
        _canonical(program)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        program = {}
        _issue(issues, "inference_program:hostile_or_noncanonical")
    value = _closed(program, _INFERENCE_FIELDS, "inference_program", issues)
    if value.get("schema") != INFERENCE_PROGRAM_SCHEMA:
        _issue(issues, "inference_program:schema_invalid")
    policy_report = validate_learned_policy(value.get("policy"))
    if policy_report.get("status") != "PASS":
        _issue(issues, "inference_program:policy_invalid")
    task = _closed(value.get("task"), _TASK_FIELDS, "inference_program.task", issues)
    if not _identifier(task.get("task_id")) or not _identifier(task.get("task_family")):
        _issue(issues, "inference_program:task_identity_invalid")
    if task.get("difficulty_bucket") not in DIFFICULTY_BUCKETS:
        _issue(issues, "inference_program:difficulty_invalid")
    if issues:
        return {
            "schema": INFERENCE_REPORT_SCHEMA,
            "status": "FAIL",
            "issues": sorted(set(issues)),
            "task_id": None,
            "policy_sha256": None,
            "learned_policy_applied": False,
            "fallback_policy": STANDING_DEFAULTS_ID,
            "sizer_recommendation": None,
            "stopping_signal": None,
            "advisory_only": True,
            "split_gate_required": True,
            "deepening_gate_required": True,
            "workers_permitted": False,
            "authority_granted": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    policy = value["policy"]
    rule = next(
        (
            row
            for row in policy["rules"]
            if row["task_family"] == task["task_family"]
            and row["difficulty_bucket"] == task["difficulty_bucket"]
        ),
        None,
    )
    return {
        "schema": INFERENCE_REPORT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "task_id": task["task_id"],
        "policy_sha256": policy["policy_sha256"],
        "learned_policy_applied": rule is not None,
        "fallback_policy": None if rule is not None else STANDING_DEFAULTS_ID,
        "sizer_recommendation": dict(rule["sizer"]) if rule is not None else None,
        "stopping_signal": dict(rule["stopping"]) if rule is not None else None,
        "advisory_only": True,
        "split_gate_required": True,
        "deepening_gate_required": True,
        "workers_permitted": False,
        "authority_granted": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _promotion_report(
    issues: Sequence[str], record: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    valid = not issues and isinstance(record, Mapping)
    return {
        "schema": PROMOTION_REPORT_SCHEMA,
        "status": "PASS" if valid else "FAIL",
        "issues": sorted(set(str(item) for item in issues)),
        "disposition": record.get("disposition") if valid else "REFUSE",
        "candidate_retained": record.get("candidate_retained") if valid else False,
        "global_policy_retained": record.get("global_policy_retained") if valid else False,
        "per_family_policies": list(record.get("per_family_policies", [])) if valid else [],
        "family_classifier": dict(record.get("family_classifier", {})) if valid else None,
        "family_results": list(record.get("family_results", [])) if valid else [],
        "default_change_eligible": record.get("default_change_eligible") if valid else False,
        "default_changed": False,
        "promotion_record": dict(record) if valid else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _evaluation_material(
    campaign: Mapping[str, Any],
    report: Mapping[str, Any],
    candidate_policy_sha256: str,
    standing_defaults_id: str,
    issues: list[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    summaries = {
        row.get("configuration_id"): row
        for row in report.get("configurations", [])
        if isinstance(row, Mapping)
    }
    grouped: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    lineages: list[str] = []
    for configuration in campaign.get("configuration_grid", []):
        params = _parameter_map(configuration)
        if set(params) != _EVALUATION_PARAMETER_FIELDS:
            _issue(issues, "evaluation:configuration_shape_invalid")
            continue
        family = params.get("task_family")
        role = params.get("policy_role")
        policy_ref = params.get("policy_ref")
        lineage = params.get("lineage_sha256")
        if (
            params.get("data_partition") != "evaluation"
            or not _identifier(family)
            or role not in {"candidate", "standing_default"}
            or not _digest(lineage)
        ):
            _issue(issues, "evaluation:configuration_value_invalid")
            continue
        expected_ref = candidate_policy_sha256 if role == "candidate" else standing_defaults_id
        if policy_ref != expected_ref:
            _issue(issues, "evaluation:policy_binding_mismatch")
            continue
        if role in grouped[str(family)]:
            _issue(issues, "evaluation:family_role_duplicate")
        summary = summaries.get(configuration.get("configuration_id"))
        if (
            not isinstance(summary, Mapping)
            or summary.get("status") != "complete"
            or summary.get("decision_rule_outcome") != "pass"
        ):
            _issue(issues, "evaluation:configuration_incomplete")
            continue
        score_issues: list[str] = []
        score = _fraction(summary.get("primary_metric_mean"), "evaluation.score", score_issues)
        if score_issues:
            _issue(issues, "evaluation:score_invalid")
            continue
        grouped[str(family)][str(role)] = {
            "score": score,
            "lineage_sha256": lineage,
        }
        lineages.append(str(lineage))
    normalized: list[dict[str, Any]] = []
    for family, roles in sorted(grouped.items()):
        if set(roles) != {"candidate", "standing_default"}:
            _issue(issues, "evaluation:family_pair_incomplete")
            continue
        normalized.append(
            {
                "task_family": family,
                "candidate_score": roles["candidate"]["score"],
                "standing_default_score": roles["standing_default"]["score"],
            }
        )
    if not normalized:
        _issue(issues, "evaluation:no_family_pairs")
    return normalized, sorted(set(lineages))


def evaluate_policy_promotion(
    program: Any,
    experiment_ledger_path: str | Path,
    dogfood_corpus_paths: Mapping[str, str | Path],
) -> dict[str, Any]:
    issues: list[str] = []
    try:
        _canonical(program)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return _promotion_report(["promotion_program:hostile_or_noncanonical"])
    value = _closed(program, _PROMOTION_FIELDS, "promotion_program", issues)
    if value.get("schema") != PROMOTION_PROGRAM_SCHEMA:
        _issue(issues, "promotion_program:schema_invalid")
    if not _identifier(value.get("promotion_id")):
        _issue(issues, "promotion_program:promotion_id_invalid")

    manifest_report = derive_training_manifest(
        value.get("training_request"), experiment_ledger_path, dogfood_corpus_paths
    )
    manifest = manifest_report.get("training_manifest")
    if manifest_report.get("status") != "PASS" or not isinstance(manifest, Mapping):
        _issue(issues, "training_manifest:rederivation_failed")
    elif value.get("training_manifest") != manifest:
        _issue(issues, "training_manifest:rederivation_mismatch")
    if validate_training_manifest(value.get("training_manifest")).get("status") != "PASS":
        _issue(issues, "training_manifest:invalid")

    policy = value.get("candidate_policy")
    if validate_learned_policy(policy).get("status") != "PASS" or not isinstance(policy, Mapping):
        _issue(issues, "candidate_policy:invalid")
        policy = {}
    elif isinstance(manifest, Mapping) and policy.get("training_manifest_sha256") != manifest.get("manifest_sha256"):
        _issue(issues, "candidate_policy:manifest_mismatch")

    evaluation_campaign = value.get("evaluation_campaign")
    campaign_report = campaigns.verify_campaign(evaluation_campaign)
    if campaign_report.get("status") != "PASS" or not isinstance(evaluation_campaign, Mapping):
        _issue(issues, "evaluation_campaign:invalid")
        evaluation_campaign = {}
    campaign_result = value.get("campaign_result")
    result_report = campaigns.verify_campaign_result(evaluation_campaign, campaign_result)
    if result_report.get("status") != "PASS":
        _issue(issues, "campaign_result:invalid")
    elif (
        not isinstance(campaign_result, Mapping)
        or campaign_result.get("default_change_eligible") is not True
        or campaign_result.get("finding", {}).get("kind") != "preregistered"
        or campaign_result.get("finding", {}).get("decision_rule_outcome") != "pass"
    ):
        _issue(issues, "campaign_result:not_promotion_eligible")

    promotion_rule = _closed(
        value.get("promotion_rule"), _PROMOTION_RULE_FIELDS, "promotion_rule", issues
    )
    if promotion_rule.get("direction") != "higher_is_better":
        _issue(issues, "promotion_rule:direction_invalid")
    minimum_improvement = _fraction(
        promotion_rule.get("minimum_improvement"), "promotion_rule.minimum_improvement", issues
    )
    if minimum_improvement < 0:
        _issue(issues, "promotion_rule:minimum_improvement_negative")
    standing = _closed(
        value.get("standing_defaults"), _STANDING_DEFAULT_FIELDS, "standing_defaults", issues
    )
    if standing != {
        "id": STANDING_DEFAULTS_ID,
        "sizer": "first-wave-estimator/v0",
        "stopping": "deepening-policy/v1",
    }:
        _issue(issues, "standing_defaults:invalid")

    entries, chain_issues = sweep.read_experiment_ledger(experiment_ledger_path)
    for item in chain_issues:
        _issue(issues, item)
    checkpoint = manifest.get("experiment_ledger_checkpoint", {}) if isinstance(manifest, Mapping) else {}
    checkpoint_length = checkpoint.get("length")
    if (
        type(checkpoint_length) is not int
        or checkpoint_length < 1
        or checkpoint_length > len(entries)
        or entries[checkpoint_length - 1].get("record_sha256") != checkpoint.get("last_sha256")
    ):
        _issue(issues, "evaluation:training_checkpoint_stale")
    campaign_rows = [
        row
        for row in entries
        if row.get("record", {}).get("schema") == sweep.CAMPAIGN_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == evaluation_campaign.get("campaign_sha256")
    ]
    if len(campaign_rows) != 1:
        _issue(issues, "evaluation:campaign_registration_missing_or_duplicate")
        evaluation_seq = None
    else:
        evaluation_seq = campaign_rows[0]["seq"]
        if type(checkpoint_length) is int and evaluation_seq <= checkpoint_length:
            _issue(issues, "evaluation:not_fresh")
    if isinstance(manifest, Mapping) and evaluation_campaign.get("campaign_sha256") in manifest.get("sweep_campaign_sha256s", []):
        _issue(issues, "evaluation:training_campaign_reused")
    sweep_report = sweep.summarize_sweep_campaign(
        experiment_ledger_path, str(evaluation_campaign.get("campaign_sha256"))
    )
    if sweep_report.get("status") != "PASS":
        _issue(issues, "evaluation:sweep_incomplete")
        family_material: list[dict[str, Any]] = []
        evaluation_lineages: list[str] = []
    else:
        family_material, evaluation_lineages = _evaluation_material(
            evaluation_campaign,
            sweep_report,
            str(policy.get("policy_sha256")),
            str(standing.get("id")),
            issues,
        )
    training_lineages = sorted(
        {row["lineage_sha256"] for row in manifest.get("examples", [])}
    ) if isinstance(manifest, Mapping) else []
    lineage_disjoint = not (set(training_lineages) & set(evaluation_lineages))
    if not lineage_disjoint:
        _issue(issues, "evaluation:lineage_not_disjoint")
    policy_families = set(policy.get("family_classifier", {}).get("known_families", []))
    if any(row["task_family"] not in policy_families for row in family_material):
        _issue(issues, "evaluation:family_not_learned")
    if issues:
        return _promotion_report(issues)

    family_results: list[dict[str, Any]] = []
    for row in family_material:
        improvement = row["candidate_score"] - row["standing_default_score"]
        beats = improvement > 0 and improvement >= minimum_improvement
        family_results.append(
            {
                "task_family": row["task_family"],
                "candidate_score": _rational(row["candidate_score"]),
                "standing_default_score": _rational(row["standing_default_score"]),
                "improvement": _rational(improvement),
                "minimum_improvement": _rational(minimum_improvement),
                "candidate_beats_default": beats,
            }
        )
    passing = sorted(row["task_family"] for row in family_results if row["candidate_beats_default"])
    all_families = sorted(row["task_family"] for row in family_results)
    if not passing:
        disposition = "BEATEN"
        candidate_retained = False
        global_retained = False
    elif passing == all_families:
        disposition = "PROMOTE_GLOBAL"
        candidate_retained = True
        global_retained = True
    else:
        disposition = "PROMOTE_PER_FAMILY"
        candidate_retained = True
        global_retained = False
    per_family = [
        {
            "task_family": family,
            "candidate_policy_sha256": policy["policy_sha256"],
            "rule_ids": sorted(
                row["rule_id"] for row in policy["rules"] if row["task_family"] == family
            ),
        }
        for family in passing
    ]
    assignments = {
        family: "candidate" if family in passing else "standing_default"
        for family in all_families
    }
    core = {
        "schema": PROMOTION_RECORD_SCHEMA,
        "promotion_id": value["promotion_id"],
        "candidate_policy_sha256": policy["policy_sha256"],
        "training_manifest_sha256": manifest["manifest_sha256"],
        "evaluation_campaign_sha256": evaluation_campaign["campaign_sha256"],
        "campaign_result_sha256": campaign_result["result_sha256"],
        "standing_defaults": standing,
        "promotion_rule": {
            "direction": "higher_is_better",
            "minimum_improvement": _rational(minimum_improvement),
        },
        "freshness": {
            "training_checkpoint_length": checkpoint_length,
            "training_checkpoint_sha256": checkpoint["last_sha256"],
            "evaluation_campaign_seq": evaluation_seq,
            "fresh": True,
        },
        "lineage": {
            "training_lineage_sha256s": training_lineages,
            "evaluation_lineage_sha256s": evaluation_lineages,
            "disjoint": True,
        },
        "family_results": family_results,
        "disposition": disposition,
        "candidate_retained": candidate_retained,
        "global_policy_retained": global_retained,
        "per_family_policies": per_family,
        "family_classifier": {
            "feature": "task_family",
            "assignments": assignments,
            "unknown_family_fallback": STANDING_DEFAULTS_ID,
        },
        "default_change_eligible": disposition != "BEATEN",
        "default_changed": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return _promotion_report([], _sealed(core, "record_sha256"))


def validate_promotion_record(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    try:
        _canonical(value)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        value = {}
        _issue(issues, "promotion_record:hostile_or_noncanonical")
    record = _closed(value, _PROMOTION_RECORD_FIELDS, "promotion_record", issues)
    if record.get("schema") != PROMOTION_RECORD_SCHEMA:
        _issue(issues, "promotion_record:schema_invalid")
    if not _identifier(record.get("promotion_id")):
        _issue(issues, "promotion_record:promotion_id_invalid")
    for field in (
        "candidate_policy_sha256",
        "training_manifest_sha256",
        "evaluation_campaign_sha256",
        "campaign_result_sha256",
    ):
        if not _digest(record.get(field)):
            _issue(issues, "promotion_record:" + field + "_invalid")
    standing = _closed(
        record.get("standing_defaults"),
        _STANDING_DEFAULT_FIELDS,
        "promotion_record.standing_defaults",
        issues,
    )
    if standing != {
        "id": STANDING_DEFAULTS_ID,
        "sizer": "first-wave-estimator/v0",
        "stopping": "deepening-policy/v1",
    }:
        _issue(issues, "promotion_record:standing_defaults_invalid")
    rule = _closed(record.get("promotion_rule"), _PROMOTION_RULE_FIELDS, "promotion_record.rule", issues)
    if rule.get("direction") != "higher_is_better":
        _issue(issues, "promotion_record:direction_invalid")
    _fraction(rule.get("minimum_improvement"), "promotion_record.minimum_improvement", issues)
    freshness = _closed(record.get("freshness"), _FRESHNESS_FIELDS, "promotion_record.freshness", issues)
    if (
        freshness.get("fresh") is not True
        or not _bounded_int(freshness.get("training_checkpoint_length"), minimum=1)
        or not _digest(freshness.get("training_checkpoint_sha256"))
        or not _bounded_int(freshness.get("evaluation_campaign_seq"), minimum=1)
        or (
            type(freshness.get("training_checkpoint_length")) is int
            and type(freshness.get("evaluation_campaign_seq")) is int
            and freshness["evaluation_campaign_seq"]
            <= freshness["training_checkpoint_length"]
        )
    ):
        _issue(issues, "promotion_record:freshness_invalid")
    lineage = _closed(record.get("lineage"), _LINEAGE_FIELDS, "promotion_record.lineage", issues)
    lineage_lists: dict[str, list[str]] = {}
    for field in ("training_lineage_sha256s", "evaluation_lineage_sha256s"):
        values = lineage.get(field)
        if not isinstance(values, list) or any(not _digest(item) for item in values):
            _issue(issues, "promotion_record:lineage_hashes_invalid")
            lineage_lists[field] = []
        else:
            lineage_lists[field] = list(values)
    if lineage.get("disjoint") is not True or set(
        lineage_lists.get("training_lineage_sha256s", [])
    ) & set(lineage_lists.get("evaluation_lineage_sha256s", [])):
        _issue(issues, "promotion_record:lineage_not_disjoint")
    family_results = record.get("family_results")
    if not isinstance(family_results, list) or not family_results:
        _issue(issues, "promotion_record:family_results_invalid")
        family_results = []
    normalized_results: list[dict[str, Any]] = []
    for raw in family_results:
        row = _closed(raw, _FAMILY_RESULT_FIELDS, "promotion_record.family_result", issues)
        if not _identifier(row.get("task_family")) or type(row.get("candidate_beats_default")) is not bool:
            _issue(issues, "promotion_record:family_result_invalid")
        values = {
            field: _fraction(
                row.get(field), "promotion_record.family_result." + field, issues
            )
            for field in (
                "candidate_score",
                "standing_default_score",
                "improvement",
                "minimum_improvement",
            )
        }
        expected_improvement = values["candidate_score"] - values["standing_default_score"]
        expected_beats = (
            expected_improvement > 0
            and expected_improvement >= values["minimum_improvement"]
        )
        if values["improvement"] != expected_improvement or row.get(
            "candidate_beats_default"
        ) is not expected_beats:
            _issue(issues, "promotion_record:family_result_derivation_invalid")
        if _identifier(row.get("task_family")):
            normalized_results.append(row)
    families = [str(row["task_family"]) for row in normalized_results]
    if families != sorted(set(families)):
        _issue(issues, "promotion_record:family_results_order_or_duplicate")
    passing_families = sorted(
        str(row["task_family"])
        for row in normalized_results
        if row.get("candidate_beats_default") is True
    )
    disposition = record.get("disposition")
    if disposition not in PROMOTION_DISPOSITIONS:
        _issue(issues, "promotion_record:disposition_invalid")
    expected_disposition = (
        "BEATEN"
        if not passing_families
        else "PROMOTE_GLOBAL"
        if passing_families == families
        else "PROMOTE_PER_FAMILY"
    )
    if disposition != expected_disposition:
        _issue(issues, "promotion_record:disposition_derivation_invalid")
    expected_retained = disposition != "BEATEN"
    if record.get("candidate_retained") is not expected_retained:
        _issue(issues, "promotion_record:candidate_retention_invalid")
    if record.get("global_policy_retained") is not (disposition == "PROMOTE_GLOBAL"):
        _issue(issues, "promotion_record:global_retention_invalid")
    per_family = record.get("per_family_policies")
    if not isinstance(per_family, list):
        _issue(issues, "promotion_record:per_family_policies_invalid")
        per_family = []
    per_family_names: list[str] = []
    for raw in per_family:
        row = _closed(raw, _PER_FAMILY_FIELDS, "promotion_record.per_family", issues)
        if not _identifier(row.get("task_family")) or not _digest(row.get("candidate_policy_sha256")):
            _issue(issues, "promotion_record:per_family_invalid")
        rule_ids = row.get("rule_ids")
        if not isinstance(rule_ids, list) or not rule_ids or any(
            not _identifier(item) for item in rule_ids
        ):
            _issue(issues, "promotion_record:per_family_rule_ids_invalid")
        if _identifier(row.get("task_family")):
            per_family_names.append(str(row["task_family"]))
    if per_family_names != passing_families:
        _issue(issues, "promotion_record:per_family_retention_mismatch")
    classifier = _closed(
        record.get("family_classifier"),
        _PROMOTION_CLASSIFIER_FIELDS,
        "promotion_record.family_classifier",
        issues,
    )
    if classifier.get("feature") != "task_family" or classifier.get("unknown_family_fallback") != STANDING_DEFAULTS_ID:
        _issue(issues, "promotion_record:classifier_invalid")
    assignments = classifier.get("assignments")
    if not isinstance(assignments, Mapping) or any(
        not _identifier(key) or item not in {"candidate", "standing_default"}
        for key, item in assignments.items()
    ):
        _issue(issues, "promotion_record:classifier_assignments_invalid")
    elif dict(assignments) != {
        family: "candidate" if family in passing_families else "standing_default"
        for family in families
    }:
        _issue(issues, "promotion_record:classifier_assignment_mismatch")
    if record.get("default_change_eligible") is not expected_retained:
        _issue(issues, "promotion_record:eligibility_invalid")
    for field, expected in (
        ("default_changed", False),
        ("provider_free", True),
        ("model_calls", 0),
        ("hosted_calls", 0),
    ):
        if record.get(field) != expected or type(record.get(field)) is not type(expected):
            _issue(issues, "promotion_record:" + field + "_invalid")
    if not _seal_valid(record, "record_sha256"):
        _issue(issues, "promotion_record:seal_mismatch")
    return {
        "schema": PROMOTION_VALIDATION_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "record_sha256": record.get("record_sha256") if not issues else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def record_policy_promotion(
    program: Any,
    experiment_ledger_path: str | Path,
    dogfood_corpus_paths: Mapping[str, str | Path],
) -> dict[str, Any]:
    report = evaluate_policy_promotion(
        program, experiment_ledger_path, dogfood_corpus_paths
    )
    record = report.get("promotion_record")
    if report.get("status") != "PASS" or not isinstance(record, Mapping):
        return report
    entries, issues = sweep.read_experiment_ledger(experiment_ledger_path)
    if issues:
        return _promotion_report(issues)
    if any(
        row.get("record", {}).get("schema") == PROMOTION_RECORD_SCHEMA
        and row.get("record", {}).get("promotion_id") == record.get("promotion_id")
        for row in entries
    ):
        return _promotion_report(["promotion_record:duplicate"])
    try:
        receipt = trace.append_trace_record(experiment_ledger_path, record)
    except (OSError, TypeError, ValueError):
        return _promotion_report(["ledger:append_failed"])
    return {**report, "chain_receipt": receipt}


__all__ = [
    "FIT_PROGRAM_SCHEMA",
    "INFERENCE_PROGRAM_SCHEMA",
    "LEARNED_POLICY_SCHEMA",
    "PROMOTION_PROGRAM_SCHEMA",
    "PROMOTION_RECORD_SCHEMA",
    "STANDING_DEFAULTS_ID",
    "TRAINING_MANIFEST_SCHEMA",
    "TRAINING_REQUEST_SCHEMA",
    "derive_training_manifest",
    "evaluate_learned_policy",
    "evaluate_policy_promotion",
    "fit_learned_policy",
    "record_policy_promotion",
    "validate_learned_policy",
    "validate_promotion_record",
    "validate_training_manifest",
]
