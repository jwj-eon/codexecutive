#!/usr/bin/env python3
"""Closed provider-free preregistration contracts for experiment campaigns.

This module seals campaign material before execution and verifies exact
post-seal identity.  It does not enumerate or execute runs, call a provider,
record replay data, or authorize a default change.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any

try:
    from orch_dork_hostile_input import (
        PROFILE,
        HostileInputError,
        canonicalize_bounded_json,
    )
except ImportError:  # pragma: no cover - isolated direct-file loading.
    _hostile_path = Path(__file__).resolve().with_name("orch_dork_hostile_input.py")
    _hostile_spec = importlib.util.spec_from_file_location(
        "orch_dork_hostile_input", _hostile_path
    )
    if _hostile_spec is None or _hostile_spec.loader is None:
        raise
    _hostile = importlib.util.module_from_spec(_hostile_spec)
    sys.modules.setdefault("orch_dork_hostile_input", _hostile)
    _hostile_spec.loader.exec_module(_hostile)
    PROFILE = _hostile.PROFILE
    HostileInputError = _hostile.HostileInputError
    canonicalize_bounded_json = _hostile.canonicalize_bounded_json


PROGRAM_SCHEMA = "orch-dork/experiment-campaign-program/v1"
REPORT_SCHEMA = "orch-dork/experiment-campaign-report/v1"
CAMPAIGN_DRAFT_SCHEMA = "orch-dork/campaign-draft/v1"
CAMPAIGN_SCHEMA = "orch-dork/campaign/v1"
CAMPAIGN_RESULT_DRAFT_SCHEMA = "orch-dork/campaign-result-draft/v1"
CAMPAIGN_RESULT_SCHEMA = "orch-dork/campaign-result/v1"

OPERATIONS = frozenset(
    {"seal_campaign", "verify_campaign", "seal_result", "verify_result"}
)
OPERATORS = frozenset(
    {
        "greater_than",
        "greater_than_or_equal",
        "less_than",
        "less_than_or_equal",
        "equal",
    }
)
PASS_DISPOSITIONS = frozenset({"candidate_default_change", "retain_default"})

_CAMPAIGN_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "question",
        "configuration_grid",
        "replicate_count",
        "seeds",
        "decision_rule",
    }
)
_PROGRAM_FIELDS = frozenset(
    {"schema", "operation", "campaign", "campaign_result"}
)
_SEALED_CAMPAIGN_FIELDS = _CAMPAIGN_FIELDS | frozenset({"campaign_sha256"})
_QUESTION_FIELDS = frozenset(
    {
        "question_id",
        "statement",
        "primary_metric",
        "population",
        "null_hypothesis",
    }
)
_CONFIGURATION_FIELDS = frozenset({"configuration_id", "parameters"})
_PARAMETER_FIELDS = frozenset({"name", "value"})
_DECISION_RULE_FIELDS = frozenset(
    {
        "metric",
        "operator",
        "threshold",
        "minimum_complete_replicates",
        "pass_disposition",
        "fail_disposition",
        "incomplete_disposition",
    }
)
_THRESHOLD_FIELDS = frozenset({"numerator", "denominator"})
_RESULT_DRAFT_FIELDS = frozenset(
    {"schema", "result_id", "campaign_sha256", "finding"}
)
_RESULT_FIELDS = _RESULT_DRAFT_FIELDS | frozenset(
    {"default_change_eligible", "result_sha256"}
)
_PREREGISTERED_FINDING_FIELDS = frozenset(
    {"kind", "question_id", "metric", "decision_rule_outcome", "summary"}
)
_EXPLORATORY_FINDING_FIELDS = frozenset(
    {"kind", "summary", "next_campaign_question"}
)
_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


def _canonical(value: Any) -> bytes:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return canonicalize_bounded_json(raw, profile=PROFILE, batch=False)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _closed(
    value: Any,
    fields: frozenset[str],
    label: str,
    issues: list[str],
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


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value.encode("utf-8")) <= PROFILE.max_string_bytes
    )


def _bounded_int(
    value: Any,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> bool:
    return (
        type(value) is int
        and value >= minimum
        and (maximum is None or value <= maximum)
    )


def _sha_valid(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _report(
    operation: str,
    issues: list[str],
    result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "operation": operation,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "result": dict(result) if isinstance(result, Mapping) else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "runs_executed": 0,
        "default_changed": False,
    }


def _parameter_value_valid(value: Any) -> bool:
    return type(value) in {str, int, bool} and (
        type(value) is not str or _text(value)
    )


def _campaign_material(
    value: Any,
    *,
    expected_schema: str,
    sealed: bool,
    issues: list[str],
) -> dict[str, Any]:
    fields = _SEALED_CAMPAIGN_FIELDS if sealed else _CAMPAIGN_FIELDS
    campaign = _closed(value, fields, "campaign", issues)
    if campaign.get("schema") != expected_schema:
        _issue(issues, "campaign:schema_invalid")
    if not _identifier(campaign.get("campaign_id")):
        _issue(issues, "campaign:campaign_id_invalid")

    question = _closed(
        campaign.get("question"), _QUESTION_FIELDS, "campaign.question", issues
    )
    for field in ("question_id", "primary_metric"):
        if not _identifier(question.get(field)):
            _issue(issues, f"campaign.question:{field}_invalid")
    for field in ("statement", "population", "null_hypothesis"):
        if not _text(question.get(field)):
            _issue(issues, f"campaign.question:{field}_invalid")

    raw_grid = campaign.get("configuration_grid")
    if (
        not isinstance(raw_grid, list)
        or not raw_grid
        or len(raw_grid) > PROFILE.max_array_items
    ):
        _issue(issues, "campaign.configuration_grid:array_invalid")
        raw_grid = []
    normalized_grid: list[dict[str, Any]] = []
    configuration_ids: set[str] = set()
    configuration_material: set[str] = set()
    for index, raw in enumerate(raw_grid):
        label = f"campaign.configuration_grid[{index}]"
        configuration = _closed(raw, _CONFIGURATION_FIELDS, label, issues)
        configuration_id = configuration.get("configuration_id")
        if not _identifier(configuration_id) or configuration_id in configuration_ids:
            _issue(issues, f"{label}:configuration_id_invalid_or_duplicate")
        else:
            configuration_ids.add(str(configuration_id))
        raw_parameters = configuration.get("parameters")
        if (
            not isinstance(raw_parameters, list)
            or not raw_parameters
            or len(raw_parameters) > PROFILE.max_array_items
        ):
            _issue(issues, f"{label}.parameters:array_invalid")
            raw_parameters = []
        parameters: list[dict[str, Any]] = []
        parameter_names: set[str] = set()
        for parameter_index, raw_parameter in enumerate(raw_parameters):
            parameter_label = f"{label}.parameters[{parameter_index}]"
            parameter = _closed(
                raw_parameter, _PARAMETER_FIELDS, parameter_label, issues
            )
            name = parameter.get("name")
            if not _identifier(name) or name in parameter_names:
                _issue(issues, f"{parameter_label}:name_invalid_or_duplicate")
            else:
                parameter_names.add(str(name))
            if not _parameter_value_valid(parameter.get("value")):
                _issue(issues, f"{parameter_label}:value_invalid")
            parameters.append({"name": name, "value": parameter.get("value")})
        try:
            material_key = _sha256(parameters)
        except (HostileInputError, TypeError, ValueError, OverflowError):
            _issue(issues, f"{label}:parameters_noncanonical")
        else:
            if material_key in configuration_material:
                _issue(issues, "campaign.configuration_grid:duplicate_configuration")
            configuration_material.add(material_key)
        normalized_grid.append(
            {"configuration_id": configuration_id, "parameters": parameters}
        )

    replicate_count = campaign.get("replicate_count")
    if not _bounded_int(
        replicate_count, minimum=1, maximum=PROFILE.max_array_items
    ):
        _issue(issues, "campaign:replicate_count_invalid")
    seeds = campaign.get("seeds")
    if not isinstance(seeds, list) or len(seeds) > PROFILE.max_array_items:
        _issue(issues, "campaign.seeds:array_invalid")
        seeds = []
    for index, seed in enumerate(seeds):
        if not _bounded_int(seed, maximum=(2**63) - 1):
            _issue(issues, f"campaign.seeds[{index}]:invalid")
    if len(seeds) != len(set(seeds)):
        _issue(issues, "campaign.seeds:duplicate")
    if type(replicate_count) is int and len(seeds) != replicate_count:
        _issue(issues, "campaign:replicate_seed_count_mismatch")

    rule = _closed(
        campaign.get("decision_rule"),
        _DECISION_RULE_FIELDS,
        "campaign.decision_rule",
        issues,
    )
    if not _identifier(rule.get("metric")):
        _issue(issues, "campaign.decision_rule:metric_invalid")
    elif rule.get("metric") != question.get("primary_metric"):
        _issue(issues, "campaign.decision_rule:metric_question_mismatch")
    if rule.get("operator") not in OPERATORS:
        _issue(issues, "campaign.decision_rule:operator_invalid")
    threshold = _closed(
        rule.get("threshold"),
        _THRESHOLD_FIELDS,
        "campaign.decision_rule.threshold",
        issues,
    )
    if not _bounded_int(
        threshold.get("numerator"), minimum=-(10**12), maximum=10**12
    ):
        _issue(issues, "campaign.decision_rule.threshold:numerator_invalid")
    if not _bounded_int(
        threshold.get("denominator"), minimum=1, maximum=10**12
    ):
        _issue(issues, "campaign.decision_rule.threshold:denominator_invalid")
    minimum_complete = rule.get("minimum_complete_replicates")
    if not _bounded_int(minimum_complete, minimum=1):
        _issue(issues, "campaign.decision_rule:minimum_complete_replicates_invalid")
    elif type(replicate_count) is int and minimum_complete > replicate_count:
        _issue(issues, "campaign.decision_rule:minimum_exceeds_replicates")
    if rule.get("pass_disposition") not in PASS_DISPOSITIONS:
        _issue(issues, "campaign.decision_rule:pass_disposition_invalid")
    if rule.get("fail_disposition") != "retain_default":
        _issue(issues, "campaign.decision_rule:fail_disposition_invalid")
    if rule.get("incomplete_disposition") != "inconclusive":
        _issue(issues, "campaign.decision_rule:incomplete_disposition_invalid")

    material = {
        "schema": expected_schema,
        "campaign_id": campaign.get("campaign_id"),
        "question": dict(question),
        "configuration_grid": normalized_grid,
        "replicate_count": replicate_count,
        "seeds": list(seeds),
        "decision_rule": {
            "metric": rule.get("metric"),
            "operator": rule.get("operator"),
            "threshold": dict(threshold),
            "minimum_complete_replicates": minimum_complete,
            "pass_disposition": rule.get("pass_disposition"),
            "fail_disposition": rule.get("fail_disposition"),
            "incomplete_disposition": rule.get("incomplete_disposition"),
        },
    }
    if sealed:
        material["campaign_sha256"] = campaign.get("campaign_sha256")
    return material


def seal_campaign(draft: Any) -> dict[str, Any]:
    """Validate and seal every preregistered campaign decision input."""

    issues: list[str] = []
    try:
        draft_sha256 = _sha256(draft)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        return _report("seal_campaign", ["campaign:hostile_or_noncanonical"])
    material = _campaign_material(
        draft,
        expected_schema=CAMPAIGN_DRAFT_SCHEMA,
        sealed=False,
        issues=issues,
    )
    if issues:
        return _report("seal_campaign", issues)
    sealed_material = {**material, "schema": CAMPAIGN_SCHEMA}
    sealed_campaign = {
        **sealed_material,
        "campaign_sha256": _sha256(sealed_material),
    }
    return _report(
        "seal_campaign",
        [],
        {"campaign": sealed_campaign, "draft_sha256": draft_sha256},
    )


def verify_campaign(value: Any) -> dict[str, Any]:
    """Verify one campaign seal without executing or repairing anything."""

    issues: list[str] = []
    try:
        _canonical(value)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        return _report("verify_campaign", ["campaign:hostile_or_noncanonical"])
    campaign = _campaign_material(
        value,
        expected_schema=CAMPAIGN_SCHEMA,
        sealed=True,
        issues=issues,
    )
    recorded_sha256 = campaign.pop("campaign_sha256", None)
    if not _sha_valid(recorded_sha256):
        _issue(issues, "campaign:campaign_sha256_invalid")
    else:
        actual_sha256 = _sha256(campaign)
        if recorded_sha256 != actual_sha256:
            _issue(issues, "campaign:seal_mismatch")
    result = None
    if not issues:
        result = {
            "verified": True,
            "campaign_sha256": recorded_sha256,
            "campaign_id": campaign.get("campaign_id"),
        }
    return _report("verify_campaign", issues, result)


def _campaign_result_material(
    campaign: Mapping[str, Any],
    value: Any,
    *,
    expected_schema: str,
    sealed: bool,
    issues: list[str],
) -> tuple[dict[str, Any], bool]:
    fields = _RESULT_FIELDS if sealed else _RESULT_DRAFT_FIELDS
    result = _closed(value, fields, "campaign_result", issues)
    if result.get("schema") != expected_schema:
        _issue(issues, "campaign_result:schema_invalid")
    if not _identifier(result.get("result_id")):
        _issue(issues, "campaign_result:result_id_invalid")
    campaign_sha256 = result.get("campaign_sha256")
    if not _sha_valid(campaign_sha256):
        _issue(issues, "campaign_result:campaign_sha256_invalid")
    elif campaign_sha256 != campaign.get("campaign_sha256"):
        _issue(issues, "campaign_result:campaign_sha256_mismatch")

    raw_finding = result.get("finding")
    finding_value = raw_finding if isinstance(raw_finding, Mapping) else {}
    kind = finding_value.get("kind")
    default_change_eligible = False
    if kind == "preregistered":
        finding = _closed(
            raw_finding,
            _PREREGISTERED_FINDING_FIELDS,
            "campaign_result.finding",
            issues,
        )
        question = campaign.get("question")
        question = question if isinstance(question, Mapping) else {}
        rule = campaign.get("decision_rule")
        rule = rule if isinstance(rule, Mapping) else {}
        if finding.get("question_id") != question.get("question_id"):
            _issue(issues, "campaign_result.finding:question_mismatch")
        if finding.get("metric") != question.get("primary_metric"):
            _issue(issues, "campaign_result.finding:metric_mismatch")
        outcome = finding.get("decision_rule_outcome")
        if outcome not in {"pass", "fail", "incomplete"}:
            _issue(issues, "campaign_result.finding:decision_rule_outcome_invalid")
        if not _text(finding.get("summary")):
            _issue(issues, "campaign_result.finding:summary_invalid")
        default_change_eligible = (
            outcome == "pass"
            and rule.get("pass_disposition") == "candidate_default_change"
        )
        normalized_finding = {
            "kind": "preregistered",
            "question_id": finding.get("question_id"),
            "metric": finding.get("metric"),
            "decision_rule_outcome": outcome,
            "summary": finding.get("summary"),
        }
    elif kind == "exploratory":
        finding = _closed(
            raw_finding,
            _EXPLORATORY_FINDING_FIELDS,
            "campaign_result.finding",
            issues,
        )
        for field in ("summary", "next_campaign_question"):
            if not _text(finding.get(field)):
                _issue(issues, f"campaign_result.finding:{field}_invalid")
        normalized_finding = {
            "kind": "exploratory",
            "summary": finding.get("summary"),
            "next_campaign_question": finding.get("next_campaign_question"),
        }
    else:
        _issue(issues, "campaign_result.finding:kind_invalid")
        normalized_finding = {
            "kind": kind,
        }

    material = {
        "schema": expected_schema,
        "result_id": result.get("result_id"),
        "campaign_sha256": campaign_sha256,
        "finding": normalized_finding,
    }
    if sealed:
        declared_eligible = result.get("default_change_eligible")
        if type(declared_eligible) is not bool:
            _issue(issues, "campaign_result:default_change_eligible_invalid")
        elif declared_eligible != default_change_eligible:
            _issue(issues, "campaign_result:default_change_eligibility_mismatch")
        material["default_change_eligible"] = declared_eligible
        material["result_sha256"] = result.get("result_sha256")
    return material, default_change_eligible


def seal_campaign_result(campaign: Any, draft: Any) -> dict[str, Any]:
    """Seal one result against an already-valid exact campaign digest."""

    campaign_report = verify_campaign(campaign)
    if campaign_report.get("status") != "PASS":
        return _report(
            "seal_result",
            ["campaign:" + str(item) for item in campaign_report.get("issues", [])],
        )
    issues: list[str] = []
    try:
        draft_sha256 = _sha256(draft)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        return _report("seal_result", ["campaign_result:hostile_or_noncanonical"])
    assert isinstance(campaign, Mapping)
    material, default_change_eligible = _campaign_result_material(
        campaign,
        draft,
        expected_schema=CAMPAIGN_RESULT_DRAFT_SCHEMA,
        sealed=False,
        issues=issues,
    )
    if issues:
        return _report("seal_result", issues)
    result_core = {
        **material,
        "schema": CAMPAIGN_RESULT_SCHEMA,
        "default_change_eligible": default_change_eligible,
    }
    sealed_result = {
        **result_core,
        "result_sha256": _sha256(result_core),
    }
    return _report(
        "seal_result",
        [],
        {"campaign_result": sealed_result, "draft_sha256": draft_sha256},
    )


def verify_campaign_result(campaign: Any, value: Any) -> dict[str, Any]:
    """Verify one sealed result and its exact campaign binding."""

    campaign_report = verify_campaign(campaign)
    if campaign_report.get("status") != "PASS":
        return _report(
            "verify_result",
            ["campaign:" + str(item) for item in campaign_report.get("issues", [])],
        )
    try:
        _canonical(value)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        return _report("verify_result", ["campaign_result:hostile_or_noncanonical"])
    issues: list[str] = []
    assert isinstance(campaign, Mapping)
    material, _ = _campaign_result_material(
        campaign,
        value,
        expected_schema=CAMPAIGN_RESULT_SCHEMA,
        sealed=True,
        issues=issues,
    )
    recorded_sha256 = material.pop("result_sha256", None)
    if not _sha_valid(recorded_sha256):
        _issue(issues, "campaign_result:result_sha256_invalid")
    elif recorded_sha256 != _sha256(material):
        _issue(issues, "campaign_result:seal_mismatch")
    result = None
    if not issues:
        result = {
            "verified": True,
            "result_sha256": recorded_sha256,
            "campaign_sha256": material.get("campaign_sha256"),
            "finding_kind": material.get("finding", {}).get("kind"),
            "default_change_eligible": material.get("default_change_eligible"),
        }
    return _report("verify_result", issues, result)


def evaluate_experiment_campaign(program: Any) -> dict[str, Any]:
    """Route one closed campaign-contract operation without side effects."""

    try:
        _canonical(program)
    except (HostileInputError, TypeError, ValueError, OverflowError):
        return _report("unknown", ["program:hostile_or_noncanonical"])
    issues: list[str] = []
    value = _closed(program, _PROGRAM_FIELDS, "program", issues)
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    operation = value.get("operation")
    if operation not in OPERATIONS:
        _issue(issues, "program:operation_invalid")
    if operation in {"seal_campaign", "verify_campaign"}:
        if value.get("campaign_result") is not None:
            _issue(issues, "program:campaign_result_must_be_null")
    elif operation in {"seal_result", "verify_result"}:
        if not isinstance(value.get("campaign_result"), Mapping):
            _issue(issues, "program:campaign_result_required")
    if issues:
        return _report(str(operation) if operation in OPERATIONS else "unknown", issues)
    if operation == "seal_campaign":
        return seal_campaign(value.get("campaign"))
    if operation == "verify_campaign":
        return verify_campaign(value.get("campaign"))
    if operation == "seal_result":
        return seal_campaign_result(value.get("campaign"), value.get("campaign_result"))
    return verify_campaign_result(value.get("campaign"), value.get("campaign_result"))


__all__ = [
    "CAMPAIGN_DRAFT_SCHEMA",
    "CAMPAIGN_RESULT_DRAFT_SCHEMA",
    "CAMPAIGN_RESULT_SCHEMA",
    "CAMPAIGN_SCHEMA",
    "OPERATIONS",
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "evaluate_experiment_campaign",
    "seal_campaign",
    "seal_campaign_result",
    "verify_campaign",
    "verify_campaign_result",
]
