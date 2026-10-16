#!/usr/bin/env python3
"""Hash-keyed model-call recording and provider-free counterfactual replay.

The recorder is a downstream experiment adapter.  It stores lossless bounded
JSON request/response values in the ordinary append-only experiment ledger,
keyed by the canonical request hash.  Public reports contain only hashes,
typed cell metadata, exact rational scores, and closed statuses.

Replay accepts no model or transport callback.  It evaluates a closed rational
score policy over recorded response fields and fails if any sealed campaign
cell lacks a recording.  A replay plan, including the baseline score policy and
holdout tolerance, must be sealed and appended before the first model call.
Live-holdout evidence is recorded later; disagreement is recomputed from ledger
records and automatically labels the replay ``hypothesis_generation_only``.
Neither agreement nor disagreement can change a default in this layer.
"""

from __future__ import annotations

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
PROFILE = hostile.PROFILE

SCORE_POLICY_DRAFT_SCHEMA = "orch-dork/replay-score-policy-draft/v1"
SCORE_POLICY_SCHEMA = "orch-dork/replay-score-policy/v1"
SCORE_POLICY_REPORT_SCHEMA = "orch-dork/replay-score-policy-report/v1"
REPLAY_PLAN_DRAFT_SCHEMA = "orch-dork/record-replay-plan-draft/v1"
REPLAY_PLAN_SCHEMA = "orch-dork/record-replay-plan/v1"
REPLAY_PLAN_REPORT_SCHEMA = "orch-dork/record-replay-plan-report/v1"
REPLAY_PLAN_RECORD_SCHEMA = "orch-dork/record-replay-plan-record/v1"
MODEL_CALL_EVIDENCE_SCHEMA = "orch-dork/model-call-evidence/v1"
MODEL_CALL_RECORD_SCHEMA = "orch-dork/model-call-record/v1"
MODEL_CALL_REPORT_SCHEMA = "orch-dork/model-call-record-report/v1"
REPLAY_RECORD_SCHEMA = "orch-dork/counterfactual-replay/v1"
REPLAY_REPORT_SCHEMA = "orch-dork/counterfactual-replay-report/v1"
LIVE_HOLDOUT_EVIDENCE_SCHEMA = "orch-dork/live-holdout-evidence/v1"
LIVE_HOLDOUT_RECORD_SCHEMA = "orch-dork/live-holdout-record/v1"
HOLDOUT_CONCLUSION_SCHEMA = "orch-dork/replay-holdout-conclusion/v1"
HOLDOUT_REPORT_SCHEMA = "orch-dork/replay-holdout-report/v1"
LIVE_CAMPAIGN_RECORD_SCHEMA = "orch-dork/live-sweep-campaign-record/v1"

MAX_SCORE_TERMS = 32
MAX_SCORE_PATH_DEPTH = 16
MAX_REPLAY_CALLS = PROFILE.max_array_items

_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_RATIONAL_FIELDS = frozenset({"numerator", "denominator"})
_TERM_FIELDS = frozenset({"path", "weight"})
_POLICY_DRAFT_FIELDS = frozenset({"schema", "policy_id", "terms", "intercept"})
_POLICY_FIELDS = _POLICY_DRAFT_FIELDS | frozenset({"policy_sha256"})
_PLAN_DRAFT_FIELDS = frozenset(
    {"schema", "plan_id", "campaign_sha256", "baseline_policy", "holdout_tolerance"}
)
_PLAN_FIELDS = _PLAN_DRAFT_FIELDS | frozenset({"plan_sha256"})
_PLAN_RECORD_FIELDS = frozenset(
    {"schema", "campaign_sha256", "replay_plan", "plan_sha256", "record_sha256"}
)
_CALL_EVIDENCE_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "configuration_id",
        "replicate_index",
        "seed",
        "request",
        "response",
        "governed_report_sha256",
    }
)
_CALL_RECORD_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "replay_plan_sha256",
        "configuration_id",
        "replicate_index",
        "seed",
        "request_sha256",
        "response_sha256",
        "request",
        "response",
        "baseline_policy_sha256",
        "recorded_score",
        "governed_report_sha256",
        "record_sha256",
    }
)
_REPLAY_SCORE_FIELDS = frozenset(
    {
        "configuration_id",
        "replicate_index",
        "seed",
        "request_sha256",
        "response_sha256",
        "score",
    }
)
_REPLAY_RECORD_FIELDS = frozenset(
    {
        "schema",
        "replay_id",
        "campaign_sha256",
        "replay_plan_sha256",
        "replay_policy",
        "replay_policy_sha256",
        "source_call_record_sha256s",
        "scores",
        "aggregate_score",
        "unchanged_policy",
        "recorded_scores_reproduced",
        "model_calls",
        "hosted_calls",
        "conclusion_label",
        "default_change_eligible",
        "record_sha256",
    }
)
_HOLDOUT_EVIDENCE_FIELDS = frozenset(
    {
        "schema",
        "holdout_id",
        "campaign_sha256",
        "replay_record_sha256",
        "lineage_disjoint",
        "observations",
    }
)
_OBSERVATION_FIELDS = frozenset(
    {"observation_id", "score", "governed_report_sha256"}
)
_HOLDOUT_RECORD_FIELDS = frozenset(
    {
        "schema",
        "holdout_id",
        "campaign_sha256",
        "replay_plan_sha256",
        "replay_record_sha256",
        "lineage_disjoint",
        "observations",
        "aggregate_score",
        "record_sha256",
    }
)
_CONCLUSION_FIELDS = frozenset(
    {
        "schema",
        "campaign_sha256",
        "replay_plan_sha256",
        "replay_record_sha256",
        "holdout_record_sha256",
        "replay_aggregate_score",
        "holdout_aggregate_score",
        "absolute_disagreement",
        "holdout_tolerance",
        "demoted",
        "conclusion_label",
        "default_change_eligible",
        "record_sha256",
    }
)


class ScoringError(ValueError):
    """A recorded response cannot be scored by a closed replay policy."""


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
    value: Any,
    fields: frozenset[str],
    label: str,
    issues: list[str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _issue(issues, f"{label}:shape_invalid")
        return dict(value) if isinstance(value, Mapping) else {}
    return dict(value)


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value.encode("utf-8")) <= PROFILE.max_string_bytes
    )


def _sha_valid(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _int(value: Any, *, minimum: int, maximum: int = 10**12) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _sealed(core: Mapping[str, Any], field: str = "record_sha256") -> dict[str, Any]:
    value = dict(core)
    return {**value, field: _sha256(value)}


def _seal_valid(value: Any, field: str = "record_sha256") -> bool:
    if not isinstance(value, Mapping):
        return False
    core = dict(value)
    recorded = core.pop(field, None)
    try:
        return _sha_valid(recorded) and recorded == _sha256(core)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return False


def _rational(
    value: Any,
    label: str,
    issues: list[str],
    *,
    nonnegative: bool = False,
) -> dict[str, Any]:
    item = _closed(value, _RATIONAL_FIELDS, label, issues)
    minimum = 0 if nonnegative else -(10**12)
    if not _int(item.get("numerator"), minimum=minimum):
        _issue(issues, f"{label}:numerator_invalid")
    if not _int(item.get("denominator"), minimum=1):
        _issue(issues, f"{label}:denominator_invalid")
    return {
        "numerator": item.get("numerator"),
        "denominator": item.get("denominator"),
    }


def _fraction(value: Mapping[str, Any]) -> Fraction:
    return Fraction(int(value["numerator"]), int(value["denominator"]))


def _fraction_record(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}


def _policy_material(
    value: Any,
    *,
    schema: str,
    sealed: bool,
    issues: list[str],
) -> dict[str, Any]:
    policy = _closed(
        value, _POLICY_FIELDS if sealed else _POLICY_DRAFT_FIELDS, "policy", issues
    )
    if policy.get("schema") != schema:
        _issue(issues, "policy:schema_invalid")
    if not _identifier(policy.get("policy_id")):
        _issue(issues, "policy:policy_id_invalid")
    raw_terms = policy.get("terms")
    if (
        not isinstance(raw_terms, list)
        or not raw_terms
        or len(raw_terms) > MAX_SCORE_TERMS
    ):
        _issue(issues, "policy:terms_invalid")
        raw_terms = []
    terms: list[dict[str, Any]] = []
    paths: set[tuple[str, ...]] = set()
    for index, raw in enumerate(raw_terms):
        term = _closed(raw, _TERM_FIELDS, f"policy.term[{index}]", issues)
        path = term.get("path")
        if (
            not isinstance(path, list)
            or not path
            or len(path) > MAX_SCORE_PATH_DEPTH
            or any(not _text(part) for part in path)
        ):
            _issue(issues, f"policy.term[{index}]:path_invalid")
            path = []
        path_key = tuple(path)
        if path_key in paths:
            _issue(issues, "policy:duplicate_path")
        paths.add(path_key)
        weight = _rational(term.get("weight"), f"policy.term[{index}].weight", issues)
        terms.append({"path": list(path), "weight": weight})
    intercept = _rational(policy.get("intercept"), "policy.intercept", issues)
    material = {
        "schema": schema,
        "policy_id": policy.get("policy_id"),
        "terms": terms,
        "intercept": intercept,
    }
    if sealed:
        material["policy_sha256"] = policy.get("policy_sha256")
    return material


def _policy_report(
    operation: str,
    issues: list[str],
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": SCORE_POLICY_REPORT_SCHEMA,
        "operation": operation,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "score_policy": dict(policy) if isinstance(policy, Mapping) else None,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "default_changed": False,
    }


def seal_score_policy(draft: Any) -> dict[str, Any]:
    """Seal one deterministic rational response-scoring policy."""

    issues: list[str] = []
    try:
        _canonical(draft)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return _policy_report("seal", ["policy:hostile_or_noncanonical"])
    material = _policy_material(
        draft, schema=SCORE_POLICY_DRAFT_SCHEMA, sealed=False, issues=issues
    )
    if issues:
        return _policy_report("seal", issues)
    core = {**material, "schema": SCORE_POLICY_SCHEMA}
    return _policy_report("seal", [], _sealed(core, "policy_sha256"))


def validate_score_policy(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    try:
        _canonical(value)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return _policy_report("verify", ["policy:hostile_or_noncanonical"])
    material = _policy_material(
        value, schema=SCORE_POLICY_SCHEMA, sealed=True, issues=issues
    )
    if not _seal_valid(material, "policy_sha256"):
        _issue(issues, "policy:seal_mismatch")
    return _policy_report("verify", issues, material if not issues else None)


def _score(response: Any, policy: Mapping[str, Any]) -> Fraction:
    total = _fraction(policy["intercept"])
    for term in policy["terms"]:
        value = response
        for part in term["path"]:
            if not isinstance(value, Mapping) or part not in value:
                raise ScoringError("response_path_missing")
            value = value[part]
        if type(value) is int:
            selected = Fraction(value, 1)
        elif isinstance(value, Mapping) and set(value) == _RATIONAL_FIELDS:
            numerator = value.get("numerator")
            denominator = value.get("denominator")
            if not _int(numerator, minimum=-(10**12)) or not _int(
                denominator, minimum=1
            ):
                raise ScoringError("response_value_invalid")
            selected = Fraction(numerator, denominator)
        else:
            raise ScoringError("response_value_invalid")
        total += selected * _fraction(term["weight"])
    return total


def _plan_material(
    campaign: Any,
    value: Any,
    *,
    schema: str,
    sealed: bool,
    issues: list[str],
) -> dict[str, Any]:
    plan = _closed(value, _PLAN_FIELDS if sealed else _PLAN_DRAFT_FIELDS, "plan", issues)
    if plan.get("schema") != schema:
        _issue(issues, "replay_plan:schema_invalid")
    if not _identifier(plan.get("plan_id")):
        _issue(issues, "replay_plan:plan_id_invalid")
    campaign_report = campaign_contract.verify_campaign(campaign)
    if campaign_report.get("status") != "PASS":
        _issue(issues, "replay_plan:campaign_invalid")
    campaign_value = campaign if isinstance(campaign, Mapping) else {}
    if plan.get("campaign_sha256") != campaign_value.get("campaign_sha256"):
        _issue(issues, "replay_plan:campaign_mismatch")
    policy_report = validate_score_policy(plan.get("baseline_policy"))
    if policy_report.get("status") != "PASS":
        _issue(issues, "replay_plan:baseline_policy_invalid")
    baseline_policy = policy_report.get("score_policy") or {}
    tolerance = _rational(
        plan.get("holdout_tolerance"),
        "replay_plan.holdout_tolerance",
        issues,
        nonnegative=True,
    )
    material = {
        "schema": schema,
        "plan_id": plan.get("plan_id"),
        "campaign_sha256": plan.get("campaign_sha256"),
        "baseline_policy": dict(baseline_policy),
        "holdout_tolerance": tolerance,
    }
    if sealed:
        material["plan_sha256"] = plan.get("plan_sha256")
    return material


def _plan_report(
    operation: str,
    issues: list[str],
    *,
    replay_plan: Mapping[str, Any] | None = None,
    record_sha256: str | None = None,
) -> dict[str, Any]:
    plan = replay_plan if isinstance(replay_plan, Mapping) else {}
    return {
        "schema": REPLAY_PLAN_REPORT_SCHEMA,
        "operation": operation,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "campaign_sha256": plan.get("campaign_sha256"),
        "plan_sha256": plan.get("plan_sha256"),
        "record_sha256": record_sha256,
        "replay_plan": (
            dict(plan) if operation in {"seal", "verify"} and not issues else None
        ),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "default_changed": False,
    }


def seal_replay_plan(campaign: Any, draft: Any) -> dict[str, Any]:
    """Seal baseline policy and holdout tolerance before model recording."""

    issues: list[str] = []
    try:
        _canonical(draft)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return _plan_report("seal", ["replay_plan:hostile_or_noncanonical"])
    material = _plan_material(
        campaign,
        draft,
        schema=REPLAY_PLAN_DRAFT_SCHEMA,
        sealed=False,
        issues=issues,
    )
    if issues:
        return _plan_report("seal", issues)
    core = {**material, "schema": REPLAY_PLAN_SCHEMA}
    sealed_plan = _sealed(core, "plan_sha256")
    return _plan_report("seal", [], replay_plan=sealed_plan)


def validate_replay_plan(campaign: Any, value: Any) -> dict[str, Any]:
    issues: list[str] = []
    try:
        _canonical(value)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return _plan_report("verify", ["replay_plan:hostile_or_noncanonical"])
    material = _plan_material(
        campaign,
        value,
        schema=REPLAY_PLAN_SCHEMA,
        sealed=True,
        issues=issues,
    )
    if not _seal_valid(material, "plan_sha256"):
        _issue(issues, "replay_plan:seal_mismatch")
    return _plan_report(
        "verify", issues, replay_plan=material if not issues else None
    )


def _append(path: str | Path, record: Mapping[str, Any]) -> bool:
    try:
        result = trace.append_trace_record(path, record)
    except (OSError, TypeError, ValueError):
        return False
    return result.get("status") == "PASS"


def _entries(path: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    return sweep.read_experiment_ledger(path)


def _find_plan(
    campaign: Any, entries: Sequence[Mapping[str, Any]], issues: list[str]
) -> Mapping[str, Any] | None:
    campaign_value = campaign if isinstance(campaign, Mapping) else {}
    digest = campaign_value.get("campaign_sha256")
    rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema") == REPLAY_PLAN_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == digest
    ]
    if len(rows) != 1:
        _issue(
            issues,
            "replay_plan:missing" if not rows else "replay_plan:duplicate",
        )
        return None
    record = _closed(rows[0], _PLAN_RECORD_FIELDS, "replay_plan_record", issues)
    if not _seal_valid(record):
        _issue(issues, "replay_plan_record:seal_mismatch")
    plan_report = validate_replay_plan(campaign, record.get("replay_plan"))
    if plan_report.get("status") != "PASS":
        _issue(issues, "replay_plan_record:plan_invalid")
        return None
    plan = plan_report.get("replay_plan") or {}
    if (
        record.get("plan_sha256") != plan.get("plan_sha256")
        or record.get("campaign_sha256") != digest
    ):
        _issue(issues, "replay_plan_record:binding_mismatch")
    return plan


def register_replay_plan(
    campaign: Any, ledger_path: str | Path, replay_plan: Any
) -> dict[str, Any]:
    """Append one campaign-bound replay plan before any model-call record."""

    plan_report = validate_replay_plan(campaign, replay_plan)
    if plan_report.get("status") != "PASS":
        return _plan_report("register", ["replay_plan:invalid"])
    plan = plan_report["replay_plan"]
    entries, chain_issues = _entries(ledger_path)
    if chain_issues:
        return _plan_report("register", chain_issues, replay_plan=plan)
    digest = plan["campaign_sha256"]
    relevant = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("campaign_sha256") == digest
    ]
    if any(row.get("schema") == REPLAY_PLAN_RECORD_SCHEMA for row in relevant):
        return _plan_report("register", ["replay_plan:already_registered"], replay_plan=plan)
    if any(row.get("schema") == MODEL_CALL_RECORD_SCHEMA for row in relevant):
        return _plan_report("register", ["replay_plan:model_calls_already_recorded"], replay_plan=plan)
    core = {
        "schema": REPLAY_PLAN_RECORD_SCHEMA,
        "campaign_sha256": digest,
        "replay_plan": dict(plan),
        "plan_sha256": plan["plan_sha256"],
    }
    try:
        record = _sealed(core)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return _plan_report(
            "register", ["replay_plan:record_too_large"], replay_plan=plan
        )
    if not _append(ledger_path, record):
        return _plan_report("register", ["ledger:append_failed"], replay_plan=plan)
    return _plan_report(
        "register",
        [],
        replay_plan=plan,
        record_sha256=record["record_sha256"],
    )


def _campaign_cells(campaign: Mapping[str, Any]) -> dict[tuple[str, int, int], None]:
    cells: dict[tuple[str, int, int], None] = {}
    for configuration in campaign.get("configuration_grid", []):
        configuration_id = str(configuration.get("configuration_id"))
        for index, seed in enumerate(campaign.get("seeds", []), start=1):
            cells[(configuration_id, index, seed)] = None
    return cells


def _call_report(
    issues: list[str],
    *,
    campaign_sha256: str | None = None,
    request_sha256: str | None = None,
    response_sha256: str | None = None,
    record_sha256: str | None = None,
    score: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": MODEL_CALL_REPORT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "campaign_sha256": campaign_sha256,
        "request_sha256": request_sha256,
        "response_sha256": response_sha256,
        "model_call_record_sha256": record_sha256,
        "score": dict(score) if isinstance(score, Mapping) else None,
        "recorded_model_calls": 1 if not issues else 0,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "default_changed": False,
    }


def _validate_call_evidence(
    campaign: Mapping[str, Any], value: Any, issues: list[str]
) -> dict[str, Any]:
    evidence = _closed(value, _CALL_EVIDENCE_FIELDS, "call_evidence", issues)
    if evidence.get("schema") != MODEL_CALL_EVIDENCE_SCHEMA:
        _issue(issues, "call_evidence:schema_invalid")
    if evidence.get("campaign_sha256") != campaign.get("campaign_sha256"):
        _issue(issues, "call_evidence:campaign_mismatch")
    key = (
        evidence.get("configuration_id"),
        evidence.get("replicate_index"),
        evidence.get("seed"),
    )
    if key not in _campaign_cells(campaign):
        _issue(issues, "call_evidence:cell_invalid")
    if not _sha_valid(evidence.get("governed_report_sha256")):
        _issue(issues, "call_evidence:governed_report_sha256_invalid")
    try:
        request_sha256 = _sha256(evidence.get("request"))
        response_sha256 = _sha256(evidence.get("response"))
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        _issue(issues, "call_evidence:payload_invalid")
        request_sha256 = None
        response_sha256 = None
    return {
        "campaign_sha256": evidence.get("campaign_sha256"),
        "configuration_id": evidence.get("configuration_id"),
        "replicate_index": evidence.get("replicate_index"),
        "seed": evidence.get("seed"),
        "request": evidence.get("request"),
        "response": evidence.get("response"),
        "request_sha256": request_sha256,
        "response_sha256": response_sha256,
        "governed_report_sha256": evidence.get("governed_report_sha256"),
    }


def record_model_call(
    campaign: Any, ledger_path: str | Path, evidence: Any
) -> dict[str, Any]:
    """Append one lossless request/response record at the model-call boundary."""

    campaign_report = campaign_contract.verify_campaign(campaign)
    if campaign_report.get("status") != "PASS" or not isinstance(campaign, Mapping):
        return _call_report(["campaign:invalid"])
    entries, chain_issues = _entries(ledger_path)
    if chain_issues:
        return _call_report(chain_issues, campaign_sha256=campaign.get("campaign_sha256"))
    issues: list[str] = []
    plan = _find_plan(campaign, entries, issues)
    has_sweep_registration = any(
        row.get("record", {}).get("schema")
        in {sweep.CAMPAIGN_RECORD_SCHEMA, LIVE_CAMPAIGN_RECORD_SCHEMA}
        and row.get("record", {}).get("campaign_sha256") == campaign.get("campaign_sha256")
        for row in entries
    )
    if not has_sweep_registration:
        _issue(issues, "sweep_campaign:registration_missing")
    normalized = _validate_call_evidence(campaign, evidence, issues)
    existing_calls = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema") == MODEL_CALL_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == campaign.get("campaign_sha256")
    ]
    cell = (
        normalized.get("configuration_id"),
        normalized.get("replicate_index"),
        normalized.get("seed"),
    )
    if any(
        (
            row.get("configuration_id"),
            row.get("replicate_index"),
            row.get("seed"),
        )
        == cell
        for row in existing_calls
    ):
        _issue(issues, "model_call:duplicate_cell")
    if any(
        row.get("request_sha256") == normalized.get("request_sha256")
        for row in existing_calls
    ):
        _issue(issues, "model_call:duplicate_request_hash")
    score: Fraction | None = None
    if plan is not None:
        try:
            score = _score(normalized.get("response"), plan["baseline_policy"])
        except (ScoringError, KeyError, TypeError, ValueError, ZeroDivisionError):
            _issue(issues, "model_call:response_unscorable")
    if issues:
        return _call_report(
            issues,
            campaign_sha256=campaign.get("campaign_sha256"),
            request_sha256=normalized.get("request_sha256"),
            response_sha256=normalized.get("response_sha256"),
        )
    score_record = _fraction_record(score or Fraction(0, 1))
    core = {
        "schema": MODEL_CALL_RECORD_SCHEMA,
        "campaign_sha256": campaign.get("campaign_sha256"),
        "replay_plan_sha256": plan["plan_sha256"],
        "configuration_id": normalized["configuration_id"],
        "replicate_index": normalized["replicate_index"],
        "seed": normalized["seed"],
        "request_sha256": normalized["request_sha256"],
        "response_sha256": normalized["response_sha256"],
        "request": normalized["request"],
        "response": normalized["response"],
        "baseline_policy_sha256": plan["baseline_policy"]["policy_sha256"],
        "recorded_score": score_record,
        "governed_report_sha256": normalized["governed_report_sha256"],
    }
    try:
        record = _sealed(core)
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        return _call_report(
            ["model_call:record_too_large"],
            campaign_sha256=campaign.get("campaign_sha256"),
            request_sha256=normalized["request_sha256"],
            response_sha256=normalized["response_sha256"],
        )
    if not _append(ledger_path, record):
        return _call_report(
            ["ledger:append_failed"],
            campaign_sha256=campaign.get("campaign_sha256"),
            request_sha256=normalized["request_sha256"],
            response_sha256=normalized["response_sha256"],
        )
    return _call_report(
        [],
        campaign_sha256=campaign.get("campaign_sha256"),
        request_sha256=normalized["request_sha256"],
        response_sha256=normalized["response_sha256"],
        record_sha256=record["record_sha256"],
        score=score_record,
    )


def _validate_call_record(
    campaign: Mapping[str, Any],
    plan: Mapping[str, Any],
    value: Any,
    issues: list[str],
) -> Mapping[str, Any]:
    record = _closed(value, _CALL_RECORD_FIELDS, "model_call_record", issues)
    if record.get("schema") != MODEL_CALL_RECORD_SCHEMA:
        _issue(issues, "model_call_record:schema_invalid")
    if not _seal_valid(record):
        _issue(issues, "model_call_record:seal_mismatch")
    if record.get("campaign_sha256") != campaign.get("campaign_sha256"):
        _issue(issues, "model_call_record:campaign_mismatch")
    if record.get("replay_plan_sha256") != plan.get("plan_sha256"):
        _issue(issues, "model_call_record:plan_mismatch")
    if record.get("baseline_policy_sha256") != plan.get("baseline_policy", {}).get(
        "policy_sha256"
    ):
        _issue(issues, "model_call_record:baseline_policy_mismatch")
    key = (
        record.get("configuration_id"),
        record.get("replicate_index"),
        record.get("seed"),
    )
    if key not in _campaign_cells(campaign):
        _issue(issues, "model_call_record:cell_invalid")
    try:
        request_sha256 = _sha256(record.get("request"))
        response_sha256 = _sha256(record.get("response"))
    except (hostile.HostileInputError, TypeError, ValueError, OverflowError):
        _issue(issues, "model_call_record:payload_invalid")
        request_sha256 = None
        response_sha256 = None
    if record.get("request_sha256") != request_sha256:
        _issue(issues, "model_call_record:request_hash_mismatch")
    if record.get("response_sha256") != response_sha256:
        _issue(issues, "model_call_record:response_hash_mismatch")
    score_issues: list[str] = []
    recorded_score = _rational(
        record.get("recorded_score"), "model_call_record.recorded_score", score_issues
    )
    if score_issues:
        _issue(issues, "model_call_record:score_invalid")
    try:
        expected_score = _score(record.get("response"), plan["baseline_policy"])
    except (ScoringError, KeyError, TypeError, ValueError, ZeroDivisionError):
        _issue(issues, "model_call_record:response_unscorable")
    else:
        if not score_issues and _fraction(recorded_score) != expected_score:
            _issue(issues, "model_call_record:score_mismatch")
    if not _sha_valid(record.get("governed_report_sha256")):
        _issue(issues, "model_call_record:governed_report_sha256_invalid")
    return record


def _replay_failure(
    campaign_sha256: str | None, issues: list[str]
) -> dict[str, Any]:
    return {
        "schema": REPLAY_REPORT_SCHEMA,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "campaign_sha256": campaign_sha256,
        "replay_plan_sha256": None,
        "replay_policy_sha256": None,
        "replay_record_sha256": None,
        "call_count": 0,
        "scores": None,
        "aggregate_score": None,
        "unchanged_policy": None,
        "recorded_scores_reproduced": None,
        "conclusion_label": None,
        "default_change_eligible": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _replay_report(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": REPLAY_REPORT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "campaign_sha256": record.get("campaign_sha256"),
        "replay_plan_sha256": record.get("replay_plan_sha256"),
        "replay_policy_sha256": record.get("replay_policy_sha256"),
        "replay_record_sha256": record.get("record_sha256"),
        "call_count": len(record.get("scores", [])),
        "scores": [dict(row) for row in record.get("scores", [])],
        "aggregate_score": dict(record.get("aggregate_score", {})),
        "unchanged_policy": record.get("unchanged_policy"),
        "recorded_scores_reproduced": record.get("recorded_scores_reproduced"),
        "conclusion_label": record.get("conclusion_label"),
        "default_change_eligible": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def replay_campaign(
    campaign: Any, ledger_path: str | Path, replay_policy: Any
) -> dict[str, Any]:
    """Re-score a complete recorded campaign without a model-call seam."""

    campaign_report = campaign_contract.verify_campaign(campaign)
    if campaign_report.get("status") != "PASS" or not isinstance(campaign, Mapping):
        return _replay_failure(None, ["campaign:invalid"])
    policy_report = validate_score_policy(replay_policy)
    if policy_report.get("status") != "PASS":
        return _replay_failure(campaign.get("campaign_sha256"), ["replay_policy:invalid"])
    policy = policy_report["score_policy"]
    entries, chain_issues = _entries(ledger_path)
    if chain_issues:
        return _replay_failure(campaign.get("campaign_sha256"), chain_issues)
    issues: list[str] = []
    plan = _find_plan(campaign, entries, issues)
    if plan is None:
        return _replay_failure(campaign.get("campaign_sha256"), issues)
    raw_calls = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema") == MODEL_CALL_RECORD_SCHEMA
        and row.get("record", {}).get("campaign_sha256") == campaign.get("campaign_sha256")
    ]
    expected = _campaign_cells(campaign)
    if len(expected) > MAX_REPLAY_CALLS:
        _issue(issues, "replay:call_bound_exceeded")
    calls: dict[tuple[str, int, int], Mapping[str, Any]] = {}
    request_hashes: set[str] = set()
    for raw in raw_calls:
        row_issues: list[str] = []
        record = _validate_call_record(campaign, plan, raw, row_issues)
        if row_issues:
            _issue(issues, "replay:model_call_record_invalid")
            continue
        key = (
            str(record.get("configuration_id")),
            int(record.get("replicate_index")),
            int(record.get("seed")),
        )
        if key in calls:
            _issue(issues, "replay:duplicate_cell")
        request_hash = str(record.get("request_sha256"))
        if request_hash in request_hashes:
            _issue(issues, "replay:duplicate_request_hash")
        calls[key] = record
        request_hashes.add(request_hash)
    if set(calls) != set(expected):
        _issue(issues, "replay:unrecorded_cell")
    if any(
        row.get("schema") == REPLAY_RECORD_SCHEMA
        and row.get("campaign_sha256") == campaign.get("campaign_sha256")
        and row.get("replay_policy_sha256") == policy.get("policy_sha256")
        for row in (entry.get("record", {}) for entry in entries)
    ):
        _issue(issues, "replay:duplicate_policy")
    if issues:
        return _replay_failure(campaign.get("campaign_sha256"), issues)
    scores: list[dict[str, Any]] = []
    source_hashes: list[str] = []
    reproduced = True
    for key in expected:
        record = calls[key]
        try:
            score = _score(record["response"], policy)
        except (ScoringError, KeyError, TypeError, ValueError, ZeroDivisionError):
            return _replay_failure(
                campaign.get("campaign_sha256"), ["replay:recorded_response_unscorable"]
            )
        score_record = _fraction_record(score)
        if score_record != record.get("recorded_score"):
            reproduced = False
        scores.append(
            {
                "configuration_id": key[0],
                "replicate_index": key[1],
                "seed": key[2],
                "request_sha256": record["request_sha256"],
                "response_sha256": record["response_sha256"],
                "score": score_record,
            }
        )
        source_hashes.append(str(record["record_sha256"]))
    aggregate = sum(
        (_fraction(row["score"]) for row in scores), Fraction(0, 1)
    ) / len(scores)
    unchanged = policy.get("policy_sha256") == plan["baseline_policy"].get(
        "policy_sha256"
    )
    if unchanged and not reproduced:
        return _replay_failure(
            campaign.get("campaign_sha256"), ["replay:unchanged_score_mismatch"]
        )
    replay_id = "replay-" + str(policy["policy_sha256"])[:16]
    core = {
        "schema": REPLAY_RECORD_SCHEMA,
        "replay_id": replay_id,
        "campaign_sha256": campaign.get("campaign_sha256"),
        "replay_plan_sha256": plan["plan_sha256"],
        "replay_policy": dict(policy),
        "replay_policy_sha256": policy["policy_sha256"],
        "source_call_record_sha256s": source_hashes,
        "scores": scores,
        "aggregate_score": _fraction_record(aggregate),
        "unchanged_policy": unchanged,
        "recorded_scores_reproduced": reproduced if unchanged else None,
        "model_calls": 0,
        "hosted_calls": 0,
        "conclusion_label": "hypothesis_generation_pending_holdout",
        "default_change_eligible": False,
    }
    record = _sealed(core)
    if not _append(ledger_path, record):
        return _replay_failure(campaign.get("campaign_sha256"), ["ledger:append_failed"])
    return _replay_report(record)


def _validate_replay_record(value: Any, issues: list[str]) -> Mapping[str, Any]:
    record = _closed(value, _REPLAY_RECORD_FIELDS, "replay_record", issues)
    if record.get("schema") != REPLAY_RECORD_SCHEMA or not _seal_valid(record):
        _issue(issues, "replay_record:invalid")
    for field in (
        "campaign_sha256",
        "replay_plan_sha256",
        "replay_policy_sha256",
        "record_sha256",
    ):
        if not _sha_valid(record.get(field)):
            _issue(issues, "replay_record:hash_invalid")
    policy = validate_score_policy(record.get("replay_policy"))
    if (
        policy.get("status") != "PASS"
        or policy.get("score_policy", {}).get("policy_sha256")
        != record.get("replay_policy_sha256")
    ):
        _issue(issues, "replay_record:policy_invalid")
    scores = record.get("scores")
    if not isinstance(scores, list) or not scores or len(scores) > MAX_REPLAY_CALLS:
        _issue(issues, "replay_record:scores_invalid")
        scores = []
    for raw in scores:
        score = _closed(raw, _REPLAY_SCORE_FIELDS, "replay_score", issues)
        for field in ("request_sha256", "response_sha256"):
            if not _sha_valid(score.get(field)):
                _issue(issues, "replay_score:hash_invalid")
        score_issues: list[str] = []
        _rational(score.get("score"), "replay_score.score", score_issues)
        if score_issues:
            _issue(issues, "replay_score:value_invalid")
    aggregate_issues: list[str] = []
    aggregate = _rational(
        record.get("aggregate_score"), "replay_record.aggregate_score", aggregate_issues
    )
    if aggregate_issues:
        _issue(issues, "replay_record:aggregate_invalid")
    elif scores:
        expected = sum(
            (_fraction(row["score"]) for row in scores), Fraction(0, 1)
        ) / len(scores)
        if _fraction(aggregate) != expected:
            _issue(issues, "replay_record:aggregate_mismatch")
    if record.get("model_calls") != 0 or record.get("hosted_calls") != 0:
        _issue(issues, "replay_record:model_call_claim_invalid")
    if (
        record.get("conclusion_label") != "hypothesis_generation_pending_holdout"
        or record.get("default_change_eligible") is not False
    ):
        _issue(issues, "replay_record:conclusion_invalid")
    return record


def _holdout_failure(campaign_sha256: str | None, issues: list[str]) -> dict[str, Any]:
    return {
        "schema": HOLDOUT_REPORT_SCHEMA,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "campaign_sha256": campaign_sha256,
        "replay_plan_sha256": None,
        "replay_record_sha256": None,
        "holdout_record_sha256": None,
        "conclusion_record_sha256": None,
        "replay_aggregate_score": None,
        "holdout_aggregate_score": None,
        "absolute_disagreement": None,
        "holdout_tolerance": None,
        "demoted": None,
        "conclusion_label": None,
        "default_change_eligible": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _holdout_report(conclusion: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": HOLDOUT_REPORT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "campaign_sha256": conclusion.get("campaign_sha256"),
        "replay_plan_sha256": conclusion.get("replay_plan_sha256"),
        "replay_record_sha256": conclusion.get("replay_record_sha256"),
        "holdout_record_sha256": conclusion.get("holdout_record_sha256"),
        "conclusion_record_sha256": conclusion.get("record_sha256"),
        "replay_aggregate_score": dict(conclusion.get("replay_aggregate_score", {})),
        "holdout_aggregate_score": dict(conclusion.get("holdout_aggregate_score", {})),
        "absolute_disagreement": dict(conclusion.get("absolute_disagreement", {})),
        "holdout_tolerance": dict(conclusion.get("holdout_tolerance", {})),
        "demoted": conclusion.get("demoted"),
        "conclusion_label": conclusion.get("conclusion_label"),
        "default_change_eligible": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _find_record(
    entries: Sequence[Mapping[str, Any]], schema: str, record_sha256: str
) -> Mapping[str, Any] | None:
    rows = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema") == schema
        and row.get("record", {}).get("record_sha256") == record_sha256
    ]
    return rows[0] if len(rows) == 1 else None


def _holdout_material(value: Any, issues: list[str]) -> dict[str, Any]:
    evidence = _closed(value, _HOLDOUT_EVIDENCE_FIELDS, "holdout_evidence", issues)
    if evidence.get("schema") != LIVE_HOLDOUT_EVIDENCE_SCHEMA:
        _issue(issues, "holdout_evidence:schema_invalid")
    if not _identifier(evidence.get("holdout_id")):
        _issue(issues, "holdout_evidence:holdout_id_invalid")
    for field in ("campaign_sha256", "replay_record_sha256"):
        if not _sha_valid(evidence.get(field)):
            _issue(issues, "holdout_evidence:hash_invalid")
    if evidence.get("lineage_disjoint") is not True:
        _issue(issues, "holdout_evidence:lineage_not_disjoint")
    raw_observations = evidence.get("observations")
    if (
        not isinstance(raw_observations, list)
        or not raw_observations
        or len(raw_observations) > PROFILE.max_array_items
    ):
        _issue(issues, "holdout_evidence:observations_invalid")
        raw_observations = []
    observations: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, raw in enumerate(raw_observations):
        observation = _closed(raw, _OBSERVATION_FIELDS, "holdout_observation", issues)
        observation_id = observation.get("observation_id")
        if not _identifier(observation_id) or observation_id in ids:
            _issue(issues, "holdout_observation:id_invalid_or_duplicate")
        ids.add(str(observation_id))
        score = _rational(observation.get("score"), "holdout_observation.score", issues)
        if not _sha_valid(observation.get("governed_report_sha256")):
            _issue(issues, "holdout_observation:governed_report_sha256_invalid")
        observations.append(
            {
                "observation_id": observation_id,
                "score": score,
                "governed_report_sha256": observation.get("governed_report_sha256"),
            }
        )
    return {
        "holdout_id": evidence.get("holdout_id"),
        "campaign_sha256": evidence.get("campaign_sha256"),
        "replay_record_sha256": evidence.get("replay_record_sha256"),
        "lineage_disjoint": evidence.get("lineage_disjoint"),
        "observations": observations,
    }


def record_live_holdout(
    campaign: Any, ledger_path: str | Path, evidence: Any
) -> dict[str, Any]:
    """Record live holdout scores and append the automatic replay conclusion."""

    campaign_report = campaign_contract.verify_campaign(campaign)
    if campaign_report.get("status") != "PASS" or not isinstance(campaign, Mapping):
        return _holdout_failure(None, ["campaign:invalid"])
    entries, chain_issues = _entries(ledger_path)
    if chain_issues:
        return _holdout_failure(campaign.get("campaign_sha256"), chain_issues)
    issues: list[str] = []
    plan = _find_plan(campaign, entries, issues)
    normalized = _holdout_material(evidence, issues)
    if normalized.get("campaign_sha256") != campaign.get("campaign_sha256"):
        _issue(issues, "holdout_evidence:campaign_mismatch")
    replay_record = _find_record(
        entries,
        REPLAY_RECORD_SCHEMA,
        str(normalized.get("replay_record_sha256")),
    )
    if replay_record is None:
        _issue(issues, "holdout_evidence:replay_missing")
    else:
        replay_issues: list[str] = []
        _validate_replay_record(replay_record, replay_issues)
        if replay_issues:
            _issue(issues, "holdout_evidence:replay_invalid")
        if replay_record.get("campaign_sha256") != campaign.get("campaign_sha256"):
            _issue(issues, "holdout_evidence:replay_campaign_mismatch")
        if plan is not None and replay_record.get("replay_plan_sha256") != plan.get(
            "plan_sha256"
        ):
            _issue(issues, "holdout_evidence:replay_plan_mismatch")
    if any(
        row.get("record", {}).get("schema") == LIVE_HOLDOUT_RECORD_SCHEMA
        and row.get("record", {}).get("holdout_id") == normalized.get("holdout_id")
        for row in entries
    ):
        _issue(issues, "holdout_evidence:duplicate_holdout_id")
    if issues:
        return _holdout_failure(campaign.get("campaign_sha256"), issues)
    observations = normalized["observations"]
    holdout_mean = sum(
        (_fraction(row["score"]) for row in observations), Fraction(0, 1)
    ) / len(observations)
    holdout_core = {
        "schema": LIVE_HOLDOUT_RECORD_SCHEMA,
        "holdout_id": normalized["holdout_id"],
        "campaign_sha256": campaign.get("campaign_sha256"),
        "replay_plan_sha256": plan["plan_sha256"],
        "replay_record_sha256": replay_record["record_sha256"],
        "lineage_disjoint": True,
        "observations": observations,
        "aggregate_score": _fraction_record(holdout_mean),
    }
    holdout_record = _sealed(holdout_core)
    if not _append(ledger_path, holdout_record):
        return _holdout_failure(campaign.get("campaign_sha256"), ["ledger:append_failed"])
    replay_mean = _fraction(replay_record["aggregate_score"])
    tolerance = _fraction(plan["holdout_tolerance"])
    disagreement = abs(replay_mean - holdout_mean)
    demoted = disagreement > tolerance
    conclusion_core = {
        "schema": HOLDOUT_CONCLUSION_SCHEMA,
        "campaign_sha256": campaign.get("campaign_sha256"),
        "replay_plan_sha256": plan["plan_sha256"],
        "replay_record_sha256": replay_record["record_sha256"],
        "holdout_record_sha256": holdout_record["record_sha256"],
        "replay_aggregate_score": _fraction_record(replay_mean),
        "holdout_aggregate_score": _fraction_record(holdout_mean),
        "absolute_disagreement": _fraction_record(disagreement),
        "holdout_tolerance": dict(plan["holdout_tolerance"]),
        "demoted": demoted,
        "conclusion_label": (
            "hypothesis_generation_only" if demoted else "holdout_consistent"
        ),
        "default_change_eligible": False,
    }
    conclusion = _sealed(conclusion_core)
    if not _append(ledger_path, conclusion):
        return _holdout_failure(
            campaign.get("campaign_sha256"), ["ledger:conclusion_append_failed"]
        )
    return summarize_holdout_conclusion(
        ledger_path, campaign.get("campaign_sha256"), conclusion["record_sha256"]
    )


def _validate_holdout_record(value: Any, issues: list[str]) -> Mapping[str, Any]:
    record = _closed(value, _HOLDOUT_RECORD_FIELDS, "holdout_record", issues)
    if record.get("schema") != LIVE_HOLDOUT_RECORD_SCHEMA or not _seal_valid(record):
        _issue(issues, "holdout_record:invalid")
    observations = record.get("observations")
    if not isinstance(observations, list) or not observations:
        _issue(issues, "holdout_record:observations_invalid")
        observations = []
    scores: list[Fraction] = []
    for raw in observations:
        observation = _closed(raw, _OBSERVATION_FIELDS, "holdout_observation", issues)
        score_issues: list[str] = []
        score = _rational(observation.get("score"), "holdout_observation.score", score_issues)
        if score_issues:
            _issue(issues, "holdout_record:score_invalid")
        else:
            scores.append(_fraction(score))
        if not _sha_valid(observation.get("governed_report_sha256")):
            _issue(issues, "holdout_record:governed_report_sha256_invalid")
    aggregate_issues: list[str] = []
    aggregate = _rational(
        record.get("aggregate_score"), "holdout_record.aggregate_score", aggregate_issues
    )
    if aggregate_issues:
        _issue(issues, "holdout_record:aggregate_invalid")
    elif scores and _fraction(aggregate) != sum(scores, Fraction(0, 1)) / len(scores):
        _issue(issues, "holdout_record:aggregate_mismatch")
    if record.get("lineage_disjoint") is not True:
        _issue(issues, "holdout_record:lineage_invalid")
    return record


def summarize_holdout_conclusion(
    ledger_path: str | Path,
    campaign_sha256: str,
    conclusion_record_sha256: str,
) -> dict[str, Any]:
    """Recompute one holdout demotion from exact ledger records only."""

    if not _sha_valid(campaign_sha256) or not _sha_valid(conclusion_record_sha256):
        return _holdout_failure(None, ["conclusion:identity_invalid"])
    entries, chain_issues = _entries(ledger_path)
    if chain_issues:
        return _holdout_failure(campaign_sha256, chain_issues)
    conclusion = _find_record(
        entries, HOLDOUT_CONCLUSION_SCHEMA, conclusion_record_sha256
    )
    if conclusion is None:
        return _holdout_failure(campaign_sha256, ["conclusion:missing"])
    issues: list[str] = []
    conclusion_value = _closed(conclusion, _CONCLUSION_FIELDS, "conclusion", issues)
    if (
        conclusion_value.get("schema") != HOLDOUT_CONCLUSION_SCHEMA
        or not _seal_valid(conclusion_value)
        or conclusion_value.get("campaign_sha256") != campaign_sha256
    ):
        _issue(issues, "conclusion:invalid")
    replay_record = _find_record(
        entries,
        REPLAY_RECORD_SCHEMA,
        str(conclusion_value.get("replay_record_sha256")),
    )
    holdout_record = _find_record(
        entries,
        LIVE_HOLDOUT_RECORD_SCHEMA,
        str(conclusion_value.get("holdout_record_sha256")),
    )
    if replay_record is None or holdout_record is None:
        _issue(issues, "conclusion:source_missing")
    else:
        replay_issues: list[str] = []
        holdout_issues: list[str] = []
        _validate_replay_record(replay_record, replay_issues)
        _validate_holdout_record(holdout_record, holdout_issues)
        if replay_issues:
            _issue(issues, "conclusion:replay_invalid")
        if holdout_issues:
            _issue(issues, "conclusion:holdout_invalid")
        if (
            replay_record.get("campaign_sha256") != campaign_sha256
            or holdout_record.get("campaign_sha256") != campaign_sha256
            or replay_record.get("replay_plan_sha256")
            != conclusion_value.get("replay_plan_sha256")
            or holdout_record.get("replay_plan_sha256")
            != conclusion_value.get("replay_plan_sha256")
            or holdout_record.get("replay_record_sha256")
            != replay_record.get("record_sha256")
        ):
            _issue(issues, "conclusion:source_binding_mismatch")
    plan_records = [
        row["record"]
        for row in entries
        if row.get("record", {}).get("schema") == REPLAY_PLAN_RECORD_SCHEMA
        and row.get("record", {}).get("plan_sha256")
        == conclusion_value.get("replay_plan_sha256")
    ]
    if len(plan_records) != 1 or not _seal_valid(plan_records[0]):
        _issue(issues, "conclusion:plan_missing_or_invalid")
        plan = None
    else:
        plan_record = plan_records[0]
        plan = plan_record.get("replay_plan")
        policy_report = (
            validate_score_policy(plan.get("baseline_policy"))
            if isinstance(plan, Mapping)
            else {"status": "FAIL"}
        )
        tolerance_issues: list[str] = []
        if isinstance(plan, Mapping):
            _rational(
                plan.get("holdout_tolerance"),
                "replay_plan.holdout_tolerance",
                tolerance_issues,
                nonnegative=True,
            )
        if (
            not isinstance(plan, Mapping)
            or set(plan) != _PLAN_FIELDS
            or plan.get("schema") != REPLAY_PLAN_SCHEMA
            or plan.get("campaign_sha256") != campaign_sha256
            or plan_record.get("campaign_sha256") != campaign_sha256
            or plan.get("plan_sha256") != plan_record.get("plan_sha256")
            or not _seal_valid(plan, "plan_sha256")
            or policy_report.get("status") != "PASS"
            or tolerance_issues
        ):
            _issue(issues, "conclusion:plan_missing_or_invalid")
            plan = None
    if not issues and isinstance(plan, Mapping):
        replay_mean = _fraction(replay_record["aggregate_score"])
        holdout_mean = _fraction(holdout_record["aggregate_score"])
        tolerance = _fraction(plan["holdout_tolerance"])
        disagreement = abs(replay_mean - holdout_mean)
        demoted = disagreement > tolerance
        expected = {
            "replay_aggregate_score": _fraction_record(replay_mean),
            "holdout_aggregate_score": _fraction_record(holdout_mean),
            "absolute_disagreement": _fraction_record(disagreement),
            "holdout_tolerance": dict(plan["holdout_tolerance"]),
            "demoted": demoted,
            "conclusion_label": (
                "hypothesis_generation_only" if demoted else "holdout_consistent"
            ),
            "default_change_eligible": False,
        }
        for field, expected_value in expected.items():
            if conclusion_value.get(field) != expected_value:
                _issue(issues, "conclusion:derived_value_mismatch")
                break
    if issues:
        return _holdout_failure(campaign_sha256, issues)
    return _holdout_report(conclusion_value)


__all__ = [
    "HOLDOUT_CONCLUSION_SCHEMA",
    "HOLDOUT_REPORT_SCHEMA",
    "LIVE_HOLDOUT_EVIDENCE_SCHEMA",
    "LIVE_HOLDOUT_RECORD_SCHEMA",
    "MODEL_CALL_EVIDENCE_SCHEMA",
    "MODEL_CALL_RECORD_SCHEMA",
    "MODEL_CALL_REPORT_SCHEMA",
    "REPLAY_PLAN_DRAFT_SCHEMA",
    "REPLAY_PLAN_RECORD_SCHEMA",
    "REPLAY_PLAN_REPORT_SCHEMA",
    "REPLAY_PLAN_SCHEMA",
    "REPLAY_RECORD_SCHEMA",
    "REPLAY_REPORT_SCHEMA",
    "SCORE_POLICY_DRAFT_SCHEMA",
    "SCORE_POLICY_REPORT_SCHEMA",
    "SCORE_POLICY_SCHEMA",
    "record_live_holdout",
    "record_model_call",
    "register_replay_plan",
    "replay_campaign",
    "seal_replay_plan",
    "seal_score_policy",
    "summarize_holdout_conclusion",
    "validate_replay_plan",
    "validate_score_policy",
]
