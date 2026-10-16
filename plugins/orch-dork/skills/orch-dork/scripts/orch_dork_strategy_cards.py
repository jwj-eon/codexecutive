#!/usr/bin/env python3
"""Provider-free evaluation of closed Orch Dork strategy-card lifecycles.

The module owns one small public seam, :func:`evaluate`, dispatched over three
closed request actions:

* ``propose_card`` seals a candidate ``orch-dork/strategy-card/v1`` from one
  fully known terminal source record.  A single run can never yield an active
  card; the card always seals in the fixed ``candidate`` lifecycle state and
  external or model-authored observations are stored only as quoted
  non-executable evidence.
* ``decide_card`` produces an immutable lifecycle decision record for
  activate, retire, or quarantine.  Every decision requires either an exact
  explicit Owner review bound to the card or a sealed preregistered evidence
  rule with at least two lineage-distinct qualifying outcomes.  The evaluator
  returns records only and grants no mutation or authority.
* ``retrieve_cards`` performs bounded deterministic retrieval over supplied
  cards plus lifecycle records: active only, project exact, privacy may only
  narrow, unexpired, conflict-aware, duplicate/tamper-safe, at most three
  results, deterministic ranking, exact context-token charging, and visible
  source/evidence refs.  Returned advice is typed untrusted advisory data and
  grants no truth, evidence, execution, tools, or authority.

The evaluator is pure: no model or hosted calls, no file-backed store, no
second authority or state machine.  Lifecycle state is derived by pure
replay of decision records over the sealed candidate card.
"""

from __future__ import annotations

from copy import deepcopy
import importlib.util
from math import ceil
from pathlib import Path
import re
import sys
from typing import Any, Mapping


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


core = _load_sibling("orch_dork_evidence_core")
profiles = _load_sibling("orch_dork_workflow_profiles")


PROGRAM_SCHEMA = "orch-dork/strategy-card-program/v1"
SOURCE_SCHEMA = "orch-dork/strategy-source-record/v1"
CARD_SCHEMA = "orch-dork/strategy-card/v1"
OWNER_REVIEW_SCHEMA = "orch-dork/owner-review/v1"
PREREGISTERED_RULE_SCHEMA = "orch-dork/preregistered-rule/v1"
DECISION_RECORD_SCHEMA = "orch-dork/strategy-card-decision-record/v1"
REPORT_SCHEMA = "orch-dork/strategy-card-report/v1"
ADVISORY_SCHEMA = "orch-dork/strategy-card-advisory/v1"

ACTIONS = ("propose_card", "decide_card", "retrieve_cards")

PRIVACY_SCOPES = ("local_only", "hosted_restricted", "hosted_standard")
PRIVACY_RANK = {scope: rank for rank, scope in enumerate(PRIVACY_SCOPES)}
TERMINAL_OUTCOMES = ("success", "failure", "cancelled", "escalated")
VERIFICATION_STAGES = ("pass", "not_required", "failed", "escalated", "unknown")
CONFIDENCE_BASES = (
    "provenance",
    "lineage_count",
    "verification",
    "human_feedback",
)
LIFECYCLE_DECISIONS = ("activate", "retire", "quarantine")
CARD_STATES = ("candidate", "active", "retired", "quarantined")
DECISION_BASES = ("owner_review", "preregistered_rule")

MAX_TEXT_LENGTH = 4096
MAX_LIST_ITEMS = 16
MAX_REF_ITEMS = 16
MAX_LINEAGE_ITEMS = 16
MAX_RETRIEVE_RESULTS = 3
MIN_RULE_LINEAGES = 2
MAX_CANONICAL_BYTES = 262_144

ADVISORY_TOKEN_BASE = 64
ADVISORY_TOKEN_REF = 8
ADVISORY_TOKEN_LINEAGE = 4
ADVISORY_TOKEN_DIVISOR = 4

ADVISORY_GRANT_FIELDS = ("truth", "evidence", "execution", "tools", "authority")
EXCLUSION_REASONS = (
    "tampered",
    "duplicate",
    "not_active",
    "project_mismatch",
    "privacy_widening",
    "expired",
    "conflict",
)

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")

_PROGRAM_FIELDS = frozenset({"schema", "action", "request"})
_PROPOSE_FIELDS = frozenset({"source_record"})
_DECIDE_FIELDS = frozenset({"card", "decisions", "review", "rule", "decided_at"})
_RETRIEVE_FIELDS = frozenset(
    {
        "cards",
        "decisions",
        "project_id",
        "privacy_scope",
        "now",
        "context_token_budget",
    }
)

_SOURCE_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "run_lineage_sha256",
        "task_fingerprint",
        "project_id",
        "privacy_scope",
        "profile_id",
        "terminal_outcome",
        "verification",
        "source_refs",
        "evidence_refs",
        "observations",
        "supporting_lineages",
        "contradicting_lineages",
        "useful_strategy",
        "failure_pattern",
        "confidence",
        "confidence_basis",
        "created_at",
        "expires_at",
        "usage",
        "feedback",
        "run_generation",
    }
)
_CARD_FIELDS = frozenset(
    {
        field
        for field in _SOURCE_FIELDS
        if field not in ("run_id", "run_lineage_sha256")
    }
    | frozenset
    (
        {
            "provenance_run",
            "provenance_lineage_sha256",
            "lifecycle_state",
            "card_sha256",
        }
    )
)

_LINEAGE_FIELDS = frozenset({"run_id", "lineage_sha256", "outcome"})
_STRATEGY_FIELDS = frozenset({"statement", "factor_refs"})
_VERIFICATION_FIELDS = frozenset({"stage", "evidence_refs"})
_USAGE_FIELDS = frozenset({"tokens", "cost_cents", "wall_seconds"})
_FEEDBACK_FIELDS = frozenset({"score", "comment"})
_GENERATION_FIELDS = frozenset({"model", "runtime", "evaluator_version"})
_OWNER_REVIEW_FIELDS = frozenset(
    {
        "schema",
        "review_id",
        "operator_id",
        "card_sha256",
        "decision",
        "rationale",
        "decided_at",
        "review_sha256",
    }
)
_RULE_FIELDS = frozenset(
    {
        "schema",
        "rule_id",
        "decision_allowed",
        "min_distinct_lineages",
        "qualifying_outcomes",
        "created_at",
        "rule_sha256",
    }
)
_DECISION_RECORD_FIELDS = frozenset(
    {
        "schema",
        "card_sha256",
        "decision",
        "basis",
        "basis_sha256",
        "from_state",
        "to_state",
        "qualifying_lineages",
        "contradicted",
        "decided_at",
        "decision_sha256",
    }
)
_ADVISORY_FIELDS = frozenset(
    {
        "schema",
        "card_sha256",
        "task_fingerprint",
        "project_id",
        "privacy_scope",
        "profile_id",
        "terminal_outcome",
        "verification_stage",
        "kind",
        "statement",
        "factor_refs",
        "confidence",
        "confidence_basis",
        "created_at",
        "expires_at",
        "current_state",
        "source_refs",
        "evidence_refs",
        "supporting_lineages",
        "contradicting_lineages",
        "observations",
        "quoted_evidence_only",
        "untrusted_advisory",
        "grants",
        "token_charge",
    }
)

DECISION_CARD_PROPOSED = "CARD_PROPOSED"
DECISION_SOURCE_REJECTED = "SOURCE_REJECTED"
DECISION_LIFECYCLE_DECIDED = "LIFECYCLE_DECIDED"
DECISION_CARD_REJECTED = "CARD_REJECTED"
DECISION_TRANSITION_INVALID = "TRANSITION_INVALID"
DECISION_BASIS_MISSING = "DECISION_BASIS_MISSING"
DECISION_BASIS_CONFLICT = "DECISION_BASIS_CONFLICT"
DECISION_REVIEW_REJECTED = "REVIEW_REJECTED"
DECISION_RULE_REJECTED = "RULE_REJECTED"
DECISION_CONFLICT_UNRESOLVED = "CONFLICT_UNRESOLVED"
DECISION_LINEAGE_INSUFFICIENT = "LINEAGE_INSUFFICIENT"
DECISION_DECISION_REJECTED = "DECISION_REJECTED"
DECISION_REJECTED = DECISION_DECISION_REJECTED
DECISION_RETRIEVED = "RETRIEVED"
DECISION_EMPTY = "EMPTY"
DECISION_BUDGET_EXCEEDED = "CONTEXT_BUDGET_EXCEEDED"
DECISION_RETRIEVE_REJECTED = "REJECTED"
DECISION_ENVELOPE_INVALID = "ENVELOPE_INVALID"

_TRANSITIONS = {
    ("activate", "candidate"): "active",
    ("retire", "candidate"): "retired",
    ("retire", "active"): "retired",
    ("quarantine", "candidate"): "quarantined",
    ("quarantine", "active"): "quarantined",
}


def _transition(decision: Any, from_state: Any) -> str | None:
    return _TRANSITIONS.get((decision, from_state))


def _is_identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _closed(value: Any, fields: frozenset, label: str, issues: list[str]):
    if not isinstance(value, Mapping):
        core.add_issue(issues, label + ":not_object")
        return None
    for key in value:
        if not isinstance(key, str):
            core.add_issue(issues, label + ":non_string_keys")
            return None
    return core.closed(value, fields, label, issues)


def _bounded_str(
    value: Any, label: str, issues: list[str], *, allow_empty: bool = False
) -> str | None:
    if not isinstance(value, str):
        core.add_issue(issues, label + ":not_string")
        return None
    if len(value) > MAX_TEXT_LENGTH:
        core.add_issue(issues, label + ":too_long")
        return None
    if not allow_empty and not value:
        core.add_issue(issues, label + ":empty")
        return None
    return value


def _refs(
    value: Any,
    label: str,
    issues: list[str],
    *,
    minimum: int,
    maximum: int,
) -> list[str] | None:
    if not isinstance(value, list):
        core.add_issue(issues, label + ":not_list")
        return None
    if not minimum <= len(value) <= maximum:
        core.add_issue(issues, label + ":bounds")
        return None
    seen = set()
    for item in value:
        if not _is_identifier(item):
            core.add_issue(issues, label + ":item_invalid")
            return None
        if item in seen:
            core.add_issue(issues, label + ":duplicate")
            return None
        seen.add(item)
    return list(value)


def _lineages(
    value: Any,
    label: str,
    issues: list[str],
    *,
    self_sha: Any,
    require_self: bool,
    forbid_self: bool,
     minimum: int = 0,
) -> list[dict[str, Any]] | None:
    if not isinstance(value, list):
        core.add_issue(issues, label + ":not_list")
        return None
    if len(value) < minimum:
        core.add_issue(issues, label + ":empty")
        return None
    if len(value) > MAX_LINEAGE_ITEMS:
        core.add_issue(issues, label + ":too_many")
        return None
    shas: set[str] = set()
    self_count = 0
    entries: list[dict[str, Any]] = []
    for entry in value:
        if _closed(entry, _LINEAGE_FIELDS, label + ":entry", issues) is None:
            return None
        if not _is_identifier(entry["run_id"]):
            core.add_issue(issues, label + ":run_id_invalid")
            return None
        if not _is_sha(entry["lineage_sha256"]):
            core.add_issue(issues, label + ":lineage_sha_invalid")
            return None
        if entry["outcome"] not in TERMINAL_OUTCOMES:
            core.add_issue(issues, label + ":outcome_invalid")
            return None
        if entry["lineage_sha256"] in shas:
            core.add_issue(issues, label + ":duplicate_lineage")
            return None
        shas.add(entry["lineage_sha256"])
        if self_sha is not None and entry["lineage_sha256"] == self_sha:
            self_count += 1
        entries.append(dict(entry))
    if self_sha is not None and require_self and self_count == 0:
        core.add_issue(issues, label + ":self_lineage_missing")
        return None
    if self_sha is not None and require_self and self_count > 1:
        core.add_issue(issues, label + ":self_lineage_doubled")
        return None
    if self_sha is not None and forbid_self and self_count > 0:
        core.add_issue(issues, label + ":self_contradiction")
        return None
    return entries


def _strategy(
    value: Any, label: str, issues: list[str]
) -> dict[str, Any] | None:
    if value is None:
        return None
    if _closed(value, _STRATEGY_FIELDS, label, issues) is None:
        return None
    if _bounded_str(value["statement"], label + ":statement", issues) is None:
        return None
    if _refs(
        value["factor_refs"],
        label + ":factor_refs",
        issues,
        minimum=1,
        maximum=MAX_REF_ITEMS,
    ) is None:
        return None
    return dict(value)


def _verification(
    value: Any, label: str, issues: list[str], outcome: Any
) -> dict[str, Any] | None:
    if _closed(value, _VERIFICATION_FIELDS, label, issues) is None:
        return None
    stage = value["stage"]
    if stage not in VERIFICATION_STAGES:
        core.add_issue(issues, label + ":stage_invalid")
        return None
    evidence_refs = _refs(
        value["evidence_refs"],
        label + ":evidence_refs",
        issues,
        minimum=0,
        maximum=MAX_REF_ITEMS,
    )
    if evidence_refs is None:
        return None
    if stage == "pass" and not evidence_refs:
        core.add_issue(issues, label + ":pass_requires_refs")
        return None
    if outcome == "success" and stage not in ("pass", "not_required"):
        core.add_issue(issues, label + ":success_requires_passed_verification")
        return None
    return dict(value)


def _int_field(value: Any, label: str, issues: list[str], *, lo: int, hi: int) -> None:
    if type(value) is not int or not lo <= value <= hi:
        core.add_issue(issues, label + ":value_invalid")


def _stricted(issues: list[str], label: str) -> bool:
    return (
        label + ":value_invalid" in issues
        or label + ":not_string" in issues
        or label + ":too_long" in issues
    )


def _verdict(issues: list[str]) -> dict[str, Any]:
    unique = sorted(set(issues))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


def _validate_record_fields(
    rec: Mapping[str, Any],
    label: str,
    issues: list[str],
    run_id: Any,
    self_lineage_sha: Any,
) -> bool:
    ok = True
    if not _is_identifier(run_id):
        core.add_issue(issues, label + ":run_id_invalid")
        ok = False
    if not _is_sha(self_lineage_sha):
        core.add_issue(issues, label + ":lineage_sha_invalid")
        ok = False
    if not _is_sha(rec["task_fingerprint"]):
        core.add_issue(issues, label + ":task_fingerprint_invalid")
        ok = False
    if not _is_identifier(rec["project_id"]):
        core.add_issue(issues, label + ":project_id_invalid")
        ok = False
    if rec["privacy_scope"] not in PRIVACY_RANK:
        core.add_issue(issues, label + ":privacy_invalid")
        ok = False
    if not _is_identifier(rec["profile_id"]):
        core.add_issue(issues, label + ":profile_id_invalid")
        ok = False
    else:
        try:
            profiles.profile(rec["profile_id"])
        except Exception:
            core.add_issue(issues, label + ":profile_unregistered")
            ok = False
    outcome = rec["terminal_outcome"]
    if outcome not in TERMINAL_OUTCOMES:
        core.add_issue(issues, label + ":outcome_invalid")
        ok = False
    if (
        _verification(
            rec["verification"], label + ":verification", issues, outcome
        )
        is None
    ):
        ok = False
    source_refs = _refs(
        rec["source_refs"],
        label + ":source_refs",
        issues,
        minimum=1,
        maximum=MAX_REF_ITEMS,
    )
    if source_refs is None:
        ok = False
    elif _is_identifier(run_id) and run_id not in source_refs:
        core.add_issue(issues, label + ":source_refs:provenance_missing")
        ok = False
    if _refs(
        rec["evidence_refs"],
        label + ":evidence_refs",
        issues,
        minimum=1,
        maximum=MAX_REF_ITEMS,
    ) is None:
        ok = False
    observations = rec["observations"]
    if not isinstance(observations, list) or len(observations) > MAX_LIST_ITEMS:
        core.add_issue(issues, label + ":observations_invalid")
        ok = False
    else:
        for obs in observations:
            if not isinstance(obs, str) or not obs or len(obs) > MAX_TEXT_LENGTH:
                core.add_issue(issues, label + ":observations_item_invalid")
                ok = False
                break
    if _lineages(
        rec["supporting_lineages"],
        label + ":supporting_lineages",
        issues,
        self_sha=self_lineage_sha,
        require_self=True,
        forbid_self=False,
        minimum=1,
    ) is None:
        ok = False
    if _lineages(
        rec["contradicting_lineages"],
        label + ":contradicting_lineages",
        issues,
        self_sha=self_lineage_sha,
        require_self=False,
        forbid_self=True,
    ) is None:
        ok = False
    useful = rec["useful_strategy"]
    failure = rec["failure_pattern"]
    if (useful is None) == (failure is None):
        core.add_issue(issues, label + ":strategy_exclusivity")
        ok = False
    elif (
        useful is not None
        and _strategy(useful, label + ":useful_strategy", issues) is None
    ):
        ok = False
    elif (
        failure is not None
        and _strategy(failure, label + ":failure_pattern", issues) is None
    ):
        ok = False
    _int_field(rec["confidence"], label + ":confidence", issues, lo=1, hi=100)
    if label + ":confidence:value_invalid" in issues:
        ok = False
    if rec["confidence_basis"] not in CONFIDENCE_BASES:
        core.add_issue(issues, label + ":confidence_basis_invalid")
        ok = False
    created_at = core.instant(rec["created_at"])
    expires_at = core.instant(rec["expires_at"])
    if created_at is None:
        core.add_issue(issues, label + ":created_at_invalid")
        ok = False
    if expires_at is None:
        core.add_issue(issues, label + ":expires_at_invalid")
        ok = False
    if created_at is not None and expires_at is not None and expires_at <= created_at:
        core.add_issue(issues, label + ":expires_not_after_created")
        ok = False
    usage = rec["usage"]
    if _closed(usage, _USAGE_FIELDS, label + ":usage", issues) is None:
        ok = False
    else:
        for field in sorted(_USAGE_FIELDS):
            _int_field(
                usage[field], label + ":usage:" + field, issues, lo=0, hi=10**12
            )
        if any(issue.startswith(label + ":usage:") for issue in issues):
            ok = False
    feedback = rec["feedback"]
    if _closed(feedback, _FEEDBACK_FIELDS, label + ":feedback", issues) is None:
        ok = False
    else:
        _int_field(feedback["score"], label + ":feedback:score", issues, lo=1, hi=100)
        if (
            label + ":feedback:score:value_invalid" in issues
            or _stricted(issues, label + ":feedback:comment")
        ):
            ok = False
    generation = rec["run_generation"]
    if _closed(generation, _GENERATION_FIELDS, label + ":run_generation", issues) is None:
        ok = False
    else:
        if not _is_identifier(generation["model"]):
            core.add_issue(issues, label + ":generation_model_invalid")
            ok = False
        if not _is_identifier(generation["runtime"]):
            core.add_issue(issues, label + ":generation_runtime_invalid")
            ok = False
        _int_field(
            generation["evaluator_version"],
            label + ":generation_version",
            issues,
            lo=1,
            hi=10**9,
        )
        if any(issue.startswith(label + ":generation_") for issue in issues):
            ok = False
    return ok


def validate_source_record(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    rec = _closed(value, _SOURCE_FIELDS, "source", issues)
    if rec is not None:
        if rec["schema"] != SOURCE_SCHEMA:
            core.add_issue(issues, "source:schema_mismatch")
        else:
            _validate_record_fields(
                rec, "source", issues, rec["run_id"], rec["run_lineage_sha256"]
            )
    return _verdict(issues)


def validate_card(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    rec = _closed(value, _CARD_FIELDS, "card", issues)
    if rec is not None:
        if rec["schema"] != CARD_SCHEMA:
            core.add_issue(issues, "card:schema_mismatch")
        elif not _is_identifier(rec["provenance_run"]):
            core.add_issue(issues, "card:provenance_run_invalid")
        elif not _is_sha(rec["provenance_lineage_sha256"]):
            core.add_issue(issues, "card:provenance_lineage_invalid")
        elif rec["lifecycle_state"] != "candidate":
            core.add_issue(issues, "card:state_not_candidate")
        else:
            _validate_record_fields(
                rec,
                "card",
                issues,
                rec["provenance_run"],
                rec["provenance_lineage_sha256"],
            )
            if not any(
                issue.startswith("card:state_not_candidate")
                for issue in issues
            ):
                if not core.check_seal(rec, "card_sha256"):
                    core.add_issue(issues, "card:seal_invalid")
    return _verdict(issues)


def build_card_from_source(
    source: Mapping[str, Any],
) -> tuple[str, dict[str, Any] | None]:
    validation = validate_source_record(source)
    if validation["status"] != "PASS":
        card_sha = None
        card = None
    else:
        card_core = {
            field: deepcopy(source[field]) for field in sorted(_CARD_FIELDS) if field in source
        }
        card_core["provenance_run"] = source["run_id"]
        card_core["provenance_lineage_sha256"] = source["run_lineage_sha256"]
        card_core["schema"] = CARD_SCHEMA
        card_core["lifecycle_state"] = "candidate"
        card_sha = core.digest(card_core)
        card = {"card_sha256": card_sha, **card_core}
    return card_sha, card


def validate_owner_review(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    rec = _closed(value, _OWNER_REVIEW_FIELDS, "review", issues)
    if rec is not None:
        if rec["schema"] != OWNER_REVIEW_SCHEMA:
            core.add_issue(issues, "review:schema_mismatch")
        else:
            if not _is_identifier(rec["review_id"]):
                core.add_issue(issues, "review:review_id_invalid")
            if not _is_identifier(rec["operator_id"]):
                core.add_issue(issues, "review:operator_id_invalid")
            if not _is_sha(rec["card_sha256"]):
                core.add_issue(issues, "review:card_binding_invalid")
            if rec["decision"] not in LIFECYCLE_DECISIONS:
                core.add_issue(issues, "review:decision_invalid")
            if (
                _bounded_str(rec["rationale"], "review:rationale", issues)
                is None
            ):
                pass
            if core.instant(rec["decided_at"]) is None:
                core.add_issue(issues, "review:decided_at_invalid")
            if not core.check_seal(rec, "review_sha256"):
                core.add_issue(issues, "review:seal_invalid")
    return _verdict(issues)


def validate_rule(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    rec = _closed(value, _RULE_FIELDS, "rule", issues)
    if rec is not None:
        if rec["schema"] != PREREGISTERED_RULE_SCHEMA:
            core.add_issue(issues, "rule:schema_mismatch")
        else:
            if not _is_identifier(rec["rule_id"]):
                core.add_issue(issues, "rule:rule_id_invalid")
            if rec["decision_allowed"] not in LIFECYCLE_DECISIONS:
                core.add_issue(issues, "rule:decision_invalid")
            if (
                type(rec["min_distinct_lineages"]) is not int
                or rec["min_distinct_lineages"] < MIN_RULE_LINEAGES
            ):
                core.add_issue(issues, "rule:min_lineages_invalid")
            outcomes = rec["qualifying_outcomes"]
            if (
                not isinstance(outcomes, list)
                or not outcomes
                or len(outcomes) > len(TERMINAL_OUTCOMES)
                or any(
                    not isinstance(item, str) or item not in TERMINAL_OUTCOMES
                    for item in outcomes
                )
                or len(set(outcomes)) != len(outcomes)
            ):
                core.add_issue(issues, "rule:qualifying_outcomes_invalid")
            if core.instant(rec["created_at"]) is None:
                core.add_issue(issues, "rule:created_at_invalid")
            if not core.check_seal(rec, "rule_sha256"):
                core.add_issue(issues, "rule:seal_invalid")
    return _verdict(issues)


def validate_decision_record(value: Any) -> dict[str, Any]:
    issues: list[str] = []
    rec = _closed(value, _DECISION_RECORD_FIELDS, "record", issues)
    if rec is not None:
        if rec["schema"] != DECISION_RECORD_SCHEMA:
            core.add_issue(issues, "record:schema_mismatch")
        else:
            if not _is_sha(rec["card_sha256"]):
                core.add_issue(issues, "record:card_binding_invalid")
            if rec["decision"] not in LIFECYCLE_DECISIONS:
                core.add_issue(issues, "record:decision_invalid")
            if rec["basis"] not in DECISION_BASES:
                core.add_issue(issues, "record:basis_invalid")
            if not _is_sha(rec["basis_sha256"]):
                core.add_issue(issues, "record:basis_sha_invalid")
            if rec["from_state"] not in CARD_STATES or rec["to_state"] not in CARD_STATES:
                core.add_issue(issues, "record:state_invalid")
            elif rec["to_state"] != _transition(rec["decision"], rec["from_state"]):
                core.add_issue(issues, "record:transition_invalid")
            qualifying = rec["qualifying_lineages"]
            if (
                not isinstance(qualifying, list)
                or len(qualifying) > MAX_LINEAGE_ITEMS
                or not all(_is_sha(item) for item in qualifying)
                or len(set(qualifying)) != len(qualifying)
            ):
                core.add_issue(issues, "record:qualifying_lineages_invalid")
            if type(rec["contradicted"]) is not bool:
                core.add_issue(issues, "record:contradicted_invalid")
            if core.instant(rec["decided_at"]) is None:
                core.add_issue(issues, "record:decided_at_invalid")
            if not core.check_seal(rec, "decision_sha256"):
                core.add_issue(issues, "record:seal_invalid")
    return _verdict(issues)


def derive_card_state(card_sha: Any, decisions: Any) -> str | None:
    if not isinstance(card_sha, str) or not isinstance(decisions, list):
        return None
    matching = [
        record
        for record in decisions
        if isinstance(record, Mapping) and record.get("card_sha256") == card_sha
    ]
    for record in matching:
        if not core.check_seal(record, "decision_sha256"):
            return None
    entries = sorted(
        matching,
        key=lambda record: (
            str(record.get("decided_at")),
            str(record.get("decision_sha256")),
        ),
    )
    state = "candidate"
    for record in entries:
        if (
            not _is_sha(record.get("card_sha256"))
            or not _is_sha(record.get("decision_sha256"))
            or not isinstance(record.get("decided_at"), str)
            or record.get("decision") not in LIFECYCLE_DECISIONS
            or record.get("from_state") != state
            or record.get("to_state") != _transition(record.get("decision"), state)
            or type(record.get("contradicted")) is not bool
        ):
            return None
        state = record["to_state"]
    return state


def advisory_context_tokens(advisory: Any) -> int:
    if not isinstance(advisory, Mapping):
        return 0
    def _count(value: Any) -> int:
        return len(value) if isinstance(value, list) else 0

    statement = advisory.get("statement")
    statement_len = len(statement) if isinstance(statement, str) else 0
    try:
        charge = ADVISORY_TOKEN_BASE
        charge += ADVISORY_TOKEN_REF * _count(advisory.get("source_refs"))
        charge += ADVISORY_TOKEN_REF * _count(advisory.get("evidence_refs"))
        charge += ADVISORY_TOKEN_LINEAGE * _count(
            advisory.get("supporting_lineages")
        )
        charge += ADVISORY_TOKEN_LINEAGE * _count(
            advisory.get("contradicting_lineages")
        )
        charge += ceil(statement_len / ADVISORY_TOKEN_DIVISOR)
        return charge
    except Exception:
        return 0


def _advisory(card: Mapping[str, Any], card_sha: str) -> dict[str, Any]:
    verification = card["verification"]
    if isinstance(verification, Mapping) and isinstance(
        verification.get("stage"), str
    ):
        stage = verification.get("stage")
    else:
        stage = "unknown"
    if card["useful_strategy"] is not None:
        kind = "useful_strategy"
        strategy = card["useful_strategy"]
    else:
        kind = "failure_pattern"
        strategy = card["failure_pattern"]
    strategy = strategy if isinstance(strategy, Mapping) else {}
    factor_refs = strategy.get("factor_refs")
    advisory = {
        "schema": ADVISORY_SCHEMA,
        "card_sha256": card_sha,
        "task_fingerprint": card["task_fingerprint"],
        "project_id": card["project_id"],
        "privacy_scope": card["privacy_scope"],
        "profile_id": card["profile_id"],
        "terminal_outcome": card["terminal_outcome"],
        "verification_stage": stage,
        "kind": kind,
        "statement": strategy.get("statement"),
        "factor_refs": (
            deepcopy(factor_refs) if isinstance(factor_refs, list) else []
        ),
        "confidence": card["confidence"],
        "confidence_basis": card["confidence_basis"],
        "created_at": card["created_at"],
        "expires_at": card["expires_at"],
        "current_state": "active",
        "source_refs": deepcopy(card["source_refs"]),
        "evidence_refs": deepcopy(card["evidence_refs"]),
        "supporting_lineages": deepcopy(card["supporting_lineages"]),
        "contradicting_lineages": deepcopy(card["contradicting_lineages"]),
        "observations": deepcopy(card["observations"]),
        "quoted_evidence_only": True,
        "untrusted_advisory": True,
        "grants": {field: False for field in ADVISORY_GRANT_FIELDS},
    }
    advisory["token_charge"] = advisory_context_tokens(advisory)
    return advisory


def _blank_payload(action: str) -> dict[str, Any]:
    if action == "propose_card":
        return {"card": None, "card_sha256": None}
    if action == "decide_card":
        return {
            "card_sha256": None,
            "lifecycle_decision": None,
            "from_state": None,
            "to_state": None,
            "decision_record": None,
        }
    return {
        "advisories": [],
        "context_tokens_charged": 0,
        "context_tokens_requested": 0,
        "conflicts": [],
        "excluded": {reason: 0 for reason in EXCLUSION_REASONS},
        "duplicates_removed": 0,
    }


def _evaluate_propose_card(
    request: Any, issues: list[str]
) -> tuple[str, list[str], dict[str, Any]]:
    payload = _blank_payload("propose_card")
    if not isinstance(request, Mapping):
        core.add_issue(issues, "request:not_object")
        return DECISION_ENVELOPE_INVALID, issues, payload
    if _closed(request, _PROPOSE_FIELDS, "request", issues) is None:
        return DECISION_ENVELOPE_INVALID, issues, payload
    source = _closed(
        request["source_record"], _SOURCE_FIELDS, "request:source_record", issues
    )
    if source is None:
        return DECISION_ENVELOPE_INVALID, issues, payload
    verdict = validate_source_record(source)
    if verdict["status"] != "PASS":
        issues.extend(verdict["issues"])
        return DECISION_SOURCE_REJECTED, issues, payload
    card_sha, card = build_card_from_source(source)
    payload["card"] = card
    payload["card_sha256"] = card_sha
    return DECISION_CARD_PROPOSED, issues, payload


def _evaluate_decide_card(
    request: Any, issues: list[str]
) -> tuple[str, list[str], dict[str, Any]]:
    payload = _blank_payload("decide_card")
    if not isinstance(request, Mapping):
        core.add_issue(issues, "request:not_object")
        return DECISION_ENVELOPE_INVALID, issues, payload
    if _closed(request, _DECIDE_FIELDS, "request", issues) is None:
        return DECISION_ENVELOPE_INVALID, issues, payload
    card = request["card"]
    if validate_card(card)["status"] != "PASS":
        issues.extend(validate_card(card)["issues"])
        return DECISION_CARD_REJECTED, issues, payload
    decisions = request["decisions"]
    if not isinstance(decisions, list):
        core.add_issue(issues, "request:decisions_not_list")
        return DECISION_ENVELOPE_INVALID, issues, payload
    ledger_bad = False
    for record in decisions:
        if validate_decision_record(record)["status"] != "PASS":
            ledger_bad = True
            break
    if ledger_bad:
        core.add_issue(issues, "ledger:record_invalid")
        return DECISION_TRANSITION_INVALID, issues, payload
    card_sha = card["card_sha256"]
    state = derive_card_state(card_sha, decisions)
    if state is None:
        core.add_issue(issues, "ledger:chain_invalid")
        return DECISION_TRANSITION_INVALID, issues, payload
    decided_raw = request["decided_at"]
    decided = core.instant(decided_raw)
    if decided is None:
        core.add_issue(issues, "request:decided_at_invalid")
        return DECISION_ENVELOPE_INVALID, issues, payload
    for record in decisions:
        if not isinstance(record, Mapping) or record.get("card_sha256") != card_sha:
            continue
        past = core.instant(record.get("decided_at"))
        if past is not None and decided <= past:
            core.add_issue(issues, "ledger:decided_at_not_after")
            return DECISION_TRANSITION_INVALID, issues, payload
    review = request["review"]
    rule = request["rule"]
    if not (review is None or isinstance(review, Mapping)) or not (
        rule is None or isinstance(rule, Mapping)
    ):
        core.add_issue(issues, "request:basis_not_object")
        return DECISION_ENVELOPE_INVALID, issues, payload
    if review is None and rule is None:
        core.add_issue(issues, "basis:missing")
        return DECISION_BASIS_MISSING, issues, payload
    if review is not None and rule is not None:
        core.add_issue(issues, "basis:both_provided")
        return DECISION_BASIS_CONFLICT, issues, payload
    qualifying: list[str] = []
    contradicted = bool(card["contradicting_lineages"])
    if review is not None:
        verdict = validate_owner_review(review)
        if verdict["status"] != "PASS":
            issues.extend(verdict["issues"])
            return DECISION_REVIEW_REJECTED, issues, payload
        if review["card_sha256"] != card_sha:
            core.add_issue(issues, "review:card_binding_mismatch")
            return DECISION_REVIEW_REJECTED, issues, payload
        decision_value = review["decision"]
        basis = "owner_review"
        basis_sha = review["review_sha256"]
    else:
        verdict = validate_rule(rule)
        if verdict["status"] != "PASS":
            issues.extend(verdict["issues"])
            return DECISION_RULE_REJECTED, issues, payload
        decision_value = rule["decision_allowed"]
        basis = "preregistered_rule"
        basis_sha = rule["rule_sha256"]
        if decision_value == "activate" and contradicted:
            core.add_issue(issues, "conflict:unresolved")
            return DECISION_CONFLICT_UNRESOLVED, issues, payload
        qualifying = sorted(
            {
                entry["lineage_sha256"]
                for entry in card["supporting_lineages"]
                if entry["outcome"] in rule["qualifying_outcomes"]
            }
        )
        if len(qualifying) < rule["min_distinct_lineages"]:
            core.add_issue(issues, "lineage:insufficient_distinct")
            return DECISION_LINEAGE_INSUFFICIENT, issues, payload
    to_state = _transition(decision_value, state)
    if to_state is None:
        if state in ("retired", "quarantined"):
            core.add_issue(issues, "ledger:final_state")
        else:
            core.add_issue(issues, "ledger:invalid_transition")
        return DECISION_TRANSITION_INVALID, issues, payload
    record = core.seal(
        {
            "schema": DECISION_RECORD_SCHEMA,
            "card_sha256": card_sha,
            "decision": decision_value,
            "basis": basis,
            "basis_sha256": basis_sha,
            "from_state": state,
            "to_state": to_state,
            "qualifying_lineages": (
                qualifying if basis == "preregistered_rule" else []
            ),
            "contradicted": contradicted,
            "decided_at": decided_raw,
        },
        "decision_sha256",
    )
    if validate_decision_record(record)["status"] != "PASS":
        core.add_issue(issues, "record:self_invalid")
        return DECISION_DECISION_REJECTED, issues, payload
    payload["card_sha256"] = card_sha
    payload["lifecycle_decision"] = decision_value
    payload["from_state"] = state
    payload["to_state"] = to_state
    payload["decision_record"] = record
    return DECISION_LIFECYCLE_DECIDED, issues, payload


def _evaluate_retrieve_cards(
    request: Any, issues: list[str]
) -> tuple[str, list[str], dict[str, Any]]:
    payload = _blank_payload("retrieve_cards")
    if not isinstance(request, Mapping):
        core.add_issue(issues, "request:not_object")
        return DECISION_ENVELOPE_INVALID, issues, payload
    if _closed(request, _RETRIEVE_FIELDS, "request", issues) is None:
        return DECISION_ENVELOPE_INVALID, issues, payload
    cards = request["cards"]
    if not isinstance(cards, list):
        core.add_issue(issues, "request:cards_not_list")
        return DECISION_RETRIEVE_REJECTED, issues, payload
    decisions = request["decisions"]
    if not isinstance(decisions, list):
        core.add_issue(issues, "request:decisions_not_list")
        return DECISION_RETRIEVE_REJECTED, issues, payload
    for record in decisions:
        if validate_decision_record(record)["status"] != "PASS":
            core.add_issue(issues, "decision:record_invalid")
            return DECISION_RETRIEVE_REJECTED, issues, payload
    if not _is_identifier(request["project_id"]):
        core.add_issue(issues, "request:project_id_invalid")
        return DECISION_RETRIEVE_REJECTED, issues, payload
    if request["privacy_scope"] not in PRIVACY_RANK:
        core.add_issue(issues, "request:privacy_scope_invalid")
        return DECISION_RETRIEVE_REJECTED, issues, payload
    now = core.instant(request["now"])
    if now is None:
        core.add_issue(issues, "request:now_invalid")
        return DECISION_RETRIEVE_REJECTED, issues, payload
    budget = request["context_token_budget"]
    if type(budget) is not int or budget < 0:
        core.add_issue(issues, "request:budget_invalid")
        return DECISION_RETRIEVE_REJECTED, issues, payload
    excluded = {reason: 0 for reason in EXCLUSION_REASONS}
    seen: set[str] = set()
    conflicts: list[str] = []
    eligible: list[tuple[dict[str, Any], str]] = []
    for card in cards:
        if not isinstance(card, Mapping):
            excluded["tampered"] += 1
            continue
        if validate_card(card)["status"] != "PASS":
            excluded["tampered"] += 1
            continue
        card_sha = card["card_sha256"]
        if card_sha in seen:
            excluded["duplicate"] += 1
            continue
        seen.add(card_sha)
        if derive_card_state(card_sha, decisions) != "active":
            excluded["not_active"] += 1
            continue
        if card["project_id"] != request["project_id"]:
            excluded["project_mismatch"] += 1
            continue
        if PRIVACY_RANK[request["privacy_scope"]] > PRIVACY_RANK[
            card["privacy_scope"]
        ]:
            excluded["privacy_widening"] += 1
            continue
        expires = core.instant(card["expires_at"])
        if expires is None or expires <= now:
            excluded["expired"] += 1
            continue
        if card["contradicting_lineages"]:
            excluded["conflict"] += 1
            conflicts.append(card_sha)
            continue
        eligible.append((card, card_sha))
    payload["excluded"] = excluded
    payload["duplicates_removed"] = excluded["duplicate"]
    payload["conflicts"] = sorted(conflicts)
    if not eligible:
        return DECISION_EMPTY, issues, payload
    ranked = sorted(
        eligible,
        key=lambda item: (-int(item[0]["confidence"]), item[1]),
    )
    top = ranked[:MAX_RETRIEVE_RESULTS]
    advisories = [_advisory(card, sha) for card, sha in top]
    requested = sum(advisory["token_charge"] for advisory in advisories)
    payload["context_tokens_requested"] = requested
    if requested > budget:
        payload["advisories"] = []
        payload["context_tokens_charged"] = 0
        return DECISION_BUDGET_EXCEEDED, issues, payload
    payload["advisories"] = advisories
    payload["context_tokens_charged"] = requested
    return DECISION_RETRIEVED, issues, payload


_HANDLERS = {
    "propose_card": _evaluate_propose_card,
    "decide_card": _evaluate_decide_card,
    "retrieve_cards": _evaluate_retrieve_cards,
}


def evaluate(program: Any) -> dict[str, Any]:
    issues: list[str] = []
    action: str | None = None
    if isinstance(program, Mapping) and any(
        not isinstance(key, str) for key in program
    ):
        envelope = _closed(program, _PROGRAM_FIELDS, "program", issues)
    else:
        try:
            canonical = core.canonical_bytes(program)
            if len(canonical) > MAX_CANONICAL_BYTES:
                raise ValueError("canonical_bytes_exceeded")
        except (TypeError, ValueError, OverflowError):
            core.add_issue(issues, "input:hostile_or_noncanonical")
            envelope = None
        else:
            envelope = _closed(program, _PROGRAM_FIELDS, "program", issues)
    decision = DECISION_ENVELOPE_INVALID
    payload: dict[str, Any] | None = None
    if envelope is not None:
        raw_action = envelope["action"]
        if envelope["schema"] != PROGRAM_SCHEMA:
            core.add_issue(issues, "program:schema_mismatch")
        if envelope["schema"] == PROGRAM_SCHEMA and raw_action in ACTIONS:
            action = raw_action
            try:
                decision, issues, payload = _HANDLERS[action](
                    envelope["request"], issues
                )
            except Exception:
                decision = DECISION_ENVELOPE_INVALID
                payload = None
                core.add_issue(issues, "program:internal_error")
        elif raw_action not in ACTIONS:
            core.add_issue(issues, "program:action_invalid")
    if payload is None:
        payload = _blank_payload(action if action in ACTIONS else "retrieve_cards")
    report = {
        "schema": REPORT_SCHEMA,
        "action": action if action in ACTIONS else "unknown",
        "status": "FAIL" if issues else "PASS",
        "decision": decision,
        "issues": sorted(set(issues)),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "authority_granted": False,
        "workers_permitted": False,
        "mutation_permitted": False,
    }
    for key in sorted(payload):
        report[key] = deepcopy(payload[key])
    return core.seal(report, "report_sha256")


__all__ = [
    "ADVISORY_GRANT_FIELDS",
    "ADVISORY_SCHEMA",
    "ACTIONS",
    "CARD_SCHEMA",
    "CARD_STATES",
    "CONFIDENCE_BASES",
    "DECISION_BASES",
    "DECISION_BASIS_CONFLICT",
    "DECISION_BASIS_MISSING",
    "DECISION_BUDGET_EXCEEDED",
    "DECISION_CARD_PROPOSED",
    "DECISION_CARD_REJECTED",
    "DECISION_CONFLICT_UNRESOLVED",
    "DECISION_DECISION_REJECTED",
    "DECISION_EMPTY",
    "DECISION_ENVELOPE_INVALID",
    "DECISION_LINEAGE_INSUFFICIENT",
    "DECISION_LIFECYCLE_DECIDED",
    "DECISION_RECORD_SCHEMA",
    "DECISION_REJECTED",
    "DECISION_RETRIEVED",
    "DECISION_REVIEW_REJECTED",
    "DECISION_RULE_REJECTED",
    "DECISION_SOURCE_REJECTED",
    "DECISION_TRANSITION_INVALID",
    "EXCLUSION_REASONS",
    "LIFECYCLE_DECISIONS",
    "MAX_RETRIEVE_RESULTS",
    "MIN_RULE_LINEAGES",
    "OWNER_REVIEW_SCHEMA",
    "PREREGISTERED_RULE_SCHEMA",
    "PRIVACY_RANK",
    "PRIVACY_SCOPES",
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "SOURCE_SCHEMA",
    "TERMINAL_OUTCOMES",
    "VERIFICATION_STAGES",
    "advisory_context_tokens",
    "build_card_from_source",
    "derive_card_state",
    "evaluate",
    "validate_card",
    "validate_decision_record",
    "validate_owner_review",
    "validate_rule",
    "validate_source_record",
]
