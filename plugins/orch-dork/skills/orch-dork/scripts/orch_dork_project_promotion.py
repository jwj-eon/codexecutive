#!/usr/bin/env python3
"""Pure FR60 promotion-path replay for one project adoption (Issue 199).

The evaluator replays one already-recorded promotion path in its only
admissible order: offline evaluation, shadow observation, a separately
approved canary, and the forward-activation eligibility that follows.
Every stage is replayed through the existing Champion/Challenger
evaluator, so the lexicographic gate order, corpus validity, partition
coverage, and within-stage training/holdout separation keep exactly
their original meaning and their original failure issues.  This module
adds only what one stage cannot see: that all three stages ran the same
sealed configurations, over corpora and observations that were never
reused between stages, in chronological order, and that a separately
sealed host canary authority was approved after the shadow stage was
evaluated and before the canary stage was.

The module is inert.  It dispatches nothing, calls no model, writes no
file, approves nothing, activates nothing, and mutates no policy.  A
READY report states only that the recorded evidence replays cleanly.
The host still owns the approval it generated, the installed-generation
release qualification, the admissibility of the source, configuration
and profile, and the future-only compare-and-set that applies any
per-project setting while no governed run is active.  Per-project
adoption is not a global role-default promotion, so this evaluator takes
no qualification receipt and no model or role tuple, and carries no
qualification or model-eligibility authority of any kind.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


def _load_sibling(name: str):
    """Load a sibling when this module itself was loaded by file path."""

    try:
        return __import__(name)
    except ImportError:
        path = Path(__file__).resolve().with_name(name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


cc = _load_sibling("orch_dork_champion_challenger")

BUNDLE_SCHEMA = "orch-dork/project-promotion-bundle/v1"
REPORT_SCHEMA = "orch-dork/project-promotion-report/v1"
CANARY_AUTHORITY_SCHEMA = "orch-dork/project-canary-authority/v1"

STAGE_ORDER = ("offline", "shadow", "canary")

# One bundle carries three stage requests, so its own envelope is larger
# than one Champion/Challenger program.  Each stage is still replayed as
# its own program, so the existing evaluator's canonical, nesting, list
# and node ceilings continue to apply to every stage unchanged.
MAX_CANONICAL_BYTES = 1_048_576
MAX_LIST_ITEMS = 512
MAX_NESTING = 32
MAX_COMPOSITE_NODES = 16_384

_SHA256 = re.compile("[0-9a-f]{64}")
_IDENTIFIER = re.compile("[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}")

_BUNDLE_FIELDS = frozenset(
    {
        "schema",
        "proposal_sha256",
        "project_id",
        "requesting_thread_id",
        "champion",
        "challenger",
        "stages",
        "canary_authority",
        "evaluated_at",
    }
)
# Exactly the existing evaluate_offline request.  A stage carries its own
# evidence and no verdict: there is no boolean, status, or decision input
# anywhere in the bundle that could assert a stage already passed.
_STAGE_REQUEST_FIELDS = frozenset(
    {
        "champion",
        "challenger",
        "corpus",
        "champion_results",
        "challenger_results",
        "evaluated_at",
    }
)
_AUTHORITY_FIELDS = frozenset(
    {
        "schema",
        "proposal_sha256",
        "project_id",
        "requesting_thread_id",
        "champion_sha256",
        "challenger_sha256",
        "canary_corpus_sha256",
        "approved_at",
        "expires_at",
        "authority_sha256",
    }
)
_AUTHORITY_DRAFT_FIELDS = _AUTHORITY_FIELDS - frozenset({"authority_sha256"})
_AUTHORITY_BINDINGS = (
    ("proposal_sha256", "proposal_sha256", "proposal_unbound"),
    ("project_id", "project_id", "project_unbound"),
    ("requesting_thread_id", "requesting_thread_id", "thread_unbound"),
)
_STAGE_ENTRY_FIELDS = frozenset(
    {
        "stage",
        "status",
        "decision",
        "corpus_sha256",
        "evaluated_at",
        "gate_order",
        "gates",
        "evaluation_sha256",
    }
)
_REPORT_IDENTITY_FIELDS = (
    "proposal_sha256",
    "champion_sha256",
    "challenger_sha256",
    "canary_authority_sha256",
)
_REPORT_INACTIVE_FIELDS = (
    "policy_mutated",
    "dispatch_permitted",
    "activation_performed",
    "approval_granted",
    "qualification_authority",
    "model_eligibility_authority",
    "tools_permitted",
    "workers_permitted",
    "authority_granted",
    "release_permitted",
    "installation_permitted",
)
_REPORT_COUNTER_FIELDS = (
    "model_calls",
    "hosted_calls",
    "retries",
    "fallbacks",
    "replacements",
)
_REPORT_FIELDS = (
    frozenset(
        {
            "schema",
            "status",
            "project_id",
            "requesting_thread_id",
            "stage_order",
            "stages",
            "evaluated_at",
            "issues",
            "forward_activation_eligible",
            "provider_free",
            "report_sha256",
        }
    )
    | frozenset(_REPORT_IDENTITY_FIELDS)
    | frozenset(_REPORT_INACTIVE_FIELDS)
    | frozenset(_REPORT_COUNTER_FIELDS)
)

json_sha256 = cc.json_sha256


def _canonical_safe(value: Any) -> bool:
    try:
        if not _shape_within_bounds(value):
            return False
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False
    return len(raw) <= MAX_CANONICAL_BYTES


def _shape_within_bounds(value: Any) -> bool:
    stack = [(value, 0)]
    composite_nodes = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, Mapping):
            composite_nodes += 1
            if (
                depth > MAX_NESTING
                or composite_nodes > MAX_COMPOSITE_NODES
                or len(current) > MAX_LIST_ITEMS
            ):
                return False
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            composite_nodes += 1
            if (
                depth > MAX_NESTING
                or composite_nodes > MAX_COMPOSITE_NODES
                or len(current) > MAX_LIST_ITEMS
            ):
                return False
            stack.extend((item, depth + 1) for item in current)
    return True


def _sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _instant(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


def _digest(value: Any) -> str | None:
    try:
        return json_sha256(value)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    record = deepcopy(dict(value))
    record.pop(field, None)
    record[field] = json_sha256(record)
    return record


def _sealed(value: Any, field: str) -> bool:
    if not isinstance(value, Mapping) or not _sha(value.get(field)):
        return False
    core = dict(value)
    digest = core.pop(field)
    return digest == _digest(core)


def _closed(value: Any, fields: frozenset[str]) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) != fields:
        return None
    return deepcopy(dict(value))


def seal_canary_authority(draft: Any) -> dict[str, Any]:
    """Seal one host-generated canary authority draft.

    The host decides and generates the approval; this only computes the
    canonical digest it is bound by, so an agent cannot mint authority by
    guessing a different sealing convention.
    """

    record = _closed(draft, _AUTHORITY_DRAFT_FIELDS)
    if record is None:
        raise ValueError("canary_authority:contract_invalid")
    record["schema"] = CANARY_AUTHORITY_SCHEMA
    return _seal(record, "authority_sha256")


def _authority_shape_issues(value: Any) -> list[str]:
    label = "canary_authority:"
    record = _closed(value, _AUTHORITY_FIELDS)
    if record is None:
        return [label + "contract_invalid"]
    issues: list[str] = []
    if record.get("schema") != CANARY_AUTHORITY_SCHEMA:
        issues.append(label + "schema_invalid")
    if not _sealed(record, "authority_sha256"):
        issues.append(label + "seal_invalid")
    for field in (
        "proposal_sha256",
        "champion_sha256",
        "challenger_sha256",
        "canary_corpus_sha256",
    ):
        if not _sha(record.get(field)):
            issues.append(label + field + "_invalid")
    for field in ("project_id", "requesting_thread_id"):
        if not _identifier(record.get(field)):
            issues.append(label + field + "_invalid")
    approved = _instant(record.get("approved_at"))
    expires = _instant(record.get("expires_at"))
    if approved is None:
        issues.append(label + "approved_at_invalid")
    if expires is None:
        issues.append(label + "expires_at_invalid")
    if approved is not None and expires is not None and expires <= approved:
        issues.append(label + "validity_invalid")
    return issues


def validate_canary_authority(value: Any) -> dict[str, Any]:
    if not _canonical_safe(value):
        return {
            "status": "FAIL",
            "issues": ["canary_authority:hostile_or_noncanonical"],
        }
    unique = sorted(set(_authority_shape_issues(value)))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


def _blank_entry(stage: str) -> dict[str, Any]:
    return {
        "stage": stage,
        "status": "BLOCKED",
        "decision": None,
        "corpus_sha256": None,
        "evaluated_at": None,
        "gate_order": list(cc.GATE_ORDER),
        "gates": [],
        "evaluation_sha256": None,
    }


def _replay_stage(
    stage: str,
    request: Any,
    champion: Any,
    challenger: Any,
    issues: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    label = "stage:" + stage
    entry = _blank_entry(stage)
    context: dict[str, Any] = {
        "instant": None,
        "corpus": None,
        "results": frozenset(),
    }
    value = _closed(request, _STAGE_REQUEST_FIELDS)
    if value is None:
        issues.append(label + ":request_invalid")
        return entry, context

    for role, expected in (("champion", champion), ("challenger", challenger)):
        if _digest(value.get(role)) != _digest(expected):
            issues.append(label + ":" + role + "_drift")

    report = cc.evaluate(
        {
            "schema": cc.PROGRAM_SCHEMA,
            "action": "evaluate_offline",
            "request": deepcopy(value),
        }
    )
    for issue in report["issues"]:
        issues.append(label + ":cc:" + issue)
    decision = report.get("decision")
    if decision != "OFFLINE_CHALLENGER_RETAINED":
        issues.append(label + ":decision_not_retained:" + str(decision))

    entry["decision"] = decision if isinstance(decision, str) else None
    if isinstance(value.get("evaluated_at"), str):
        entry["evaluated_at"] = value["evaluated_at"]
    context["instant"] = _instant(value.get("evaluated_at"))
    corpus = value.get("corpus")
    if isinstance(corpus, Mapping) and _sha(corpus.get("corpus_sha256")):
        entry["corpus_sha256"] = corpus["corpus_sha256"]
        context["corpus"] = deepcopy(dict(corpus))

    record = report.get("evaluation")
    if isinstance(record, Mapping):
        if decision == "OFFLINE_CHALLENGER_RETAINED":
            entry["status"] = "PASS"
        if isinstance(record.get("gate_order"), list):
            entry["gate_order"] = deepcopy(record["gate_order"])
        if isinstance(record.get("gates"), list):
            entry["gates"] = deepcopy(record["gates"])
        if _sha(record.get("evaluation_sha256")):
            entry["evaluation_sha256"] = record["evaluation_sha256"]
        context["results"] = frozenset(
            list(record.get("champion_result_sha256s") or [])
            + list(record.get("challenger_result_sha256s") or [])
        )
    return entry, context


def _corpus_sets(corpus: Any) -> tuple[frozenset[str], frozenset[str]]:
    if not isinstance(corpus, Mapping):
        return frozenset(), frozenset()
    partitions = corpus.get("partitions")
    fixtures: list[str] = []
    if isinstance(partitions, Mapping):
        for partition in cc.PARTITIONS:
            entries = partitions.get(partition)
            if isinstance(entries, list):
                fixtures.extend(item for item in entries if _sha(item))
    lineages: list[str] = []
    for field in ("training_lineage_sha256s", "holdout_lineage_sha256s"):
        entries = corpus.get(field)
        if isinstance(entries, list):
            lineages.extend(item for item in entries if _sha(item))
    return frozenset(fixtures), frozenset(lineages)


def _cross_stage_issues(
    contexts: Mapping[str, Mapping[str, Any]], issues: list[str]
) -> None:
    corpora = [
        context["corpus"]["corpus_sha256"]
        for context in contexts.values()
        if isinstance(context["corpus"], Mapping)
    ]
    if len(corpora) != len(set(corpora)):
        issues.append("stages:corpus_reused")

    sets = {
        stage: (
            _corpus_sets(context["corpus"]),
            context["results"],
        )
        for stage, context in contexts.items()
    }
    for index, first in enumerate(STAGE_ORDER):
        for second in STAGE_ORDER[index + 1 :]:
            (first_fixtures, first_lineages), first_results = sets[first]
            (second_fixtures, second_lineages), second_results = sets[second]
            if first_fixtures & second_fixtures:
                issues.append("stages:fixture_reused")
            if first_lineages & second_lineages:
                issues.append("stages:lineage_reused")
            if first_results & second_results:
                issues.append("stages:result_reused")

    instants = [contexts[stage]["instant"] for stage in STAGE_ORDER]
    if any(instant is None for instant in instants):
        return
    if not instants[0] < instants[1] < instants[2]:
        issues.append("stages:not_chronological")


def _authority_issues(
    authority: Any,
    bundle: Mapping[str, Any],
    contexts: Mapping[str, Mapping[str, Any]],
    issues: list[str],
) -> str | None:
    label = "canary_authority:"
    found = _authority_shape_issues(authority)
    issues.extend(found)
    if not isinstance(authority, Mapping):
        return None
    for field, bundle_field, issue in _AUTHORITY_BINDINGS:
        if authority.get(field) != bundle.get(bundle_field):
            issues.append(label + issue)
    for role, issue in (
        ("champion", "champion_unbound"),
        ("challenger", "challenger_unbound"),
    ):
        config = bundle.get(role)
        expected = (
            config.get("configuration_sha256")
            if isinstance(config, Mapping)
            else None
        )
        if authority.get(role + "_sha256") != expected:
            issues.append(label + issue)
    canary_corpus = contexts["canary"]["corpus"]
    expected_corpus = (
        canary_corpus.get("corpus_sha256")
        if isinstance(canary_corpus, Mapping)
        else None
    )
    if authority.get("canary_corpus_sha256") != expected_corpus:
        issues.append(label + "corpus_unbound")

    approved = _instant(authority.get("approved_at"))
    expires = _instant(authority.get("expires_at"))
    shadow = contexts["shadow"]["instant"]
    canary = contexts["canary"]["instant"]
    if approved is not None:
        if shadow is not None and approved <= shadow:
            issues.append(label + "before_shadow")
        if canary is not None and approved >= canary:
            issues.append(label + "after_canary")
    if expires is not None and canary is not None and expires < canary:
        issues.append(label + "expired")
    return authority.get("authority_sha256") if _sha(
        authority.get("authority_sha256")
    ) else None


def _report(
    header: Mapping[str, Any],
    entries: list[dict[str, Any]],
    issues: list[str],
) -> dict[str, Any]:
    unique = sorted(set(issues))
    ready = not unique
    report = {
        "schema": REPORT_SCHEMA,
        "status": "READY" if ready else "BLOCKED",
        "proposal_sha256": header.get("proposal_sha256"),
        "project_id": header.get("project_id"),
        "requesting_thread_id": header.get("requesting_thread_id"),
        "champion_sha256": header.get("champion_sha256"),
        "challenger_sha256": header.get("challenger_sha256"),
        "stage_order": list(STAGE_ORDER),
        "stages": deepcopy(entries),
        "canary_authority_sha256": header.get("canary_authority_sha256"),
        "evaluated_at": header.get("evaluated_at"),
        "issues": unique,
        "forward_activation_eligible": ready,
        "policy_mutated": False,
        "dispatch_permitted": False,
        "activation_performed": False,
        "approval_granted": False,
        "qualification_authority": False,
        "model_eligibility_authority": False,
        "tools_permitted": False,
        "workers_permitted": False,
        "authority_granted": False,
        "release_permitted": False,
        "installation_permitted": False,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
        "retries": 0,
        "fallbacks": 0,
        "replacements": 0,
    }
    return _seal(report, "report_sha256")


def evaluate(bundle: Any) -> dict[str, Any]:
    """Replay one recorded promotion path and report READY or BLOCKED.

    The report is evidence, not permission.  Forward-activation
    eligibility means the recorded path replays cleanly; applying it
    remains the host's separate, approved, future-only compare-and-set.
    """

    issues: list[str] = []
    if not _canonical_safe(bundle):
        return _report({}, [], ["input:hostile_or_noncanonical"])
    value = _closed(bundle, _BUNDLE_FIELDS)
    if value is None:
        return _report({}, [], ["bundle:contract_invalid"])

    if value.get("schema") != BUNDLE_SCHEMA:
        issues.append("bundle:schema_invalid")
    if not _sha(value.get("proposal_sha256")):
        issues.append("bundle:proposal_sha256_invalid")
    if not _identifier(value.get("project_id")):
        issues.append("bundle:project_id_invalid")
    if not _identifier(value.get("requesting_thread_id")):
        issues.append("bundle:requesting_thread_id_invalid")

    champion = value.get("champion")
    challenger = value.get("challenger")
    for role, config in (("champion", champion), ("challenger", challenger)):
        if (
            not isinstance(config, Mapping)
            or config.get("role") != role
            or cc.validate_configuration(config)["status"] != "PASS"
        ):
            issues.append("bundle:" + role + "_invalid")
    if (
        isinstance(champion, Mapping)
        and isinstance(challenger, Mapping)
        and champion.get("configuration_sha256")
        == challenger.get("configuration_sha256")
    ):
        issues.append("bundle:configurations_not_distinct")

    final = _instant(value.get("evaluated_at"))
    if final is None:
        issues.append("bundle:evaluated_at_invalid")

    header: dict[str, Any] = {
        "proposal_sha256": value.get("proposal_sha256")
        if _sha(value.get("proposal_sha256"))
        else None,
        "project_id": value.get("project_id")
        if _identifier(value.get("project_id"))
        else None,
        "requesting_thread_id": value.get("requesting_thread_id")
        if _identifier(value.get("requesting_thread_id"))
        else None,
        "champion_sha256": champion.get("configuration_sha256")
        if isinstance(champion, Mapping)
        and _sha(champion.get("configuration_sha256"))
        else None,
        "challenger_sha256": challenger.get("configuration_sha256")
        if isinstance(challenger, Mapping)
        and _sha(challenger.get("configuration_sha256"))
        else None,
        "canary_authority_sha256": None,
        "evaluated_at": value.get("evaluated_at") if final is not None else None,
    }

    stages = _closed(value.get("stages"), frozenset(STAGE_ORDER))
    if stages is None:
        issues.append("stages:contract_invalid")
        return _report(header, [], issues)

    entries: list[dict[str, Any]] = []
    contexts: dict[str, Mapping[str, Any]] = {}
    for stage in STAGE_ORDER:
        entry, context = _replay_stage(
            stage, stages[stage], champion, challenger, issues
        )
        entries.append(entry)
        contexts[stage] = context

    _cross_stage_issues(contexts, issues)
    header["canary_authority_sha256"] = _authority_issues(
        value.get("canary_authority"), value, contexts, issues
    )

    canary = contexts["canary"]["instant"]
    if final is not None and canary is not None and final < canary:
        issues.append("report:evaluated_at_before_canary")

    return _report(header, entries, issues)


def _stage_entry_issues(entries: Any) -> list[str]:
    if not isinstance(entries, list) or len(entries) not in (0, len(STAGE_ORDER)):
        return ["report:stages_invalid"]
    issues: list[str] = []
    for stage, entry in zip(STAGE_ORDER, entries):
        normalized = _closed(entry, _STAGE_ENTRY_FIELDS)
        if normalized is None or normalized.get("stage") != stage:
            issues.append("report:stages_invalid")
            continue
        if normalized.get("status") not in {"PASS", "BLOCKED"}:
            issues.append("report:stage_status_invalid")
        if not isinstance(normalized.get("gate_order"), list) or not isinstance(
            normalized.get("gates"), list
        ):
            issues.append("report:stage_gates_invalid")
        for field in ("corpus_sha256", "evaluation_sha256"):
            if normalized.get(field) is not None and not _sha(
                normalized.get(field)
            ):
                issues.append("report:stage_identity_invalid")
        if normalized.get("evaluated_at") is not None and _instant(
            normalized.get("evaluated_at")
        ) is None:
            issues.append("report:stage_evaluated_at_invalid")
    return issues


def validate_report(value: Any) -> dict[str, Any]:
    if not _canonical_safe(value):
        return {"status": "FAIL", "issues": ["report:hostile_or_noncanonical"]}
    issues: list[str] = []
    record = _closed(value, _REPORT_FIELDS)
    if record is None:
        return {"status": "FAIL", "issues": ["report:contract_invalid"]}
    if record.get("schema") != REPORT_SCHEMA:
        issues.append("report:schema_invalid")
    if not _sealed(record, "report_sha256"):
        issues.append("report:seal_invalid")
    status = record.get("status")
    if status not in {"READY", "BLOCKED"}:
        issues.append("report:status_invalid")
    if record.get("stage_order") != list(STAGE_ORDER):
        issues.append("report:stage_order_invalid")
    issues.extend(_stage_entry_issues(record.get("stages")))

    found = record.get("issues")
    if (
        not isinstance(found, list)
        or len(found) > MAX_LIST_ITEMS
        or any(not isinstance(item, str) for item in found)
        or sorted(set(found)) != found
    ):
        issues.append("report:issues_invalid")
        found = None
    eligible = record.get("forward_activation_eligible")
    if not isinstance(eligible, bool) or (
        found is not None and eligible != (status == "READY" and not found)
    ):
        issues.append("report:eligibility_invalid")

    for field in _REPORT_INACTIVE_FIELDS:
        if record.get(field) is not False:
            issues.append("report:inactive_flag_invalid")
    if record.get("provider_free") is not True:
        issues.append("report:inactive_flag_invalid")
    for field in _REPORT_COUNTER_FIELDS:
        if record.get(field) != 0 or isinstance(record.get(field), bool):
            issues.append("report:provider_boundary_invalid")

    for field in _REPORT_IDENTITY_FIELDS:
        if record.get(field) is not None and not _sha(record.get(field)):
            issues.append("report:identity_invalid")
    for field in ("project_id", "requesting_thread_id"):
        if record.get(field) is not None and not _identifier(record.get(field)):
            issues.append("report:identity_invalid")
    if record.get("evaluated_at") is not None and _instant(
        record.get("evaluated_at")
    ) is None:
        issues.append("report:evaluated_at_invalid")

    unique = sorted(set(issues))
    return {"status": "PASS" if not unique else "FAIL", "issues": unique}


__all__ = [
    "BUNDLE_SCHEMA",
    "REPORT_SCHEMA",
    "CANARY_AUTHORITY_SCHEMA",
    "STAGE_ORDER",
    "json_sha256",
    "seal_canary_authority",
    "validate_canary_authority",
    "validate_report",
    "evaluate",
]


if __name__ == "__main__":
    raise SystemExit("Import and call evaluate(bundle); no CLI is provided.")
