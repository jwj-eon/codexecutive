#!/usr/bin/env python3
"""Provider-free per-project improvement proposals for Issue 199 (FR60/FR68/FR69).

The evaluator reads one project's observed run history and proposes observed
alternatives in exactly three dimensions: the Workflow Profile, the worker
count, or one role's model.  It is pure.  It reads no corpus, no file, no
network and no model, holds no state, activates nothing, dispatches nothing,
and decides no promotion.  Each proposal is an advisory record for the
existing FR60 Champion/Challenger path to evaluate and for the user to
approve; adopting one is someone else's action and applies only to later runs.

Closed input contract.  Every mapping is closed: an unknown or missing field
is refused rather than defaulted.

    {"schema": "orch-dork/project-proposal-request/v1",
     "project_id": <identifier, the host's project key>,
     "evaluated_at": <RFC3339 instant in UTC>,
     "current": {"settings": <settings>, "configuration": <sealed CC config>},
     "candidates": [{"schema": "orch-dork/project-proposal-candidate/v1",
                     "candidate_id": <identifier>,
                     "dimension": "workflow_profile" | "worker_count"
                                  | "role_model",
                     "choice": <choice>,
                     "configuration": <sealed CC config>},
                    ...],
     "history": <orch-dork/project-improvement-history/v1 envelope>}

`settings` is the host's effective project settings, exactly
`{"workflow_profile", "worker_count", "models": {role: model},
"efforts": {role: effort}}`.  A `choice` names one observed alternative in
its dimension: `{"workflow_profile": ...}`, `{"worker_count": ...}` or
`{"role": ..., "model": ...}`.  The baseline choice in every dimension is
read from `current.settings`, so no caller declares it separately.

`history` is the host reader's envelope verbatim:
`{"schema", "status", "project_id", "history", "excluded", "provider_free"}`,
where each row is `{"run_id", "project_id", "settings", "configuration",
"factored_record"}`.  A row's `factored_record` is either existing validated
`orch-dork/factored-run-record/v2` evidence or the host's
`orch-dork/project-run-factors/v1` wrapper over the same Issue 186 role
grammar; the row's own schema field selects which validator runs.
Configurations are validated by the existing Champion/Challenger
`validate_configuration` at v2 or v3.

There is no floors field.  The production floors below are not reachable from
any model-facing input: twenty distinct eligible project runs, and five
comparable runs for each of the baseline and candidate choices.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from types import MappingProxyType
from typing import Any, Mapping


def _load_sibling(name: str):
    try:
        return __import__(name)
    except ImportError:  # pragma: no cover - direct-file loading.
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


admission = _load_sibling("orch_dork_governed_admission")
champion = _load_sibling("orch_dork_champion_challenger")
route_learning = _load_sibling("orch_dork_route_learning")


REQUEST_SCHEMA = "orch-dork/project-proposal-request/v1"
REPORT_SCHEMA = "orch-dork/project-proposal-report/v1"
PROPOSAL_SCHEMA = "orch-dork/project-improvement-proposal/v1"
CANDIDATE_SCHEMA = "orch-dork/project-proposal-candidate/v1"
# The host reader's envelope and its wrapper evidence (Issue 199 host side).
HISTORY_SCHEMA = "orch-dork/project-improvement-history/v1"
PROJECT_RUN_FACTORS_SCHEMA = "orch-dork/project-run-factors/v1"

DIMENSIONS = ("workflow_profile", "worker_count", "role_model")

# The floors the production entry always applies.
PRODUCTION_FLOORS = MappingProxyType(
    {"min_eligible_project_runs": 20, "min_comparable_runs_per_choice": 5}
)
_FLOOR_FIELDS = frozenset(PRODUCTION_FLOORS)

# The watcher's user-facing verdict vocabulary (FR69).  Only Verified and
# Failed checks are correctness observations; every other verdict stays a
# typed unknown and is never counted as a success.
HOST_VERDICTS = MappingProxyType(
    {
        "Verified": "PASS",
        "Failed checks": "FAIL",
        "Interrupted \u2014 not verified": "UNKNOWN",
        "Stopped by you": "UNKNOWN",
        "Refused": "UNKNOWN",
    }
)

_MAX_CANONICAL_BYTES = 4_194_304
_MAX_HISTORY_ROWS = 4_096
MAX_CANDIDATES = 16
_MAX_CANDIDATES = MAX_CANDIDATES
_MAX_ROLES = 16
_MAX_COUNT = 10**12

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")

_REQUEST_FIELDS = frozenset(
    {"schema", "project_id", "evaluated_at", "current", "candidates", "history"}
)
_CURRENT_FIELDS = frozenset({"settings", "configuration"})
_SETTINGS_FIELDS = frozenset({"workflow_profile", "worker_count", "models", "efforts"})
_CANDIDATE_FIELDS = frozenset(
    {"schema", "candidate_id", "dimension", "choice", "configuration"}
)
_HISTORY_FIELDS = frozenset(
    {"schema", "status", "project_id", "history", "excluded", "provider_free"}
)
_ROW_FIELDS = frozenset(
    {"run_id", "project_id", "settings", "configuration", "factored_record"}
)
_PROJECT_RUN_FACTORS_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "project_id",
        "settings",
        "terminal_record_sha256",
        "policy_sha256",
        "role_factors",
        "role_outcome_factors",
        "verdict",
        "elapsed_ms",
        "evidence_sha256",
    }
)
_CHOICE_FIELDS = MappingProxyType(
    {
        "workflow_profile": frozenset({"workflow_profile"}),
        "worker_count": frozenset({"worker_count"}),
        "role_model": frozenset({"role", "model"}),
    }
)
_CONFIGURATION_SCHEMAS = tuple(
    schema
    for schema in (
        getattr(champion, "CONFIGURATION_SCHEMA_V2", None),
        getattr(champion, "CONFIGURATION_SCHEMA_V3", None),
    )
    if schema is not None
)
_CONFIGURATION_DRAFTS = MappingProxyType(
    {
        getattr(champion, "CONFIGURATION_SCHEMA_V2", "v2-absent"): getattr(
            champion, "CONFIGURATION_DRAFT_SCHEMA_V2", None
        ),
        getattr(champion, "CONFIGURATION_SCHEMA_V3", "v3-absent"): getattr(
            champion, "CONFIGURATION_DRAFT_SCHEMA_V3", None
        ),
    }
)



class ProjectProposalError(ValueError):
    """A bounded project-proposal contract could not be canonicalized."""


def _canonical(value: Any) -> bytes:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > _MAX_CANONICAL_BYTES:
        raise ProjectProposalError("input exceeds the canonical ceiling")
    return encoded


def json_sha256(value: Any) -> str:
    """The content address of one canonical JSON value."""

    return hashlib.sha256(_canonical(value)).hexdigest()


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    body = {key: deepcopy(item) for key, item in value.items() if key != field}
    body[field] = json_sha256(body)
    return body


def _seal_valid(value: Mapping[str, Any], field: str) -> bool:
    body = {key: item for key, item in value.items() if key != field}
    return _sha(value.get(field)) and value.get(field) == json_sha256(body)


def _sha(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256.match(value))


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(_IDENTIFIER.match(value))


def _count(value: Any, *, minimum: int = 0, maximum: int = _MAX_COUNT) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _instant(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo == timezone.utc


def _issue(issues: list[str], code: str) -> None:
    if code not in issues:
        issues.append(code)


def _closed(
    value: Any, fields: frozenset[str], label: str, issues: list[str]
) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) != fields:
        _issue(issues, label + ":contract_invalid")
        return None
    return deepcopy(dict(value))


def _role_map(value: Any, label: str, issues: list[str]) -> dict[str, str] | None:
    if (
        not isinstance(value, Mapping)
        or not value
        or len(value) > _MAX_ROLES
        or any(not _identifier(key) for key in value)
        or any(not _identifier(item) for item in value.values())
    ):
        _issue(issues, label + ":invalid")
        return None
    return {key: value[key] for key in sorted(value)}


def _settings(value: Any, label: str, issues: list[str]) -> dict[str, Any] | None:
    """The host's effective project settings: shape, workers, models, efforts."""

    settings = _closed(value, _SETTINGS_FIELDS, label, issues)
    if settings is None:
        return None
    if not _identifier(settings.get("workflow_profile")):
        _issue(issues, label + ":workflow_profile_invalid")
        return None
    if not _count(settings.get("worker_count"), maximum=100):
        _issue(issues, label + ":worker_count_invalid")
        return None
    models = _role_map(settings.get("models"), label + ":models", issues)
    efforts = _role_map(settings.get("efforts"), label + ":efforts", issues)
    if models is None or efforts is None:
        return None
    if set(models) != set(efforts):
        _issue(issues, label + ":role_sets_differ")
        return None
    settings["models"] = models
    settings["efforts"] = efforts
    return settings


def _validated_configuration(
    value: Any, label: str, issues: list[str], *, roles: frozenset[str]
) -> dict[str, Any] | None:
    """One configuration the existing Champion/Challenger validator accepts."""

    if not isinstance(value, Mapping):
        _issue(issues, label + ":contract_invalid")
        return None
    if value.get("schema") not in _CONFIGURATION_SCHEMAS:
        _issue(issues, label + ":version_unsupported")
        return None
    if champion.validate_configuration(value)["status"] != "PASS":
        _issue(issues, label + ":invalid")
        return None
    if value.get("role") not in roles:
        _issue(issues, label + ":role_invalid")
        return None
    return deepcopy(dict(value))


def _as_challenger(
    configuration: Mapping[str, Any], label: str, issues: list[str]
) -> dict[str, Any] | None:
    """The same substantive configuration, sealed by CC in the Challenger role.

    The host observes a run's configuration in the `champion` role, so a
    candidate drawn from observed runs is re-sealed here through the existing
    Champion/Challenger sealer rather than hand-written into a lookalike
    promotion record.  Nothing else about it changes.
    """

    if configuration["role"] == "challenger":
        return deepcopy(dict(configuration))
    draft_schema = _CONFIGURATION_DRAFTS.get(configuration["schema"])
    if draft_schema is None:  # pragma: no cover - guarded by _CONFIGURATION_SCHEMAS.
        _issue(issues, label + ":version_unsupported")
        return None
    draft = {
        key: deepcopy(item)
        for key, item in configuration.items()
        if key != "configuration_sha256"
    }
    draft["schema"] = draft_schema
    draft["role"] = "challenger"
    report = champion.evaluate(
        {
            "schema": champion.PROGRAM_SCHEMA,
            "action": "seal_configuration",
            "request": {"configuration": draft},
        }
    )
    if report["status"] != "PASS" or report["configuration"] is None:
        _issue(issues, label + ":reseal_refused")
        return None
    return report["configuration"]


def _choice(dimension: str, value: Any, label: str, issues: list[str]) -> dict[str, Any] | None:
    fields = _CHOICE_FIELDS.get(dimension)
    if fields is None:
        return None
    choice = _closed(value, fields, label, issues)
    if choice is None:
        return None
    if dimension == "worker_count":
        if not _count(choice.get("worker_count"), maximum=100):
            _issue(issues, label + ":worker_count_invalid")
            return None
    elif any(not _identifier(item) for item in choice.values()):
        _issue(issues, label + ":invalid")
        return None
    return choice


def _choice_key(dimension: str, choice: Mapping[str, Any]) -> str:
    """The settings slot a choice occupies: one per dimension, per role."""

    if dimension == "role_model":
        return "role_model:" + str(choice.get("role"))
    return dimension


def _observed_choices(settings: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Every dimension's observed choice, read from one run's settings."""

    choices: dict[str, dict[str, Any]] = {
        "workflow_profile": {"workflow_profile": settings["workflow_profile"]},
        "worker_count": {"worker_count": settings["worker_count"]},
    }
    for role, model in settings["models"].items():
        choices["role_model:" + role] = {"role": role, "model": model}
    return choices


def _candidates(
    value: Any, issues: list[str]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > _MAX_CANDIDATES:
        _issue(issues, "candidates:contract_invalid")
        return []
    parsed: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in value:
        candidate = _closed(raw, _CANDIDATE_FIELDS, "candidate", issues)
        if candidate is None:
            continue
        if candidate.get("schema") != CANDIDATE_SCHEMA:
            _issue(issues, "candidate:schema_invalid")
            continue
        candidate_id = candidate.get("candidate_id")
        dimension = candidate.get("dimension")
        if not _identifier(candidate_id):
            _issue(issues, "candidate:id_invalid")
            continue
        if candidate_id in seen:
            _issue(issues, "candidate:id_duplicate")
            continue
        seen.add(candidate_id)
        if dimension not in DIMENSIONS:
            _issue(issues, "candidate:dimension_invalid")
            continue
        choice = _choice(dimension, candidate.get("choice"), "candidate:choice", issues)
        observed = _validated_configuration(
            candidate.get("configuration"),
            "candidate:configuration",
            issues,
            roles=frozenset({"champion", "challenger"}),
        )
        if choice is None or observed is None:
            continue
        challenger = _as_challenger(observed, "candidate:configuration", issues)
        if challenger is None:
            continue
        parsed.append(
            {
                "candidate_id": candidate_id,
                "dimension": dimension,
                "choice": choice,
                "configuration": challenger,
                "observed_configuration_sha256": observed["configuration_sha256"],
                "configuration_source": (
                    "supplied_challenger"
                    if observed["role"] == "challenger"
                    else "resealed_from_observed_champion"
                ),
            }
        )
    return parsed


def _floors(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != _FLOOR_FIELDS:
        raise ProjectProposalError(
            "floors must name exactly " + repr(sorted(_FLOOR_FIELDS))
        )
    floors = {key: value[key] for key in sorted(_FLOOR_FIELDS)}
    for item in floors.values():
        if not _count(item, minimum=1, maximum=10_000):
            raise ProjectProposalError("a floor must be a positive bounded count")
    return floors



def _factored_view(record: Mapping[str, Any], reasons: list[str]) -> dict[str, Any] | None:
    """The measurement view of existing `factored-run-record/v2` evidence."""

    if route_learning.validate_factored_record(record)["status"] != "PASS":
        reasons.append("evidence_invalid")
        return None
    route = record["route_record"]
    outcome = record["outcome_record"]
    correctness = outcome["correctness"]
    verification = outcome["verification_status"]
    if correctness == "PASS" and verification == "PASS":
        observed = "PASS"
    elif correctness == "FAIL" or verification == "FAIL":
        observed = "FAIL"
    elif correctness == "NOT_APPLICABLE" and verification == "NOT_APPLICABLE":
        observed = "NOT_APPLICABLE"
    else:
        observed = "UNKNOWN"
    return {
        "evidence_settings": None,
        "role_factors": route["role_factors"],
        "role_outcome_factors": record["role_outcome_record"]["rows"],
        "observed_workflow_profile": route["profile_id"],
        "correctness": observed,
        "human_disposition": outcome["human_disposition"],
        "cost_micros": outcome["cost"]["micros"],
        "latency_ms": outcome["latency_ms"],
        "conformance": {
            "privacy_event_refs": len(outcome["privacy_event_refs"]),
            "authority_event_refs": len(outcome["authority_event_refs"]),
        },
    }


def _shape_consistent(settings: Mapping[str, Any]) -> bool:
    """Whether the shape the host froze matches its own worker count.

    The rule is the admission module's own: zero workers run the direct
    profile, one worker the execute/verify/repair profile, and more than one
    the parallel join.  It is read from there rather than restated here.
    """

    try:
        expected = admission.workflow_profile_for(settings["worker_count"])
    except (ValueError, TypeError):  # pragma: no cover - bounded before this.
        return False
    return settings["workflow_profile"] == expected


def _wrapper_settings(
    record: Mapping[str, Any], reasons: list[str]
) -> dict[str, Any] | None:
    """The settings the host froze before the turn, closed and self-consistent.

    The wrapper supplies observed metadata only.  Its worker count is the
    actual number of native workers, where zero is valid, and is not the
    legacy route record's lane count.
    """

    issues: list[str] = []
    settings = _settings(record.get("settings"), "settings", issues)
    if settings is None:
        reasons.append("evidence_settings_invalid")
        return None
    if not _shape_consistent(settings):
        reasons.append("evidence_settings_shape_mismatch")
        return None
    if record["policy_sha256"] != json_sha256(settings):
        reasons.append("evidence_settings_digest_mismatch")
        return None
    return settings

def _project_factors_view(
    record: Mapping[str, Any], row: Mapping[str, Any], reasons: list[str]
) -> dict[str, Any] | None:
    """The measurement view of the host's `project-run-factors/v1` wrapper.

    The wrapper carries the Issue 186 role grammar, the host's verdict and the
    run's wall duration.  It observes no run cost, no human disposition and no
    privacy or authority events, so this view leaves those absent rather than
    inventing them.  The Workflow Profile and worker count come from the row's
    settings, which the host froze before the turn.
    """

    validator = getattr(route_learning, "validate_role_attribution", None)
    if validator is None:  # pragma: no cover - the host validator ships with it.
        reasons.append("evidence_validator_unavailable")
        return None
    if set(record) != _PROJECT_RUN_FACTORS_FIELDS:
        reasons.append("evidence_contract_invalid")
        return None
    if record.get("project_id") != row.get("project_id"):
        reasons.append("evidence_project_mismatch")
        return None
    if (
        not _sha(record.get("terminal_record_sha256"))
        or not _sha(record.get("policy_sha256"))
        or record.get("verdict") not in HOST_VERDICTS
        or not (record.get("elapsed_ms") is None or _count(record.get("elapsed_ms")))
        or not _seal_valid(record, "evidence_sha256")
    ):
        reasons.append("evidence_invalid")
        return None
    attribution = validator(record["role_factors"], record["role_outcome_factors"])
    if attribution.get("status") != "PASS":
        reasons.append("evidence_invalid")
        return None
    role_factors = attribution["role_factors"]
    if role_factors.get("routing_policy_sha256") != record["policy_sha256"]:
        reasons.append("evidence_policy_mismatch")
        return None
    settings = _wrapper_settings(record, reasons)
    if settings is None:
        return None
    return {
        "evidence_settings": settings,
        "role_factors": role_factors,
        "role_outcome_factors": attribution["role_outcome_factors"],
        "observed_workflow_profile": None,
        "correctness": HOST_VERDICTS[record["verdict"]],
        "human_disposition": None,
        "cost_micros": None,
        "latency_ms": record["elapsed_ms"],
        "conformance": None,
    }


def _row_view(
    row: Mapping[str, Any], project_id: str, reasons: list[str]
) -> dict[str, Any] | None:
    """One eligible run, or nothing and the reasons it cannot be compared."""

    settings = _settings(row["settings"], "history:settings", [])
    configuration = _validated_configuration(
        row["configuration"],
        "history:configuration",
        [],
        roles=frozenset({"champion", "challenger"}),
    )
    if row["project_id"] != project_id:
        reasons.append("project_mismatch")
    if settings is None:
        reasons.append("settings_invalid")
    if configuration is None:
        reasons.append("configuration_invalid")
    record = row["factored_record"]
    if not isinstance(record, Mapping):
        reasons.append("evidence_contract_invalid")
        return None
    schema = record.get("schema")
    if schema not in (
        route_learning.FACTORED_RUN_RECORD_SCHEMA_V2,
        PROJECT_RUN_FACTORS_SCHEMA,
    ):
        reasons.append("evidence_kind_unsupported")
        return None
    if record.get("run_id") != row["run_id"]:
        reasons.append("evidence_run_mismatch")
        return None
    if reasons:
        return None
    view = (
        _factored_view(record, reasons)
        if schema == route_learning.FACTORED_RUN_RECORD_SCHEMA_V2
        else _project_factors_view(record, row, reasons)
    )
    if view is None or reasons:
        return None
    role_factors = view["role_factors"]
    if (
        configuration["registry_generation"] != role_factors["registry_generation"]
        or configuration["profile_registry_sha256"] != role_factors["registry_sha256"]
        or configuration["routing_policy_sha256"]
        != role_factors["routing_policy_sha256"]
    ):
        reasons.append("configuration_factor_mismatch")
        return None
    limitations: list[str] = []
    observed_settings = view["evidence_settings"]
    if observed_settings is not None and observed_settings != settings:
        reasons.append("settings_factor_mismatch")
        return None
    for assignment in role_factors["assignments"]:
        role = assignment["role"]
        if role not in settings["models"]:
            reasons.append("settings_factor_mismatch")
            return None
        if assignment["model"] is not None and (
            settings["models"][role] != assignment["model"]
            or settings["efforts"][role] != assignment["effort"]
        ):
            reasons.append("settings_factor_mismatch")
            return None
    if set(settings["models"]) != {
        assignment["role"] for assignment in role_factors["assignments"]
    }:
        reasons.append("settings_factor_mismatch")
        return None
    if (
        view["observed_workflow_profile"] is not None
        and view["observed_workflow_profile"] != settings["workflow_profile"]
    ):
        reasons.append("settings_factor_mismatch")
        return None
    settings_digest = json_sha256(settings)
    bound = settings_digest == configuration["routing_policy_sha256"] == configuration[
        "routing_rules_sha256"
    ]
    if observed_settings is not None and not bound:
        reasons.append("settings_configuration_digest_mismatch")
        return None
    if not bound:
        limitations.append("settings_digest_not_bound_to_configuration")
    return {
        "run_id": row["run_id"],
        "evidence_schema": schema,
        "settings": settings,
        "choices": _observed_choices(settings),
        "configuration_sha256": configuration["configuration_sha256"],
        "role_outcomes": {item["role"]: item for item in view["role_outcome_factors"]},
        "correctness": view["correctness"],
        "human_disposition": view["human_disposition"],
        "cost_micros": view["cost_micros"],
        "latency_ms": view["latency_ms"],
        "conformance": view["conformance"],
        "limitations": limitations,
    }


def _history(
    value: Any, project_id: str, issues: list[str]
) -> tuple[list[dict[str, Any]], dict[str, Any]] | None:
    """Eligible run views, with every excluded run and its reasons recorded."""

    envelope = _closed(value, _HISTORY_FIELDS, "history", issues)
    if envelope is None:
        return None
    rows = envelope.get("history")
    host_excluded = envelope.get("excluded")
    if (
        envelope.get("schema") != HISTORY_SCHEMA
        or envelope.get("status") != "PASS"
        or envelope.get("provider_free") is not True
        or envelope.get("project_id") != project_id
        or not isinstance(rows, list)
        or len(rows) > _MAX_HISTORY_ROWS
        or not isinstance(host_excluded, list)
        or len(host_excluded) > _MAX_HISTORY_ROWS
    ):
        _issue(issues, "history:envelope_invalid")
        return None
    parsed: list[dict[str, Any]] = []
    for raw in rows:
        row = _closed(raw, _ROW_FIELDS, "history:row", issues)
        if row is None:
            return None
        if not _identifier(row.get("run_id")) or not _identifier(row.get("project_id")):
            _issue(issues, "history:row_identity_invalid")
            return None
        parsed.append(row)
    seen: dict[str, int] = {}
    for row in parsed:
        seen[row["run_id"]] = seen.get(row["run_id"], 0) + 1
    duplicates = sorted(run_id for run_id, count in seen.items() if count > 1)
    eligible: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    kinds: dict[str, int] = {}
    limitations: list[str] = []
    for row in parsed:
        reasons: list[str] = []
        if row["run_id"] in set(duplicates):
            reasons.append("run_id_duplicate")
            view = None
        else:
            view = _row_view(row, project_id, reasons)
        if view is None or reasons:
            entry = {"run_id": row["run_id"], "reasons": sorted(set(reasons))}
            if entry not in excluded:
                excluded.append(entry)
            continue
        eligible.append(view)
        limitations.extend(view["limitations"])
        kinds[view["evidence_schema"]] = kinds.get(view["evidence_schema"], 0) + 1
    eligible.sort(key=lambda item: item["run_id"])
    excluded.sort(key=lambda item: item["run_id"])
    if kinds.get(PROJECT_RUN_FACTORS_SCHEMA):
        limitations.append("project_run_factors_v1:no_run_cost_or_human_disposition_observed")
        limitations.append("project_run_factors_v1:no_privacy_or_authority_events_observed")
    if excluded:
        limitations.append("excluded_runs_present")
    if host_excluded:
        limitations.append("host_excluded_runs_present")
    evidence = {
        "eligible_runs": [item["run_id"] for item in eligible],
        "eligible_run_count": len(eligible),
        "excluded_runs": excluded,
        "duplicate_run_ids": duplicates,
        "evidence_schemas": {key: kinds[key] for key in sorted(kinds)},
        "host_excluded_runs": deepcopy(host_excluded),
        "limitations": sorted(set(limitations)),
    }
    return eligible, evidence



# Which other settings a comparison holds fixed.  On this host the Workflow
# Profile is a function of the worker count, and the worker count decides which
# roles exist, so a shape comparison holds neither other shape setting fixed:
# it records the coupling as a promotion gap and reports each arm's distinct
# observed settings.  A role-model comparison is not coupled that way and does
# hold the rest of the settings fixed.
_CONTROLLED = MappingProxyType(
    {
        "workflow_profile": (),
        "worker_count": (),
        "role_model": ("workflow_profile", "worker_count", "models", "efforts"),
    }
)
_COUPLING_GAPS = MappingProxyType(
    {
        "workflow_profile": (
            "workflow_profile:worker_count_coupled",
            "workflow_profile:role_assignment_coupled",
        ),
        "worker_count": (
            "worker_count:workflow_profile_coupled",
            "worker_count:role_assignment_coupled",
        ),
        "role_model": (),
    }
)
_CATEGORICAL = MappingProxyType(
    {
        # measure: (adverse categories, the categories in the denominator)
        "correctness": (("FAIL",), ("PASS", "FAIL")),
        "role_acceptance": (("rejected",), ("accepted", "rejected")),
        "human_usefulness": (
            ("rejected",),
            ("accepted", "accepted_with_edits", "rejected"),
        ),
    }
)
_NUMERIC = ("cost", "latency")
_BETTER = MappingProxyType(
    {
        "correctness": ("PASS",),
        "role_acceptance": ("accepted",),
        "human_usefulness": ("accepted", "accepted_with_edits"),
    }
)


def _known(value: Any) -> dict[str, Any]:
    return {"status": "known", "value": deepcopy(value)}


def _unknown(reason: str) -> dict[str, str]:
    return {"status": "unknown", "reason": reason}


def _role_factor(view: Mapping[str, Any], role: str, factor: str) -> dict[str, Any]:
    row = view["role_outcomes"].get(role)
    if row is None:
        return _unknown("not_attributable")
    return deepcopy(row[factor])


def _observations(
    view: Mapping[str, Any], dimension: str, role: str | None
) -> dict[str, dict[str, Any]]:
    """What one run observed for each measure, with unknowns left typed."""

    observed: dict[str, dict[str, Any]] = {
        "conformance": (
            _known(view["conformance"])
            if view["conformance"] is not None
            else _unknown("not_observed")
        ),
        "correctness": (
            _unknown("not_observed")
            if view["correctness"] == "UNKNOWN"
            else _known(view["correctness"])
        ),
    }
    if dimension == "role_model" and role is not None:
        observed["role_acceptance"] = _role_factor(view, role, "acceptance")
        observed["human_usefulness"] = _role_factor(view, role, "human_disposition")
        observed["cost"] = _role_factor(view, role, "cost")
        observed["latency"] = _role_factor(view, role, "elapsed_ms")
        return observed
    observed["human_usefulness"] = (
        _known(view["human_disposition"])
        if view["human_disposition"] is not None
        else _unknown("not_observed")
    )
    observed["cost"] = (
        _known({"currency": "USD", "micros": view["cost_micros"]})
        if view["cost_micros"] is not None
        else _unknown("cost_unpriced")
    )
    observed["latency"] = (
        _known(view["latency_ms"])
        if view["latency_ms"] is not None
        else _unknown("not_observed")
    )
    return observed


def _micros(observation: Mapping[str, Any]) -> int | None:
    if observation["status"] != "known":
        return None
    value = observation["value"]
    return value["micros"] if isinstance(value, Mapping) else value


def _median(values: list[int]) -> int | None:
    """The lower median of the observed values: no mean, no weight, no score."""

    if not values:
        return None
    ordered = sorted(values)
    return ordered[(len(ordered) - 1) // 2]


def _arm(runs: list[dict[str, Any]], measures: tuple[str, ...]) -> dict[str, Any]:
    variants: list[dict[str, Any]] = []
    for item in runs:
        settings = item["view"]["settings"]
        for variant in variants:
            if variant["settings"] == settings:
                variant["run_count"] += 1
                break
        else:
            variants.append({"settings": deepcopy(settings), "run_count": 1})
    summary: dict[str, Any] = {
        "run_count": len(runs),
        "runs": [item["view"]["run_id"] for item in runs],
        "settings_variants": sorted(variants, key=lambda item: json_sha256(item["settings"])),
    }
    for measure in measures:
        observations = [item["observations"][measure] for item in runs]
        unknown_reasons = sorted(
            {item["reason"] for item in observations if item["status"] == "unknown"}
        )
        unknown_runs = sum(1 for item in observations if item["status"] == "unknown")
        if measure == "conformance":
            summary[measure] = {
                "runs_with_privacy_event_refs": sum(
                    1
                    for item in observations
                    if item["status"] == "known" and item["value"]["privacy_event_refs"]
                ),
                "runs_with_authority_event_refs": sum(
                    1
                    for item in observations
                    if item["status"] == "known"
                    and item["value"]["authority_event_refs"]
                ),
                "runs_without_conformance_evidence": unknown_runs,
                "evaluated": False,
            }
            continue
        if measure in _CATEGORICAL:
            adverse, denominator = _CATEGORICAL[measure]
            counts: dict[str, int] = {}
            for item in observations:
                if item["status"] == "known":
                    counts[item["value"]] = counts.get(item["value"], 0) + 1
            total = sum(counts.get(key, 0) for key in denominator)
            summary[measure] = {
                "counts": {key: counts[key] for key in sorted(counts)},
                "unknown_runs": unknown_runs,
                "unknown_reasons": unknown_reasons,
                "adverse_rate": (
                    {
                        "numerator": sum(counts.get(key, 0) for key in adverse),
                        "denominator": total,
                    }
                    if total
                    else None
                ),
            }
            continue
        values = [
            _micros(item) if measure == "cost" else item["value"]
            for item in observations
            if item["status"] == "known"
        ]
        summary[measure] = {
            "unit": "usd_micros" if measure == "cost" else "milliseconds",
            "known_runs": len(values),
            "unknown_runs": unknown_runs,
            "unknown_reasons": unknown_reasons,
            "minimum": min(values) if values else None,
            "median": _median(values),
            "maximum": max(values) if values else None,
        }
    return summary


def _compare(
    measure: str, baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> str:
    if measure == "conformance":
        return "NOT_EVALUATED"
    if measure in _CATEGORICAL:
        left = baseline[measure]["adverse_rate"]
        right = candidate[measure]["adverse_rate"]
        if left is None or right is None:
            return "INCOMPLETE"
        first = right["numerator"] * left["denominator"]
        second = left["numerator"] * right["denominator"]
        if first < second:
            return "IMPROVED"
        return "REGRESSED" if first > second else "EQUAL"
    left_numeric = baseline[measure]
    right_numeric = candidate[measure]
    if (
        left_numeric["unknown_runs"]
        or right_numeric["unknown_runs"]
        or not left_numeric["known_runs"]
        or not right_numeric["known_runs"]
    ):
        return "INCOMPLETE"
    if right_numeric["median"] < left_numeric["median"]:
        return "IMPROVED"
    return "REGRESSED" if right_numeric["median"] > left_numeric["median"] else "EQUAL"


def _classify(measure: str, observation: Mapping[str, Any], reference: int | None) -> str:
    if observation["status"] != "known":
        return "unknown"
    if measure in _CATEGORICAL:
        adverse, _denominator = _CATEGORICAL[measure]
        if observation["value"] in _BETTER[measure]:
            return "better"
        return "worse" if observation["value"] in adverse else "neutral"
    if reference is None:
        return "unknown"
    value = _micros(observation) if measure == "cost" else observation["value"]
    if value < reference:
        return "better"
    return "worse" if value > reference else "neutral"


def _measures_for(dimension: str) -> tuple[str, ...]:
    if dimension == "role_model":
        return (
            "conformance",
            "correctness",
            "role_acceptance",
            "human_usefulness",
            "cost",
            "latency",
        )
    return ("conformance", "correctness", "human_usefulness", "cost", "latency")


def _decisive_order(dimension: str) -> tuple[str, ...]:
    """The measures that may decide a proposal, highest precedence first.

    Run-level correctness is not attributable to one role, so for a role-model
    candidate it can refuse the candidate but never carry it.
    """

    if dimension == "role_model":
        return ("role_acceptance", "human_usefulness", "cost", "latency")
    return ("correctness", "human_usefulness", "cost", "latency")


def _controlled_mismatch(
    settings: Mapping[str, Any],
    current: Mapping[str, Any],
    dimension: str,
    role: str | None,
) -> list[str]:
    """Why a run cannot take part in this candidate's comparison."""

    reasons: list[str] = []
    for field in _CONTROLLED[dimension]:
        if field in ("workflow_profile", "worker_count"):
            if settings[field] != current[field]:
                reasons.append("differs:" + field)
            continue
        observed = dict(settings[field])
        expected = dict(current[field])
        if dimension == "role_model" and role is not None and field == "models":
            observed.pop(role, None)
            expected.pop(role, None)
        if observed != expected:
            reasons.append("differs:" + field)
    return sorted(set(reasons))



def _candidate_verdict(
    candidate: Mapping[str, Any],
    current: Mapping[str, Any],
    eligible: list[dict[str, Any]],
    floors: Mapping[str, int],
    project_floor_met: bool,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """One candidate's observed comparison, and its support when proposable."""

    dimension = candidate["dimension"]
    choice = candidate["choice"]
    role = choice.get("role") if dimension == "role_model" else None
    key = _choice_key(dimension, choice)
    settings = current["settings"]
    baseline_choices = _observed_choices(settings)
    baseline_choice = baseline_choices.get(key)
    measures = _measures_for(dimension)
    verdict: dict[str, Any] = {
        "candidate_id": candidate["candidate_id"],
        "dimension": dimension,
        "choice": deepcopy(choice),
        "status": "NOT_SUPPORTED",
        "reasons": [],
        "baseline_choice": deepcopy(baseline_choice),
        "baseline_arm": None,
        "candidate_arm": None,
        "measures": {},
        "not_comparable_runs": [],
        "decisive_measure": None,
        "promotion_gaps": [],
        "role_attribution_limited": dimension == "role_model",
    }
    if baseline_choice is None:
        verdict["reasons"] = ["current_settings:role_absent"]
        return verdict, None
    if baseline_choice == choice:
        verdict["reasons"] = ["candidate:choice_not_distinct"]
        return verdict, None
    if (
        candidate["configuration"]["configuration_sha256"]
        == current["configuration"]["configuration_sha256"]
    ):
        verdict["reasons"] = ["candidate:configuration_not_distinct"]
        return verdict, None
    default = candidate["configuration"].get("role_default")
    if dimension == "role_model" and default is not None and default["role"] != role:
        verdict["reasons"] = ["candidate:role_default_role_mismatch"]
        return verdict, None
    baseline_runs: list[dict[str, Any]] = []
    candidate_runs: list[dict[str, Any]] = []
    not_comparable: list[dict[str, Any]] = []
    for view in eligible:
        observed = view["choices"].get(key)
        if observed is None:
            not_comparable.append(
                {"run_id": view["run_id"], "reasons": ["dimension_not_observed"]}
            )
            continue
        if observed not in (baseline_choice, choice):
            not_comparable.append(
                {"run_id": view["run_id"], "reasons": ["other_choice_observed"]}
            )
            continue
        control = _controlled_mismatch(view["settings"], settings, dimension, role)
        if control:
            not_comparable.append({"run_id": view["run_id"], "reasons": control})
            continue
        entry = {"view": view, "observations": _observations(view, dimension, role)}
        if observed == choice:
            candidate_runs.append(entry)
        else:
            baseline_runs.append(entry)
    verdict["not_comparable_runs"] = sorted(
        not_comparable, key=lambda item: item["run_id"]
    )
    baseline_arm = _arm(baseline_runs, measures)
    candidate_arm = _arm(candidate_runs, measures)
    baseline_arm["choice"] = deepcopy(baseline_choice)
    candidate_arm["choice"] = deepcopy(choice)
    verdict["baseline_arm"] = baseline_arm
    verdict["candidate_arm"] = candidate_arm
    comparisons = {
        measure: _compare(measure, baseline_arm, candidate_arm) for measure in measures
    }
    verdict["measures"] = {
        measure: {
            "comparison": comparisons[measure],
            "baseline": deepcopy(baseline_arm[measure]),
            "candidate": deepcopy(candidate_arm[measure]),
        }
        for measure in measures
    }
    floor = floors["min_comparable_runs_per_choice"]
    reasons: list[str] = []
    if not project_floor_met:
        reasons.append("floor:project_runs_not_met")
    if baseline_arm["run_count"] < floor:
        reasons.append("floor:baseline_runs_not_met")
    if candidate_arm["run_count"] < floor:
        reasons.append("floor:candidate_runs_not_met")
    if reasons:
        verdict["reasons"] = sorted(set(reasons))
        return verdict, None
    if (
        candidate_arm["conformance"]["runs_with_privacy_event_refs"]
        or candidate_arm["conformance"]["runs_with_authority_event_refs"]
    ):
        verdict["status"] = "REFUSED"
        verdict["reasons"] = ["conformance:candidate_events_unreviewed"]
        return verdict, None
    if dimension == "role_model" and comparisons["correctness"] == "REGRESSED":
        verdict["status"] = "REFUSED"
        verdict["reasons"] = ["precedence:correctness_regressed"]
        return verdict, None
    decisive: str | None = None
    for measure in _decisive_order(dimension):
        if comparisons[measure] == "REGRESSED":
            verdict["status"] = "REFUSED"
            verdict["reasons"] = ["precedence:" + measure + "_regressed"]
            return verdict, None
        if comparisons[measure] == "IMPROVED":
            decisive = measure
            break
    if decisive is None:
        verdict["reasons"] = ["evidence:no_observed_improvement"]
        return verdict, None
    gaps = ["conformance:not_evaluated_by_this_evaluator"]
    gaps.extend(_COUPLING_GAPS[dimension])
    for measure in measures:
        if comparisons[measure] == "INCOMPLETE":
            gaps.append(measure + ":evidence_incomplete")
        elif comparisons[measure] == "REGRESSED":
            gaps.append("tradeoff:" + measure + "_regressed")
    if dimension == "role_model":
        gaps.append("role_attribution:limited")
    if not any(
        item["view"]["configuration_sha256"]
        in (
            candidate["configuration"]["configuration_sha256"],
            candidate["observed_configuration_sha256"],
        )
        for item in candidate_runs
    ):
        gaps.append("candidate_configuration:not_observed")
    reference = baseline_arm[decisive]["median"] if decisive in _NUMERIC else None
    runs: list[dict[str, Any]] = []
    for arm_name, arm_runs in (
        ("baseline", baseline_runs),
        ("candidate", candidate_runs),
    ):
        for item in arm_runs:
            observation = item["observations"][decisive]
            runs.append(
                {
                    "run_id": item["view"]["run_id"],
                    "arm": arm_name,
                    "evidence_schema": item["view"]["evidence_schema"],
                    "observation": deepcopy(observation),
                    "classification": _classify(decisive, observation, reference),
                }
            )
    runs.sort(key=lambda item: (item["arm"], item["run_id"]))
    supporting = sorted(
        item["run_id"]
        for item in runs
        if (item["arm"] == "candidate" and item["classification"] == "better")
        or (item["arm"] == "baseline" and item["classification"] == "worse")
    )
    contradicting = sorted(
        item["run_id"]
        for item in runs
        if (item["arm"] == "candidate" and item["classification"] == "worse")
        or (item["arm"] == "baseline" and item["classification"] == "better")
    )
    if not supporting:
        verdict["reasons"] = ["evidence:no_supporting_run"]
        return verdict, None
    verdict["status"] = "PROPOSED"
    verdict["reasons"] = []
    verdict["decisive_measure"] = decisive
    verdict["promotion_gaps"] = sorted(set(gaps))
    support = {
        "decisive_measure": decisive,
        "baseline_reference": reference,
        "runs": runs,
        "supporting_runs": supporting,
        "contradicting_runs": contradicting,
        "neutral_runs": sorted(
            item["run_id"] for item in runs if item["classification"] == "neutral"
        ),
        "unknown_runs": sorted(
            (
                {
                    "run_id": item["run_id"],
                    "arm": item["arm"],
                    "reason": item["observation"].get("reason"),
                }
                for item in runs
                if item["classification"] == "unknown"
            ),
            key=lambda item: item["run_id"],
        ),
        "not_comparable_runs": verdict["not_comparable_runs"],
    }
    return verdict, support


def _proposal(
    *,
    project_id: str,
    evaluated_at: str,
    current: Mapping[str, Any],
    candidate: Mapping[str, Any],
    verdict: Mapping[str, Any],
    support: Mapping[str, Any],
    floors: Mapping[str, int],
    floors_source: str,
    evidence_limitations: list[str],
) -> dict[str, Any]:
    """One advisory proposal bound to an actual full Challenger configuration."""

    return _seal(
        {
            "schema": PROPOSAL_SCHEMA,
            "proposal_id": candidate["candidate_id"],
            "project_id": project_id,
            "evaluated_at": evaluated_at,
            "dimension": verdict["dimension"],
            "baseline": {
                "choice": deepcopy(verdict["baseline_choice"]),
                "settings": deepcopy(dict(current["settings"])),
                "configuration": deepcopy(dict(current["configuration"])),
                "configuration_sha256": current["configuration"]["configuration_sha256"],
            },
            "candidate": {
                "choice": deepcopy(verdict["choice"]),
                "configuration": deepcopy(candidate["configuration"]),
                "configuration_sha256": candidate["configuration"][
                    "configuration_sha256"
                ],
                "configuration_source": candidate["configuration_source"],
                "observed_configuration_sha256": candidate[
                    "observed_configuration_sha256"
                ],
            },
            "floors": dict(floors),
            "floors_source": floors_source,
            "fixture_only": floors_source != "production_default",
            "decisive_measure": verdict["decisive_measure"],
            "measures": deepcopy(verdict["measures"]),
            "support": deepcopy(dict(support)),
            "promotion_gaps": list(verdict["promotion_gaps"]),
            "evidence_limitations": sorted(set(evidence_limitations)),
            "role_attribution_limited": verdict["role_attribution_limited"],
            "promotion_path": "fr60_champion_challenger",
            "advisory_only": True,
            "approval_required": True,
            "applies_to": "future_runs_only",
            "activation_permitted": False,
            "dispatch_permitted": False,
            "promotion_decided": False,
            "policy_mutated": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        },
        "proposal_sha256",
    )


def _empty_evidence() -> dict[str, Any]:
    return {
        "eligible_runs": [],
        "eligible_run_count": 0,
        "excluded_runs": [],
        "duplicate_run_ids": [],
        "evidence_schemas": {},
        "host_excluded_runs": [],
        "limitations": [],
    }


def _report(
    *,
    status: str,
    decision: str,
    issues: list[str],
    floors: Mapping[str, int],
    floors_source: str,
    project_id: Any = None,
    evaluated_at: Any = None,
    floors_met: bool = False,
    evidence: Any = None,
    candidates: Any = None,
    proposals: Any = None,
) -> dict[str, Any]:
    return _seal(
        {
            "schema": REPORT_SCHEMA,
            "status": status,
            "decision": decision,
            "issues": sorted(set(issues)),
            "project_id": project_id if _identifier(project_id) else None,
            "evaluated_at": evaluated_at if _instant(evaluated_at) else None,
            "floors": dict(floors),
            "floors_source": floors_source,
            "fixture_only": floors_source != "production_default",
            "floors_met": floors_met,
            "evidence": evidence if evidence is not None else _empty_evidence(),
            "candidates": candidates or [],
            "proposals": proposals or [],
            "advisory_only": True,
            "approval_required": True,
            "applies_to": "future_runs_only",
            "activation_permitted": False,
            "dispatch_permitted": False,
            "promotion_decided": False,
            "policy_mutated": False,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        },
        "report_sha256",
    )


def evaluate(request: Any) -> dict[str, Any]:
    """Propose observed per-project alternatives under the production floors."""

    return _evaluate(request, dict(PRODUCTION_FLOORS), "production_default")


def evaluate_with_fixture_floors(request: Any, *, floors: Any) -> dict[str, Any]:
    """The synthetic-fixture seam: the same evaluator at explicit small floors.

    This exists so a provider-free fixture need not synthesize twenty runs per
    assertion.  Every report and proposal it produces is stamped
    `fixture_only`, and no production or model-facing input reaches it:
    `evaluate` is the only production entry and always uses
    `PRODUCTION_FLOORS`.
    """

    return _evaluate(request, _floors(floors), "synthetic_fixture")


def _evaluate(
    request: Any, floors: Mapping[str, int], floors_source: str
) -> dict[str, Any]:
    issues: list[str] = []
    try:
        canonical = _canonical(request)
    except (ProjectProposalError, TypeError, ValueError, OverflowError, RecursionError):
        canonical = None
    if canonical is None:
        return _report(
            status="FAIL",
            decision="REQUEST_REFUSED",
            issues=["input:hostile_or_noncanonical"],
            floors=floors,
            floors_source=floors_source,
        )
    parsed = _closed(request, _REQUEST_FIELDS, "request", issues)
    if parsed is not None:
        if parsed.get("schema") != REQUEST_SCHEMA:
            _issue(issues, "request:schema_invalid")
        if not _identifier(parsed.get("project_id")):
            _issue(issues, "request:project_id_invalid")
        if not _instant(parsed.get("evaluated_at")):
            _issue(issues, "request:evaluated_at_invalid")
    current = None
    candidates: list[dict[str, Any]] = []
    if parsed is not None and not issues:
        envelope = _closed(parsed.get("current"), _CURRENT_FIELDS, "current", issues)
        if envelope is not None:
            settings = _settings(envelope.get("settings"), "current:settings", issues)
            configuration = _validated_configuration(
                envelope.get("configuration"),
                "current:configuration",
                issues,
                roles=frozenset({"champion", "challenger"}),
            )
            if settings is not None and configuration is not None:
                current = {"settings": settings, "configuration": configuration}
        candidates = _candidates(parsed.get("candidates"), issues)
    read = (
        _history(parsed["history"], parsed["project_id"], issues)
        if parsed is not None and current is not None and not issues
        else None
    )
    if parsed is None or current is None or read is None or issues:
        return _report(
            status="FAIL",
            decision="REQUEST_REFUSED",
            issues=issues,
            floors=floors,
            floors_source=floors_source,
            project_id=parsed.get("project_id") if parsed else None,
            evaluated_at=parsed.get("evaluated_at") if parsed else None,
        )
    eligible, evidence = read
    floors_met = evidence["eligible_run_count"] >= floors["min_eligible_project_runs"]
    verdicts: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for candidate in candidates:
        verdict, support = _candidate_verdict(
            candidate, current, eligible, floors, floors_met
        )
        verdicts.append(verdict)
        if support is None:
            continue
        records.append(
            _proposal(
                project_id=parsed["project_id"],
                evaluated_at=parsed["evaluated_at"],
                current=current,
                candidate=candidate,
                verdict=verdict,
                support=support,
                floors=floors,
                floors_source=floors_source,
                evidence_limitations=evidence["limitations"],
            )
        )
    return _report(
        status="PASS",
        decision="PROPOSALS_RECORDED" if records else "NO_PROPOSAL",
        issues=issues,
        floors=floors,
        floors_source=floors_source,
        project_id=parsed["project_id"],
        evaluated_at=parsed["evaluated_at"],
        floors_met=floors_met,
        evidence=evidence,
        candidates=verdicts,
        proposals=records,
    )


__all__ = [
    "CANDIDATE_SCHEMA",
    "DIMENSIONS",
    "HISTORY_SCHEMA",
    "HOST_VERDICTS",
    "MAX_CANDIDATES",
    "PRODUCTION_FLOORS",
    "PROJECT_RUN_FACTORS_SCHEMA",
    "PROPOSAL_SCHEMA",
    "REPORT_SCHEMA",
    "REQUEST_SCHEMA",
    "ProjectProposalError",
    "evaluate",
    "evaluate_with_fixture_floors",
    "json_sha256",
]
