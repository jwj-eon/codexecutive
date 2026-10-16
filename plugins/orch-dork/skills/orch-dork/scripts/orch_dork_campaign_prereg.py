#!/usr/bin/env python3
"""Seal a campaign preregistration sized to the evidence it has.

The v6 lesson (TICKETS.md Issue 122) is that a campaign can be doomed by
arithmetic nobody computed: 234 lane sessions under a stop-on-any-failure
regime had a 0.05% chance of finishing, and the shortfall looked like bad
luck instead of bad sizing.  This module makes that computation a
precondition of dispatch rather than a postmortem.

Everything here is descriptive.  A preregistration binds what a campaign
intends and what the evidence says about its odds; it creates no grant,
names no token ceiling, and cannot authorize a live run.  Only a later fully
reproduced bounded dispatch packet may bind standing Owner authority.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, Sequence

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_campaign_power as power  # noqa: E402
import orch_dork_evidence_rate as evidence_rate  # noqa: E402


PREREG_SCHEMA = "orch-dork/campaign-preregistration/v1"

_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_LABEL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

# The surviving stop surface after Issue 123: an observation that cannot
# be trusted at all still ends a campaign, and no rate estimate makes
# that safe to ignore.  This is the bound a pilot exists to tighten.
TIGHTENED_BOUND = "non_continuable_observation_rate"

# The v6 grid: 90 cells at lane counts 1/2/4 across three seeds.
FULL_GRID_SESSIONS = 234

_AUTHORITY_NOTE = (
    "This record preregisters intent and reports the odds the recorded "
    "evidence implies. It creates no grant, moves no limit, and cannot "
    "authorize dispatch. Only a fully reproduced bounded dispatch packet "
    "may bind standing Owner authority."
)


def clean_sessions_for_target(*, target_sessions: int, completion: float) -> int:
    """Clean sessions needed before a target grid reaches given odds.

    Inverts the rule of three: a campaign of ``target_sessions`` reaches
    ``completion`` odds only when the failure-rate bound is at most
    ``1 - completion ** (1 / target_sessions)``, and the rule of three puts
    that bound at ``3 / n`` after ``n`` clean sessions.  The number this
    returns is usually large, which is the point: it says plainly how far
    the evidence is from supporting an ambitious grid.
    """

    if (
        not _positive_int(target_sessions)
        or type(completion) is not float
        or not 0.0 < completion < 1.0
    ):
        raise ValueError("target sizing inputs are invalid")
    allowed = 1.0 - completion ** (1.0 / target_sessions)
    return int(math.ceil(3.0 / allowed))


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _refusal(issues: list[str]) -> dict[str, Any]:
    core = {
        "schema": PREREG_SCHEMA,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "campaign_label": None,
        "required_sessions": None,
        "assumed_failure_rate": None,
        "assumed_rate_basis": None,
        "completion_probability": None,
        "pilot_outcomes_only": None,
        "binding_constraint": None,
        "bound_to_tighten": None,
        "descriptive_only": True,
        "grants_authority": False,
        "authority_note": _AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "record_sha256": _sha256(core)}


def build_campaign_preregistration(
    *,
    campaign_label: str,
    preregistered_at: str,
    cells: Sequence[str],
    sessions_per_cell: Sequence[int],
    prior_clean_sessions: int,
    prior_failures: int,
    dispatch_seed: int,
    per_cell_tokens: int | None = None,
    per_cell_wall_ms: int | None = None,
    grant_max_tokens: int | None = None,
    grant_max_wall_time_ms: int | None = None,
) -> dict[str, Any]:
    """Seal one campaign's intent, odds, and the bound it exists to move.

    ``sessions_per_cell`` is positional against ``cells``: a cell running
    four lanes contributes four chances for a non-continuable observation
    to end the campaign, which is exactly why lane-heavy grids are so much
    more fragile than their cell count suggests.

    The assumed failure rate is the *pessimistic* rule-of-three upper
    bound on the prior evidence, not its point estimate.  Zero observed
    failures does not mean a zero rate, and sizing off the optimistic read
    is how a campaign talks itself into a grid it cannot finish.

    The four budget arguments are optional because a preregistration is
    written before a grant exists.  When supplied they add a
    binding-constraint projection, which answers a different question from
    survival: whether tokens or wall clock would run out first.  For v6
    the answer was neither, which is exactly why the budget framing
    misdiagnosed it.
    """

    issues: list[str] = []
    if not isinstance(campaign_label, str) or not _LABEL.fullmatch(
        campaign_label
    ):
        issues.append("prereg:campaign_label_invalid")
    if not isinstance(preregistered_at, str) or not _TIMESTAMP.fullmatch(
        preregistered_at
    ):
        issues.append("prereg:preregistered_at_invalid")
    if (
        not isinstance(cells, Sequence)
        or isinstance(cells, (str, bytes))
        or not cells
        or any(not isinstance(cell, str) or not cell for cell in cells)
        or len(set(cells)) != len(cells)
    ):
        issues.append("prereg:cells_invalid")
    if (
        not isinstance(sessions_per_cell, Sequence)
        or isinstance(sessions_per_cell, (str, bytes))
        or not sessions_per_cell
        or any(not _positive_int(value) for value in sessions_per_cell)
        or (
            isinstance(cells, Sequence)
            and not isinstance(cells, (str, bytes))
            and len(sessions_per_cell) != len(cells)
        )
    ):
        issues.append("prereg:sessions_per_cell_invalid")
    if not _positive_int(prior_clean_sessions):
        issues.append("prereg:prior_sessions_invalid")
    if type(prior_failures) is not int or prior_failures < 0:
        issues.append("prereg:prior_failures_invalid")
    if type(dispatch_seed) is not int:
        issues.append("prereg:dispatch_seed_invalid")
    if issues:
        return _refusal(issues)

    bounds = evidence_rate.evidence_failure_rate(
        failures=prior_failures, sessions=prior_clean_sessions
    )
    if bounds["status"] != "PASS":
        return _refusal(["prereg:prior_evidence_invalid"])
    assumed = bounds["rule_of_three_upper_95"]
    basis = "rule_of_three_upper_95"
    if assumed is None:
        # The rule of three applies only at zero observed failures; with
        # real failures the Jeffreys upper bound is the pessimistic read.
        assumed = bounds["jeffreys_upper_95"]
        basis = "jeffreys_upper_95"
    if assumed is None or not 0.0 <= assumed <= 1.0:
        # Below four prior sessions the rule of three exceeds 1.0, which is
        # not a probability. Too little evidence to size against refuses
        # rather than sealing a nonsense completion figure.
        return _refusal(["prereg:prior_evidence_insufficient"])

    required_sessions = sum(int(value) for value in sessions_per_cell)
    survival = power.project_campaign_survival(
        required_sessions=required_sessions,
        cells=len(cells),
        failure_rate=assumed,
    )
    if survival.get("status") != "PASS":
        return _refusal(["prereg:survival_projection_invalid"])
    projected = evidence_rate.evidence_failure_rate(
        failures=prior_failures,
        sessions=prior_clean_sessions + required_sessions,
    )
    projected_bound = (
        projected["rule_of_three_upper_95"]
        if basis == "rule_of_three_upper_95"
        else projected["jeffreys_upper_95"]
    )
    budget_inputs = (
        per_cell_tokens,
        per_cell_wall_ms,
        grant_max_tokens,
        grant_max_wall_time_ms,
    )
    if all(value is None for value in budget_inputs):
        binding_constraint: Any = None
    elif any(not _positive_int(value) for value in budget_inputs):
        return _refusal(["prereg:budget_projection_invalid"])
    else:
        binding_constraint = power.project_binding_constraint(
            cells=len(cells),
            per_cell_tokens=int(per_cell_tokens),
            per_cell_wall_ms=int(per_cell_wall_ms),
            grant_max_tokens=int(grant_max_tokens),
            grant_max_wall_time_ms=int(grant_max_wall_time_ms),
        )
    core = {
        "schema": PREREG_SCHEMA,
        "status": "PASS",
        "issues": [],
        "campaign_label": campaign_label,
        "preregistered_at": preregistered_at,
        "cell_count": len(cells),
        "required_sessions": required_sessions,
        "assumed_failure_rate": assumed,
        "assumed_rate_basis": basis,
        # Single source: the survival projection owns this arithmetic, so
        # the record cannot carry two disagreeing completion figures.
        "completion_probability": survival["completion_probability"],
        "pilot_outcomes_only": survival["pilot_outcomes_only"],
        "survival": survival,
        "binding_constraint": binding_constraint,
        "dispatch_order": power.seal_dispatch_order(
            cells=list(cells), seed=dispatch_seed
        ),
        "rate_plan": evidence_rate.build_rate_plan_record(
            campaign_label=campaign_label,
            preregistered_at=preregistered_at,
        ),
        "failure_budget": power.build_failure_budget_record(
            campaign_label=campaign_label,
            preregistered_at=preregistered_at,
            malformed_upper_bound_limit="0.10",
            evidence_failure_upper_bound_limit="0.10",
        ),
        "bound_to_tighten": {
            "bound": TIGHTENED_BOUND,
            "prior_clean_sessions": prior_clean_sessions,
            "prior_failures": prior_failures,
            "current_bound": assumed,
            "projected_bound_if_clean": projected_bound,
            "sessions_added_if_clean": required_sessions,
            # What the full v6-shaped grid would actually require, so the
            # gap between this pilot and an ambitious campaign is a
            # number rather than an impression.
            "full_grid_sessions": FULL_GRID_SESSIONS,
            "clean_sessions_for_full_grid_even_odds": (
                clean_sessions_for_target(
                    target_sessions=FULL_GRID_SESSIONS, completion=0.5
                )
            ),
        },
        "descriptive_only": True,
        "grants_authority": False,
        "authority_note": _AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "record_sha256": _sha256(core)}


__all__ = [
    "PREREG_SCHEMA",
    "FULL_GRID_SESSIONS",
    "TIGHTENED_BOUND",
    "build_campaign_preregistration",
    "clean_sessions_for_target",
]
