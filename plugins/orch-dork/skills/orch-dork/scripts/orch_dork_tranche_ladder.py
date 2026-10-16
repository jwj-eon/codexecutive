#!/usr/bin/env python3
"""Issue 126: plan a campaign as a ladder of small tranches.

Under stop-on-any-failure, completion probability decays geometrically in
session count.  That makes every large one-shot grid a bad bet no matter
how good the evidence gets: at the current pooled bound a 90-session grid
completes with probability 0.0058, and even a five-times-better bound
leaves it a coin flip.  The v6 postmortem read that as bad sizing.  The
sharper reading is that one-shot grid dispatch is the wrong shape.

A ladder is the right shape.  Each clean tranche enlarges the evidence
pool, which tightens the rule-of-three bound, which makes the next tranche
more likely to finish.  Evidence compounds instead of being gambled.

Two properties make this honest rather than merely optimistic.  First, a
stopped tranche is not wasted: its settled cells stay sealed and still
enter the pool, because the Issue 125 deriver counts settled records, not
completed campaigns.  Second, a v4 parameterized grant needs no
predecessor binding, so each tranche is an ordinary independent campaign
and the ladder introduces no coupling, no new execution mode, and no new
authority.

Everything here is descriptive.  The ladder is a planning artifact: it
creates no grant and cannot dispatch.  Each tranche requires its own fully
reproduced bounded dispatch packet and one-use standing-authority grant.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_evidence_rate as evidence_rate  # noqa: E402


LADDER_SCHEMA = "orch-dork/campaign-tranche-ladder/v1"

_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_LABEL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

# A tranche is worth dispatching only if it finishes more often than not.
# This is a planning threshold, not a stopping rule: nothing reads it at
# runtime and no seam consults it.
VIABLE_COMPLETION = 0.5

# A size that clears the threshold by a hair is not really viable: the
# bound it was computed from is itself an estimate, and the first observed
# failure moves it. At a pool of 54, twelve sessions clear 0.5 by 0.0036
# and fall to 0.418 the moment one failure appears, while nine still holds
# at 0.520.
#
# The margin is set so the recommendation survives one observed failure at
# every pool a ladder actually walks through, not merely at its starting
# pool. A 0.05 margin was tuned to a single pool and breaks at 63 (12
# sessions -> 0.474) and at 126 (24 sessions -> 0.474); 0.08 holds across
# 54 through 150. Tests pin that survival across the walked pools, so this
# constant cannot quietly drift back to a value that only fits one point.
VIABLE_MARGIN = 0.08

# Candidate tranche sizes, smallest first. The recommendation is the
# largest candidate still clearing VIABLE_COMPLETION.
CANDIDATE_SIZES = (3, 6, 9, 12, 18, 24, 36)

_AUTHORITY_NOTE = (
    "This record plans tranche shape and reports the odds the recorded "
    "evidence implies. It creates no grant, moves no limit, and cannot "
    "authorize dispatch. Every tranche requires its own fully reproduced "
    "packet and one-use standing-authority grant."
)


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


def _round6(value: float) -> float:
    return float(round(value, 6))


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _refusal(issues: list[str]) -> dict[str, Any]:
    core = {
        "schema": LADDER_SCHEMA,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "campaign_label": None,
        "tranches": None,
        "recommended_tranche": None,
        "one_shot_comparison": None,
        "bound_basis": None,
        "settled_cells_retained_on_stop": True,
        "descriptive_only": True,
        "grants_authority": False,
        "authority_note": _AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "record_sha256": _sha256(core)}


def _bound(failures: int, sessions: int) -> tuple[float | None, str]:
    """The pessimistic upper bound on the stop-surface rate.

    Zero observed failures does not mean a zero rate, so sizing reads the
    rule of three.  With real failures the rule does not apply and the
    Jeffreys upper bound is the pessimistic read.
    """

    report = evidence_rate.evidence_failure_rate(
        failures=failures, sessions=sessions
    )
    if report["status"] != "PASS":
        return None, "invalid"
    value = report["rule_of_three_upper_95"]
    if value is not None:
        return value, "rule_of_three_upper_95"
    return report["jeffreys_upper_95"], "jeffreys_upper_95"


def _usable_bound(value: float | None) -> bool:
    """A bound of 1.0 is arithmetically legal but plans nothing.

    At or below three clean sessions the rule of three returns exactly 1.0,
    which passes a naive 0..1 range check and then seals a ladder whose
    every rung completes with probability zero. That is a fail-open shape:
    it looks like a plan and contains no information.
    """

    return type(value) is float and 0.0 <= value < 1.0


def recommend_tranche_size(
    *, prior_clean_sessions: int, prior_failures: int = 0
) -> dict[str, Any]:
    """Largest candidate tranche that still completes more often than not."""

    bound, basis = _bound(prior_failures, prior_clean_sessions)
    if bound is None or not 0.0 <= bound <= 1.0:
        return {
            "sessions": None,
            "completion_probability": None,
            "next_size_completion_probability": None,
            "rule": None,
            "bound_basis": basis,
        }
    chosen = CANDIDATE_SIZES[0]
    viable = False
    for size in CANDIDATE_SIZES:
        if (1.0 - bound) ** size > VIABLE_COMPLETION + VIABLE_MARGIN:
            chosen = size
            viable = True
        else:
            break
    if not viable:
        # No candidate clears the bar. Recommending the smallest size
        # anyway would seal a recommendation nobody should act on.
        return {
            "sessions": None,
            "completion_probability": None,
            "next_size": None,
            "next_size_completion_probability": None,
            "rule": None,
            "bound_basis": basis,
            "feasible": False,
        }
    index = CANDIDATE_SIZES.index(chosen)
    following = (
        CANDIDATE_SIZES[index + 1]
        if index + 1 < len(CANDIDATE_SIZES)
        else None
    )
    return {
        "sessions": chosen,
        "completion_probability": _round6((1.0 - bound) ** chosen),
        "next_size": following,
        "next_size_completion_probability": (
            _round6((1.0 - bound) ** following)
            if following is not None
            else 0.0
        ),
        "rule": (
            "largest candidate tranche whose completion probability at the "
            "pessimistic bound exceeds %s with a %s robustness margin, so "
            "the choice survives the first observed failure"
            % (VIABLE_COMPLETION, VIABLE_MARGIN)
        ),
        "bound_basis": basis,
        "feasible": True,
    }


def build_tranche_ladder(
    *,
    campaign_label: str,
    planned_at: str,
    prior_clean_sessions: int,
    prior_failures: int,
    sessions_per_tranche: int,
    tranche_count: int,
) -> dict[str, Any]:
    """Project a ladder of tranches, each sized by the last one's evidence.

    Every rung is priced by the pool the previous rung produced, assuming
    that rung completed cleanly. The caller fixes the rung size; the ladder
    re-prices, it does not resize. That is what makes this a plan rather
    than a prediction: a stopped rung simply re-plans from the pool it
    actually produced.
    """

    issues: list[str] = []
    if not isinstance(campaign_label, str) or not _LABEL.fullmatch(
        campaign_label
    ):
        issues.append("ladder:campaign_label_invalid")
    if not isinstance(planned_at, str) or not _TIMESTAMP.fullmatch(planned_at):
        issues.append("ladder:planned_at_invalid")
    if not _positive_int(prior_clean_sessions):
        issues.append("ladder:prior_sessions_invalid")
    if type(prior_failures) is not int or prior_failures < 0:
        issues.append("ladder:prior_failures_invalid")
    if not _positive_int(sessions_per_tranche):
        issues.append("ladder:sessions_per_tranche_invalid")
    if not _positive_int(tranche_count):
        issues.append("ladder:tranche_count_invalid")
    if issues:
        return _refusal(issues)

    bound, basis = _bound(prior_failures, prior_clean_sessions)
    if not _usable_bound(bound):
        # At or below three clean sessions the rule of three reaches 1.0
        # and every rung would complete with probability zero. Too little
        # evidence to plan against refuses rather than sealing a ladder
        # that looks like a plan and contains nothing.
        return _refusal(["ladder:prior_evidence_insufficient"])

    tranches: list[dict[str, Any]] = []
    pool = prior_clean_sessions
    for index in range(tranche_count):
        rung_bound, rung_basis = _bound(prior_failures, pool)
        if not _usable_bound(rung_bound):
            # Distinct from up-front insufficiency: the ladder started from
            # usable evidence and a later rung did not.
            return _refusal(["ladder:rung_bound_invalid"])
        completion = (1.0 - rung_bound) ** sessions_per_tranche
        tranches.append(
            {
                "index": index + 1,
                "sessions": sessions_per_tranche,
                "pool_before": pool,
                "pool_after": pool + sessions_per_tranche,
                "bound_before": rung_bound,
                "bound_basis": rung_basis,
                "completion_probability": _round6(completion),
                # A stop forfeits only the cells after the failing one;
                # everything already settled stays sealed and still counts.
                "max_sessions_forfeited_on_stop": sessions_per_tranche - 1,
            }
        )
        pool += sessions_per_tranche

    total_sessions = sessions_per_tranche * tranche_count

    # The honest comparison. Completing every rung has probability equal to
    # the product of the rungs, which is the quantity a one-shot grid of
    # the same size should be compared against -- not the best or worst
    # single rung. The ladder still wins that comparison, because each rung
    # is priced on a pool the earlier rungs enlarged, but the margin is far
    # smaller than a per-rung comparison would suggest.
    all_rungs = 1.0
    for row in tranches:
        all_rungs *= row["completion_probability"]

    # What each shape is actually expected to yield. A stopped grid forfeits
    # every undispatched cell; a stopped ladder keeps every settled cell and
    # re-plans. Expected settled sessions is therefore the comparison that
    # matches how the two shapes are really used.
    grid_yield = sum((1.0 - bound) ** index for index in range(total_sessions))
    ladder_yield = 0.0
    reached = 1.0
    for row in tranches:
        rung = row["bound_before"]
        ladder_yield += reached * sum(
            (1.0 - rung) ** index for index in range(row["sessions"])
        )
        reached *= (1.0 - rung) ** row["sessions"]

    core = {
        "schema": LADDER_SCHEMA,
        "status": "PASS",
        "issues": [],
        "campaign_label": campaign_label,
        "planned_at": planned_at,
        "prior_clean_sessions": prior_clean_sessions,
        "prior_failures": prior_failures,
        "bound_basis": basis,
        "tranches": tranches,
        "total_sessions": total_sessions,
        "final_pool": pool,
        "final_bound": _bound(prior_failures, pool)[0],
        "recommended_tranche": recommend_tranche_size(
            prior_clean_sessions=prior_clean_sessions,
            prior_failures=prior_failures,
        ),
        # The same total sessions dispatched as one grid, for contrast.
        "one_shot_comparison": {
            "sessions": total_sessions,
            "completion_probability": _round6(
                (1.0 - bound) ** total_sessions
            ),
            "ladder_all_rungs_probability": _round6(all_rungs),
            "grid_expected_settled_sessions": _round6(grid_yield),
            "ladder_expected_settled_sessions": _round6(ladder_yield),
            "note": (
                "Compare like with like: completing every rung has the "
                "product probability, not the per-rung probability. The "
                "ladder beats the grid on that comparison because later "
                "rungs are priced on a pool the earlier rungs enlarged, but "
                "its real advantage is bounded downside -- a stopped grid "
                "forfeits every undispatched cell, while a stopped ladder "
                "keeps every settled cell and re-plans from the larger pool."
            ),
        },
        "settled_cells_retained_on_stop": True,
        "descriptive_only": True,
        "grants_authority": False,
        "authority_note": _AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "record_sha256": _sha256(core)}


__all__ = [
    "LADDER_SCHEMA",
    "CANDIDATE_SIZES",
    "VIABLE_COMPLETION",
    "VIABLE_MARGIN",
    "build_tranche_ladder",
    "recommend_tranche_size",
]
