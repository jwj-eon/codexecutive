#!/usr/bin/env python3
"""Campaign survival, sizing, interval, budget, and dispatch arithmetic.

Tier-4 dossier candidates 1, 2, 6, 8, and 10, corrected against the
sealed v6 ledger (TICKETS.md Issue 122).  Every function here is
descriptive: it reports what the recorded evidence implies and never
gates, stops, sizes a grant, or moves a limit.  The stop seam in
``orch_dork_live_sweep`` remains the sole stopping authority.

The motivating correction: v6 was not bounded by tokens (its grant
covered the whole grid) or wall clock (about 1,478 cells fit the cap).
It was bounded by the interaction of a per-session evidence-failure
rate with a stop-on-any-failure regime, which made completing 234 lane
sessions a roughly 0.05% proposition.  ``project_campaign_survival``
is that arithmetic, declared before dispatch instead of discovered
afterwards.
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

import orch_dork_evidence_rate as evidence_rate  # noqa: E402


SURVIVAL_REPORT_SCHEMA = "orch-dork/campaign-survival-projection/v1"
CONSTRAINT_REPORT_SCHEMA = "orch-dork/campaign-binding-constraint/v1"
VARIANCE_REPORT_SCHEMA = "orch-dork/campaign-variance-interval/v1"
SIZING_REPORT_SCHEMA = "orch-dork/campaign-main-study-sizing/v1"
BUDGET_RECORD_SCHEMA = "orch-dork/campaign-failure-budget/v1"
BUDGET_REPORT_SCHEMA = "orch-dork/campaign-failure-budget-report/v1"
DISPATCH_ORDER_SCHEMA = "orch-dork/campaign-dispatch-order/v1"

_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_LABEL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
# A preregistered rate bound anywhere in [0, 1], written exactly as
# preregistered so the sealed record carries the original text.
_DECIMAL = re.compile(r"\A(?:0|1|0\.\d{1,6}|1\.0{1,6})\Z")

_AUTHORITY_NOTE = (
    "This record describes reporting arithmetic; it is never a stopping "
    "rule, never relaxes or fires the fail-closed stop seam, and never "
    "changes a grant bound."
)

# A campaign more likely than not to hit its stop regime before finishing
# cannot claim a completed grid, so it is declared pilot-outcomes-only.
# Recorded on every survival report so the boundary is never implicit.
PILOT_OUTCOMES_ONLY_COMPLETION_THRESHOLD = 0.5


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


def _seal(core: dict[str, Any], field: str = "report_sha256") -> dict[str, Any]:
    return {**core, field: _sha256(core)}


def _round6(value: float) -> float:
    return float(f"{value:.6f}")


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _finite_number(value: Any) -> bool:
    """A real, finite number: NaN and infinities are refused inputs.

    Canonical sealing uses ``allow_nan=False``, so a non-finite value
    that reached a report would raise instead of returning a sealed
    refusal.  Guarding here keeps every seam fail-closed.
    """

    return (
        type(value) in (int, float)
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _chi2_quantile(probability: float, degrees_of_freedom: int) -> float:
    """Chi-square quantile by bisection on the regularized lower gamma.

    Stdlib only.  ``math.lgamma`` plus a series expansion gives the CDF,
    and the CDF is strictly increasing, so bisection converges without a
    derivative.  For the df=2 case the closed form 1-exp(-x/2) provides
    an independent check, exercised by the tests.
    """

    low, high = 0.0, 1.0
    if not 0.0 < probability < 1.0 or not _positive_int(degrees_of_freedom):
        raise ValueError("chi-square quantile domain is invalid")
    while _chi2_cdf(high, degrees_of_freedom) < probability:
        high *= 2.0
        if high > 1e12:
            raise ValueError("chi-square quantile did not bracket")
    for _ in range(200):
        middle = (low + high) / 2.0
        if _chi2_cdf(middle, degrees_of_freedom) < probability:
            low = middle
        else:
            high = middle
    return (low + high) / 2.0


def _chi2_cdf(x: float, degrees_of_freedom: int) -> float:
    """Regularized lower incomplete gamma P(k/2, x/2)."""

    if x <= 0.0:
        return 0.0
    shape = degrees_of_freedom / 2.0
    scaled = x / 2.0
    if scaled < shape + 1.0:
        term = 1.0 / shape
        total = term
        index = shape
        for _ in range(1000):
            index += 1.0
            term *= scaled / index
            total += term
            if abs(term) < abs(total) * 1e-15:
                break
        return total * math.exp(-scaled + shape * math.log(scaled) - math.lgamma(shape))
    # Continued fraction for the upper tail, then complement.
    tiny = 1e-300
    b = scaled + 1.0 - shape
    c = 1.0 / tiny
    d = 1.0 / b if b != 0.0 else 1.0 / tiny
    fraction = d
    for index in range(1, 1000):
        an = -index * (index - shape)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        fraction *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    upper = fraction * math.exp(-scaled + shape * math.log(scaled) - math.lgamma(shape))
    return 1.0 - upper


def project_campaign_survival(
    *,
    required_sessions: int,
    cells: int,
    failures: int | None = None,
    observed_sessions: int | None = None,
    failure_rate: float | None = None,
) -> dict[str, Any]:
    """Project whether a campaign can survive its own stop regime.

    Under stop-on-any-evidence-failure, completing a grid means every
    one of its lane sessions producing trustworthy evidence.  At an
    observed per-session failure rate p, that probability is
    ``(1 - p) ** required_sessions`` — which falls away quickly, because
    session counts grow with lanes while p does not.  A campaign whose
    completion probability is negligible is pilot-outcomes-only by
    construction, and saying so before dispatch is the whole point.

    Descriptive only: nothing here stops, sizes, or authorizes anything.

    The rate may be given either as observed counts or, when a caller
    already holds an exact bound, as ``failure_rate`` directly.  Passing a
    bound as synthetic counts would quantize it, so the two forms are
    mutually exclusive rather than interchangeable.
    """

    counted = failures is not None or observed_sessions is not None
    if (
        not _positive_int(required_sessions)
        or not _positive_int(cells)
        or (counted and failure_rate is not None)
        or (not counted and failure_rate is None)
        or (
            counted
            and (
                type(failures) is not int
                or not _positive_int(observed_sessions)
                or failures < 0
                or failures > observed_sessions
            )
        )
        or (
            failure_rate is not None
            and (
                not _finite_number(failure_rate)
                or not 0.0 <= failure_rate <= 1.0
            )
        )
    ):
        return _seal(
            {
                "schema": SURVIVAL_REPORT_SCHEMA,
                "status": "FAIL",
                "issues": ["survival:counts_invalid"],
                "required_sessions": None,
                "cells": None,
                "observed_failure_rate": None,
                "completion_probability": None,
                "expected_sessions_to_first_failure": None,
                "expected_cells_to_first_failure": None,
                "pilot_outcomes_only": None,
                "pilot_outcomes_only_threshold": (
                    PILOT_OUTCOMES_ONLY_COMPLETION_THRESHOLD
                ),
                "descriptive_only": True,
                "authority_note": _AUTHORITY_NOTE,
                "provider_free": True,
                "model_calls": 0,
                "hosted_calls": 0,
            }
        )
    rate = (
        float(failure_rate)
        if failure_rate is not None
        else failures / observed_sessions
    )
    completion = (1.0 - rate) ** required_sessions
    sessions_per_cell = required_sessions / cells
    if rate == 0.0:
        expected_sessions = None
        expected_cells = None
    else:
        expected_sessions = _round6(1.0 / rate)
        expected_cells = _round6(1.0 / rate / sessions_per_cell)
    return _seal(
        {
            "schema": SURVIVAL_REPORT_SCHEMA,
            "status": "PASS",
            "issues": [],
            "required_sessions": required_sessions,
            "cells": cells,
            "observed_failure_rate": _round6(rate),
            "completion_probability": _round6(completion),
            "expected_sessions_to_first_failure": expected_sessions,
            "expected_cells_to_first_failure": expected_cells,
            "pilot_outcomes_only": (
                completion < PILOT_OUTCOMES_ONLY_COMPLETION_THRESHOLD
            ),
            "pilot_outcomes_only_threshold": (
                PILOT_OUTCOMES_ONLY_COMPLETION_THRESHOLD
            ),
            "descriptive_only": True,
            "authority_note": _AUTHORITY_NOTE,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    )


def project_binding_constraint(
    *,
    cells: int,
    per_cell_tokens: int,
    per_cell_wall_ms: int,
    grant_max_tokens: int,
    grant_max_wall_time_ms: int,
) -> dict[str, Any]:
    """Name which grant bound, if either, binds a grid at observed rates.

    Reported separately from survival because they answer different
    questions, and conflating them is what produced the refuted
    "the grant afforded nine cells" claim: v6's grant covered its whole
    grid, and neither bound was the reason it stopped.
    """

    if not all(
        _positive_int(value)
        for value in (
            cells,
            per_cell_tokens,
            per_cell_wall_ms,
            grant_max_tokens,
            grant_max_wall_time_ms,
        )
    ):
        return _seal(
            {
                "schema": CONSTRAINT_REPORT_SCHEMA,
                "status": "FAIL",
                "issues": ["constraint:input_invalid"],
                "cells": None,
                "cells_within_token_budget": None,
                "cells_within_wall_budget": None,
                "binding_constraint": None,
                "grid_fits": None,
                "descriptive_only": True,
                "authority_note": _AUTHORITY_NOTE,
                "provider_free": True,
                "model_calls": 0,
                "hosted_calls": 0,
            }
        )
    by_tokens = grant_max_tokens // per_cell_tokens
    by_wall = grant_max_wall_time_ms // per_cell_wall_ms
    affordable = min(by_tokens, by_wall)
    if affordable >= cells:
        binding = None
    elif by_tokens == by_wall:
        binding = "both"
    elif by_tokens < by_wall:
        binding = "tokens"
    else:
        binding = "wall_time"
    return _seal(
        {
            "schema": CONSTRAINT_REPORT_SCHEMA,
            "status": "PASS",
            "issues": [],
            "cells": cells,
            "cells_within_token_budget": by_tokens,
            "cells_within_wall_budget": by_wall,
            "binding_constraint": binding,
            "grid_fits": affordable >= cells,
            "descriptive_only": True,
            "authority_note": _AUTHORITY_NOTE,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    )


def variance_interval(*, variance: float, samples: int) -> dict[str, Any]:
    """Chi-square 95% interval on one sample variance (df = k-1).

    At the sample sizes this project actually runs (k=3), the interval
    spans orders of magnitude, which is the honest artifact: a point
    variance from three replicates is not a usable sizing input, and the
    interval says so.  No pooling and no shrinkage exist here by
    design — recorded variances span two orders of magnitude across
    configurations, so a fused estimator would be false by construction.
    """

    if (
        not _finite_number(variance)
        or variance < 0
        or not _positive_int(samples)
        or samples < 2
    ):
        return _seal(
            {
                "schema": VARIANCE_REPORT_SCHEMA,
                "status": "FAIL",
                "issues": ["variance:input_invalid"],
                "variance": None,
                "samples": None,
                "degrees_of_freedom": None,
                "lower_95": None,
                "upper_95": None,
                "descriptive_only": True,
                "authority_note": _AUTHORITY_NOTE,
                "provider_free": True,
                "model_calls": 0,
                "hosted_calls": 0,
            }
        )
    degrees = samples - 1
    lower = degrees * float(variance) / _chi2_quantile(0.975, degrees)
    upper = degrees * float(variance) / _chi2_quantile(0.025, degrees)
    return _seal(
        {
            "schema": VARIANCE_REPORT_SCHEMA,
            "status": "PASS",
            "issues": [],
            "variance": _round6(float(variance)),
            "samples": samples,
            "degrees_of_freedom": degrees,
            "lower_95": _round6(lower),
            "upper_95": _round6(upper),
            "descriptive_only": True,
            "authority_note": _AUTHORITY_NOTE,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    )


def _normal_quantile(probability: float) -> float:
    """Inverse standard normal CDF via bisection on ``math.erf``."""

    low, high = -40.0, 40.0
    for _ in range(200):
        middle = (low + high) / 2.0
        cdf = 0.5 * (1.0 + math.erf(middle / math.sqrt(2.0)))
        if cdf < probability:
            low = middle
        else:
            high = middle
    return (low + high) / 2.0


def size_main_study_replicates(
    *,
    variance: float,
    target_effect: float,
    alpha: float = 0.05,
    power_target: float = 0.80,
    pilot_samples: int | None = None,
) -> dict[str, Any]:
    """Size a main study from a pilot variance (Browne 1995/Julious 2005).

    Two-sample normal difference of means:
    ``n = 2 (z_{1-alpha/2} + z_{power})^2 s^2 / delta^2`` per group.
    When ``pilot_samples`` is supplied, Browne's correction sizes from
    the upper confidence limit of the pilot variance rather than its
    point estimate, because sizing off an underpowered pilot toward a
    true null systematically undersizes the main study.

    The variance is a caller-supplied, ledger-derived quantity: this
    function never re-reads the variance it is sizing from, and never
    sources one from a dossier.
    """

    if (
        not _finite_number(variance)
        or variance <= 0
        or not _finite_number(target_effect)
        or target_effect <= 0
        or not _finite_number(alpha)
        or not _finite_number(power_target)
        or not 0.0 < alpha < 1.0
        or not 0.0 < power_target < 1.0
        or (pilot_samples is not None and not _positive_int(pilot_samples))
    ):
        return _seal(
            {
                "schema": SIZING_REPORT_SCHEMA,
                "status": "FAIL",
                "issues": ["sizing:input_invalid"],
                "sizing_variance": None,
                "raw_replicates": None,
                "replicates": None,
                "arithmetic": None,
                "small_pilot_correction": None,
                "descriptive_only": True,
                "authority_note": _AUTHORITY_NOTE,
                "provider_free": True,
                "model_calls": 0,
                "hosted_calls": 0,
            }
        )
    sizing_variance = float(variance)
    correction = "none"
    if pilot_samples is not None and pilot_samples >= 2:
        interval = variance_interval(
            variance=sizing_variance, samples=pilot_samples
        )
        if interval["status"] == "PASS":
            sizing_variance = interval["upper_95"]
            correction = "browne_1995_upper_confidence_limit"
    z_alpha = _normal_quantile(1.0 - alpha / 2.0)
    z_power = _normal_quantile(power_target)
    raw = (
        2.0
        * (z_alpha + z_power) ** 2
        * sizing_variance
        / float(target_effect) ** 2
    )
    return _seal(
        {
            "schema": SIZING_REPORT_SCHEMA,
            "status": "PASS",
            "issues": [],
            "sizing_variance": _round6(sizing_variance),
            "raw_replicates": _round6(raw),
            "replicates": math.ceil(raw),
            "arithmetic": "two_sample_normal_difference_of_means",
            "small_pilot_correction": correction,
            "alpha": alpha,
            "power_target": power_target,
            "descriptive_only": True,
            "authority_note": _AUTHORITY_NOTE,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    )


def build_failure_budget_record(
    *,
    campaign_label: str,
    preregistered_at: str,
    malformed_upper_bound_limit: str,
    evidence_failure_upper_bound_limit: str,
) -> dict[str, Any]:
    """Seal preregistered failure-budget lines for one campaign.

    Budget lines are decimal strings so the sealed record carries the
    exact preregistered text rather than a float that may not round-trip.
    A budget is a reporting commitment: reconciliation says whether an
    observed upper bound exceeded it, and nothing else happens.  The
    fail-closed stop seam remains the only thing that can end a campaign.
    """

    if not isinstance(campaign_label, str) or not _LABEL.fullmatch(
        campaign_label
    ):
        raise ValueError("campaign label is invalid")
    if not isinstance(preregistered_at, str) or not _TIMESTAMP.fullmatch(
        preregistered_at
    ):
        raise ValueError("preregistration timestamp is invalid")
    for limit in (
        malformed_upper_bound_limit,
        evidence_failure_upper_bound_limit,
    ):
        if not isinstance(limit, str) or not _DECIMAL.fullmatch(limit):
            raise ValueError("budget limit is invalid")
    core = {
        "schema": BUDGET_RECORD_SCHEMA,
        "campaign_label": campaign_label,
        "preregistered_at": preregistered_at,
        "malformed_upper_bound_limit": malformed_upper_bound_limit,
        "evidence_failure_upper_bound_limit": (
            evidence_failure_upper_bound_limit
        ),
        "bounds_method": "jeffreys_upper_95",
        "descriptive_only": True,
        "authority_note": _AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return _seal(core, "record_sha256")


def reconcile_failure_budget(
    *,
    budget: Any,
    malformed_failures: int,
    malformed_sessions: int,
    evidence_failures: int,
    evidence_sessions: int,
) -> dict[str, Any]:
    """Compare observed upper bounds against sealed budget lines.

    The bounds come from ``orch_dork_evidence_rate`` (Issue 118) rather
    than a second implementation, so one module owns the arithmetic.
    Exceeding a budget line is reported, never enforced.
    """

    issues: list[str] = []
    if not isinstance(budget, dict) or budget.get("schema") != (
        BUDGET_RECORD_SCHEMA
    ):
        issues.append("budget:schema_invalid")
    else:
        recorded = budget.get("record_sha256")
        core = {
            key: value
            for key, value in budget.items()
            if key != "record_sha256"
        }
        if recorded != _sha256(core):
            issues.append("budget:seal_mismatch")
    malformed = evidence_rate.evidence_failure_rate(
        failures=malformed_failures, sessions=malformed_sessions
    )
    evidence = evidence_rate.evidence_failure_rate(
        failures=evidence_failures, sessions=evidence_sessions
    )
    if malformed["status"] != "PASS" or evidence["status"] != "PASS":
        issues.append("budget:counts_invalid")
    if issues:
        return _seal(
            {
                "schema": BUDGET_REPORT_SCHEMA,
                "status": "FAIL",
                "issues": sorted(set(issues)),
                "malformed_upper_bound": None,
                "evidence_failure_upper_bound": None,
                "malformed_budget_exceeded": None,
                "evidence_failure_budget_exceeded": None,
                "descriptive_only": True,
                "authority_note": _AUTHORITY_NOTE,
                "provider_free": True,
                "model_calls": 0,
                "hosted_calls": 0,
            }
        )
    malformed_bound = malformed["jeffreys_upper_95"]
    evidence_bound = evidence["jeffreys_upper_95"]
    return _seal(
        {
            "schema": BUDGET_REPORT_SCHEMA,
            "status": "PASS",
            "issues": [],
            "budget_record_sha256": budget["record_sha256"],
            "malformed_upper_bound": malformed_bound,
            "evidence_failure_upper_bound": evidence_bound,
            "malformed_budget_exceeded": (
                malformed_bound > float(budget["malformed_upper_bound_limit"])
            ),
            "evidence_failure_budget_exceeded": (
                evidence_bound
                > float(budget["evidence_failure_upper_bound_limit"])
            ),
            "descriptive_only": True,
            "authority_note": _AUTHORITY_NOTE,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    )


def seal_dispatch_order(
    *, cells: Sequence[str], seed: int
) -> dict[str, Any]:
    """Seal one fixed dispatch permutation derived from a campaign seed.

    Seeded ordering separates time-position effects (warm-up, cache
    state) from configuration effects.  The permutation is derived
    deterministically from the seed and fixed before dispatch: an order
    that can change mid-campaign is itself a confounder, so no adaptive
    or rescheduling path exists here.
    """

    if (
        not isinstance(cells, Sequence)
        or isinstance(cells, (str, bytes))
        or not cells
        or any(not isinstance(cell, str) or not cell for cell in cells)
        or len(set(cells)) != len(cells)
        or type(seed) is not int
    ):
        return _seal(
            {
                "schema": DISPATCH_ORDER_SCHEMA,
                "status": "FAIL",
                "issues": ["dispatch:cells_invalid"],
                "seed": None,
                "dispatch_order": None,
                "cell_count": None,
                "descriptive_only": True,
                "authority_note": _AUTHORITY_NOTE,
                "provider_free": True,
                "model_calls": 0,
                "hosted_calls": 0,
            }
        )
    # Deterministic, stdlib-only, and independent of PRNG versioning:
    # order by the digest of (seed, cell), which is stable across
    # interpreters and reproducible from the sealed record alone.
    ordered = sorted(
        cells,
        key=lambda cell: hashlib.sha256(
            f"{seed}:{cell}".encode("utf-8")
        ).hexdigest(),
    )
    return _seal(
        {
            "schema": DISPATCH_ORDER_SCHEMA,
            "status": "PASS",
            "issues": [],
            "seed": seed,
            "dispatch_order": list(ordered),
            "cell_count": len(ordered),
            "descriptive_only": True,
            "authority_note": _AUTHORITY_NOTE,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
    )


__all__ = [
    "SURVIVAL_REPORT_SCHEMA",
    "PILOT_OUTCOMES_ONLY_COMPLETION_THRESHOLD",
    "CONSTRAINT_REPORT_SCHEMA",
    "VARIANCE_REPORT_SCHEMA",
    "SIZING_REPORT_SCHEMA",
    "BUDGET_RECORD_SCHEMA",
    "BUDGET_REPORT_SCHEMA",
    "DISPATCH_ORDER_SCHEMA",
    "build_failure_budget_record",
    "project_binding_constraint",
    "project_campaign_survival",
    "reconcile_failure_budget",
    "seal_dispatch_order",
    "size_main_study_replicates",
    "variance_interval",
]
