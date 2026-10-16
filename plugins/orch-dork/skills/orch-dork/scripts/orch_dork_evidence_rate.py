#!/usr/bin/env python3
"""Issue 118 (C6/C7): descriptive evidence-failure rate statistics.

C6 - stdlib small-n bounds (Wilson, Jeffreys, rule of three, exact
binomial) over the preregistered statistic "evidence-failure fresh lane
sessions over all fresh lane sessions", plus a sealed preregistration
record builder for v7 onward.  Every output is descriptive: nothing here
is a stopping rule, threshold, or authority, and no stop seam or sealed
operator threshold reads these numbers.

C7 - a bounded auxiliary /proc process-group sampler in the
process-containment style: bounded factual counts when observable,
"unknown" when not, never a guess and never an authority.  Kernel PID
reuse means the counts are auxiliary observations only and must never
feed scoring or classification.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any


RATE_REPORT_SCHEMA = "orch-dork/evidence-failure-rate/v1"
RATE_PLAN_SCHEMA = "orch-dork/evidence-failure-rate-plan/v1"
AUX_SAMPLE_SCHEMA = "orch-dork/aux-process-sample/v1"

_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_LABEL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class EvidenceRateError(ValueError):
    """Raised when an input to this module is malformed."""


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


def _wilson_95(failures: int, sessions: int) -> dict[str, float]:
    z = 1.959963984540054  # standard normal 97.5th percentile
    phat = failures / sessions
    denominator = 1.0 + z * z / sessions
    centre = (phat + z * z / (2 * sessions)) / denominator
    half = (
        z
        * math.sqrt(
            phat * (1.0 - phat) / sessions
            + z * z / (4.0 * sessions * sessions)
        )
        / denominator
    )
    return {
        "method": "wilson-95",
        "low": _round6(max(0.0, centre - half)),
        "high": _round6(min(1.0, centre + half)),
    }


def _incomplete_beta(x: float, a: float, b: float) -> float:
    """Regularized incomplete beta I_x(a, b) via Lentz's continued fraction."""

    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0

    def continued_fraction(x_value: float, aa: float, bb: float) -> float:
        max_iterations = 300
        epsilon = 3e-14
        tiny = 1e-300
        qab, qap, qam = aa + bb, aa + 1.0, aa - 1.0
        c = 1.0
        d = 1.0 - qab * x_value / qap
        if abs(d) < tiny:
            d = tiny
        d = 1.0 / d
        h = d
        converged = False
        for m in range(1, max_iterations + 1):
            m2 = 2 * m
            numerator = m * (bb - m) * x_value / ((qam + m2) * (aa + m2))
            d = 1.0 + numerator * d
            if abs(d) < tiny:
                d = tiny
            c = 1.0 + numerator / c
            if abs(c) < tiny:
                c = tiny
            d = 1.0 / d
            h *= d * c
            numerator = (
                -(aa + m) * (qab + m) * x_value / ((aa + m2) * (qap + m2))
            )
            d = 1.0 + numerator * d
            if abs(d) < tiny:
                d = tiny
            c = 1.0 + numerator / c
            if abs(c) < tiny:
                c = tiny
            d = 1.0 / d
            delta = d * c
            h *= delta
            if abs(delta - 1.0) < epsilon:
                converged = True
                break
        if not converged:
            raise EvidenceRateError(
                "beta continued fraction did not converge"
            )
        return h

    log_front = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log(1.0 - x)
    )
    front = math.exp(log_front)
    if x < (a + 1.0) / (a + b + 2.0):
        return front * continued_fraction(x, a, b) / a
    return 1.0 - front * continued_fraction(1.0 - x, b, a) / b


def _beta_quantile(alpha: float, a: float, b: float) -> float:
    """The alpha quantile of Beta(a, b) by bisection on _incomplete_beta."""

    # 200 bisection steps is a deliberate fixed bound: interval width halves
    # each step, far below float precision, with bounded deterministic cost.
    low, high = 0.0, 1.0
    for _ in range(200):
        mid = (low + high) / 2.0
        if _incomplete_beta(mid, a, b) < alpha:
            low = mid
        else:
            high = mid
    return (low + high) / 2.0


def evidence_failure_rate(*, failures: int, sessions: int) -> dict[str, Any]:
    """Describe the observed evidence-failure rate with small-n bounds.

    Descriptive only: the report never encodes a decision, and no stop seam
    reads it.  The rule-of-three and exact-binomial upper bounds apply only
    at zero observed failures, mirroring the preregistered dossier plan.
    """

    if (
        type(failures) is not int
        or type(sessions) is not int
        or failures < 0
        or sessions < 1
        or failures > sessions
    ):
        core = {
            "schema": RATE_REPORT_SCHEMA,
            "status": "FAIL",
            "issues": ["rate:counts_invalid"],
            "failures": None,
            "sessions": None,
            "observed_rate": None,
            "wilson_95": None,
            "jeffreys_upper_95": None,
            "rule_of_three_upper_95": None,
            "exact_binomial_upper_95": None,
            "descriptive_only": True,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
        return {**core, "report_sha256": _sha256(core)}
    jeffreys_upper = _beta_quantile(
        0.95, failures + 0.5, sessions - failures + 0.5
    )
    rule_of_three = _round6(3.0 / sessions) if failures == 0 else None
    exact_binomial = (
        _round6(1.0 - 0.05 ** (1.0 / sessions)) if failures == 0 else None
    )
    core = {
        "schema": RATE_REPORT_SCHEMA,
        "status": "PASS",
        "issues": [],
        "failures": failures,
        "sessions": sessions,
        "observed_rate": _round6(failures / sessions),
        "wilson_95": _wilson_95(failures, sessions),
        "jeffreys_upper_95": _round6(jeffreys_upper),
        "rule_of_three_upper_95": rule_of_three,
        "exact_binomial_upper_95": exact_binomial,
        "descriptive_only": True,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "report_sha256": _sha256(core)}


def build_rate_plan_record(
    *, campaign_label: str, preregistered_at: str
) -> dict[str, Any]:
    """Seal the dossier's preregistered rate plan for one campaign label."""

    if not isinstance(campaign_label, str) or not _LABEL.fullmatch(
        campaign_label
    ):
        raise EvidenceRateError("campaign label is invalid")
    if not isinstance(preregistered_at, str) or not _TIMESTAMP.fullmatch(
        preregistered_at
    ):
        raise EvidenceRateError("preregistration timestamp is invalid")
    core = {
        "schema": RATE_PLAN_SCHEMA,
        "campaign_label": campaign_label,
        "preregistered_at": preregistered_at,
        "statistic": (
            "evidence_failure_fresh_lane_sessions / fresh_lane_sessions"
        ),
        "bounds_methods": [
            "wilson_95",
            "jeffreys_upper_95",
            "rule_of_three_upper_95",
            "exact_binomial_upper_95",
        ],
        "zero_failure_session_target": 60,
        "target_upper_bound": "0.05",
        "descriptive_only": True,
        "authority_note": (
            "This plan describes a reporting statistic; it is never a "
            "stopping rule and never relaxes the stop seam or the "
            "operator's sealed same-cause threshold."
        ),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "record_sha256": _sha256(core)}


def _proc_group_counts(pgid: int) -> tuple[int, float, int] | None:
    """Sum bounded /proc facts over one process group; None is unknown."""

    proc = Path("/proc")
    if not proc.is_dir():
        return None
    count = 0
    cpu_total = 0.0
    rss_total = 0
    try:
        entries = list(proc.iterdir())
    except OSError:
        return None
    saw_process = False
    for entry in entries:
        if not entry.name.isdigit():
            continue
        saw_process = True
        try:
            line = (entry / "stat").read_text(
                encoding="utf-8", errors="replace"
            )
            close = line.rfind(")")
            if close < 0:
                continue
            tail = line[close + 2 :].split()
            if len(tail) < 13:
                continue
            if int(tail[2]) != pgid:
                continue
            ticks = int(tail[11]) + int(tail[12])
            cpu_total += ticks / float(os.sysconf("SC_CLK_TCK"))
            count += 1
            for raw in (entry / "status").read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                if raw.startswith("VmRSS:"):
                    fields = raw.split()
                    if len(fields) >= 2:
                        rss_total += max(0, int(fields[1]) * 1024)
                    break
        except (OSError, ValueError, IndexError):
            continue
    if not saw_process:
        return None
    return count, cpu_total, rss_total


def sample_process_group(pgid: int) -> dict[str, Any]:
    """One bounded auxiliary sample of a process group.

    Auxiliary only: PID reuse makes these counts non-identity facts, so a
    sample may inform an operator's reading of a stability derivation but
    never feeds classification, scoring, or any authority decision.
    """

    if type(pgid) is not int or pgid < 1:
        raise EvidenceRateError("process group id is invalid")
    observed = _proc_group_counts(pgid)
    if observed is None:
        core = {
            "schema": AUX_SAMPLE_SCHEMA,
            "telemetry": "unknown",
            "pgid": pgid,
            "process_count": None,
            "cpu_seconds_total": None,
            "rss_bytes_total": None,
            "auxiliary_only": True,
            "provider_free": True,
            "model_calls": 0,
            "hosted_calls": 0,
        }
        return {**core, "sample_sha256": _sha256(core)}
    count, cpu_total, rss_total = observed
    core = {
        "schema": AUX_SAMPLE_SCHEMA,
        "telemetry": "observed",
        "pgid": pgid,
        "process_count": count,
        "cpu_seconds_total": _round6(cpu_total),
        "rss_bytes_total": rss_total,
        "auxiliary_only": True,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "sample_sha256": _sha256(core)}
