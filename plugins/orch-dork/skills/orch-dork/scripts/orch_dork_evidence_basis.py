#!/usr/bin/env python3
"""Issue 125: derive the campaign sizing basis from sealed ledgers.

Issue 124 sized the v7 pilot against a hand-typed constant describing one
campaign.  That constant was both wrong and too small.  Wrong because it
counted the four lanes of v6's drained thirteenth reservation, which was
never settled and therefore carries no sealed observation to read.  Too
small because v6 is not the only campaign this host recorded: five sealed
ledgers hold settled evidence observed through the same closed
vocabulary, and the sizing arithmetic simply never looked at more than
one of them.

This module reads the ledgers instead.  It counts a lane session only
when that session hangs off a *settled* record, reports drained and
quarantined lanes under their own names rather than folding them in, and
refuses a campaign outright when its hash chain does not verify.

Everything here is descriptive.  A basis report says what the recorded
evidence contains; it creates no grant, names no ceiling, moves no stop
seam, and cannot authorize dispatch.  Only a later fully reproduced bounded
dispatch packet may bind standing Owner authority and mint a one-use grant.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping, Sequence

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_live_sweep as live  # noqa: E402
import orch_dork_routing_verify as routing  # noqa: E402
import orch_dork_sweep_harness as harness  # noqa: E402


BASIS_SCHEMA = "orch-dork/evidence-basis/v1"
POOLED_BASIS_SCHEMA = "orch-dork/pooled-evidence-basis/v1"

# A schemaless terminal is settled through the v4 malformed seam, so it
# is not part of the surviving stop surface even though the observer can
# still emit it.
MALFORMED_TERMINAL_CAUSE = "terminal:schema_missing"

# The surviving stop surface, derived rather than restated: every issue
# the observer can emit, minus everything that now settles a cell, minus
# the malformed-terminal seam.  Deriving it means a vocabulary change
# cannot silently leave this module describing an older stop surface.
NON_CONTINUABLE_CAUSES = (
    frozenset(routing.OBSERVATION_ISSUE_VOCABULARY)
    - frozenset(live.SETTLEABLE_EVIDENCE_FAILURE_CAUSES)
    - {MALFORMED_TERMINAL_CAUSE}
)

_TASK_FAMILIES = ("evidence_extraction", "contract_audit", "dependency_graph")

_SETTLED_SCHEMAS = frozenset(
    {
        live.LIVE_COMPLETION_RECORD_SCHEMA,
        live.LIVE_COMPLETION_RECORD_SCHEMA_V2,
    }
) | frozenset(live.EVIDENCE_FAILURE_RECORD_SCHEMAS)

_AUTHORITY_NOTE = (
    "This record describes recorded evidence. It creates no grant, moves "
    "no limit, and cannot authorize dispatch. Only a fully reproduced bounded "
    "dispatch packet may bind standing Owner authority."
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


def _refusal(schema: str, issues: Sequence[str]) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema": schema,
        "status": "FAIL",
        "issues": sorted(set(issues)),
        "observed_lane_sessions": None,
        "non_continuable_failures": None,
        "unobserved_lane_sessions": None,
        "quarantined_lane_sessions": None,
        "descriptive_only": True,
        "grants_authority": False,
        "authority_note": _AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    if schema == BASIS_SCHEMA:
        core["campaign_label"] = None
    else:
        core["campaigns"] = []
        core["duplicate_campaign_roots"] = None
    core["cause_counts"] = None
    core["legacy_projection_sessions"] = None
    return {**core, "report_sha256": _sha256(core)}


def _read(path: Path, label: str, issues: list[str]) -> list[Mapping[str, Any]]:
    try:
        entries, chain_issues = harness.read_experiment_ledger(path)
    except (OSError, TypeError, ValueError):
        issues.append("basis:ledger_unreadable")
        return []
    for issue in chain_issues:
        issues.append("basis:%s:%s" % (label, issue))
    return [entry.get("record", {}) for entry in entries]


def _quarantined_digests(records: Iterable[Mapping[str, Any]]) -> set[str]:
    """Completion digests the Owner contradicted; excluded by name."""

    digests: set[str] = set()
    for record in records:
        quarantined = record.get("quarantined_completion")
        if isinstance(quarantined, Mapping):
            digest = quarantined.get("completion_record_sha256")
            if isinstance(digest, str):
                digests.add(digest)
    return digests


def _lane_rows(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows: list[Mapping[str, Any]] = []
    for field in ("runtime_projections", "malformed_projections"):
        value = record.get(field)
        if isinstance(value, list):
            rows.extend(row for row in value if isinstance(row, Mapping))
    return rows


def derive_campaign_basis(campaign_root: str | Path) -> dict[str, Any]:
    """Count one campaign's settled lane sessions and stop-surface events.

    Only a settled record contributes.  A reservation with no settlement is
    reported as an unobserved lane session: nobody recorded what happened
    to it, and an unobserved session is not a clean one.
    """

    root = Path(campaign_root)
    issues: list[str] = []
    ledger = root / "campaign.jsonl"
    if not ledger.is_file():
        return _refusal(BASIS_SCHEMA, ["basis:ledger_unreadable"])
    campaign_records = _read(ledger, "campaign", issues)
    if issues:
        return _refusal(BASIS_SCHEMA, issues)

    quarantined = _quarantined_digests(campaign_records)
    observed = 0
    failures = 0
    unobserved = 0
    quarantined_lanes = 0
    legacy = 0
    cause_counts: dict[str, int] = {}

    # Settlement is matched across every family before drained lanes are
    # counted. Reservation digests are unique per campaign, so a shard
    # must never decide "drained" from its own family alone.
    settled_reservations: set[str] = set()
    for family in _TASK_FAMILIES:
        shard = root / (family + ".jsonl")
        if not shard.is_file():
            continue
        for record in _read(shard, family, issues):
            if record.get("schema") not in _SETTLED_SCHEMAS:
                continue
            reservation = record.get("reservation_record_sha256")
            if isinstance(reservation, str):
                settled_reservations.add(reservation)
    if issues:
        return _refusal(BASIS_SCHEMA, issues)

    for family in _TASK_FAMILIES:
        shard = root / (family + ".jsonl")
        if not shard.is_file():
            continue
        records = _read(shard, family, issues)
        if issues:
            return _refusal(BASIS_SCHEMA, issues)
        for record in records:
            if record.get("schema") not in _SETTLED_SCHEMAS:
                continue
            rows = _lane_rows(record)
            if record.get("record_sha256") in quarantined:
                quarantined_lanes += len(rows)
                continue
            for row in rows:
                raw = row.get("observation_issues")
                if raw is None:
                    # Records sealed before the projection carried its
                    # observation issues.  The settlement is still
                    # load-bearing: a completion cannot seal unless every
                    # lane observation validated, so no non-continuable
                    # issue can hide behind the missing field.
                    legacy += 1
                    observed += 1
                    continue
                if not isinstance(raw, list):
                    issues.append("basis:%s:projection_issues_invalid" % family)
                    return _refusal(BASIS_SCHEMA, issues)
                observed += 1
                hits = sorted(set(raw) & NON_CONTINUABLE_CAUSES)
                if hits:
                    failures += 1
                    for cause in hits:
                        cause_counts[cause] = cause_counts.get(cause, 0) + 1
        for record in records:
            if record.get("schema") != live.LIVE_RESERVATION_RECORD_SCHEMA:
                continue
            if record.get("record_sha256") in settled_reservations:
                continue
            request = record.get("request")
            lanes = (
                request.get("lane_count") if isinstance(request, Mapping) else None
            )
            if type(lanes) is int and lanes > 0:
                unobserved += lanes

    if issues:
        return _refusal(BASIS_SCHEMA, issues)

    core = {
        "schema": BASIS_SCHEMA,
        "status": "PASS",
        "issues": [],
        "campaign_label": root.name,
        "observed_lane_sessions": observed,
        "non_continuable_failures": failures,
        "unobserved_lane_sessions": unobserved,
        "quarantined_lane_sessions": quarantined_lanes,
        "cause_counts": dict(sorted(cause_counts.items())),
        "legacy_projection_sessions": legacy,
        "descriptive_only": True,
        "grants_authority": False,
        "authority_note": _AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "report_sha256": _sha256(core)}


def derive_pooled_basis(
    campaign_roots: Sequence[str | Path],
) -> dict[str, Any]:
    """Pool every campaign's basis into one sizing input.

    Pooling is honest here because every campaign was observed through the
    same closed vocabulary by the same independent observer seam.  Any
    campaign that refuses takes the pool down with it rather than
    contributing a partial count that would silently shrink the
    denominator.
    """

    if not isinstance(campaign_roots, Sequence) or isinstance(
        campaign_roots, (str, bytes)
    ):
        return _refusal(POOLED_BASIS_SCHEMA, ["basis:campaigns_invalid"])
    if not campaign_roots:
        return _refusal(POOLED_BASIS_SCHEMA, ["basis:no_campaigns"])

    # The same campaign passed twice would double its sessions, which is
    # exactly the kind of quiet denominator inflation this module exists
    # to prevent. Dedupe by resolved path and report the collision.
    resolved: list[Path] = []
    seen: set[str] = set()
    duplicates = 0
    for root in campaign_roots:
        key = str(Path(root).resolve(strict=False))
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        resolved.append(Path(root))

    reports = [derive_campaign_basis(root) for root in resolved]
    issues: list[str] = []
    for report in reports:
        if report.get("status") != "PASS":
            issues.extend(report.get("issues", []))
    if issues:
        return _refusal(POOLED_BASIS_SCHEMA, issues)

    cause_counts: dict[str, int] = {}
    for report in reports:
        for cause, count in (report.get("cause_counts") or {}).items():
            cause_counts[cause] = cause_counts.get(cause, 0) + count

    core = {
        "schema": POOLED_BASIS_SCHEMA,
        "status": "PASS",
        "issues": [],
        "campaigns": [
            {
                "campaign_label": report["campaign_label"],
                "observed_lane_sessions": report["observed_lane_sessions"],
                "non_continuable_failures": (
                    report["non_continuable_failures"]
                ),
                "unobserved_lane_sessions": (
                    report["unobserved_lane_sessions"]
                ),
                "quarantined_lane_sessions": (
                    report["quarantined_lane_sessions"]
                ),
                "report_sha256": report["report_sha256"],
            }
            for report in reports
        ],
        "observed_lane_sessions": sum(
            report["observed_lane_sessions"] for report in reports
        ),
        "non_continuable_failures": sum(
            report["non_continuable_failures"] for report in reports
        ),
        "unobserved_lane_sessions": sum(
            report["unobserved_lane_sessions"] for report in reports
        ),
        "quarantined_lane_sessions": sum(
            report["quarantined_lane_sessions"] for report in reports
        ),
        "cause_counts": dict(sorted(cause_counts.items())),
        "legacy_projection_sessions": sum(
            report["legacy_projection_sessions"] for report in reports
        ),
        "duplicate_campaign_roots": duplicates,
        "descriptive_only": True,
        "grants_authority": False,
        "authority_note": _AUTHORITY_NOTE,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    return {**core, "report_sha256": _sha256(core)}


__all__ = [
    "BASIS_SCHEMA",
    "POOLED_BASIS_SCHEMA",
    "MALFORMED_TERMINAL_CAUSE",
    "NON_CONTINUABLE_CAUSES",
    "derive_campaign_basis",
    "derive_pooled_basis",
]
