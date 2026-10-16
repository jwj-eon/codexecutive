#!/usr/bin/env python3
"""Closed refusal-tier ladder for audit integration (tier-2 dossier C10).

Refusal reports already carry closed issue codes; this module classifies
those lines into a closed ordered tier ladder and names the canonical
first-blocking tier so an operator can read a report and know the
cheapest class of fix without re-running the kernel.  The ladder is
report-only annotation: it never changes a verdict, never becomes
authority, and never suggests a repair.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Sequence


ANNOTATION_SCHEMA = "orch-dork/refusal-tier-annotation/v1"

# Ordered from cheapest fix to hardest; the canonical first-blocking tier
# is the earliest ladder tier holding at least one classified issue.
TIER_ORDER = (
    "missing_input",
    "malformed_input",
    "stale_binding",
    "scope",
    "budget",
    "fence",
    "other",
)

# Classification checks the marker tables most-specific-first (the ladder
# order ranks fix cost, not marker precision): fence and budget words are
# unambiguous, scope words beat the generic ":..._invalid" suffix this
# codebase uses everywhere, and "invalid" itself classifies last.  First
# match wins, so every code maps to exactly one tier and unmatched codes
# land in the closed "other" tier.
_CLASSIFICATION_ORDER = (
    "fence",
    "budget",
    "scope",
    "stale_binding",
    "missing_input",
    "malformed_input",
)

_TIER_MARKERS: dict[str, tuple[str, ...]] = {
    "missing_input": ("missing", "required", "absent", "unavailable"),
    "malformed_input": (
        "invalid",
        "unknown_field",
        "not_closed",
        "malformed",
        "too_large",
        "canonicalization",
        "unreadable",
    ),
    "stale_binding": (
        "mismatch",
        "seal",
        "digest",
        "binding",
        "chain",
        "torn",
        "broken",
        "expired",
        "stale",
        "regression",
        "tamper",
    ),
    "scope": (
        "scope",
        "authority",
        "outside_writable",
        "escape",
        "symlink",
        "collision",
        "custody",
    ),
    "budget": (
        "budget",
        "exhausted",
        "limit",
        "token_amount",
        "overage",
        "wall_time",
    ),
    "fence": (
        "stopped",
        "terminated",
        "joined",
        "fence",
        "duplicate",
        "already_",
        "quarantine",
        "aborted",
    ),
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def classify_refusal_issue(issue: Any) -> str:
    """Map one refusal issue line to its closed tier deterministically."""

    line = str(issue).casefold()
    if ":" in line:
        # Codes read `<seam>:<condition>`; the seam label names where the
        # refusal happened, the condition names why.  Classify the why so
        # a seam label (for example `fences:`) never masquerades as the
        # condition.
        line = line.split(":", 1)[1]
    for tier in _CLASSIFICATION_ORDER:
        if any(marker in line for marker in _TIER_MARKERS[tier]):
            return tier
    return "other"


def annotate_refusal_tiers(issues: Sequence[Any]) -> dict[str, Any]:
    """Build the closed report-only tier annotation for one issue list.

    The canonical first-blocking tier is the earliest ladder tier with at
    least one classified issue, naming the cheapest class of fix.  The
    annotation is sealed so a reviewer can verify it was not edited after
    the fact, and it carries no authority: verdicts, issue lists, and
    stored ledger records are never changed by it.
    """

    tiers: dict[str, list[str]] = {}
    for issue in issues:
        tier = classify_refusal_issue(issue)
        tiers.setdefault(tier, [])
        line = str(issue)
        if line not in tiers[tier]:
            tiers[tier].append(line)
    ordered = {tier: sorted(tiers[tier]) for tier in TIER_ORDER if tier in tiers}
    first = next((tier for tier in TIER_ORDER if tier in ordered), None)
    core = {
        "schema": ANNOTATION_SCHEMA,
        "tier_order": list(TIER_ORDER),
        "first_blocking_tier": first,
        "tiers": ordered,
        "issue_count": sum(len(rows) for rows in ordered.values()),
        "report_only": True,
    }
    return {
        **core,
        "annotation_sha256": hashlib.sha256(_canonical(core)).hexdigest(),
    }


__all__ = [
    "ANNOTATION_SCHEMA",
    "TIER_ORDER",
    "annotate_refusal_tiers",
    "classify_refusal_issue",
]
