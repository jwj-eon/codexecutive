#!/usr/bin/env python3
"""Canonical sealed-evidence mechanics shared by Orch Dork boundaries.

Domain modules still own their schemas and semantic checks.  This module owns
the easy-to-fork mechanics: canonical JSON bytes, SHA-256 seals, closed-record
validation, UTC parsing, freshness ordering, and the capacity-authority
projection copied by admission and lifecycle reports.
"""

from __future__ import annotations

from dataclasses import fields
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from typing import Any, Mapping


SHA256_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")


def require_dataclass_wire(value, record_type, schema, *, shape_error, schema_error):
    """Validate a closed dataclass wire, retaining each domain's error text."""
    if not isinstance(value, dict) or set(value) != {'schema', *(field.name for field in fields(record_type))}:
        raise shape_error
    if value['schema'] != schema:
        raise schema_error


def is_canonical_absolute_path(value: Any) -> bool:
    """Check recorded lexical identity; physical resolution belongs at effects."""
    if not isinstance(value, str) or not value.startswith('/') or '\x00' in value:
        return False
    return value == '/' or all(part and part not in ('.', '..')
                               for part in value.split('/')[1:])

CAPACITY_AUTHORITY_DEFAULTS = {
    "slot_accounting_mode": None,
    "slot_accounting_evidence_tier": None,
    "capacity_authoritative": False,
    "capacity_claim_permitted": False,
    "capacity_scope": "advisory",
    "capacity_evidence_tier": "submitted",
    "capacity_authority_source": "unavailable",
    "capacity_adapter_sha256": None,
    "capacity_observation_sha256": None,
    "capacity_signed_receipt_sha256": None,
    "capacity_signing_key_id": None,
    "capacity_trust_generation": None,
    "terminal_records_consume_slots": True,
}


def canonical_bytes(value: Any) -> bytes:
    """Return the repository's compact deterministic JSON representation."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8", "strict")


def canonical_text(value: Any) -> str:
    return canonical_bytes(value).decode("utf-8")


def legacy_ascii_bytes(
    value: Any, *, limit: int | None = None, refusal: Exception | None = None,
) -> bytes:
    """Preserve escaped-Unicode wire bytes, optionally bounded by the caller.

    Only an exceeded byte bound raises the supplied refusal; JSON encoding
    errors retain their usual exceptions. Unbounded callers keep their existing
    schema identity, distinct from the UTF-8 canonical representation.
    """
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if limit is not None and len(raw) > limit:
        raise refusal if refusal is not None else ValueError("canonical JSON exceeds byte limit")
    return raw


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def legacy_ascii_digest(value: Any) -> str:
    """Preserve seals created by modules that historically escaped Unicode.

    New schemas use :func:`digest`. Existing schema versions whose original
    canonicalizer relied on ``json.dumps``'s ``ensure_ascii=True`` default must
    call this compatibility seam so consolidation cannot rewrite their wire
    identity.
    """

    return hashlib.sha256(legacy_ascii_bytes(value)).hexdigest()


def byte_digest(value: bytes | bytearray | memoryview) -> str:
    return hashlib.sha256(bytes(value)).hexdigest()


def add_issue(issues: list[str], issue: str) -> None:
    if issue not in issues:
        issues.append(issue)


def closed(
    value: Any,
    fields: set[str] | frozenset[str],
    label: str,
    issues: list[str],
) -> Mapping[str, Any] | None:
    """Validate an exact mapping while preserving existing issue spelling."""

    if not isinstance(value, Mapping):
        add_issue(issues, label + ":not_object")
        return None
    actual = set(value)
    for field in sorted(set(fields) - actual):
        add_issue(issues, label + ":missing:" + field)
    for field in sorted(actual - set(fields)):
        add_issue(issues, label + ":unknown:" + str(field))
    return value if actual == set(fields) else None


def seal(core: Mapping[str, Any], field: str) -> dict[str, Any]:
    if not isinstance(field, str) or not field or field in core:
        raise ValueError("seal field must be a new non-empty key")
    result = dict(core)
    result[field] = digest(result)
    return result


def check_seal(value: Any, field: str, *, expected: str | None = None) -> bool:
    if not isinstance(value, Mapping):
        return False
    claimed = value.get(field)
    if not isinstance(claimed, str) or SHA256_PATTERN.fullmatch(claimed) is None:
        return False
    unsigned = dict(value)
    unsigned.pop(field, None)
    computed = digest(unsigned)
    return claimed == computed and (expected is None or claimed == expected)


def instant(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def freshness_issues(
    observed_at: datetime | None,
    evaluated_at: datetime | None,
    valid_until: datetime | None,
    *,
    now: datetime | None,
    max_seconds: int | float,
) -> list[str]:
    """Validate one explicit interval; never invent a clock or timestamp."""

    issues: list[str] = []
    instants = (observed_at, evaluated_at, valid_until, now)
    if any(
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        for value in instants
    ):
        return ["freshness:timestamp_invalid"]
    assert observed_at is not None
    assert evaluated_at is not None
    assert valid_until is not None
    assert now is not None
    if (
        type(max_seconds) not in (int, float)
        or not math.isfinite(float(max_seconds))
        or max_seconds < 0
    ):
        return ["freshness:max_seconds_invalid"]
    if not (observed_at <= evaluated_at <= valid_until):
        add_issue(issues, "freshness:interval_invalid")
    if (valid_until - observed_at).total_seconds() > float(max_seconds):
        add_issue(issues, "freshness:interval_too_long")
    if evaluated_at > now:
        add_issue(issues, "freshness:evaluation_precedes_receipt")
    if now > valid_until:
        add_issue(issues, "freshness:stale")
    return issues


def capacity_authority_projection(source: Mapping[str, Any] | None) -> dict[str, Any]:
    """Project the fixed capacity-evidence contract through one interface."""

    value = source if isinstance(source, Mapping) else {}
    return {
        field: value.get(field, default)
        for field, default in CAPACITY_AUTHORITY_DEFAULTS.items()
    }


__all__ = [
    "CAPACITY_AUTHORITY_DEFAULTS",
    "SHA256_PATTERN",
    "add_issue",
    "canonical_bytes",
    "canonical_text",
    "byte_digest",
    "capacity_authority_projection",
    "check_seal",
    "closed",
    "digest",
    "freshness_issues",
    "instant",
    "legacy_ascii_bytes",
    "legacy_ascii_digest",
    "is_canonical_absolute_path",
    "require_dataclass_wire",
    "seal",
]
