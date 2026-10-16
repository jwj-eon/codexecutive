#!/usr/bin/env python3
"""Replay the sanitized Orch Dork observability scenario gallery.

The gallery is a documentation aid, not a second policy engine. It applies a
small closed display contract to sanitized facts so examples cannot turn a
submitted claim, missing value, UI observation, or contradiction into
governed success.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SCENARIO_SCHEMA = "orch-dork/observability-scenario/v1"
REPORT_SCHEMA = "orch-dork/observability-gallery-report/v1"
EVIDENCE_CLASSES = {
    "runtime",
    "ui",
    "submitted",
    "inferred",
    "sealed",
    "unknown",
    "contradictory",
}
EVIDENCE_TIERS = {"submitted", "runtime-observed", "sealed-runtime"}
MODES = {"advisory", "governed"}
DISPOSITIONS = {"success", "failure", "cancelled", "blocked"}
FORBIDDEN_KEYS = {
    "chain_of_thought",
    "private_reasoning",
    "raw_prompt",
    "session_body",
    "credential",
    "secret",
    "access_token",
    "raw_authorization",
}
SCENARIO_FIELDS = {
    "schema",
    "scenario_id",
    "title",
    "mode",
    "summary",
    "disposition",
    "claims",
}
DISPOSITION_FIELDS = {
    "kind",
    "reason",
    "evidence_class",
    "evidence_tier",
    "source_pointer",
    "source_sha256",
}
CLAIM_FIELDS = {
    "claim_id",
    "label",
    "value",
    "required",
    "evidence_class",
    "evidence_tier",
    "source_pointer",
    "source_sha256",
    "unknown_reason",
    "contradictory_values",
}


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


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _scan_forbidden(value: Any, path: str, issues: list[str]) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).lower() in FORBIDDEN_KEYS:
                _issue(issues, f"{path}:forbidden_field:{key}")
            _scan_forbidden(nested, f"{path}.{key}", issues)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _scan_forbidden(nested, f"{path}[{index}]", issues)


def _check_exact_fields(
    value: Any, expected: set[str], path: str, issues: list[str]
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _issue(issues, f"{path}:object_required")
        return {}
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    for field in missing:
        _issue(issues, f"{path}:missing:{field}")
    for field in extra:
        _issue(issues, f"{path}:unexpected:{field}")
    return value


def _source_status(pointer: Any, digest: Any, path: str, issues: list[str]) -> str:
    if not _nonempty(pointer):
        _issue(issues, f"{path}:source_pointer_required")
        return "invalid"
    if digest is None:
        return "bound-by-scenario-input"
    if not _valid_sha(digest):
        _issue(issues, f"{path}:source_sha256_invalid")
        return "invalid"
    source_path = str(pointer).split("#", 1)[0]
    if not source_path.startswith("/"):
        return "hash-declared"
    candidate = Path(source_path)
    if not candidate.is_file():
        _issue(issues, f"{path}:source_missing")
        return "missing"
    if _file_sha256(candidate) != digest:
        _issue(issues, f"{path}:source_hash_mismatch")
        return "contradictory"
    return "hash-verified"


def _check_evidence(
    value: dict[str, Any], path: str, issues: list[str]
) -> dict[str, Any]:
    evidence_class = value.get("evidence_class")
    evidence_tier = value.get("evidence_tier")
    if evidence_class not in EVIDENCE_CLASSES:
        _issue(issues, f"{path}:evidence_class_invalid")
    if evidence_tier not in EVIDENCE_TIERS:
        _issue(issues, f"{path}:evidence_tier_invalid")

    allowed_tiers = {
        "submitted": {"submitted"},
        "runtime": {"runtime-observed", "sealed-runtime"},
        "ui": {"runtime-observed", "sealed-runtime"},
        "inferred": {"runtime-observed", "sealed-runtime"},
        "sealed": {"sealed-runtime"},
        "unknown": EVIDENCE_TIERS,
        "contradictory": {"runtime-observed", "sealed-runtime"},
    }
    if evidence_class in allowed_tiers and evidence_tier not in allowed_tiers[evidence_class]:
        _issue(issues, f"{path}:class_tier_mismatch")

    return {
        "class": evidence_class,
        "tier": evidence_tier,
        "source_status": _source_status(
            value.get("source_pointer"), value.get("source_sha256"), path, issues
        ),
    }


def replay_scenario(value: Any, *, source_pointer: str) -> dict[str, Any]:
    """Validate and project one sanitized scenario into user-visible state."""

    issues: list[str] = []
    scenario = _check_exact_fields(value, SCENARIO_FIELDS, "scenario", issues)
    _scan_forbidden(scenario, "scenario", issues)

    if scenario.get("schema") != SCENARIO_SCHEMA:
        _issue(issues, "scenario:schema_invalid")
    scenario_id = scenario.get("scenario_id")
    if not _nonempty(scenario_id):
        _issue(issues, "scenario:scenario_id_invalid")
    for field in ("title", "summary"):
        if not _nonempty(scenario.get(field)):
            _issue(issues, f"scenario:{field}_invalid")
    mode = scenario.get("mode")
    if mode not in MODES:
        _issue(issues, "scenario:mode_invalid")

    disposition = _check_exact_fields(
        scenario.get("disposition"), DISPOSITION_FIELDS, "disposition", issues
    )
    disposition_kind = disposition.get("kind")
    if disposition_kind not in DISPOSITIONS:
        _issue(issues, "disposition:kind_invalid")
    if not _nonempty(disposition.get("reason")):
        _issue(issues, "disposition:reason_invalid")
    disposition_evidence = _check_evidence(disposition, "disposition", issues)

    claims = scenario.get("claims")
    if not isinstance(claims, list) or not claims:
        _issue(issues, "scenario:claims_required")
        claims = []

    seen_claims: set[str] = set()
    unknowns: list[str] = []
    contradictions: list[str] = []
    evidence_counts = {name: 0 for name in sorted(EVIDENCE_CLASSES)}
    claim_reports: list[dict[str, Any]] = []
    for index, raw_claim in enumerate(claims):
        path = f"claims[{index}]"
        claim = _check_exact_fields(raw_claim, CLAIM_FIELDS, path, issues)
        claim_id = claim.get("claim_id")
        if not _nonempty(claim_id) or claim_id in seen_claims:
            _issue(issues, f"{path}:claim_id_invalid_or_duplicate")
            claim_id = f"invalid-{index}"
        else:
            seen_claims.add(str(claim_id))
        if not _nonempty(claim.get("label")):
            _issue(issues, f"{path}:label_invalid")
        if not isinstance(claim.get("required"), bool):
            _issue(issues, f"{path}:required_invalid")

        evidence = _check_evidence(claim, path, issues)
        evidence_class = evidence["class"]
        if evidence_class in evidence_counts:
            evidence_counts[evidence_class] += 1

        unknown_reason = claim.get("unknown_reason")
        contradictory_values = claim.get("contradictory_values")
        if evidence_class == "unknown":
            if claim.get("value") is not None or not _nonempty(unknown_reason):
                _issue(issues, f"{path}:unknown_shape_invalid")
            unknowns.append(str(claim_id))
        elif unknown_reason is not None:
            _issue(issues, f"{path}:unexpected_unknown_reason")

        if evidence_class == "contradictory":
            if not isinstance(contradictory_values, list) or len(contradictory_values) < 2:
                _issue(issues, f"{path}:contradictory_values_required")
            contradictions.append(str(claim_id))
        elif contradictory_values is not None:
            _issue(issues, f"{path}:unexpected_contradictory_values")

        claim_reports.append(
            {
                "claim_id": claim_id,
                "label": claim.get("label"),
                "value": claim.get("value"),
                "required": claim.get("required"),
                "evidence_class": evidence_class,
                "evidence_tier": evidence["tier"],
                "source_pointer": claim.get("source_pointer"),
                "source_status": evidence["source_status"],
                "unknown_reason": unknown_reason,
                "contradictory_values": contradictory_values,
            }
        )

    required_unknown = [
        item["claim_id"]
        for item in claim_reports
        if item["required"] is True and item["evidence_class"] == "unknown"
    ]
    if disposition_evidence["class"] == "contradictory":
        contradictions.append("disposition")

    claim_permitted = False
    if contradictions or any("source_hash_mismatch" in issue for issue in issues):
        display_status = "FAILURE"
        headline = "Contradictory evidence fails closed."
    elif disposition_kind == "failure":
        display_status = "FAILURE"
        headline = "The observed attempt failed; preserved facts remain visible."
    elif disposition_kind == "cancelled":
        display_status = "CANCELLED"
        headline = "Cancellation is terminal history, not a successful rollback."
    elif disposition_kind == "blocked":
        display_status = "BLOCKED"
        headline = "Policy blocked work before the prohibited action started."
    elif required_unknown:
        display_status = "UNKNOWN"
        headline = "Required evidence is missing, so success is unknown."
    elif mode == "advisory":
        display_status = "ADVISORY_ONLY"
        headline = "Submitted conformance is advisory and cannot grant governed success."
    elif (
        disposition_evidence["class"] == "sealed"
        and disposition_evidence["tier"] == "sealed-runtime"
        and any(
            item["evidence_class"] in {"runtime", "sealed"}
            for item in claim_reports
            if item["required"] is True
        )
    ):
        display_status = "SUCCESS"
        headline = "Independent bound runtime evidence permits governed success."
        claim_permitted = True
    else:
        display_status = "UNKNOWN"
        headline = "The available evidence does not establish governed success."

    if issues and display_status != "FAILURE":
        display_status = "FAILURE"
        headline = "The scenario evidence is malformed or inconsistent."
        claim_permitted = False

    return {
        "schema": "orch-dork/observability-scenario-report/v1",
        "scenario_id": scenario_id,
        "title": scenario.get("title"),
        "mode": mode,
        "displayed_result": {
            "status": display_status,
            "headline": headline,
            "claim_permitted": claim_permitted,
            "disposition": disposition_kind,
            "unknown_claims": sorted(set(unknowns)),
            "contradictory_claims": sorted(set(contradictions)),
            "evidence_counts": evidence_counts,
        },
        "claims": claim_reports,
        "source_pointer": source_pointer,
        "scenario_sha256": _sha256(scenario),
        "issues": issues,
        "privacy": {
            "private_chain_of_thought_exposed": False,
            "action_trace_equated_with_private_reasoning": False,
        },
    }


def replay_gallery(path: str | Path) -> dict[str, Any]:
    """Replay one fixture or every JSON fixture in a directory."""

    source = Path(path).resolve()
    files = sorted(source.glob("*.json")) if source.is_dir() else [source]
    scenarios: list[dict[str, Any]] = []
    inventory: list[dict[str, str]] = []
    for fixture in files:
        raw = fixture.read_bytes()
        value = json.loads(raw)
        inventory.append({"path": fixture.name, "sha256": hashlib.sha256(raw).hexdigest()})
        scenarios.append(replay_scenario(value, source_pointer=str(fixture)))

    duplicate_ids = sorted(
        scenario_id
        for scenario_id in {item.get("scenario_id") for item in scenarios}
        if sum(item.get("scenario_id") == scenario_id for item in scenarios) > 1
    )
    issues = [f"gallery:duplicate_scenario_id:{item}" for item in duplicate_ids]
    for scenario in scenarios:
        issues.extend(
            f"{scenario.get('scenario_id')}:{issue}" for issue in scenario.get("issues", [])
        )
    return {
        "schema": REPORT_SCHEMA,
        "status": "PASS" if files and not issues else "FAIL",
        "gallery_root": str(source),
        "gallery_sha256": _sha256(inventory),
        "scenario_count": len(scenarios),
        "scenarios": scenarios,
        "issues": issues,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="Scenario JSON file or fixture directory")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    report = replay_gallery(args.path)
    print(
        json.dumps(
            report,
            sort_keys=True,
            separators=(",", ":") if args.compact else None,
            indent=None if args.compact else 2,
        )
    )
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
