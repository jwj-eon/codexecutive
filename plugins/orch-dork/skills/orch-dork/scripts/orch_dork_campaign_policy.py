#!/usr/bin/env python3
"""Bounded provider-free campaign authority and adjudication contracts."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


PROGRAM_SCHEMA = "orch-dork/campaign-policy-program/v1"
REPORT_SCHEMA = "orch-dork/campaign-policy-report/v1"
SERIES_AUTHORITY_SCHEMA = "orch-dork/series-authority-program/v1"
SERIES_LEDGER_SCHEMA = "orch-dork/series-ledger/v1"
EVALUATOR_INTEGRITY_SCHEMA = "orch-dork/evaluator-integrity/v1"
FALSIFYING_WITNESS_SCHEMA = "orch-dork/falsifying-witness/v1"
BATCH_ADJUDICATION_SCHEMA = "orch-dork/batch-adjudication/v1"

CAMPAIGN_POLICY_OPERATIONS = (
    "series_authority",
    "evaluator_integrity",
    "batch_adjudication",
)
DRAW_OUTCOMES = frozenset({"reserved", "succeeded", "failed", "cancelled"})
HOSTILE_STRATEGIES = frozenset({"constant", "oracle", "abstention"})
PROBE_OUTCOMES = frozenset({"reject", "disqualify", "win", "qualify"})
RISK_FACTS = frozenset({"security_sensitive", "irreversible", "external_write"})
COMPATIBILITY = frozenset({"compatible", "incompatible", "unknown"})
DISPOSITIONS = frozenset({"integrate", "extract"})
MAX_ITEMS = 64
MAX_CANONICAL_BYTES = 262_144
MAX_DEPTH = 32
MAX_NODES = 4_096
MAX_OBJECT_KEYS = 256
MAX_ARRAY_ITEMS = 256
MAX_STRING_BYTES = 65_536
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_bytes(value: Any) -> bytes:
    _validate_json(value, depth=0, nodes=[0])
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > MAX_CANONICAL_BYTES:
        raise ValueError("canonical_json:too_large")
    return raw


def _validate_json(value: Any, *, depth: int, nodes: list[int]) -> None:
    nodes[0] += 1
    if nodes[0] > MAX_NODES or depth > MAX_DEPTH:
        raise ValueError("canonical_json:structure_bound")
    if value is None or type(value) in (bool, int, float):
        return
    if type(value) is str:
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise ValueError("canonical_json:string_bound")
        return
    if type(value) is list:
        if len(value) > MAX_ARRAY_ITEMS:
            raise ValueError("canonical_json:array_bound")
        for child in value:
            _validate_json(child, depth=depth + 1, nodes=nodes)
        return
    if type(value) is dict:
        if len(value) > MAX_OBJECT_KEYS or any(type(key) is not str for key in value):
            raise ValueError("canonical_json:object_bound")
        for key, child in value.items():
            _validate_json(key, depth=depth + 1, nodes=nodes)
            _validate_json(child, depth=depth + 1, nodes=nodes)
        return
    raise ValueError("canonical_json:type_invalid")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _closed(value: Any, path: str, required: frozenset[str], issues: list[str]) -> dict[str, Any] | None:
    if type(value) is not dict:
        issues.append(f"{path}:not_object")
        return None
    for key in sorted(set(value) - required):
        issues.append(f"{path}:unknown_field:{key}")
    for key in sorted(required - set(value)):
        issues.append(f"{path}:missing:{key}")
    return value


def _identifier(value: Any, path: str, issues: list[str]) -> str | None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        issues.append(f"{path}:invalid")
        return None
    return value


def _sha(value: Any, path: str, issues: list[str]) -> str | None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        issues.append(f"{path}:invalid_sha256")
        return None
    return value


def _integer(value: Any, path: str, issues: list[str], minimum: int = 0) -> int | None:
    if type(value) is not int or value < minimum:
        issues.append(f"{path}:invalid_integer")
        return None
    return value


def _boolean(value: Any, path: str, issues: list[str]) -> bool | None:
    if type(value) is not bool:
        issues.append(f"{path}:not_boolean")
        return None
    return value


def _report(operation: str | None, issues: list[str], result: dict[str, Any] | None) -> dict[str, Any]:
    unique = sorted(set(issues))
    return {
        "schema": REPORT_SCHEMA,
        "status": "FAIL" if unique else "PASS",
        "decision": "REJECTED" if unique else "ACCEPTED",
        "operation": operation,
        "issues": unique,
        "result": result,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _series_authority(payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    item = _closed(
        payload,
        "series",
        frozenset({"schema", "series_id", "expected_version", "ledger", "draw"}),
        issues,
    )
    result = None
    if item is not None:
        if item.get("schema") != SERIES_AUTHORITY_SCHEMA:
            issues.append("series:schema_invalid")
        series_id = _identifier(item.get("series_id"), "series.series_id", issues)
        expected_version = _integer(item.get("expected_version"), "series.expected_version", issues)
        ledger = _closed(
            item.get("ledger"),
            "ledger",
            frozenset(
                {
                    "schema",
                    "series_id",
                    "version",
                    "draw_limit",
                    "token_limit",
                    "charged_draws",
                    "charged_tokens",
                    "entries",
                }
            ),
            issues,
        )
        draw = _closed(
            item.get("draw"),
            "draw",
            frozenset({"draw_id", "reserved_tokens", "outcome"}),
            issues,
        )
        parsed_entries: list[dict[str, Any]] = []
        entry_ids: set[str] = set()
        version = draw_limit = token_limit = charged_draws = charged_tokens = None
        if ledger is not None:
            if ledger.get("schema") != SERIES_LEDGER_SCHEMA:
                issues.append("ledger:schema_invalid")
            ledger_series = _identifier(ledger.get("series_id"), "ledger.series_id", issues)
            if ledger_series != series_id:
                issues.append("ledger:series_id_mismatch")
            version = _integer(ledger.get("version"), "ledger.version", issues)
            draw_limit = _integer(ledger.get("draw_limit"), "ledger.draw_limit", issues, 1)
            token_limit = _integer(ledger.get("token_limit"), "ledger.token_limit", issues, 1)
            charged_draws = _integer(ledger.get("charged_draws"), "ledger.charged_draws", issues)
            charged_tokens = _integer(ledger.get("charged_tokens"), "ledger.charged_tokens", issues)
            entries = ledger.get("entries")
            if type(entries) is not list or len(entries) > MAX_ITEMS:
                issues.append("ledger.entries:invalid_array")
                entries = []
            for index, raw in enumerate(entries):
                entry = _closed(
                    raw,
                    f"ledger.entries[{index}]",
                    frozenset({"draw_id", "reserved_tokens", "outcome", "charged"}),
                    issues,
                )
                if entry is None:
                    continue
                draw_id = _identifier(entry.get("draw_id"), f"ledger.entries[{index}].draw_id", issues)
                reserved = _integer(
                    entry.get("reserved_tokens"),
                    f"ledger.entries[{index}].reserved_tokens",
                    issues,
                    1,
                )
                outcome = entry.get("outcome")
                if outcome not in DRAW_OUTCOMES:
                    issues.append(f"ledger.entries[{index}].outcome:invalid")
                charged = _boolean(entry.get("charged"), f"ledger.entries[{index}].charged", issues)
                if charged is False:
                    issues.append("ledger:draw_not_permanently_charged")
                if draw_id is not None:
                    if draw_id in entry_ids:
                        issues.append("ledger:duplicate_draw_id")
                    entry_ids.add(draw_id)
                if draw_id is not None and reserved is not None and outcome in DRAW_OUTCOMES:
                    parsed_entries.append(
                        {
                            "draw_id": draw_id,
                            "reserved_tokens": reserved,
                            "outcome": outcome,
                            "charged": True,
                        }
                    )
            if version is not None and version != len(parsed_entries):
                issues.append("ledger:version_entry_count_mismatch")
            if charged_draws is not None and charged_draws != len(parsed_entries):
                issues.append("ledger:charged_draw_count_mismatch")
            computed_tokens = sum(entry["reserved_tokens"] for entry in parsed_entries)
            if charged_tokens is not None and charged_tokens != computed_tokens:
                issues.append("ledger:charged_token_count_mismatch")
            if expected_version is not None and version != expected_version:
                issues.append("ledger:stale_version")
        new_draw = None
        if draw is not None:
            draw_id = _identifier(draw.get("draw_id"), "draw.draw_id", issues)
            reserved = _integer(draw.get("reserved_tokens"), "draw.reserved_tokens", issues, 1)
            outcome = draw.get("outcome")
            if outcome not in DRAW_OUTCOMES:
                issues.append("draw.outcome:invalid")
            if draw_id in entry_ids:
                issues.append("draw:replayed")
            if draw_id is not None and reserved is not None and outcome in DRAW_OUTCOMES:
                new_draw = {
                    "draw_id": draw_id,
                    "reserved_tokens": reserved,
                    "outcome": outcome,
                    "charged": True,
                }
        if new_draw is not None and draw_limit is not None and len(parsed_entries) + 1 > draw_limit:
            issues.append("series:draw_budget_exceeded")
        projected_tokens = sum(entry["reserved_tokens"] for entry in parsed_entries)
        if new_draw is not None:
            projected_tokens += new_draw["reserved_tokens"]
        if token_limit is not None and projected_tokens > token_limit:
            issues.append("series:token_budget_exceeded")
        if not issues and new_draw is not None:
            next_ledger = {
                "schema": SERIES_LEDGER_SCHEMA,
                "series_id": series_id,
                "version": len(parsed_entries) + 1,
                "draw_limit": draw_limit,
                "token_limit": token_limit,
                "charged_draws": len(parsed_entries) + 1,
                "charged_tokens": projected_tokens,
                "entries": parsed_entries + [new_draw],
            }
            result = {
                "next_ledger": next_ledger,
                "ledger_sha256": canonical_sha256(next_ledger),
                "draw_permanently_charged": True,
            }
    return _report("series_authority", issues, result)


def _evaluator_integrity(payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    item = _closed(
        payload,
        "integrity",
        frozenset({"schema", "evaluator_id", "criteria", "hostile_probes"}),
        issues,
    )
    result = None
    if item is not None:
        if item.get("schema") != EVALUATOR_INTEGRITY_SCHEMA:
            issues.append("integrity:schema_invalid")
        evaluator_id = _identifier(item.get("evaluator_id"), "integrity.evaluator_id", issues)
        criteria = item.get("criteria")
        if type(criteria) is not list or not criteria or len(criteria) > MAX_ITEMS:
            issues.append("integrity.criteria:invalid_array")
            criteria = []
        criterion_ids: set[str] = set()
        sensitive_ids: list[str] = []
        witnessed_ids: list[str] = []
        for index, raw in enumerate(criteria):
            criterion = _closed(
                raw,
                f"integrity.criteria[{index}]",
                frozenset({"criterion_id", "sensitive", "witness"}),
                issues,
            )
            if criterion is None:
                continue
            criterion_id = _identifier(
                criterion.get("criterion_id"),
                f"integrity.criteria[{index}].criterion_id",
                issues,
            )
            sensitive = _boolean(
                criterion.get("sensitive"),
                f"integrity.criteria[{index}].sensitive",
                issues,
            )
            if criterion_id is not None:
                if criterion_id in criterion_ids:
                    issues.append("integrity:duplicate_criterion_id")
                criterion_ids.add(criterion_id)
            witness = criterion.get("witness")
            if sensitive is True:
                if criterion_id is not None:
                    sensitive_ids.append(criterion_id)
                parsed = _closed(
                    witness,
                    f"integrity.criteria[{index}].witness",
                    frozenset(
                        {
                            "schema",
                            "witness_id",
                            "criterion_id",
                            "falsifying_input_sha256",
                            "expected_disposition",
                            "observed_disposition",
                            "effective",
                        }
                    ),
                    issues,
                )
                if parsed is not None:
                    if parsed.get("schema") != FALSIFYING_WITNESS_SCHEMA:
                        issues.append("witness:schema_invalid")
                    _identifier(parsed.get("witness_id"), "witness.witness_id", issues)
                    witness_criterion = _identifier(
                        parsed.get("criterion_id"), "witness.criterion_id", issues
                    )
                    _sha(parsed.get("falsifying_input_sha256"), "witness.falsifying_input_sha256", issues)
                    expected = parsed.get("expected_disposition")
                    observed = parsed.get("observed_disposition")
                    effective = _boolean(parsed.get("effective"), "witness.effective", issues)
                    if witness_criterion != criterion_id:
                        issues.append("witness:criterion_mismatch")
                    if expected != "reject" or observed != "reject" or effective is not True:
                        issues.append("witness:not_effective")
                    elif criterion_id is not None:
                        witnessed_ids.append(criterion_id)
            elif sensitive is False and witness is not None:
                issues.append("witness:unexpected_for_nonsensitive_criterion")
        probes = item.get("hostile_probes")
        if type(probes) is not list or len(probes) > MAX_ITEMS:
            issues.append("integrity.hostile_probes:invalid_array")
            probes = []
        seen_strategies: set[str] = set()
        probe_results: dict[str, str] = {}
        for index, raw in enumerate(probes):
            probe = _closed(
                raw,
                f"integrity.hostile_probes[{index}]",
                frozenset({"strategy", "outcome"}),
                issues,
            )
            if probe is None:
                continue
            strategy = probe.get("strategy")
            outcome = probe.get("outcome")
            if strategy not in HOSTILE_STRATEGIES:
                issues.append("probe:strategy_invalid")
                continue
            if strategy in seen_strategies:
                issues.append("probe:duplicate_strategy")
            seen_strategies.add(strategy)
            if outcome not in PROBE_OUTCOMES:
                issues.append("probe:outcome_invalid")
            elif outcome in {"win", "qualify"}:
                issues.append(f"probe:{strategy}_strategy_cannot_{outcome}")
            probe_results[strategy] = outcome
        if seen_strategies != HOSTILE_STRATEGIES:
            issues.append("probe:required_strategy_missing")
        result = {
            "evaluator_id": evaluator_id,
            "sensitive_criterion_ids": sensitive_ids,
            "witnessed_criterion_ids": witnessed_ids,
            "hostile_probe_outcomes": {key: probe_results[key] for key in sorted(probe_results)},
            "evaluation_integrity_met": not issues,
        }
    return _report("evaluator_integrity", issues, result)


def _expected_disposition(facts: dict[str, Any]) -> tuple[str, str, str]:
    risk_facts = facts["risk_facts"]
    compatibility = facts["compatibility"]
    evidence_complete = facts["evidence_complete"]
    if risk_facts:
        return "high", "extract", "high_risk"
    if not evidence_complete:
        return "unknown", "extract", "evidence_unknown"
    if compatibility == "incompatible":
        return "low", "extract", "incompatible"
    if compatibility == "unknown":
        return "low", "extract", "compatibility_unknown"
    return "low", "integrate", "ready"


def _batch_adjudication(payload: Any) -> dict[str, Any]:
    issues: list[str] = []
    item = _closed(
        payload,
        "batch",
        frozenset({"schema", "batch_id", "items", "dispositions"}),
        issues,
    )
    result = None
    if item is not None:
        if item.get("schema") != BATCH_ADJUDICATION_SCHEMA:
            issues.append("batch:schema_invalid")
        batch_id = _identifier(item.get("batch_id"), "batch.batch_id", issues)
        raw_items = item.get("items")
        if type(raw_items) is not list or not raw_items or len(raw_items) > MAX_ITEMS:
            issues.append("batch.items:invalid_array")
            raw_items = []
        expected: dict[str, dict[str, str]] = {}
        ordered_ids: list[str] = []
        for index, raw in enumerate(raw_items):
            parsed = _closed(
                raw,
                f"batch.items[{index}]",
                frozenset({"item_id", "facts"}),
                issues,
            )
            if parsed is None:
                continue
            item_id = _identifier(parsed.get("item_id"), f"batch.items[{index}].item_id", issues)
            facts = _closed(
                parsed.get("facts"),
                f"batch.items[{index}].facts",
                frozenset({"risk_facts", "compatibility", "evidence_complete"}),
                issues,
            )
            if item_id is None or facts is None:
                continue
            if item_id in expected:
                issues.append("batch:duplicate_item_id")
                continue
            risk_facts = facts.get("risk_facts")
            if type(risk_facts) is not list or len(risk_facts) > len(RISK_FACTS):
                issues.append(f"batch.items[{index}].risk_facts:invalid_array")
                risk_facts = []
            if any(fact not in RISK_FACTS for fact in risk_facts):
                issues.append(f"batch.items[{index}].risk_facts:invalid")
            if len(risk_facts) != len(set(risk_facts)):
                issues.append(f"batch.items[{index}].risk_facts:duplicate")
            compatibility = facts.get("compatibility")
            if compatibility not in COMPATIBILITY:
                issues.append(f"batch.items[{index}].compatibility:invalid")
            evidence_complete = _boolean(
                facts.get("evidence_complete"),
                f"batch.items[{index}].evidence_complete",
                issues,
            )
            if compatibility in COMPATIBILITY and evidence_complete is not None:
                normalized_facts = {
                    "risk_facts": sorted(risk_facts),
                    "compatibility": compatibility,
                    "evidence_complete": evidence_complete,
                }
                risk, disposition, reason = _expected_disposition(normalized_facts)
                expected[item_id] = {
                    "item_id": item_id,
                    "risk": risk,
                    "compatibility": compatibility,
                    "disposition": disposition,
                    "reason": reason,
                }
                ordered_ids.append(item_id)
        raw_dispositions = item.get("dispositions")
        if type(raw_dispositions) is not list or len(raw_dispositions) > MAX_ITEMS:
            issues.append("batch.dispositions:invalid_array")
            raw_dispositions = []
        seen: set[str] = set()
        for index, raw in enumerate(raw_dispositions):
            parsed = _closed(
                raw,
                f"batch.dispositions[{index}]",
                frozenset({"item_id", "disposition", "reason"}),
                issues,
            )
            if parsed is None:
                continue
            item_id = _identifier(parsed.get("item_id"), f"batch.dispositions[{index}].item_id", issues)
            disposition = parsed.get("disposition")
            reason = parsed.get("reason")
            if disposition not in DISPOSITIONS:
                issues.append("batch:disposition_invalid")
            if type(reason) is not str or _IDENTIFIER.fullmatch(reason) is None:
                issues.append("batch:reason_invalid")
            if item_id is None:
                continue
            if item_id in seen:
                issues.append("batch:duplicate_disposition")
            seen.add(item_id)
            if item_id not in expected:
                issues.append("batch:disposition_for_unknown_item")
            elif disposition != expected[item_id]["disposition"] or reason != expected[item_id]["reason"]:
                issues.append("batch:disposition_not_mechanically_derived")
        if seen != set(expected):
            issues.append("batch:missing_disposition")
        normalized = [expected[item_id] for item_id in ordered_ids]
        extracted = [entry["item_id"] for entry in normalized if entry["disposition"] == "extract"]
        result = {
            "batch_id": batch_id,
            "dispositions": normalized,
            "extracted_item_ids": extracted,
            "all_inputs_accounted": seen == set(expected) and len(seen) == len(raw_dispositions),
        }
    return _report("batch_adjudication", issues, result)


def evaluate_campaign_policy(program: Any) -> dict[str, Any]:
    """Evaluate one closed campaign policy operation without side effects."""

    try:
        canonical_bytes(program)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return _report(None, ["program:invalid_or_unbounded_json"], None)
    issues: list[str] = []
    item = _closed(program, "program", frozenset({"schema", "operation", "payload"}), issues)
    if item is None:
        return _report(None, issues, None)
    if item.get("schema") != PROGRAM_SCHEMA:
        issues.append("program:schema_invalid")
    operation = item.get("operation")
    if operation not in CAMPAIGN_POLICY_OPERATIONS:
        issues.append("program:operation_invalid")
    if type(item.get("payload")) is not dict:
        issues.append("program.payload:not_object")
    if issues:
        return _report(operation if operation in CAMPAIGN_POLICY_OPERATIONS else None, issues, None)
    evaluators = {
        "series_authority": _series_authority,
        "evaluator_integrity": _evaluator_integrity,
        "batch_adjudication": _batch_adjudication,
    }
    try:
        return evaluators[operation](item["payload"])
    except (TypeError, ValueError, OverflowError):
        return _report(operation, [f"{operation}:evaluation_failed"], None)


__all__ = [
    "BATCH_ADJUDICATION_SCHEMA",
    "CAMPAIGN_POLICY_OPERATIONS",
    "EVALUATOR_INTEGRITY_SCHEMA",
    "FALSIFYING_WITNESS_SCHEMA",
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "SERIES_AUTHORITY_SCHEMA",
    "SERIES_LEDGER_SCHEMA",
    "canonical_bytes",
    "canonical_sha256",
    "evaluate_campaign_policy",
]
