#!/usr/bin/env python3
"""Provider-free, exactly-once task-creation intent policy.

This module never creates, stops, archives, hands off, or mutates a Codex
task.  It seals one target-bound intent and evaluates durable call,
reconciliation, and duplicate-disposition facts supplied by a controller.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


INTENT_SCHEMA = "orch-dork/task-creation-intent/v1"
PROGRAM_SCHEMA = "orch-dork/task-creation-program/v1"
REPORT_SCHEMA = "orch-dork/task-creation-report/v1"
LEDGER_SCHEMA = "orch-dork/task-creation-ledger/v1"
RECONCILIATION_SCHEMA = "orch-dork/task-creation-reconciliation/v1"
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_CALL_STATUSES = frozenset(
    {"created", "failed", "timed_out", "ambiguous", "malformed"}
)
_LIVE_STATUSES = frozenset({"created", "active", "idle", "read_only"})
_DISPOSED_STATUSES = frozenset({"stopped", "archived"})


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, keys: set[str], label: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return False
    for key in sorted(keys - set(value)):
        _issue(issues, label + ":missing:" + key)
    for key in sorted(set(value) - keys):
        _issue(issues, label + ":unknown:" + str(key))
    return set(value) == keys


def _timestamp(value: Any) -> datetime | None:
    if not _text(value):
        return None
    raw = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _identity(intent: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(intent.get(key))
        for key in (
            "project_id",
            "initial_cwd",
            "host",
            "permission_profile",
            "prompt_marker",
            "creation_window",
            "parent_task_id",
            "supervisor_task_id",
            "task_role",
            "purpose",
            "authoritative_sources",
        )
    }


def intent_nonce(intent_or_identity: Mapping[str, Any]) -> str:
    value = intent_or_identity if isinstance(intent_or_identity, Mapping) else {}
    return _sha(_identity(value))


def build_task_creation_intent(identity: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(identity) if isinstance(identity, Mapping) else {}
    intent = {"schema": INTENT_SCHEMA, **deepcopy(value)}
    intent["nonce"] = intent_nonce(intent)
    return intent


def _validate_intent(intent: Any, issues: list[str]) -> dict[str, Any]:
    keys = {
        "schema",
        "nonce",
        "project_id",
        "initial_cwd",
        "host",
        "permission_profile",
        "prompt_marker",
        "creation_window",
        "parent_task_id",
        "supervisor_task_id",
        "task_role",
        "purpose",
        "authoritative_sources",
    }
    _exact(intent, keys, "intent", issues)
    value = dict(intent) if isinstance(intent, Mapping) else {}
    if value.get("schema") != INTENT_SCHEMA:
        _issue(issues, "intent:schema_invalid")
    for field in (
        "project_id",
        "host",
        "permission_profile",
        "prompt_marker",
        "parent_task_id",
        "supervisor_task_id",
        "task_role",
        "purpose",
    ):
        if not _text(value.get(field)):
            _issue(issues, "intent:" + field + "_invalid")
    cwd = value.get("initial_cwd")
    if not _text(cwd) or not Path(str(cwd)).is_absolute():
        _issue(issues, "intent:initial_cwd_invalid")
    window = value.get("creation_window")
    _exact(window, {"opens_at", "closes_at"}, "intent:creation_window", issues)
    opens = _timestamp(window.get("opens_at")) if isinstance(window, Mapping) else None
    closes = _timestamp(window.get("closes_at")) if isinstance(window, Mapping) else None
    if opens is None or closes is None or opens >= closes:
        _issue(issues, "intent:creation_window_invalid")
    sources = value.get("authoritative_sources")
    if not isinstance(sources, list) or not sources:
        _issue(issues, "intent:authoritative_sources_invalid")
        sources = []
    normalized_sources = []
    for index, source in enumerate(sources):
        _exact(source, {"host", "store"}, f"intent:authoritative_sources[{index}]", issues)
        if not isinstance(source, Mapping) or not _text(source.get("host")) or not _text(source.get("store")):
            _issue(issues, f"intent:authoritative_sources[{index}]:invalid")
            continue
        normalized_sources.append((str(source["host"]), str(source["store"])))
    if len(set(normalized_sources)) != len(normalized_sources):
        _issue(issues, "intent:authoritative_sources_duplicate")
    if not _SHA256.fullmatch(str(value.get("nonce", ""))) or value.get("nonce") != intent_nonce(value):
        _issue(issues, "intent:nonce_mismatch")
    return value


def empty_ledger() -> dict[str, Any]:
    return {"schema": LEDGER_SCHEMA, "records": []}


def accept_task_creation_intent(
    ledger: Mapping[str, Any],
    intent: Mapping[str, Any],
    *,
    accepted_at: str,
    source_pointer: str,
) -> dict[str, Any]:
    """Pure idempotent ledger transition; callers persist the returned value."""

    issues: list[str] = []
    value = dict(ledger) if isinstance(ledger, Mapping) else {}
    _exact(value, {"schema", "records"}, "ledger", issues)
    if value.get("schema") != LEDGER_SCHEMA:
        _issue(issues, "ledger:schema_invalid")
    records = value.get("records")
    if not isinstance(records, list):
        _issue(issues, "ledger:records_not_array")
        records = []
    intent_value = _validate_intent(intent, issues)
    if _timestamp(accepted_at) is None or not _text(source_pointer):
        _issue(issues, "ledger:acceptance_evidence_invalid")
    digest = _sha(intent_value)
    matching = [row for row in records if isinstance(row, Mapping) and row.get("nonce") == intent_value.get("nonce")]
    if len(matching) > 1:
        _issue(issues, "ledger:duplicate_nonce_records")
    if matching and matching[0].get("intent_sha256") != digest:
        _issue(issues, "ledger:nonce_identity_conflict")
    if issues:
        return {"status": "FAIL", "issues": sorted(issues), "ledger": deepcopy(value), "idempotent": False}
    if matching:
        return {"status": "PASS", "issues": [], "ledger": deepcopy(value), "idempotent": True}
    updated = deepcopy(value)
    updated["records"].append(
        {
            "nonce": intent_value["nonce"],
            "intent_sha256": digest,
            "accepted_at": accepted_at,
            "source_pointer": source_pointer,
        }
    )
    return {"status": "PASS", "issues": [], "ledger": updated, "idempotent": False}


def adapt_task_creation_receipt(
    raw: Any, *, nonce: str, turn_id: str, source_pointer: str
) -> dict[str, Any]:
    """Normalize a native create response without inferring success."""

    expected = {"status", "task_id"}
    if not isinstance(raw, Mapping) or set(raw) != expected:
        return {
            "nonce": nonce,
            "turn_id": turn_id,
            "status": "malformed",
            "returned_task_id": None,
            "source_pointer": source_pointer,
        }
    status = raw.get("status")
    task_id = raw.get("task_id")
    if status != "created" or not _text(task_id):
        return {
            "nonce": nonce,
            "turn_id": turn_id,
            "status": "malformed" if status not in _CALL_STATUSES else str(status),
            "returned_task_id": None,
            "source_pointer": source_pointer,
        }
    return {
        "nonce": nonce,
        "turn_id": turn_id,
        "status": "created",
        "returned_task_id": str(task_id),
        "source_pointer": source_pointer,
    }


def _matching_candidates(
    intent: Mapping[str, Any],
    candidates: Any,
    issues: list[str],
    *,
    observed_at: datetime | None,
    now: datetime,
):
    if not isinstance(candidates, list):
        _issue(issues, "reconciliation:candidates_not_array")
        return [], []
    fields = {
        "project_id": "project_id",
        "initial_cwd": "initial_cwd",
        "host": "host",
        "permission_profile": "permission_profile",
        "prompt_marker": "prompt_marker",
        "parent_task_id": "parent_task_id",
        "supervisor_task_id": "supervisor_task_id",
        "task_role": "task_role",
    }
    matches, mismatches = [], []
    required = {"task_id", "created_at", "status", *fields}
    opens = _timestamp(intent.get("creation_window", {}).get("opens_at"))
    closes = _timestamp(intent.get("creation_window", {}).get("closes_at"))
    for index, raw in enumerate(candidates):
        _exact(raw, required, f"reconciliation:candidates[{index}]", issues)
        if not isinstance(raw, Mapping):
            continue
        reasons = []
        for candidate_field, intent_field in fields.items():
            if raw.get(candidate_field) != intent.get(intent_field):
                reasons.append(candidate_field + "_mismatch")
        created = _timestamp(raw.get("created_at"))
        task_id = str(raw.get("task_id"))
        if created is not None and created > now:
            _issue(issues, "candidate:" + task_id + ":created_at_in_future")
        if created is not None and observed_at is not None and created > observed_at:
            _issue(issues, "candidate:" + task_id + ":created_after_observation")
        if created is None or opens is None or closes is None or not opens <= created <= closes:
            reasons.append("creation_window_mismatch")
        if not _text(raw.get("task_id")) or raw.get("status") not in _LIVE_STATUSES | _DISPOSED_STATUSES:
            reasons.append("candidate_identity_or_status_invalid")
        if reasons:
            mismatches.append({"task_id": raw.get("task_id"), "reasons": sorted(set(reasons))})
        else:
            matches.append(dict(raw))
    return matches, mismatches


def evaluate_task_creation(
    program: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    evaluation_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    issues: list[str] = []
    value = dict(program) if isinstance(program, Mapping) else {}
    _exact(
        value,
        {"schema", "intent", "ledger", "creation_calls", "reconciliation", "duplicate_dispositions"},
        "program",
        issues,
    )
    if value.get("schema") != PROGRAM_SCHEMA:
        _issue(issues, "program:schema_invalid")
    intent = _validate_intent(value.get("intent"), issues)
    ledger = value.get("ledger")
    _exact(ledger, {"schema", "records"}, "ledger", issues)
    ledger_value = dict(ledger) if isinstance(ledger, Mapping) else {}
    if ledger_value.get("schema") != LEDGER_SCHEMA or not isinstance(ledger_value.get("records"), list):
        _issue(issues, "ledger:invalid")
    records = ledger_value.get("records") if isinstance(ledger_value.get("records"), list) else []
    accepted = [
        row
        for row in records
        if isinstance(row, Mapping)
        and row.get("nonce") == intent.get("nonce")
        and row.get("intent_sha256") == _sha(intent)
    ]
    if len(accepted) != 1:
        _issue(issues, f"ledger:intent_record_count:{len(accepted)}")

    calls = value.get("creation_calls")
    if not isinstance(calls, list):
        _issue(issues, "creation_calls:not_array")
        calls = []
    call_keys = {"nonce", "turn_id", "status", "returned_task_id", "source_pointer"}
    for index, call in enumerate(calls):
        _exact(call, call_keys, f"creation_calls[{index}]", issues)
        if not isinstance(call, Mapping):
            continue
        if call.get("nonce") != intent.get("nonce"):
            _issue(issues, f"creation_calls[{index}]:nonce_mismatch")
        if not _text(call.get("turn_id")) or not _text(call.get("source_pointer")):
            _issue(issues, f"creation_calls[{index}]:evidence_invalid")
        if call.get("status") not in _CALL_STATUSES:
            _issue(issues, f"creation_calls[{index}]:status_invalid")
        if call.get("status") == "created":
            if not _text(call.get("returned_task_id")):
                _issue(issues, f"creation_calls[{index}]:returned_task_id_invalid")
        elif call.get("returned_task_id") is not None:
            _issue(issues, f"creation_calls[{index}]:unexpected_task_id")
    if len(calls) > 1:
        _issue(issues, "creation:second_call_forbidden")

    reconciliation = value.get("reconciliation")
    _exact(
        reconciliation,
        {"schema", "status", "observed_at", "settlement", "sources", "candidates"},
        "reconciliation",
        issues,
    )
    rec = dict(reconciliation) if isinstance(reconciliation, Mapping) else {}
    if rec.get("schema") != RECONCILIATION_SCHEMA:
        _issue(issues, "reconciliation:schema_invalid")
    if rec.get("status") not in {"not_started", "observed"}:
        _issue(issues, "reconciliation:status_invalid")
    if rec.get("settlement") not in {"open", "closed"}:
        _issue(issues, "reconciliation:settlement_invalid")
    observed_at = _timestamp(rec.get("observed_at")) if rec.get("status") == "observed" else None
    if rec.get("status") == "observed" and observed_at is None:
        _issue(issues, "reconciliation:observed_at_invalid")
    if observed_at is not None and observed_at > evaluation_now:
        _issue(issues, "reconciliation:observed_at_in_future")
    if rec.get("status") == "not_started" and rec.get("observed_at") is not None:
        _issue(issues, "reconciliation:not_started_has_observation")
    sources = rec.get("sources")
    if not isinstance(sources, list):
        _issue(issues, "reconciliation:sources_not_array")
        sources = []
    observed_sources = set()
    for index, source in enumerate(sources):
        _exact(source, {"host", "store", "searched", "source_pointer"}, f"reconciliation:sources[{index}]", issues)
        if not isinstance(source, Mapping):
            continue
        if source.get("searched") is not True or not _text(source.get("source_pointer")):
            _issue(issues, f"reconciliation:sources[{index}]:not_authoritatively_searched")
        else:
            observed_sources.add((source.get("host"), source.get("store")))
    required_sources = {
        (source.get("host"), source.get("store"))
        for source in intent.get("authoritative_sources", [])
        if isinstance(source, Mapping)
    }
    sources_complete = observed_sources == required_sources
    if rec.get("status") == "observed" and not sources_complete:
        _issue(issues, "reconciliation:authoritative_sources_incomplete")
    matches, mismatches = _matching_candidates(
        intent,
        rec.get("candidates"),
        issues,
        observed_at=observed_at,
        now=evaluation_now,
    )

    dispositions = value.get("duplicate_dispositions")
    if not isinstance(dispositions, list):
        _issue(issues, "duplicate_dispositions:not_array")
        dispositions = []
    disposed = set()
    for index, row in enumerate(dispositions):
        _exact(row, {"task_id", "action", "observed", "source_pointer"}, f"duplicate_dispositions[{index}]", issues)
        if not isinstance(row, Mapping):
            continue
        if row.get("action") not in _DISPOSED_STATUSES or row.get("observed") is not True or not _text(row.get("source_pointer")):
            _issue(issues, f"duplicate_dispositions[{index}]:invalid")
        else:
            disposed.add(str(row.get("task_id")))
    matched_ids = {str(row.get("task_id")) for row in matches}
    if not disposed <= matched_ids:
        _issue(issues, "duplicate_dispositions:task_outside_intent")

    live_matches = [row for row in matches if row.get("status") in _LIVE_STATUSES and str(row.get("task_id")) not in disposed]
    if any(row.get("status") in _DISPOSED_STATUSES for row in matches):
        disposed.update(str(row.get("task_id")) for row in matches if row.get("status") in _DISPOSED_STATUSES)
    call_count = len(calls)
    call_status = calls[0].get("status") if call_count == 1 and isinstance(calls[0], Mapping) else None
    outcome = "READY_FOR_SINGLE_CALL" if call_count == 0 else "OUTCOME_UNKNOWN"
    candidate_task_id = None
    duplicate_cleanup_complete = False
    if call_count == 1 and rec.get("status") == "observed" and sources_complete:
        returned_task_id = calls[0].get("returned_task_id") if isinstance(calls[0], Mapping) else None
        if (
            call_status == "created"
            and _text(returned_task_id)
            and returned_task_id not in {row.get("task_id") for row in matches}
        ):
            _issue(issues, "creation:returned_candidate_mismatch")
        if len(matches) > 1:
            duplicate_cleanup_complete = len(live_matches) == 1 and len(disposed) >= len(matches) - 1
            if duplicate_cleanup_complete:
                outcome = "READ_ONLY_CANDIDATE"
                candidate_task_id = live_matches[0].get("task_id")
            else:
                outcome = "DUPLICATE_QUARANTINE_REQUIRED"
        elif len(matches) == 1:
            if len(live_matches) == 1:
                outcome = "READ_ONLY_CANDIDATE"
                candidate_task_id = live_matches[0].get("task_id")
            else:
                outcome = "NO_LIVE_MATCH"
        elif rec.get("settlement") == "closed" and observed_at is not None:
            closes = _timestamp(intent.get("creation_window", {}).get("closes_at"))
            outcome = "NO_MATCH_CONFIRMED" if closes is not None and observed_at > closes else "RECONCILIATION_PENDING"
        else:
            outcome = "RECONCILIATION_PENDING"

    # A native `created` result is still reconciled against authoritative
    # inventory; non-created results can never authorize a same-turn retry.
    issues = sorted(set(issues))
    return {
        "schema": REPORT_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "outcome": "REFUSED" if issues else outcome,
        "issues": issues,
        "intent_nonce": intent.get("nonce"),
        "intent_sha256": _sha(intent),
        "ledger_intent_accepted": len(accepted) == 1,
        "ledger_idempotent": len(accepted) == 1,
        "create_call_count": call_count,
        "create_call_status": call_status,
        "create_call_permitted": not issues and call_count == 0,
        "second_create_call_permitted": False,
        "same_turn_retry_permitted": False,
        "fallback_target_permitted": False,
        "delayed_reconciliation_required": call_count == 1 and outcome in {"OUTCOME_UNKNOWN", "RECONCILIATION_PENDING"},
        "authoritative_sources_complete": sources_complete,
        "matching_candidates": matches,
        "mismatched_candidates": mismatches,
        "candidate_task_id": candidate_task_id,
        "candidate_read_only_required": candidate_task_id is not None,
        "candidate_mutation_permitted": False,
        "lease_transfer_permitted": False,
        "duplicate_cleanup_complete": duplicate_cleanup_complete,
        "duplicate_disposition_required": outcome == "DUPLICATE_QUARANTINE_REQUIRED",
        "post_creation_repair_permitted": False,
        "provider_free": True,
        "live_task_operations": 0,
        "model_calls": 0,
        "hosted_calls": 0,
        "report_sha256": _sha({"program": value, "issues": issues, "outcome": outcome}),
    }


__all__ = [
    "INTENT_SCHEMA",
    "PROGRAM_SCHEMA",
    "REPORT_SCHEMA",
    "LEDGER_SCHEMA",
    "RECONCILIATION_SCHEMA",
    "accept_task_creation_intent",
    "adapt_task_creation_receipt",
    "build_task_creation_intent",
    "empty_ledger",
    "evaluate_task_creation",
    "intent_nonce",
]
