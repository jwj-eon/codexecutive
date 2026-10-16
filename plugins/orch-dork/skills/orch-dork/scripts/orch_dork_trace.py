#!/usr/bin/env python3
"""Provider-free run-trace instrumentation for Orch Dork (north star P4).

Every orchestration run is normalized into one append-only event graph so a
later, separately authorized phase can study how runs were split and routed
from data.  This module only instruments: it validates the frozen event-graph
shape, seals a passing trace with a sha256 over the canonical document,
summarizes what the run's produced artifacts were actually consumed, and
keeps finished-run summaries in an append-only JSONL chain of sealed
records.  The same chain accepts closed deepening decision and integration
measurements derived from exact proposal, controller-report, plan-revision,
and trace seals.  It contains no reward functions, no learned policies, and
no adaptation: the validation rules below are static, and nothing in this
module changes how a run is planned or executed.

The legacy lane-event conformance schema orch-dork/trace/v1 lives in
orch_dork_policy and is left untouched; the two schemas coexist without
importing each other.

Design constraints, all enforced here rather than by convention:

* Unknown fields are rejected at every level, so the trace_sha256 seal
  hashes exactly what the document contains rather than silently absorbing
  additions.
* Events are 1-based, strictly contiguous (a gap or duplicate fails),
  strictly non-decreasing in time, and must honor the node ordering
  invariants (start before finish, assign before write, and release before
  consume for the same artifact ref).
* The free-form event data blob is bounded in canonical bytes so a trace
  stays a log and never a document store.
* Finished-run summaries accumulate in an append-only JSONL chain in the
  same concept as the dogfood corpus (chained hashes of prior records, an
  independent implementation): each line seals the (seq, prev_sha256,
  record) tuple, and any tamper anywhere is refused, never rewritten.
* Deepening measurements are derived from trace timestamps and event counts.
  Missing observations remain typed unknown or not-applicable values; they
  are never converted to zero.
* Writes go only to the exact path the caller passes.  Provider-free: zero
  model calls, zero credentials, zero network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
import os
from pathlib import Path
import re
import statistics
from typing import Any, Mapping, Sequence

import orch_dork_decomposition as decomposition

TRACE_SCHEMA = "orch-dork/run-trace/v1"
UPTAKE_SCHEMA = "orch-dork/run-trace-uptake/v1"
CHAIN_SCHEMA = "orch-dork/run-trace-chain/v1"
DEEPENING_EVENT_SCHEMA = "orch-dork/deepening-event/v1"
DEEPENING_DECISION_EVIDENCE_SCHEMA = "orch-dork/deepening-decision-evidence/v1"
DEEPENING_INTEGRATION_EVIDENCE_SCHEMA = "orch-dork/deepening-integration-evidence/v1"
DEEPENING_DECISION_SCHEMA = "orch-dork/deepening-decision/v1"
DEEPENING_INTEGRATION_SCHEMA = "orch-dork/deepening-integration/v1"
DEEPENING_RECORD_REPORT_SCHEMA = "orch-dork/deepening-record-report/v1"
DEEPENING_SUMMARY_SCHEMA = "orch-dork/deepening-summary/v1"
DEEPENING_MEASUREMENT_VALIDATION_SCHEMA = (
    "orch-dork/deepening-measurement-validation/v1"
)

# The closed vocabulary of orchestration events, in the order a typical run
# visits them.  An unknown type is a conformance failure, not a new signal.
EVENT_TYPES = (
    "plan",
    "assign",
    "start",
    "read",
    "tool",
    "checkpoint",
    "propose_split",
    "approve",
    "reject",
    "write",
    "verify",
    "release",
    "consume",
    "integrate",
    "finish",
)

# Who acted.  model and effort stay nullable so a purely mechanical
# (non-model) actor remains expressible.
ACTOR_KINDS = ("root", "worker", "tool", "validator")

# The free-form event data blob is bounded so a trace stays a log rather
# than a document store, in the same spirit as the dogfood corpus note bound.
MAX_DATA_BYTES = 4096
MAX_REF_CHARS = 2048

_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_CHAIN_LINE_KEYS = {"seq", "prev_sha256", "record", "record_sha256"}


class OrchDorkTraceError(ValueError):
    """Raised for any trace, uptake, or chain condition that fails closed."""


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


def _issue(issues: list[str], value: str) -> None:
    if value not in issues:
        issues.append(value)


def _exact(value: Any, keys: set[str], label: str, issues: list[str]) -> bool:
    if not isinstance(value, Mapping):
        _issue(issues, label + ":not_object")
        return False
    for key in sorted(keys - set(value)):
        _issue(issues, label + ":missing:" + str(key))
    for key in sorted(set(value) - keys):
        _issue(issues, label + ":unknown:" + str(key))
    return set(value) == keys


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _bounded_text(value: Any, limit: int) -> bool:
    return _text(value) and len(value) <= limit


def _report(schema: str, issues: list[str], extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema": schema,
        "status": "PASS" if not issues else "FAIL",
        "issues": sorted(set(issues)),
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }
    if extra:
        core.update(extra)
    return core


def _declared_revisions(revisions: Any, issues: list[str]) -> set[int]:
    """Return the declared revision numbers, or nothing if the list is bad."""

    seen: set[int] = set()
    if not isinstance(revisions, list):
        _issue(issues, "plan_revisions:not_array")
        return seen
    for index, revision in enumerate(revisions):
        label = "plan_revisions[%d]" % index
        if not _exact(revision, {"revision", "plan_sha256"}, label, issues):
            continue
        number = revision.get("revision")
        if not isinstance(number, int) or isinstance(number, bool) or number < 1:
            _issue(issues, label + ":revision_invalid")
            continue
        sha = revision.get("plan_sha256")
        if not isinstance(sha, str) or not _SHA256.match(sha):
            _issue(issues, label + ":plan_sha256_invalid")
            continue
        if number in seen:
            _issue(issues, label + ":duplicate_revision")
            continue
        seen.add(number)
    return seen


def _timestamps_in_order(events: list[Any], issues: list[str]) -> None:
    """Every event carries a parseable, non-decreasing UTC ISO-8601 time."""

    last: datetime | None = None
    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            continue
        label = "events[%d]" % index
        stamp = event.get("at")
        if not isinstance(stamp, str) or not _TIMESTAMP.match(stamp):
            _issue(issues, label + ":timestamp_invalid")
            continue
        try:
            moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            _issue(issues, label + ":timestamp_invalid")
            continue
        if last is not None and moment < last:
            _issue(issues, label + ":timestamp_regression")
        last = moment


def validate_run_trace(trace: Any) -> dict[str, Any]:
    """Validate one normalized run trace, or report exactly what is wrong.

    The report is deterministic: identical traces yield identical reports,
    and on a PASS it also seals the canonical document with trace_sha256 so a
    later phase can pin a decision to this exact trace without re-deriving
    the serialization.
    """

    issues: list[str] = []
    if not _exact(trace, {"schema", "run_id", "plan_revisions", "events"}, "trace", issues):
        return _report(
            TRACE_SCHEMA,
            issues,
            {"run_id": None, "event_count": 0, "trace_sha256": None},
        )

    if trace.get("schema") != TRACE_SCHEMA:
        _issue(issues, "trace:schema_mismatch")

    run_id = trace.get("run_id")
    if not _bounded_text(run_id, 255):
        _issue(issues, "trace:run_id_invalid")

    declared = _declared_revisions(trace.get("plan_revisions"), issues)

    events = trace.get("events")
    if not isinstance(events, list):
        _issue(issues, "events:not_array")
        events = []

    for index, event in enumerate(events):
        label = "events[%d]" % index
        if not _exact(
            event,
            {
                "seq",
                "type",
                "node_id",
                "plan_revision",
                "actor",
                "at",
                "artifact_refs",
                "data",
            },
            label,
            issues,
        ):
            continue

        seq = event.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            _issue(issues, label + ":seq_invalid")
        elif seq != index + 1:
            _issue(issues, "events:seq_not_contiguous")

        if event.get("type") not in EVENT_TYPES:
            _issue(issues, label + ":type_invalid")

        node = event.get("node_id")
        if node is not None and not _bounded_text(node, 255):
            _issue(issues, label + ":node_id_invalid")

        revision = event.get("plan_revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            _issue(issues, label + ":plan_revision_invalid")
        elif revision not in declared:
            _issue(issues, label + ":unknown_revision")

        if _exact(event.get("actor"), {"kind", "model", "effort"}, label + ".actor", issues):
            actor = event["actor"]
            if actor.get("kind") not in ACTOR_KINDS:
                _issue(issues, label + ".actor:kind_invalid")
            if not (actor.get("model") is None or _bounded_text(actor.get("model"), 4096)):
                _issue(issues, label + ".actor:model_invalid")
            if not (actor.get("effort") is None or _bounded_text(actor.get("effort"), 4096)):
                _issue(issues, label + ".actor:effort_invalid")

        refs = event.get("artifact_refs")
        if not isinstance(refs, list):
            _issue(issues, label + ":artifact_refs:not_array")
            refs = []
        for ref_index, ref in enumerate(refs):
            if not _bounded_text(ref, MAX_REF_CHARS):
                _issue(issues, "%s.artifact_refs[%d]:invalid" % (label, ref_index))

        data = event.get("data")
        if not isinstance(data, Mapping):
            _issue(issues, label + ":data_not_object")
        else:
            try:
                length = len(_canonical(data))
            except (TypeError, ValueError):
                _issue(issues, label + ":data_unserializable")
            else:
                if length > MAX_DATA_BYTES:
                    _issue(issues, label + ":data_too_large")

    _timestamps_in_order(events, issues)

    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            continue
        label = "events[%d]" % index
        etype = event.get("type")
        node = event.get("node_id")
        node_ok = isinstance(node, str) and bool(node.strip())
        if etype == "finish" and node_ok:
            started = any(
                isinstance(prev, Mapping)
                and prev.get("type") == "start"
                and prev.get("node_id") == node
                for prev in events[:index]
            )
            if not started:
                _issue(issues, label + ":finish_before_start")
        if etype == "write" and node_ok:
            assigned = any(
                isinstance(prev, Mapping)
                and prev.get("type") == "assign"
                and prev.get("node_id") == node
                for prev in events[:index]
            )
            if not assigned:
                _issue(issues, label + ":write_before_assign")
        if etype in ("consume", "integrate"):
            released: set[str] = set()
            for prev in events[:index]:
                if isinstance(prev, Mapping) and prev.get("type") == "release":
                    prev_refs = prev.get("artifact_refs")
                    if isinstance(prev_refs, list):
                        released.update(ref for ref in prev_refs if isinstance(ref, str))
            refs = event.get("artifact_refs")
            if isinstance(refs, list):
                for ref in refs:
                    if isinstance(ref, str) and ref.strip() and ref not in released:
                        _issue(issues, label + ":consume_before_release")
                        break

    extra = {
        "run_id": run_id if _bounded_text(run_id, 255) else None,
        "event_count": len(events),
    }
    if issues:
        return _report(TRACE_SCHEMA, issues, {**extra, "trace_sha256": None})
    return _report(TRACE_SCHEMA, issues, {**extra, "trace_sha256": _sha256(dict(trace))})


def compute_uptake(trace: Any) -> dict[str, Any]:
    """Summarize what the run produced and what of it was actually consumed.

    Every released artifact is "produced"; every ref touched by a consume or
    integrate event is "consumed".  A produced artifact nobody consumed is
    the orchestration waste the north star wants to eliminate, so the
    orphaned list is the observing unit.  The ratio is a plain description
    of how much of what was produced was put to use, not a score anything is
    allowed to adapt to.
    """

    check = validate_run_trace(trace)
    if check["status"] != "PASS":
        return _report(UPTAKE_SCHEMA, check["issues"])

    events = trace["events"]
    released: list[str] = []
    consumed: list[str] = []
    produced_by_node: dict[str, set[str]] = {}
    consumed_by: list[tuple[str, str]] = []
    for event in events:
        refs = event.get("artifact_refs")
        if not isinstance(refs, list):
            continue
        refs = [ref for ref in refs if isinstance(ref, str)]
        if event.get("type") == "release":
            released.extend(refs)
            node = event.get("node_id")
            if isinstance(node, str):
                produced_by_node.setdefault(node, set()).update(refs)
        if event.get("type") in ("consume", "integrate"):
            consumed.extend(refs)
            node = event.get("node_id")
            node = node if isinstance(node, str) else ""
            consumed_by.extend((ref, node) for ref in refs)

    produced = sorted(set(released))
    consumed_keys = sorted(set(consumed))
    produced_set = set(produced)
    consumed_set = set(consumed_keys)
    orphaned = sorted(produced_set - consumed_set)

    notes: list[str] = []
    if not produced_set:
        ratio = 1.0
        notes.append("trace:nothing_produced")
    else:
        ratio = round(len(produced_set & consumed_set) / len(produced_set), 6)

    per_node: list[dict[str, Any]] = []
    others_consumed: dict[str, set[str]] = {}
    for ref, consumer_node in consumed_by:
        for producer, owned in produced_by_node.items():
            if producer != consumer_node and ref in owned:
                others_consumed.setdefault(producer, set()).add(ref)
    for node in sorted(produced_by_node):
        owned = produced_by_node[node]
        per_node.append(
            {
                "node_id": node,
                "produced": len(owned),
                "consumed_by_others": len(others_consumed.get(node, set())),
                "orphaned": len(owned - consumed_set),
            }
        )

    return _report(
        UPTAKE_SCHEMA,
        [],
        {
            "run_id": trace.get("run_id"),
            "produced": produced,
            "consumed": consumed_keys,
            "orphaned": orphaned,
            "uptake_ratio": ratio,
            "notes": notes,
            "per_node": per_node,
        },
    )


def _sealed_report_sha256(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    core = dict(value)
    reported = core.pop("report_sha256", None)
    if not isinstance(reported, str) or not _SHA256.match(reported):
        return None
    try:
        actual = _sha256(core)
    except (TypeError, ValueError):
        return None
    return reported if reported == actual else None


def _deepening_event_data(
    event: Mapping[str, Any],
    *,
    proposal_event_id: str,
    proposal_sha256: str,
) -> bool:
    data = event.get("data")
    return (
        isinstance(data, Mapping)
        and data.get("schema") == DEEPENING_EVENT_SCHEMA
        and data.get("proposal_event_id") == proposal_event_id
        and data.get("proposal_sha256") == proposal_sha256
    )


def _deepening_event_fields_valid(event: Mapping[str, Any]) -> bool:
    common = {"schema", "proposal_event_id", "proposal_sha256"}
    expected = {
        "checkpoint": common,
        "propose_split": common,
        "approve": common | {"decision", "decision_report_sha256"},
        "reject": common | {"decision", "decision_report_sha256"},
        "plan": common | {"plan_sha256"},
    }.get(str(event.get("type")))
    data = event.get("data")
    return expected is not None and isinstance(data, Mapping) and set(data) == expected


def _milliseconds(start: Any, end: Any) -> int | None:
    if not isinstance(start, str) or not isinstance(end, str):
        return None
    if not _TIMESTAMP.match(start) or not _TIMESTAMP.match(end):
        return None
    try:
        first = datetime.fromisoformat(start.replace("Z", "+00:00"))
        last = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except ValueError:
        return None
    delta = int((last - first).total_seconds() * 1000)
    return delta if delta >= 0 else None


def _deepening_record_report(
    issues: list[str],
    *,
    record: Mapping[str, Any] | None = None,
    chain_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return _report(
        DEEPENING_RECORD_REPORT_SCHEMA,
        issues,
        {
            "record": dict(record) if isinstance(record, Mapping) else None,
            "chain_receipt": dict(chain_receipt) if isinstance(chain_receipt, Mapping) else None,
        },
    )


def _document_matches_sha256(value: Any, digest: Any) -> bool:
    if not isinstance(value, Mapping) or not isinstance(digest, str) or not _SHA256.match(digest):
        return False
    try:
        return _sha256(dict(value)) == digest
    except (TypeError, ValueError):
        return False


def _parse_deepening_evidence(
    evidence: Any,
    expected_schema: str,
    issues: list[str],
) -> dict[str, Any]:
    fields = {"schema", "proposal", "decision_report", "trace"}
    if not _exact(evidence, fields, "evidence", issues):
        return {}
    assert isinstance(evidence, Mapping)
    if evidence.get("schema") != expected_schema:
        _issue(issues, "evidence:schema_mismatch")

    proposal = evidence.get("proposal")
    proposal_report = decomposition.validate_decomposition_proposal(proposal)
    if proposal_report.get("status") != "PASS":
        for item in proposal_report.get("issues", []):
            _issue(issues, "proposal:" + str(item))
    proposal_sha256 = proposal_report.get("proposal_sha256")
    if not isinstance(proposal_sha256, str) or not _SHA256.match(proposal_sha256):
        _issue(issues, "proposal:sha256_unavailable")
    proposal_value = proposal if isinstance(proposal, Mapping) else {}
    base_revision = proposal_value.get("base_plan_revision")

    decision_report = evidence.get("decision_report")
    decision_value = decision_report if isinstance(decision_report, Mapping) else {}
    decision_report_sha256 = _sealed_report_sha256(decision_report)
    if decision_report_sha256 is None:
        _issue(issues, "decision_report:seal_invalid")
    if decision_value.get("schema") != "orch-dork/adaptive-finite-dag-report/v1":
        _issue(issues, "decision_report:schema_mismatch")
    if decision_value.get("active_revision") != base_revision:
        _issue(issues, "binding:base_revision_mismatch")

    base_plan_sha256 = decision_value.get("active_plan_sha256")
    result_revision = decision_value.get("effective_revision")
    result_plan_sha256 = decision_value.get("effective_plan_sha256")
    active_plan = decision_value.get("active_plan")
    effective_plan = decision_value.get("effective_plan")
    if not _document_matches_sha256(active_plan, base_plan_sha256):
        _issue(issues, "binding:active_plan_document_mismatch")
    if not _document_matches_sha256(effective_plan, result_plan_sha256):
        _issue(issues, "binding:effective_plan_document_mismatch")

    run_trace = evidence.get("trace")
    trace_report = validate_run_trace(run_trace)
    if trace_report.get("status") != "PASS":
        for item in trace_report.get("issues", []):
            _issue(issues, "trace:" + str(item))
    trace_value = run_trace if isinstance(run_trace, Mapping) else {}
    declared_revisions = {
        item.get("revision"): item.get("plan_sha256")
        for item in trace_value.get("plan_revisions", [])
        if isinstance(item, Mapping)
    }
    if declared_revisions.get(base_revision) != base_plan_sha256:
        _issue(issues, "binding:trace_base_plan_mismatch")
    return {
        "proposal": proposal_value,
        "proposal_sha256": proposal_sha256,
        "proposal_event_id": proposal_value.get("event_id"),
        "parent_node_id": proposal_value.get("parent_node_id"),
        "base_revision": base_revision,
        "base_plan_sha256": base_plan_sha256,
        "decision_report": decision_value,
        "decision_report_sha256": decision_report_sha256,
        "decision_code": decision_value.get("decision"),
        "result_revision": result_revision,
        "result_plan_sha256": result_plan_sha256,
        "effective_plan": effective_plan,
        "trace": trace_value,
        "trace_report": trace_report,
        "declared_revisions": declared_revisions,
        "events": trace_value.get("events") if isinstance(trace_value.get("events"), list) else [],
    }


def _observed_ms(value: int) -> dict[str, Any]:
    return {"status": "observed", "value_ms": value, "reason": None}


def _unobserved_ms(status: str, reason: str) -> dict[str, Any]:
    return {"status": status, "value_ms": None, "reason": reason}


def _count_measurement(value: int | None, unit: str, reason: str | None = None) -> dict[str, Any]:
    return {
        "status": "observed" if reason is None else "unknown",
        "value": value if reason is None else None,
        "unit": unit,
        "reason": reason,
    }


def _seal_measurement(record_core: Mapping[str, Any]) -> dict[str, Any]:
    return {**record_core, "record_sha256": _sha256(dict(record_core))}


def _record_seal_valid(record: Any) -> bool:
    if not isinstance(record, Mapping):
        return False
    core = dict(record)
    recorded_sha256 = core.pop("record_sha256", None)
    try:
        return (
            isinstance(recorded_sha256, str)
            and _SHA256.match(recorded_sha256) is not None
            and recorded_sha256 == _sha256(core)
        )
    except (TypeError, ValueError):
        return False


def record_deepening(evidence: Any, ledger_path: str | Path) -> dict[str, Any]:
    """Derive, validate, seal, and append one deepening measurement record."""

    if (
        isinstance(evidence, Mapping)
        and evidence.get("schema") == DEEPENING_INTEGRATION_EVIDENCE_SCHEMA
    ):
        return _record_deepening_integration(evidence, ledger_path)

    issues: list[str] = []
    context = _parse_deepening_evidence(
        evidence,
        DEEPENING_DECISION_EVIDENCE_SCHEMA,
        issues,
    )
    proposal_sha256 = context.get("proposal_sha256")
    proposal_event_id = context.get("proposal_event_id")
    parent_node_id = context.get("parent_node_id")
    base_revision = context.get("base_revision")
    base_plan_sha256 = context.get("base_plan_sha256")
    decision_report_sha256 = context.get("decision_report_sha256")
    decision_code = context.get("decision_code")
    trace_value = context.get("trace", {})
    trace_report = context.get("trace_report", {})
    declared_revisions = context.get("declared_revisions", {})
    proposal_events = [
        item
        for item in context.get("events", [])
        if isinstance(item, Mapping)
        and _deepening_event_data(
            item,
            proposal_event_id=str(proposal_event_id),
            proposal_sha256=str(proposal_sha256),
        )
    ]
    for event in proposal_events:
        if not _deepening_event_fields_valid(event):
            _issue(issues, "trace:%s_event_data_invalid" % event.get("type"))
    checkpoints = [
        item
        for item in proposal_events
        if item.get("type") == "checkpoint" and item.get("node_id") == parent_node_id
    ]
    propose_events = [
        item
        for item in proposal_events
        if item.get("type") == "propose_split" and item.get("node_id") == parent_node_id
    ]
    decisions = [
        item
        for item in proposal_events
        if item.get("type") in {"approve", "reject"}
        and isinstance(item.get("data"), Mapping)
        and item["data"].get("decision_report_sha256") == decision_report_sha256
        and item["data"].get("decision") == decision_code
    ]
    checkpoint = checkpoints[0] if len(checkpoints) == 1 else None
    proposed = propose_events[0] if len(propose_events) == 1 else None
    decision = decisions[0] if len(decisions) == 1 else None
    outcome = (
        "accepted"
        if decision_code == "REVISION_BOUND"
        else "deferred" if decision_code == "PROPOSAL_UNAPPROVED" else "denied"
    )
    if len(checkpoints) > 1:
        _issue(issues, "trace:checkpoint_event_ambiguous")
    if not propose_events:
        _issue(issues, "trace:proposal_event_missing")
    elif len(propose_events) > 1:
        _issue(issues, "trace:proposal_event_ambiguous")
    if not decisions and outcome != "deferred":
        _issue(issues, "trace:decision_event_missing")
    elif len(decisions) > 1:
        _issue(issues, "trace:decision_event_ambiguous")

    accepted = outcome == "accepted"
    result_revision = context.get("result_revision")
    result_plan_sha256 = context.get("result_plan_sha256")
    effective = None
    if accepted:
        effective_events = [
            item
            for item in proposal_events
            if item.get("type") == "plan"
            and item.get("plan_revision") == result_revision
            and isinstance(item.get("data"), Mapping)
            and item["data"].get("plan_sha256") == result_plan_sha256
        ]
        effective = effective_events[0] if len(effective_events) == 1 else None
        if len(effective_events) > 1:
            _issue(issues, "trace:effective_revision_event_ambiguous")
        if type(result_revision) is not int or result_revision != base_revision + 1:
            _issue(issues, "binding:result_revision_invalid")
        if not isinstance(result_plan_sha256, str) or not _SHA256.match(result_plan_sha256):
            _issue(issues, "binding:result_plan_sha256_invalid")
        if declared_revisions.get(result_revision) != result_plan_sha256:
            _issue(issues, "binding:trace_result_plan_mismatch")
    elif result_revision != base_revision or result_plan_sha256 != base_plan_sha256:
        _issue(issues, "binding:denied_plan_changed")

    decision_latency = _milliseconds(
        proposed.get("at") if isinstance(proposed, Mapping) else None,
        decision.get("at") if isinstance(decision, Mapping) else None,
    )
    round_trip = (
        _milliseconds(
            checkpoint.get("at") if isinstance(checkpoint, Mapping) else None,
            effective.get("at") if isinstance(effective, Mapping) else None,
        )
        if accepted
        else None
    )
    if decision_latency is None and outcome != "deferred":
        _issue(issues, "measurement:decision_latency_unavailable")
    if issues:
        return _deepening_record_report(issues)

    if outcome == "denied":
        round_trip_metric = _unobserved_ms("not_applicable", "proposal_not_bound")
    elif outcome == "deferred":
        round_trip_metric = _unobserved_ms("not_applicable", "proposal_deferred")
    elif checkpoint is None:
        round_trip_metric = _unobserved_ms("unknown", "checkpoint_event_missing")
    elif effective is None:
        round_trip_metric = _unobserved_ms("unknown", "effective_revision_event_missing")
    else:
        round_trip_metric = _observed_ms(round_trip)

    record_core = {
        "schema": DEEPENING_DECISION_SCHEMA,
        "run_id": trace_value.get("run_id"),
        "proposal_event_id": proposal_event_id,
        "parent_node_id": parent_node_id,
        "proposal_sha256": proposal_sha256,
        "base_plan": {"revision": base_revision, "plan_sha256": base_plan_sha256},
        "decision": {
            "outcome": outcome,
            "code": decision_code,
            "report_sha256": decision_report_sha256,
        },
        "result_plan": (
            {
                "status": "observed",
                "revision": result_revision,
                "plan_sha256": result_plan_sha256,
                "reason": None,
            }
            if accepted
            else {
                "status": "not_applicable",
                "revision": None,
                "plan_sha256": None,
                "reason": "proposal_deferred" if outcome == "deferred" else "proposal_not_bound",
            }
        ),
        "decision_latency": (
            _observed_ms(decision_latency)
            if decision_latency is not None
            else _unobserved_ms("unknown", "decision_event_missing")
        ),
        "replan_round_trip": round_trip_metric,
        "trace_sha256": trace_report.get("trace_sha256"),
    }
    record = _seal_measurement(record_core)
    entries, chain_issues = _read_chain(ledger_path)
    for item in chain_issues:
        _issue(issues, item)
    duplicate = any(
        isinstance(entry.get("record"), Mapping)
        and entry["record"].get("schema") == DEEPENING_DECISION_SCHEMA
        and entry["record"].get("run_id") == record["run_id"]
        and entry["record"].get("proposal_sha256") == proposal_sha256
        for entry in entries
    )
    if duplicate:
        _issue(issues, "decision:duplicate_record")
    if issues:
        return _deepening_record_report(issues)
    receipt = append_trace_record(ledger_path, record)
    return _deepening_record_report([], record=record, chain_receipt=receipt)


def _record_deepening_integration(
    evidence: Mapping[str, Any], ledger_path: str | Path
) -> dict[str, Any]:
    issues: list[str] = []
    context = _parse_deepening_evidence(
        evidence,
        DEEPENING_INTEGRATION_EVIDENCE_SCHEMA,
        issues,
    )
    proposal_value = context.get("proposal", {})
    proposal_sha256 = context.get("proposal_sha256")
    proposal_event_id = context.get("proposal_event_id")
    parent_node_id = context.get("parent_node_id")
    base_revision = context.get("base_revision")
    base_plan_sha256 = context.get("base_plan_sha256")
    decision_report_sha256 = context.get("decision_report_sha256")
    result_revision = context.get("result_revision")
    result_plan_sha256 = context.get("result_plan_sha256")
    effective_plan = context.get("effective_plan")
    trace_value = context.get("trace", {})
    trace_report = context.get("trace_report", {})
    declared_revisions = context.get("declared_revisions", {})
    if context.get("decision_code") != "REVISION_BOUND":
        _issue(issues, "decision:not_revision_bound")
    if type(result_revision) is not int or result_revision != base_revision + 1:
        _issue(issues, "binding:result_revision_invalid")
    for label, digest in (
        ("base_plan", base_plan_sha256),
        ("result_plan", result_plan_sha256),
    ):
        if not isinstance(digest, str) or not _SHA256.match(digest):
            _issue(issues, "binding:" + label + "_sha256_invalid")

    if declared_revisions.get(result_revision) != result_plan_sha256:
        _issue(issues, "binding:trace_result_plan_mismatch")

    entries, chain_issues = _read_chain(ledger_path)
    for item in chain_issues:
        _issue(issues, item)
    decision_records = [
        entry.get("record")
        for entry in entries
        if isinstance(entry.get("record"), Mapping)
        and entry["record"].get("schema") == DEEPENING_DECISION_SCHEMA
        and entry["record"].get("run_id") == trace_value.get("run_id")
        and entry["record"].get("proposal_sha256") == proposal_sha256
    ]
    integration_duplicate = any(
        isinstance(entry.get("record"), Mapping)
        and entry["record"].get("schema") == DEEPENING_INTEGRATION_SCHEMA
        and entry["record"].get("run_id") == trace_value.get("run_id")
        and entry["record"].get("proposal_sha256") == proposal_sha256
        for entry in entries
    )
    if integration_duplicate:
        _issue(issues, "integration:duplicate_record")
    if len(decision_records) != 1:
        _issue(issues, "integration:decision_record_missing_or_ambiguous")
        decision_record: Mapping[str, Any] = {}
    else:
        decision_record = decision_records[0]
        if not _record_seal_valid(decision_record):
            _issue(issues, "integration:decision_record_seal_invalid")
        if decision_record.get("decision", {}).get("report_sha256") != decision_report_sha256:
            _issue(issues, "integration:decision_report_mismatch")
        if decision_record.get("result_plan", {}).get("revision") != result_revision:
            _issue(issues, "integration:result_revision_mismatch")
        if decision_record.get("result_plan", {}).get("plan_sha256") != result_plan_sha256:
            _issue(issues, "integration:result_plan_mismatch")

    sublane_node_ids = sorted(
        str(item.get("proposed_id"))
        for item in proposal_value.get("children", [])
        if isinstance(item, Mapping) and isinstance(item.get("proposed_id"), str)
    )
    join_node_id = str(parent_node_id) + ".join"
    measured_node_ids = set(sublane_node_ids + [join_node_id])
    effective_workers = (
        effective_plan.get("workers") if isinstance(effective_plan, Mapping) else None
    )
    effective_worker_ids = {
        str(item.get("id"))
        for item in effective_workers or []
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    if not isinstance(effective_workers, list) or not measured_node_ids <= effective_worker_ids:
        _issue(issues, "integration:effective_plan_nodes_mismatch")
    events = [
        item
        for item in trace_value.get("events", [])
        if isinstance(item, Mapping)
        and item.get("plan_revision") == result_revision
        and item.get("node_id") in measured_node_ids
    ]
    join_starts = [
        item
        for item in events
        if item.get("node_id") == join_node_id and item.get("type") == "start"
    ]
    join_finishes = [
        item
        for item in events
        if item.get("node_id") == join_node_id and item.get("type") == "finish"
    ]
    if len(join_starts) > 1 or len(join_finishes) > 1:
        _issue(issues, "integration:join_window_ambiguous")
    missing_join_reason = (
        "join_start_missing"
        if not join_starts
        else "join_finish_missing" if not join_finishes else None
    )
    join_wall_ms = _milliseconds(
        join_starts[0].get("at") if len(join_starts) == 1 else None,
        join_finishes[0].get("at") if len(join_finishes) == 1 else None,
    )
    if missing_join_reason is None and join_wall_ms is None:
        _issue(issues, "integration:join_wall_time_invalid")

    integration_events = sum(
        1
        for item in events
        if item.get("node_id") == join_node_id and item.get("type") in {"consume", "integrate"}
    )
    verification_events = sum(
        1
        for item in events
        if item.get("node_id") == join_node_id and item.get("type") == "verify"
    )
    starts_by_node = {
        node_id: sum(1 for item in events if item.get("node_id") == node_id and item.get("type") == "start")
        for node_id in measured_node_ids
    }
    rework_events = sum(max(0, count - 1) for count in starts_by_node.values())
    released = {
        ref
        for item in events
        if item.get("node_id") in set(sublane_node_ids) and item.get("type") == "release"
        for ref in item.get("artifact_refs", [])
        if isinstance(ref, str)
    }
    integrated = {
        ref
        for item in events
        if item.get("node_id") == join_node_id and item.get("type") in {"consume", "integrate"}
        for ref in item.get("artifact_refs", [])
        if isinstance(ref, str)
    }
    orphaned_artifacts = len(released - integrated)
    if issues:
        return _deepening_record_report(issues)

    if missing_join_reason is None:
        integration_cost = {
            "join_wall_time": _observed_ms(join_wall_ms),
            "integration_events": _count_measurement(integration_events, "events"),
            "verification_events": _count_measurement(verification_events, "events"),
            "rework_events": _count_measurement(rework_events, "events"),
            "orphaned_artifacts": _count_measurement(orphaned_artifacts, "artifacts"),
        }
    else:
        integration_cost = {
            "join_wall_time": _unobserved_ms("unknown", missing_join_reason),
            "integration_events": _count_measurement(None, "events", missing_join_reason),
            "verification_events": _count_measurement(None, "events", missing_join_reason),
            "rework_events": _count_measurement(None, "events", missing_join_reason),
            "orphaned_artifacts": _count_measurement(None, "artifacts", missing_join_reason),
        }

    record_core = {
        "schema": DEEPENING_INTEGRATION_SCHEMA,
        "run_id": trace_value.get("run_id"),
        "proposal_event_id": proposal_event_id,
        "parent_node_id": parent_node_id,
        "proposal_sha256": proposal_sha256,
        "decision_record_sha256": decision_record.get("record_sha256"),
        "result_plan": {"revision": result_revision, "plan_sha256": result_plan_sha256},
        "sublane_node_ids": sublane_node_ids,
        "join_node_id": join_node_id,
        "integration_cost": integration_cost,
        "trace_sha256": trace_report.get("trace_sha256"),
    }
    record = _seal_measurement(record_core)
    receipt = append_trace_record(ledger_path, record)
    return _deepening_record_report([], record=record, chain_receipt=receipt)


def _summarize_timing_metrics(metrics: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    values = sorted(
        int(item["value_ms"])
        for item in metrics
        if item.get("status") == "observed" and type(item.get("value_ms")) is int
    )
    unknown: dict[str, int] = {}
    not_applicable: dict[str, int] = {}
    for item in metrics:
        target = (
            unknown
            if item.get("status") == "unknown"
            else not_applicable if item.get("status") == "not_applicable" else None
        )
        if target is not None:
            reason = str(item.get("reason") or "unspecified")
            target[reason] = target.get(reason, 0) + 1
    median: int | float | None = statistics.median(values) if values else None
    if isinstance(median, float) and median.is_integer():
        median = int(median)
    return {
        "observed_count": len(values),
        "unknown": dict(sorted(unknown.items())),
        "not_applicable": dict(sorted(not_applicable.items())),
        "min_ms": values[0] if values else None,
        "median_ms": median,
        "max_ms": values[-1] if values else None,
    }


def summarize_deepening(ledger_path: str | Path) -> dict[str, Any]:
    """Verify and summarize deepening measurements from the trace ledger."""

    entries, chain_issues = _read_chain(ledger_path)
    issues = list(chain_issues)
    records = [
        entry.get("record")
        for entry in entries
        if isinstance(entry.get("record"), Mapping)
        and entry["record"].get("schema")
        in {DEEPENING_DECISION_SCHEMA, DEEPENING_INTEGRATION_SCHEMA}
    ]
    for index, record in enumerate(records):
        for item in _validate_deepening_record(record):
            _issue(issues, "records[%d]:%s" % (index, item))

    decision_records = [
        item for item in records if item.get("schema") == DEEPENING_DECISION_SCHEMA
    ]
    integration_records = [
        item for item in records if item.get("schema") == DEEPENING_INTEGRATION_SCHEMA
    ]
    decisions_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
    for record in decision_records:
        key = (str(record.get("run_id")), str(record.get("proposal_sha256")))
        if key in decisions_by_key:
            _issue(issues, "summary:duplicate_decision:" + ":".join(key))
        else:
            decisions_by_key[key] = record
    integrations_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
    for record in integration_records:
        key = (str(record.get("run_id")), str(record.get("proposal_sha256")))
        if key in integrations_by_key:
            _issue(issues, "summary:duplicate_integration:" + ":".join(key))
            continue
        integrations_by_key[key] = record
        decision_record = decisions_by_key.get(key)
        if decision_record is None:
            _issue(issues, "summary:integration_without_decision:" + ":".join(key))
            continue
        if decision_record.get("decision", {}).get("outcome") != "accepted":
            _issue(issues, "summary:integration_for_denied_proposal:" + ":".join(key))
        if record.get("decision_record_sha256") != decision_record.get("record_sha256"):
            _issue(issues, "summary:decision_record_sha256_mismatch:" + ":".join(key))
        if record.get("result_plan") != {
            "revision": decision_record.get("result_plan", {}).get("revision"),
            "plan_sha256": decision_record.get("result_plan", {}).get("plan_sha256"),
        }:
            _issue(issues, "summary:result_plan_mismatch:" + ":".join(key))

    accepted_keys = {
        key
        for key, record in decisions_by_key.items()
        if record.get("decision", {}).get("outcome") == "accepted"
    }
    accepted_without_integration = sorted(accepted_keys - set(integrations_by_key))
    decision_latencies = [
        item.get("decision_latency", {})
        for item in decision_records
        if isinstance(item.get("decision_latency"), Mapping)
    ]
    round_trips = [
        item.get("replan_round_trip", {})
        for item in decision_records
        if isinstance(item.get("replan_round_trip"), Mapping)
    ]
    integration_wall_times = [
        item.get("integration_cost", {}).get("join_wall_time", {})
        for item in integration_records
        if isinstance(item.get("integration_cost"), Mapping)
        and isinstance(item.get("integration_cost", {}).get("join_wall_time"), Mapping)
    ]
    integration_wall_times.extend(
        {
            "status": "unknown",
            "value_ms": None,
            "reason": "integration_record_missing",
        }
        for _ in accepted_without_integration
    )
    counts = {
        "decision_records": len(decision_records),
        "accepted": len(accepted_keys),
        "denied": sum(
            1
            for item in decision_records
            if item.get("decision", {}).get("outcome") == "denied"
        ),
        "deferred": sum(
            1
            for item in decision_records
            if item.get("decision", {}).get("outcome") == "deferred"
        ),
        "integration_records": len(integration_records),
        "accepted_without_integration": len(accepted_without_integration),
    }
    return _report(
        DEEPENING_SUMMARY_SCHEMA,
        issues,
        {
            "counts": counts,
            "measurements": {
                "decision_latency": _summarize_timing_metrics(decision_latencies),
                "replan_round_trip": _summarize_timing_metrics(round_trips),
                "integration_wall_time": _summarize_timing_metrics(integration_wall_times),
            },
            "chain_length": len(entries),
            "chain_last_sha256": entries[-1]["record_sha256"] if entries else None,
        },
    )


def _record_sha(seq: int, prev_sha256: str | None, record: Any) -> str:
    return _sha256({"seq": seq, "prev_sha256": prev_sha256, "record": record})


def _validate_timing_metric(
    value: Any,
    label: str,
    issues: list[str],
    *,
    allow_not_applicable: bool,
) -> None:
    if not _exact(value, {"status", "value_ms", "reason"}, label, issues):
        return
    status = value.get("status")
    duration = value.get("value_ms")
    reason = value.get("reason")
    if status == "observed":
        if type(duration) is not int or duration < 0 or reason is not None:
            _issue(issues, label + ":observed_invalid")
    elif status == "unknown":
        if duration is not None or reason not in {
            "checkpoint_event_missing",
            "decision_event_missing",
            "effective_revision_event_missing",
            "join_start_missing",
            "join_finish_missing",
        }:
            _issue(issues, label + ":unknown_invalid")
    elif status == "not_applicable" and allow_not_applicable:
        if duration is not None or reason not in {"proposal_not_bound", "proposal_deferred"}:
            _issue(issues, label + ":not_applicable_invalid")
    else:
        _issue(issues, label + ":status_invalid")


def _validate_count_metric(
    value: Any,
    label: str,
    issues: list[str],
    *,
    unit: str,
) -> None:
    if not _exact(value, {"status", "value", "unit", "reason"}, label, issues):
        return
    if value.get("unit") != unit:
        _issue(issues, label + ":unit_invalid")
    if value.get("status") == "observed":
        if type(value.get("value")) is not int or value.get("value") < 0 or value.get("reason") is not None:
            _issue(issues, label + ":observed_invalid")
    elif value.get("status") == "unknown":
        if value.get("value") is not None or value.get("reason") not in {
            "join_start_missing",
            "join_finish_missing",
        }:
            _issue(issues, label + ":unknown_invalid")
    else:
        _issue(issues, label + ":status_invalid")


def _validate_deepening_record(record: Any) -> list[str]:
    issues: list[str] = []
    if not isinstance(record, Mapping):
        return ["deepening_record:not_object"]
    schema = record.get("schema")
    if schema == DEEPENING_DECISION_SCHEMA:
        fields = {
            "schema",
            "run_id",
            "proposal_event_id",
            "parent_node_id",
            "proposal_sha256",
            "base_plan",
            "decision",
            "result_plan",
            "decision_latency",
            "replan_round_trip",
            "trace_sha256",
            "record_sha256",
        }
        _exact(record, fields, "deepening_record", issues)
        if not _bounded_text(record.get("run_id"), 255):
            _issue(issues, "deepening_record:run_id_invalid")
        for field in ("proposal_event_id", "parent_node_id"):
            if not _bounded_text(record.get(field), 255):
                _issue(issues, "deepening_record:" + field + "_invalid")
        for field in ("proposal_sha256", "trace_sha256"):
            if not isinstance(record.get(field), str) or not _SHA256.match(record[field]):
                _issue(issues, "deepening_record:" + field + "_invalid")

        base_plan = record.get("base_plan")
        if _exact(base_plan, {"revision", "plan_sha256"}, "deepening_record.base_plan", issues):
            if type(base_plan.get("revision")) is not int or base_plan.get("revision") < 1:
                _issue(issues, "deepening_record.base_plan:revision_invalid")
            if not isinstance(base_plan.get("plan_sha256"), str) or not _SHA256.match(base_plan["plan_sha256"]):
                _issue(issues, "deepening_record.base_plan:plan_sha256_invalid")

        decision = record.get("decision")
        if _exact(decision, {"outcome", "code", "report_sha256"}, "deepening_record.decision", issues):
            if decision.get("outcome") not in {"accepted", "denied", "deferred"}:
                _issue(issues, "deepening_record.decision:outcome_invalid")
            if not _bounded_text(decision.get("code"), 255):
                _issue(issues, "deepening_record.decision:code_invalid")
            if not isinstance(decision.get("report_sha256"), str) or not _SHA256.match(decision["report_sha256"]):
                _issue(issues, "deepening_record.decision:report_sha256_invalid")

        result_plan = record.get("result_plan")
        if _exact(
            result_plan,
            {"status", "revision", "plan_sha256", "reason"},
            "deepening_record.result_plan",
            issues,
        ):
            outcome = decision.get("outcome") if isinstance(decision, Mapping) else None
            if outcome == "accepted":
                if (
                    result_plan.get("status") != "observed"
                    or type(result_plan.get("revision")) is not int
                    or result_plan.get("revision") < 1
                    or not isinstance(result_plan.get("plan_sha256"), str)
                    or not _SHA256.match(result_plan["plan_sha256"])
                    or result_plan.get("reason") is not None
                ):
                    _issue(issues, "deepening_record.result_plan:accepted_invalid")
            elif outcome == "denied" and result_plan != {
                "status": "not_applicable",
                "revision": None,
                "plan_sha256": None,
                "reason": "proposal_not_bound",
            }:
                _issue(issues, "deepening_record.result_plan:denied_invalid")
            elif outcome == "deferred" and result_plan != {
                "status": "not_applicable",
                "revision": None,
                "plan_sha256": None,
                "reason": "proposal_deferred",
            }:
                _issue(issues, "deepening_record.result_plan:deferred_invalid")

        _validate_timing_metric(
            record.get("decision_latency"),
            "deepening_record.decision_latency",
            issues,
            allow_not_applicable=False,
        )
        _validate_timing_metric(
            record.get("replan_round_trip"),
            "deepening_record.replan_round_trip",
            issues,
            allow_not_applicable=True,
        )
    elif schema == DEEPENING_INTEGRATION_SCHEMA:
        fields = {
            "schema",
            "run_id",
            "proposal_event_id",
            "parent_node_id",
            "proposal_sha256",
            "decision_record_sha256",
            "result_plan",
            "sublane_node_ids",
            "join_node_id",
            "integration_cost",
            "trace_sha256",
            "record_sha256",
        }
        _exact(record, fields, "deepening_record", issues)
        if not _bounded_text(record.get("run_id"), 255):
            _issue(issues, "deepening_record:run_id_invalid")
        for field in ("proposal_event_id", "parent_node_id", "join_node_id"):
            if not _bounded_text(record.get(field), 255):
                _issue(issues, "deepening_record:" + field + "_invalid")
        if (
            isinstance(record.get("parent_node_id"), str)
            and record.get("join_node_id") != record["parent_node_id"] + ".join"
        ):
            _issue(issues, "deepening_record:join_node_id_mismatch")
        for field in ("proposal_sha256", "decision_record_sha256", "trace_sha256"):
            if not isinstance(record.get(field), str) or not _SHA256.match(record[field]):
                _issue(issues, "deepening_record:" + field + "_invalid")
        result_plan = record.get("result_plan")
        if _exact(result_plan, {"revision", "plan_sha256"}, "deepening_record.result_plan", issues):
            if type(result_plan.get("revision")) is not int or result_plan.get("revision") < 1:
                _issue(issues, "deepening_record.result_plan:revision_invalid")
            if not isinstance(result_plan.get("plan_sha256"), str) or not _SHA256.match(result_plan["plan_sha256"]):
                _issue(issues, "deepening_record.result_plan:plan_sha256_invalid")
        sublanes = record.get("sublane_node_ids")
        if (
            not isinstance(sublanes, list)
            or not sublanes
            or any(not _bounded_text(item, 255) for item in sublanes)
            or sublanes != sorted(set(sublanes))
        ):
            _issue(issues, "deepening_record:sublane_node_ids_invalid")
        cost = record.get("integration_cost")
        cost_fields = {
            "join_wall_time",
            "integration_events",
            "verification_events",
            "rework_events",
            "orphaned_artifacts",
        }
        if _exact(cost, cost_fields, "deepening_record.integration_cost", issues):
            _validate_timing_metric(
                cost.get("join_wall_time"),
                "deepening_record.integration_cost.join_wall_time",
                issues,
                allow_not_applicable=False,
            )
            for field, unit in (
                ("integration_events", "events"),
                ("verification_events", "events"),
                ("rework_events", "events"),
                ("orphaned_artifacts", "artifacts"),
            ):
                _validate_count_metric(
                    cost.get(field),
                    "deepening_record.integration_cost." + field,
                    issues,
                    unit=unit,
                )
            statuses = {
                item.get("status")
                for item in cost.values()
                if isinstance(item, Mapping)
            }
            if len(statuses) != 1:
                _issue(issues, "deepening_record.integration_cost:status_mismatch")
    else:
        return issues

    if not _record_seal_valid(record):
        _issue(issues, "deepening_record:record_sha256_invalid")
    return sorted(set(issues))


def validate_deepening_measurement_record(record: Any) -> dict[str, Any]:
    """Validate one sealed Issue 104 measurement through a public seam.

    The trace ledger previously used this validator only while reading a
    complete chain.  Deepening policy needs the same closed validation over
    explicitly supplied records, without accepting an unknown record schema
    merely because the internal dispatcher has no branch for it.
    """

    issues: list[str] = []
    supplied_schema = record.get("schema") if isinstance(record, Mapping) else None
    supported_schemas = {
        DEEPENING_DECISION_SCHEMA,
        DEEPENING_INTEGRATION_SCHEMA,
    }
    record_schema = supplied_schema if supplied_schema in supported_schemas else None
    if record_schema is None:
        _issue(issues, "deepening_record:schema_unsupported")
    else:
        for item in _validate_deepening_record(record):
            _issue(issues, item)
    record_sha256 = (
        record.get("record_sha256")
        if not issues and isinstance(record, Mapping)
        else None
    )
    return _report(
        DEEPENING_MEASUREMENT_VALIDATION_SCHEMA,
        issues,
        {
            "record_schema": record_schema,
            "record_sha256": record_sha256,
        },
    )


def _read_chain(path: str | Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Read every line and verify the append-only chain without repairs.

    A missing file is an empty (valid) chain.  Any non-object line, non-JSON
    line, out-of-order sequence, broken prev link, or record_sha256 that does
    not match its (seq, prev_sha256, record) material fails closed with
    chain:broken:SEQ at the first such line, and the remainder is neither
    repaired nor inspected further.  When the first failing line is also the
    final non-empty line the failure is reported as chain:torn_tail:SEQ
    instead: every prior line verified, so the break is consistent with an
    append crashed mid-write, which an operator investigates differently
    from interior corruption.  Both classifications fail closed identically
    — no entries, no truncation, no repair.
    """

    target = Path(path)
    if not target.exists():
        return [], []
    issues: list[str] = []
    entries: list[dict[str, Any]] = []
    prev_sha256: str | None = None
    raw_lines = target.read_text(encoding="utf-8").splitlines()
    populated = [index for index, line in enumerate(raw_lines) if line.strip()]
    last_populated = populated[-1] if populated else -1

    def _break(seq: int, index: int) -> None:
        kind = "torn_tail" if index == last_populated else "broken"
        _issue(issues, "chain:%s:%d" % (kind, seq))

    for index, line in enumerate(raw_lines):
        seq = index + 1
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            _break(seq, index)
            break
        if not isinstance(entry, Mapping) or set(entry) != _CHAIN_LINE_KEYS:
            _break(seq, index)
            break
        if entry.get("seq") != seq or isinstance(entry.get("seq"), bool):
            _break(seq, index)
            break
        recorded_prev = entry.get("prev_sha256")
        if seq == 1:
            if recorded_prev is not None:
                _break(seq, index)
                break
        elif (
            not isinstance(recorded_prev, str)
            or not _SHA256.match(recorded_prev)
            or recorded_prev != prev_sha256
        ):
            _break(seq, index)
            break
        record = entry.get("record")
        if not isinstance(record, Mapping):
            _break(seq, index)
            break
        recorded_sha = entry.get("record_sha256")
        if (
            not isinstance(recorded_sha, str)
            or not _SHA256.match(recorded_sha)
            or recorded_sha != _record_sha(seq, recorded_prev, record)
        ):
            _break(seq, index)
            break
        prev_sha256 = recorded_sha
        entries.append(dict(entry))
    if issues:
        return [], issues
    return entries, issues


def append_trace_record(path: str | Path, record: Any) -> dict[str, Any]:
    """Append one finished-run summary to the append-only chain.

    The existing chain is verified in full before any write; any tamper
    anywhere is refused with the broken sequence reported and the file left
    byte-for-byte untouched.  Only the exact path the caller passes is
    written, in append mode only.
    """

    if not isinstance(record, Mapping):
        raise OrchDorkTraceError("record must be a mapping")
    record_issues = _validate_deepening_record(record)
    if record_issues:
        raise OrchDorkTraceError(record_issues[0])
    entries, issues = _read_chain(path)
    if issues:
        raise OrchDorkTraceError(issues[0])
    seq = len(entries) + 1
    prev_sha256 = entries[-1]["record_sha256"] if entries else None
    record_sha256 = _record_sha(seq, prev_sha256, record)
    line = {
        "seq": seq,
        "prev_sha256": prev_sha256,
        "record": dict(record),
        "record_sha256": record_sha256,
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(
            line,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    try:
        descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
        )
        try:
            written = os.write(descriptor, encoded)
            if written != len(encoded):
                raise OrchDorkTraceError("chain append was incomplete")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OrchDorkTraceError:
        raise
    except OSError as exc:
        raise OrchDorkTraceError("chain append failed: %s" % exc) from exc
    return {
        "schema": CHAIN_SCHEMA,
        "status": "PASS",
        "issues": [],
        "seq": seq,
        "prev_sha256": prev_sha256,
        "record_sha256": record_sha256,
        "chain_length": len(entries) + 1,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def read_trace_chain(path: str | Path) -> dict[str, Any]:
    """Read and verify the append-only chain of finished-run summaries.

    Returns a report with status, length, last_sha256, and issues.  A
    missing file is an empty, passing chain: there is nothing to verify, so
    there is nothing to fail.
    """

    entries, issues = _read_chain(path)
    return {
        "schema": CHAIN_SCHEMA,
        "status": "PASS" if not issues else "FAIL",
        "length": len(entries),
        "last_sha256": entries[-1]["record_sha256"] if entries else None,
        "issues": issues,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def _read_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("cannot read JSON: %s" % path) from exc


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point for trace and deepening operations."""

    parser = argparse.ArgumentParser(
        description="Provider-free Orch Dork run-trace instrumentation"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    validate_p = sub.add_parser("validate", help="validate a run trace JSON file")
    validate_p.add_argument("trace")
    uptake_p = sub.add_parser("uptake", help="compute uptake for a run trace JSON file")
    uptake_p.add_argument("trace")
    append_p = sub.add_parser("append", help="append one finished-run summary")
    append_p.add_argument("chain")
    append_p.add_argument("record")
    read_p = sub.add_parser("read", help="read and verify the append-only chain")
    read_p.add_argument("chain")
    deepening_p = sub.add_parser(
        "record-deepening",
        help="derive and append one typed deepening measurement",
    )
    deepening_p.add_argument("chain")
    deepening_p.add_argument("evidence")
    summary_p = sub.add_parser(
        "summarize-deepening",
        help="summarize typed deepening measurements in a trace chain",
    )
    summary_p.add_argument("chain")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            result = validate_run_trace(_read_json(args.trace))
        elif args.command == "uptake":
            result = compute_uptake(_read_json(args.trace))
        elif args.command == "append":
            result = append_trace_record(args.chain, _read_json(args.record))
        elif args.command == "read":
            result = read_trace_chain(args.chain)
        elif args.command == "record-deepening":
            result = record_deepening(_read_json(args.evidence), args.chain)
        else:
            result = summarize_deepening(args.chain)
    except (OrchDorkTraceError, ValueError, OSError) as exc:
        print(
            json.dumps(
                {
                    "schema": CHAIN_SCHEMA,
                    "status": "REFUSE",
                    "issues": [str(exc)],
                    "provider_free": True,
                    "model_calls": 0,
                    "hosted_calls": 0,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
