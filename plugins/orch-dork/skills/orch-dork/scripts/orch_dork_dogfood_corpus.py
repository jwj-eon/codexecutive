#!/usr/bin/env python3
"""Issue 77: longitudinal dogfood corpus for real Orch Dork runs.

Every existing observer answers *what happened mechanically*: timing, usage,
custody, spawn proofs, lane graphs. Nothing records whether the run was any
good. The run-source-catalog/v1 schema is per-ticket, so nothing accumulates
across runs either. This module closes both gaps with the cheapest honest
instrument: a small human verdict appended to an immutable JSONL log, joined to
the compact mechanical facts already produced by attempt-observation/v1.

Design constraints, all enforced here rather than by convention:

* Not a gate. Nothing in this module admits, refuses, or scores a run. It
  records outcomes so a later, separately authorized analysis can look at them.
* Not training-by-tuning. Records are immutable and a run may be labeled once.
  A changed opinion is appended as a correction that cites the original; the
  original is never rewritten or removed. There is deliberately no "expected"
  or "target" field to tune a prompt against.
* Label before analysis. Each record declares which aggregate summary its
  labeler had already seen. A record written with none is blind. Summaries
  count blind records separately, so verdicts shaped by a hoped-for aggregate
  cannot silently pass as independent evidence.
* Provider-free. Zero model calls, zero credentials, zero network.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

RECORD_SCHEMA = "orch-dork/dogfood-record/v1"
MARKER_SCHEMA = "orch-dork/dogfood-analysis-marker/v1"
SUMMARY_SCHEMA = "orch-dork/dogfood-summary/v1"
CORPUS_VERSION = "dogfood-corpus/1.0"
OBSERVATION_SCHEMA = "orch-dork/attempt-observation/v1"
SPINE_SCHEMA = "orch-dork/dogfood-run-spine/v1"
SPINE_CORRECTION_SCHEMA = "orch-dork/dogfood-run-spine-correction/v1"

ZERO_DIGEST = "0" * 64

# The three cheap fields. Each is a closed set so a corpus stays countable, and
# each is answerable in well under a minute by whoever ran the work.
CLASSES = ("atomic", "orchestrated", "refused")
CLASSIFICATION_VERDICTS = (
    "agree",
    "should_have_been_atomic",
    "should_have_been_orchestrated",
    "should_have_been_refused",
    "unclear",
)
PLAN_VERDICTS = ("good", "wrong_split", "missed_coupling", "over_split", "not_applicable")
OUTCOMES = ("shipped", "needed_rework", "abandoned")

# Free text is expected to be the highest-value early field: it catches failure
# modes nobody anticipated well enough to enumerate. Bound it so the corpus
# stays a log rather than a document store.
MAX_NOTE_CHARS = 2000

# Aggregates below this are noise. The threshold is advisory in the sense that
# the counts are still returned, but aggregate_reportable stays false.
DEFAULT_MIN_RECORDS = 20

_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_SECRET = re.compile(
    r"(?:prompt|message|body|reasoning|credential|password|secret|token|"
    r"api[_-]?key|private[_-]?key|cookie|raw[_-]?(?:file|session|trace|record))",
    re.IGNORECASE,
)


class DogfoodCorpusError(ValueError):
    """Raised for any record, corpus, or chain that fails closed."""


def canonical_json(value: Any) -> str:
    """Return the canonical JSON encoding shared by dogfood artifacts."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def content_digest(value: Any) -> str:
    """Hash an artifact exactly as supplied, without chain-field rewriting."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _digest(value: Mapping[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "entry_sha256"}
    return content_digest(payload)


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.match(value):
        raise DogfoodCorpusError(f"{field} must be a bounded identifier")
    return value


def validate_timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _TIMESTAMP.match(value):
        raise DogfoodCorpusError(f"{field} must be an ISO 8601 UTC timestamp ending in Z")
    return value


def _choice(value: Any, allowed: Sequence[str], field: str) -> str:
    if value not in allowed:
        raise DogfoodCorpusError(f"{field} must be one of {', '.join(allowed)}")
    return str(value)


def reject_secret_fields(value: Any, path: str = "record") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and _SECRET.search(key):
                raise DogfoodCorpusError(f"{path}.{key} looks like private session or credential material")
            reject_secret_fields(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            reject_secret_fields(item, f"{path}[{index}]")


def compact_observation(report: Mapping[str, Any]) -> dict[str, Any]:
    """Join the mechanical facts worth keeping from one attempt observation.

    Only compact, already-public fields are copied. The observer itself refuses
    prompts, messages, and reasoning, and this function narrows further to the
    handful of facts a longitudinal question would actually ask about.
    """

    if not isinstance(report, Mapping) or report.get("schema") != OBSERVATION_SCHEMA:
        raise DogfoodCorpusError(f"observation schema must be {OBSERVATION_SCHEMA}")
    graph = report.get("graph") if isinstance(report.get("graph"), Mapping) else {}
    children = graph.get("children") if isinstance(graph.get("children"), list) else []
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    timing = report.get("timing") if isinstance(report.get("timing"), Mapping) else {}
    usage = report.get("usage") if isinstance(report.get("usage"), Mapping) else {}
    checks = report.get("checks") if isinstance(report.get("checks"), Mapping) else {}
    root = graph.get("root") if isinstance(graph.get("root"), Mapping) else {}
    observation = {
        "attempt_id": report.get("attempt_id"),
        "binding_status": report.get("binding_status"),
        "status": report.get("status"),
        "root_thread_id": root.get("thread_id"),
        "lane_count": len(children),
        "edge_count": len(edges),
        "timing_status": timing.get("status"),
        "usage_status": usage.get("status"),
        "checks_count": checks.get("count", 0),
        "checks_passed": checks.get("passed", 0),
    }
    reject_secret_fields(observation, "observation")
    return observation


def validate_verdict_values(
    *,
    actual_class: Any,
    classification_verdict: Any,
    plan_verdict: Any,
    outcome: Any,
) -> dict[str, str]:
    """Validate the shared verdict vocabulary and applicability contract."""

    values = {
        "actual_class": _choice(actual_class, CLASSES, "actual_class"),
        "classification_verdict": _choice(
            classification_verdict,
            CLASSIFICATION_VERDICTS,
            "classification_verdict",
        ),
        "plan_verdict": _choice(plan_verdict, PLAN_VERDICTS, "plan_verdict"),
        "outcome": _choice(outcome, OUTCOMES, "outcome"),
    }
    if values["classification_verdict"] == (
        f"should_have_been_{values['actual_class']}"
    ):
        raise DogfoodCorpusError("classification_verdict contradicts actual_class")
    if (
        values["actual_class"] in ("atomic", "refused")
        and values["plan_verdict"] != "not_applicable"
    ):
        raise DogfoodCorpusError(
            "plan_verdict must be not_applicable when no plan was executed"
        )
    if (
        values["actual_class"] == "orchestrated"
        and values["plan_verdict"] == "not_applicable"
    ):
        raise DogfoodCorpusError(
            "plan_verdict is applicable for an orchestrated run"
        )
    return values


def build_record(
    *,
    run_key: str,
    recorded_at: str,
    ticket_key: str,
    actual_class: str,
    classification_verdict: str,
    plan_verdict: str,
    outcome: str,
    labeler: str,
    host: str | None = None,
    note: str | None = None,
    analysis_digest_seen: str | None = None,
    observation: Mapping[str, Any] | None = None,
    corrects: str | None = None,
    correction_reason: str | None = None,
) -> dict[str, Any]:
    """Validate one verdict and return the canonical record body."""

    verdict = validate_verdict_values(
        actual_class=actual_class,
        classification_verdict=classification_verdict,
        plan_verdict=plan_verdict,
        outcome=outcome,
    )
    record: dict[str, Any] = {
        "schema": RECORD_SCHEMA,
        "kind": "correction" if corrects is not None else "record",
        "run_key": _identifier(run_key, "run_key"),
        "recorded_at": validate_timestamp(recorded_at, "recorded_at"),
        "ticket_key": _identifier(ticket_key, "ticket_key"),
        **verdict,
        "labeler": _identifier(labeler, "labeler"),
    }

    # Each host keeps its own independent chain, because the sealed sequence
    # cannot survive two corpora being concatenated.  Recording which host
    # produced a run is therefore the only way a later cross-host reader can
    # keep provenance while summarizing each chain separately.  It is optional
    # and null-by-default so existing records stay valid unchanged.
    record["host"] = _identifier(host, "host") if host is not None else None

    if note is not None:
        if not isinstance(note, str) or not note.strip():
            raise DogfoodCorpusError("note must be non-empty text when present")
        if len(note) > MAX_NOTE_CHARS:
            raise DogfoodCorpusError(f"note must be at most {MAX_NOTE_CHARS} characters")
        record["note"] = note

    if analysis_digest_seen is not None:
        if not isinstance(analysis_digest_seen, str) or not _SHA256.match(analysis_digest_seen):
            raise DogfoodCorpusError("analysis_digest_seen must be a sha256 digest or null")
        record["analysis_digest_seen"] = analysis_digest_seen
    else:
        record["analysis_digest_seen"] = None
    record["blind"] = record["analysis_digest_seen"] is None

    if observation is not None:
        if not isinstance(observation, Mapping):
            raise DogfoodCorpusError("observation must be a mapping")
        reject_secret_fields(observation, "observation")
        record["observation"] = dict(observation)

    if corrects is not None:
        record["corrects"] = _identifier(corrects, "corrects")
        if not isinstance(correction_reason, str) or not correction_reason.strip():
            raise DogfoodCorpusError("correction_reason is required for a correction")
        if len(correction_reason) > MAX_NOTE_CHARS:
            raise DogfoodCorpusError(f"correction_reason must be at most {MAX_NOTE_CHARS} characters")
        record["correction_reason"] = correction_reason
    elif correction_reason is not None:
        raise DogfoodCorpusError("correction_reason requires corrects")

    reject_secret_fields(record)
    return record


def _seal(
    entry: Mapping[str, Any],
    *,
    sequence: int,
    prev_sha256: str,
    corpus_version: str = CORPUS_VERSION,
) -> dict[str, Any]:
    sealed = dict(entry)
    sealed["sequence"] = sequence
    sealed["prev_sha256"] = prev_sha256
    sealed["corpus_version"] = corpus_version
    sealed["entry_sha256"] = _digest(sealed)
    return sealed


def append_entry(
    path: str | Path,
    entry: Mapping[str, Any],
    *,
    corpus_version: str = CORPUS_VERSION,
) -> dict[str, Any]:
    """Seal one already-validated entry onto the end of the chain.

    This is the single write primitive every entry kind goes through, so a new
    kind cannot quietly acquire a second, weaker sealing path. It performs no
    kind-specific validation; callers own that and must run it first.
    """

    entries = read_corpus(path)
    previous = entries[-1]["entry_sha256"] if entries else ZERO_DIGEST
    sealed = _seal(
        entry,
        sequence=len(entries),
        prev_sha256=str(previous),
        corpus_version=_identifier(corpus_version, "corpus_version"),
    )
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = (canonical_json(sealed) + "\n").encode("utf-8")
    try:
        descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
        )
        try:
            written = os.write(descriptor, encoded)
            if written != len(encoded):
                raise DogfoodCorpusError("corpus append was incomplete")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except DogfoodCorpusError:
        raise
    except OSError as exc:
        raise DogfoodCorpusError("corpus append failed: " + str(exc)) from exc
    return sealed


def read_corpus(
    path: str | Path, *, expected_host: str | None = None
) -> list[dict[str, Any]]:
    """Read every entry and verify the append-only chain, or fail closed.

    A failure on the final populated line is reported as a torn tail —
    every prior entry verified, so the break is consistent with an append
    crashed mid-write — while an interior failure keeps its specific
    message. Both refuse identically: no entries, no truncation, no repair.

    When expected_host is supplied the chain origin is pinned: the genesis
    of a prev-hash chain proves ordering, not provenance, so the first
    record's sealed host is the real trust anchor and a mismatch refuses
    fail-closed. An absent file remains an empty valid chain.
    """

    target = Path(path)
    if not target.exists():
        return []
    entries: list[dict[str, Any]] = []
    previous = ZERO_DIGEST
    lines = target.read_text(encoding="utf-8").splitlines()
    populated = [index for index, line in enumerate(lines) if line.strip()]
    last_populated = populated[-1] if populated else -1

    def _refuse(index: int, message: str) -> DogfoodCorpusError:
        if index == last_populated:
            return DogfoodCorpusError(
                f"corpus torn tail (line {index + 1} {message})"
            )
        return DogfoodCorpusError(f"corpus line {index + 1} {message}")

    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise _refuse(index, "is not valid JSON") from exc
        if not isinstance(entry, Mapping):
            raise _refuse(index, "is not an object")
        if entry.get("sequence") != len(entries):
            raise _refuse(index, "has a broken sequence")
        if entry.get("prev_sha256") != previous:
            raise _refuse(index, "breaks the append-only chain")
        if entry.get("entry_sha256") != _digest(entry):
            raise _refuse(index, "has a modified body")
        previous = str(entry["entry_sha256"])
        entries.append(dict(entry))
    if expected_host is not None and entries:
        genesis_host = entries[0].get("host")
        if genesis_host != expected_host:
            raise DogfoodCorpusError(
                "corpus genesis host %r does not match expected origin %r"
                % (genesis_host, expected_host)
            )
    return entries


def append_record(path: str | Path, record: Mapping[str, Any]) -> dict[str, Any]:
    """Append one verdict. A run may be labeled once; corrections are additive."""

    if not isinstance(record, Mapping) or record.get("schema") != RECORD_SCHEMA:
        raise DogfoodCorpusError(f"record schema must be {RECORD_SCHEMA}")
    if record.get("host") is None:
        raise DogfoodCorpusError("host is required when appending a dogfood record")
    entries = read_corpus(path)
    labeled = {entry.get("run_key") for entry in entries if entry.get("kind") == "record"}
    run_key = record.get("run_key")
    kind = record.get("kind")
    if kind == "record" and run_key in labeled:
        raise DogfoodCorpusError(
            f"run_key {run_key} is already labeled; append a correction instead of relabeling"
        )
    if kind == "correction":
        if record.get("corrects") not in labeled:
            raise DogfoodCorpusError("a correction must cite an already labeled run_key")
    elif kind != "record":
        raise DogfoodCorpusError("record kind must be record or correction")

    return append_entry(path, record)


def append_analysis_marker(
    path: str | Path, summary: Mapping[str, Any], *, observed_at: str
) -> dict[str, Any]:
    """Record that an aggregate was looked at, so later labels can declare it."""

    if not isinstance(summary, Mapping) or summary.get("schema") != SUMMARY_SCHEMA:
        raise DogfoodCorpusError(f"summary schema must be {SUMMARY_SCHEMA}")
    marker = {
        "schema": MARKER_SCHEMA,
        "kind": "analysis_marker",
        "observed_at": validate_timestamp(observed_at, "observed_at"),
        "summary_sha256": content_digest(dict(summary)),
        "record_count": summary.get("record_count", 0),
    }
    return append_entry(path, marker)


def effective_records(entries: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return one current verdict per run, with corrections applied additively.

    Superseded originals stay in the corpus and stay readable. They are simply
    not counted twice in an aggregate.
    """

    current: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    entries = list(entries)
    for entry in entries:
        if entry.get("kind") == "record":
            run_key = str(entry.get("run_key"))
            if run_key not in current:
                order.append(run_key)
            current[run_key] = dict(entry)
    for entry in entries:
        if entry.get("kind") == "correction":
            target = str(entry.get("corrects"))
            if target in current:
                superseded = current[target]
                replacement = dict(entry)
                replacement["supersedes_sequence"] = superseded.get("sequence")
                current[target] = replacement
    return [current[run_key] for run_key in order]


def resolve_effective_spines(
    entries: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve additive spine corrections without rewriting prior evidence.

    Each correction must cite the exact currently effective corpus entry and
    spine digest.  A stale, forked, orphaned, or cross-run correction fails
    closed instead of silently selecting one branch.
    """

    states: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    chain_fields = {"sequence", "prev_sha256", "corpus_version", "entry_sha256"}
    for entry in entries:
        kind = entry.get("kind")
        if kind == "run_spine":
            if entry.get("schema") != SPINE_SCHEMA:
                raise DogfoodCorpusError("run spine schema is invalid")
            run_key = _identifier(entry.get("run_key"), "run_key")
            if run_key in states:
                raise DogfoodCorpusError(f"run_key {run_key} has duplicate original spines")
            order.append(run_key)
            states[run_key] = {
                "run_key": run_key,
                "spine": dict(entry),
                "entry": dict(entry),
                "correction_count": 0,
                "superseded_sequences": [],
            }
            continue
        if kind != "run_spine_correction":
            continue
        if entry.get("schema") != SPINE_CORRECTION_SCHEMA:
            raise DogfoodCorpusError("run spine correction schema is invalid")
        run_key = _identifier(entry.get("run_key"), "run_key")
        state = states.get(run_key)
        if state is None:
            raise DogfoodCorpusError(f"run_key {run_key} has an orphaned spine correction")
        corrects = entry.get("corrects")
        replacement = entry.get("replacement_spine")
        if not isinstance(corrects, Mapping) or not isinstance(replacement, Mapping):
            raise DogfoodCorpusError("run spine correction body is invalid")
        current_entry = state["entry"]
        current_spine = state["spine"]
        expected = {
            "sequence": current_entry.get("sequence"),
            "entry_sha256": current_entry.get("entry_sha256"),
            "spine_sha256": current_spine.get("spine_sha256"),
        }
        if dict(corrects) != expected:
            raise DogfoodCorpusError(f"run_key {run_key} spine correction is stale or forked")
        if replacement.get("schema") != SPINE_SCHEMA or replacement.get("kind") != "run_spine":
            raise DogfoodCorpusError("replacement spine identity is invalid")
        if replacement.get("run_key") != run_key:
            raise DogfoodCorpusError("replacement spine run_key does not match its correction")
        if replacement.get("host") != entry.get("host") or replacement.get("host") != current_spine.get("host"):
            raise DogfoodCorpusError("replacement spine host does not match its correction chain")
        if chain_fields.intersection(replacement):
            raise DogfoodCorpusError("replacement spine must be an unsealed spine body")
        source = replacement.get("source")
        facts = replacement.get("facts")
        if not isinstance(source, Mapping) or not isinstance(facts, Mapping):
            raise DogfoodCorpusError("replacement spine evidence body is invalid")
        if replacement.get("spine_sha256") != _digest(
            {"source": dict(source), "facts": dict(facts)}
        ):
            raise DogfoodCorpusError("replacement spine digest is invalid")
        state = {
            "run_key": run_key,
            "spine": dict(replacement),
            "entry": dict(entry),
            "correction_count": int(state["correction_count"]) + 1,
            "superseded_sequences": list(state["superseded_sequences"])
            + [current_entry.get("sequence")],
        }
        states[run_key] = state
    return [states[run_key] for run_key in order]


def effective_spines(entries: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return one current mechanical spine per run, with corrections applied."""

    return [dict(state["spine"]) for state in resolve_effective_spines(entries)]


def spine_label_readiness(spine: Mapping[str, Any]) -> dict[str, Any]:
    """Decide whether one mechanical spine has a bounded run identity.

    This does not judge the run.  It only prevents a known multi-turn full-file
    capture from being presented as one labelable sample.
    """

    facts = spine.get("facts") if isinstance(spine.get("facts"), Mapping) else {}
    source = spine.get("source") if isinstance(spine.get("source"), Mapping) else {}
    version = facts.get("spine_version")
    turn_count = facts.get("turn_count")
    issues: list[str] = []
    if version == "dogfood-run-spine/1.0" and type(turn_count) is int and turn_count > 1:
        issues.append("spine:multi_turn_full_file_requires_bounded_segment")
    if version == "dogfood-run-spine/1.1":
        selection = source.get("selection")
        if not isinstance(selection, Mapping):
            issues.append("spine:bounded_selection_missing")
        else:
            if selection.get("schema") != "orch-dork/dogfood-session-segment/v1":
                issues.append("spine:bounded_selection_schema_invalid")
            start = selection.get("line_start")
            end = selection.get("line_end")
            if type(start) is not int or type(end) is not int or start < 1 or end < start:
                issues.append("spine:bounded_selection_lines_invalid")
            if not isinstance(selection.get("expected_ticket_id"), str):
                issues.append("spine:bounded_selection_ticket_missing")
            plan_sha = selection.get("expected_plan_sha256")
            if not isinstance(plan_sha, str) or not _SHA256.match(plan_sha):
                issues.append("spine:bounded_selection_plan_missing")
    return {
        "ready": not issues,
        "status": "READY" if not issues else "UNRESOLVED",
        "issues": sorted(set(issues)),
    }


def summarize_verdict_records(
    records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Project the shared verdict distributions and rates for one source."""

    total = len(records)
    blind = sum(record.get("blind") is True for record in records)
    actual = Counter(str(record.get("actual_class")) for record in records)
    classification = Counter(
        str(record.get("classification_verdict")) for record in records
    )
    plan = Counter(str(record.get("plan_verdict")) for record in records)
    outcome = Counter(str(record.get("outcome")) for record in records)
    scoreable_plan = total - plan.get("not_applicable", 0)
    return {
        "record_count": total,
        "blind_record_count": blind,
        "actual_class": dict(sorted(actual.items())),
        "classification_verdict": dict(sorted(classification.items())),
        "plan_verdict": dict(sorted(plan.items())),
        "outcome": dict(sorted(outcome.items())),
        "classification_agreement_rate": round(
            classification.get("agree", 0) / total, 6
        )
        if total
        else None,
        "good_plan_rate": round(plan.get("good", 0) / scoreable_plan, 6)
        if scoreable_plan
        else None,
        "shipped_rate": round(outcome.get("shipped", 0) / total, 6)
        if total
        else None,
    }


def summarize_corpus(
    entries: Sequence[Mapping[str, Any]],
    *,
    min_records: int = DEFAULT_MIN_RECORDS,
) -> dict[str, Any]:
    """Count what the corpus currently says. This is description, not a gate."""

    entries = list(entries)
    records = effective_records(entries)
    verdict_summary = summarize_verdict_records(records)
    total = verdict_summary["record_count"]
    blind = verdict_summary["blind_record_count"]
    notes = sum(1 for record in records if record.get("note"))
    corrections = sum(1 for entry in entries if entry.get("kind") == "correction")

    # A spine is captured mechanically when a run ends, so an unlabeled run
    # becomes a visible, countable debt instead of a silent loss. Spines are
    # facts, never verdicts: they are counted separately and never fold into
    # record_count, the verdict distributions, or any rate.
    spine_states = resolve_effective_spines(entries)
    spines = [state["spine"] for state in spine_states]
    spine_corrections = sum(
        1 for entry in entries if entry.get("kind") == "run_spine_correction"
    )
    labeled_runs = {str(record.get("run_key")) for record in records}
    awaiting = sorted(
        {
            str(entry.get("run_key"))
            for entry in spines
            if str(entry.get("run_key")) not in labeled_runs
        }
    )
    readiness = {
        str(spine.get("run_key")): spine_label_readiness(spine) for spine in spines
    }
    label_ready_awaiting = sorted(
        run_key for run_key in awaiting if readiness[run_key]["ready"]
    )
    unresolved_awaiting = sorted(
        run_key for run_key in awaiting if not readiness[run_key]["ready"]
    )

    reasons: list[str] = []
    if total < min_records:
        reasons.append(f"corpus:below_min_records:{total}<{min_records}")
    if blind < min_records:
        reasons.append(f"corpus:below_min_blind_records:{blind}<{min_records}")

    return {
        "schema": SUMMARY_SCHEMA,
        "corpus_version": CORPUS_VERSION,
        "record_count": total,
        "entry_count": len(entries),
        "blind_record_count": blind,
        "correction_count": corrections,
        "note_count": notes,
        "run_spine_count": len(spines),
        "run_spine_correction_count": spine_corrections,
        "unlabeled_run_keys": awaiting,
        "unlabeled_run_count": len(awaiting),
        "label_ready_unlabeled_run_keys": label_ready_awaiting,
        "label_ready_unlabeled_run_count": len(label_ready_awaiting),
        "unresolved_unlabeled_run_keys": unresolved_awaiting,
        "unresolved_unlabeled_run_count": len(unresolved_awaiting),
        "actual_class": verdict_summary["actual_class"],
        "classification_verdict": verdict_summary["classification_verdict"],
        "plan_verdict": verdict_summary["plan_verdict"],
        "outcome": verdict_summary["outcome"],
        "classification_agreement_rate": verdict_summary[
            "classification_agreement_rate"
        ],
        "good_plan_rate": verdict_summary["good_plan_rate"],
        "shipped_rate": verdict_summary["shipped_rate"],
        "aggregate_reportable": not reasons,
        "insufficient_reasons": reasons,
        "min_records": min_records,
        "provider_free": True,
        "model_calls": 0,
        "hosted_calls": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", help="Path to the append-only dogfood corpus JSONL file")
    parser.add_argument(
        "--append",
        metavar="RECORD_JSON_FILE",
        help="Path to a JSON file holding one dogfood record",
    )
    parser.add_argument("--min-records", type=int, default=DEFAULT_MIN_RECORDS)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()

    try:
        if args.append:
            record = json.loads(Path(args.append).read_text(encoding="utf-8"))
            result: Mapping[str, Any] = append_record(args.corpus, record)
        else:
            result = summarize_corpus(read_corpus(args.corpus), min_records=args.min_records)
    except DogfoodCorpusError as exc:
        print(json.dumps({"status": "REFUSE", "reason": str(exc)}, sort_keys=True))
        return 1

    print(
        json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":") if args.compact else None,
            indent=None if args.compact else 2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
