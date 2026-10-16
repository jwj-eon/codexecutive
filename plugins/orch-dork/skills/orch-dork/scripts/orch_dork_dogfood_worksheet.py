#!/usr/bin/env python3
"""Issue 128: make one blind dogfood verdict cheap to produce.

The Issue 77 floor counts *blind* records, and the corpus holds six of the
twenty it needs.  Of its nine records the other three are permanently
non-blind, because their labeler had already seen an aggregate and that
cannot be undone.  Even labeling every recorded-but-unlabeled run reaches
eleven, so the floor also requires more real runs before it can be met.

None of that is work an agent can do.  A verdict is a human judgement about
whether a run was any good, and `SKILL.md` is explicit that a spine is not a
human verdict.  Manufacturing one would corrupt the only instrument that
measures whether orchestration helps.

What an agent *can* remove is the cost of giving a verdict.  Today a labeler
has to find the run, read its spine out of a sealed chain, recall three
closed vocabularies, know that ``plan_verdict`` is gated on ``actual_class``,
and hand-build a record body.  That friction is why runs sit unlabeled.  This
module prints what the run mechanically did, asks only the questions a human
can answer, and writes the answers through the corpus' own validation.

Blindness is the property this module protects.  A worksheet that displayed
the corpus pass rate would produce a non-blind verdict while looking like a
blind one, so no aggregate is ever rendered here.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Mapping
import sys

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import orch_dork_dogfood_corpus as corpus  # noqa: E402


WORKSHEET_SCHEMA = "orch-dork/dogfood-worksheet/v1"

# Identities that must never appear as a labeler. A verdict signed by an
# agent is not a human verdict, and the corpus has no other way to tell.
#
# Word-bounded on purpose: bare substring matching rejected real people
# ("Stewart Bott" contains "bot", "Friedrich Modell" contains "model"), and
# a check that refuses humans is worse than no check.
#
# This is a tripwire, not a proof of authorship. It catches an agent that
# signs with its own name; it cannot catch one that signs with a plausible
# human name. The real protection is the minimum-identity rule below plus
# the fact that a fabricated verdict is a deliberate act, not an accident.
_NON_HUMAN_LABELER = re.compile(
    r"\b(codex|gpt|claude|gemini|qwen|sonnet|opus|agent|assistant|llm"
    r"|bot|model|copilot|cursor)\b",
    re.IGNORECASE,
)

# A one-character initial is not an identity anyone can be held to. The
# Issue 128 review incident appended a fabricated record under the labeler
# "j", which the substring check accepted; requiring a minimum length makes
# a careless probe fail closed instead of contaminating the chain.
MIN_LABELER_CHARS = 3

# Spine facts worth showing a labeler. The full spine carries thread ids and
# paths that help nobody judge quality, so the worksheet selects rather than
# dumping.
# Verified against the field names the recovery module actually writes: the
# spine records "root_completion", not "root_reporting", so the earlier name
# silently displayed nothing on every real run.
_SHOWN_FACTS = (
    "derived_class",
    "lane_count",
    "planned_lane_count",
    "worker_attempt_count",
    "extra_worker_attempt_count",
    "gate_count",
    "gate_retry_count",
    "root_completion",
    "turn_count",
    "spawn_count",
    "wave_status",
    "plan_frozen",
    "integration_strategy",
    "integration_owner",
    "trace_qualification_status",
    "trace_qualified",
    "trace_claim_permitted",
    "trace_qualification_issues",
    "root_coordination_only_after_freeze",
    "planned_worker_model",
    "planned_worker_effort",
    "planned_retries_allowed",
    "planned_fallbacks_allowed",
    "admission_decision",
    "declared_deliverable_count",
    "redacted_deliverable_count",
    "declared_deliverables",
)


def _entries(path: str | Path) -> list[Mapping[str, Any]]:
    return list(corpus.read_corpus(path))


def _spine_for(entries, run_key: str) -> Mapping[str, Any] | None:
    for entry in corpus.effective_spines(entries):
        if entry.get("run_key") == run_key:
            return entry
    return None


def _labeled(entries, run_key: str) -> bool:
    return any(
        entry.get("schema") == corpus.RECORD_SCHEMA
        and entry.get("run_key") == run_key
        and entry.get("kind") != "correction"
        for entry in entries
    )


def render_worksheet(path: str | Path, *, run_key: str) -> str:
    """Render one run as the exact questions a human must answer.

    Deliberately returns text rather than a record: the output of this
    function is something a person reads, and it must not be mistakable for
    evidence.  No corpus aggregate appears anywhere in it.
    """

    entries = _entries(path)
    spine = _spine_for(entries, run_key)
    if spine is None:
        return (
            "There is no recorded run with key %r in this corpus. A verdict "
            "can only describe a run the corpus already witnessed." % run_key
        )
    if _labeled(entries, run_key):
        return (
            "Run %r is already labeled. A run may be labeled once; a changed "
            "opinion is appended as a correction citing the original, never "
            "as a second label." % run_key
        )
    readiness = corpus.spine_label_readiness(spine)
    if not readiness["ready"]:
        return (
            "Run %r is not label-ready. Its mechanical spine is not bounded "
            "to one run (%s). Recover and append an exact v1.1 spine "
            "correction before answering any verdict question."
            % (run_key, ", ".join(readiness["issues"]))
        )

    facts = spine.get("facts")
    facts = facts if isinstance(facts, Mapping) else {}
    lines = [
        "DOGFOOD LABELING WORKSHEET",
        "Run: %s" % run_key,
        "Host: %s" % spine.get("host"),
        "",
        "WHAT THE RUN MECHANICALLY DID",
        "  (derived from the run's own session record; carries no judgement)",
    ]
    for name in _SHOWN_FACTS:
        if name in facts:
            lines.append("  %s: %s" % (name, json.dumps(facts[name])))
    lines.extend(
        [
            "",
            "QUESTION 1 - What was this run actually?",
            "  One of: %s" % ", ".join(corpus.CLASSES),
            "",
            "QUESTION 2 - Was that the right call?",
            "  One of: %s" % ", ".join(corpus.CLASSIFICATION_VERDICTS),
            "  A verdict may not say the run should have been what it was.",
            "",
            "QUESTION 3 - If it ran a multi-lane plan, was the plan good?",
            "  One of: %s" % ", ".join(corpus.PLAN_VERDICTS),
            "  Applicability: answer not_applicable when the run was atomic",
            "    or refused, because there was no plan to judge. An",
            "    orchestrated run must get one of the other values.",
            "",
            "QUESTION 4 - How did it end up?",
            "  One of: %s" % ", ".join(corpus.OUTCOMES),
            "",
            "BLINDNESS",
            "  This worksheet deliberately shows no corpus totals or rates.",
            "  If you have already read an aggregate summary, say so when",
            "  recording, and the record will be counted as non-blind.",
        ]
    )
    return "\n".join(lines)


def record_verdict(
    path: str | Path,
    *,
    run_key: str,
    recorded_at: str,
    ticket_key: str,
    actual_class: str,
    classification_verdict: str,
    plan_verdict: str,
    outcome: str,
    labeler: str,
    host: str,
    note: str | None = None,
    analysis_digest_seen: str | None = None,
) -> dict[str, Any]:
    """Write one human verdict through the corpus' own validation.

    Every verdict field is required and has no default.  A default here
    would let an agent supply a human judgement by omission, which is
    exactly the failure this module exists to prevent.
    """

    issues: list[str] = []
    if not isinstance(labeler, str) or not labeler.strip():
        issues.append("worksheet:labeler_invalid")
    elif len(labeler.strip()) < MIN_LABELER_CHARS:
        # A one-character initial is not an identity anyone can be held to.
        issues.append("worksheet:labeler_too_short")
    elif _NON_HUMAN_LABELER.search(labeler):
        # A verdict is a human judgement. An agent-shaped identity here
        # would let synthetic labels pass as evidence of real quality.
        issues.append("worksheet:labeler_not_human")
    if not isinstance(host, str) or not host.strip():
        # Each host keeps an independent chain, so a record with no host
        # cannot be attributed when a later reader summarizes per host.
        issues.append("worksheet:host_required")
    try:
        entries = _entries(path)
    except (OSError, corpus.DogfoodCorpusError) as error:
        return {
            "status": "FAIL",
            "issues": ["worksheet:corpus_unreadable"],
            "detail": str(error),
            "blind": None,
        }
    spine = _spine_for(entries, run_key)
    if spine is None:
        issues.append("worksheet:run_unknown")
    elif not corpus.spine_label_readiness(spine)["ready"]:
        issues.append("worksheet:spine_not_label_ready")
    if _labeled(entries, run_key):
        issues.append("worksheet:already_labeled")
    if issues:
        return {
            "status": "FAIL",
            "issues": sorted(set(issues)),
            "detail": None,
            "blind": None,
        }

    try:
        record = corpus.build_record(
            run_key=run_key,
            recorded_at=recorded_at,
            ticket_key=ticket_key,
            actual_class=actual_class,
            classification_verdict=classification_verdict,
            plan_verdict=plan_verdict,
            outcome=outcome,
            labeler=labeler,
            host=host,
            note=note,
            analysis_digest_seen=analysis_digest_seen,
        )
        corpus.append_record(path, record)
    except corpus.DogfoodCorpusError as error:
        return {
            "status": "FAIL",
            "issues": ["worksheet:record_invalid"],
            "detail": str(error),
            "blind": None,
        }
    return {
        "status": "PASS",
        "issues": [],
        "detail": None,
        "blind": record["blind"],
        "run_key": run_key,
    }


def shortfall(path: str | Path) -> dict[str, Any]:
    """State how far the corpus is from its floor, without hiding the gap.

    Reports the *blind* shortfall, which binds, alongside how many recorded
    runs remain available to label and therefore how many further real runs
    the floor still requires.  This is a planning figure, not an aggregate
    analysis: it carries no rates and no verdict content, so reading it does
    not compromise a later blind label.
    """

    try:
        entries = _entries(path)
    except (OSError, corpus.DogfoodCorpusError) as error:
        return {
            "status": "FAIL",
            "issues": ["worksheet:corpus_unreadable"],
            "detail": str(error),
            "blind_records_required": None,
            "blind_records_held": None,
            "blind_records_needed": None,
            "runs_available_to_label": None,
            "further_real_runs_required": None,
        }
    summary = corpus.summarize_corpus(entries)
    required = int(summary["min_records"])
    held = int(summary["blind_record_count"])
    available = int(summary["label_ready_unlabeled_run_count"])
    needed = max(0, required - held)
    return {
        "status": "PASS",
        "issues": [],
        "detail": None,
        "blind_records_required": required,
        "blind_records_held": held,
        "blind_records_needed": needed,
        "runs_available_to_label": available,
        # Labeling every available run still leaves this many, and each one
        # needs a real orchestrated run before it can be labeled at all.
        "further_real_runs_required": max(0, needed - available),
        "note": (
            "Blind records bind. A non-blind record cannot be converted, "
            "so the gap closes only through new blind human verdicts."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    """One command per step, so labeling never needs hand-built JSON.

    Refusals print the sibling corpus vocabulary (``status: REFUSE``) so a
    labeler sees one shape across both tools.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", help="Path to the host-local corpus")
    parser.add_argument(
        "--worksheet",
        metavar="RUN_KEY",
        help="Print the labeling worksheet for one unlabeled run",
    )
    parser.add_argument(
        "--record",
        metavar="ANSWERS_JSON_FILE",
        help="Append one human verdict from a JSON answers file",
    )
    parser.add_argument(
        "--shortfall",
        action="store_true",
        help="Report how far the corpus is from its blind-record floor",
    )
    args = parser.parse_args(argv)

    if args.worksheet:
        print(render_worksheet(args.corpus, run_key=args.worksheet))
        return 0
    if args.record:
        try:
            answers = json.loads(
                Path(args.record).read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as error:
            print(
                json.dumps(
                    {"status": "REFUSE", "reason": str(error)}, sort_keys=True
                )
            )
            return 1
        if not isinstance(answers, dict):
            print(
                json.dumps(
                    {
                        "status": "REFUSE",
                        "reason": "answers file must hold one JSON object",
                    },
                    sort_keys=True,
                )
            )
            return 1
        try:
            result = record_verdict(args.corpus, **answers)
        except TypeError as error:
            # A missing verdict field lands here. Never fill one in.
            print(
                json.dumps(
                    {"status": "REFUSE", "reason": str(error)}, sort_keys=True
                )
            )
            return 1
        if result["status"] != "PASS":
            print(
                json.dumps(
                    {
                        "status": "REFUSE",
                        "reason": result["issues"],
                        "detail": result["detail"],
                    },
                    sort_keys=True,
                )
            )
            return 1
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    print(json.dumps(shortfall(args.corpus), sort_keys=True, indent=2))
    return 0


__all__ = [
    "WORKSHEET_SCHEMA",
    "MIN_LABELER_CHARS",
    "render_worksheet",
    "record_verdict",
    "shortfall",
    "main",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
