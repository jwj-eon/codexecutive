#!/usr/bin/env python3
"""Provider-free structural screening of worker terminal output.

A worker that falls into a generation loop returns a terminal answer that is
structurally degenerate: one sentence repeated hundreds of times, a single
n-gram covering most of the content, or stray markup at a density no real
report produces. Absorbed as a normal completion, such an answer enters the
root's conversation history permanently and every later root turn re-sends it.

This module decides, from the submitted text alone, whether a terminal output
is structurally degenerate. It is a pure deterministic function of that text:
no filesystem access, no network, no provider, no model call. It classifies
structure only and never judges whether the content is correct or useful.

Two properties matter as much as the decision itself:

1. The verdict is typed and carries the evidence that produced it -- which
   pattern fired, how many repetitions, and what share of the content they
   cover. A bare boolean would leave a quarantining caller nothing to report.
2. Every evidence sample is truncated to SAMPLE_LIMIT characters. The whole
   point of screening is to keep a degenerate block out of a context window,
   so a verdict that echoed the block back would reproduce the failure it
   exists to prevent.

Thresholds are conjunctive on purpose: a detector fires only when an absolute
count and a share-of-content floor are both exceeded. Real reports repeat a
heading or a boilerplate line a handful of times and legitimately embed markup
examples; counts alone are evidence of nothing. Calibration is recorded in
tests/test_orch_dork_degenerate_output.py against a real 27,107 character
degenerate artifact and six real lane reports of 21KB-45KB.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import sys
from typing import Any


SCHEMA = "orch-dork/degenerate-output/v1"

# A repeated unit must be long enough to be a real sentence or clause. Short
# lines (rules, fences, table separators, "Done.") repeat constantly in healthy
# structured reports and carry no signal.
MIN_UNIT_CHARS = 24

# Below these floors the statistics are not stable enough to judge, and a text
# this small cannot poison a context window in the first place.
MIN_TEXT_CHARS = 400
MIN_TOKENS = 200

NGRAM_SIZE = 8
SAMPLE_LIMIT = 160

# Conjunctive thresholds: count AND share must both be exceeded. The share
# floors sit near "half the document is one repeated unit" because that is the
# qualitative claim being made, and because plausible-but-repetitive real
# output lands far below it: a 120-function code appendix whose bodies share
# identical boilerplate measures 0.25 line share and 0.40 n-gram coverage,
# while the observed degenerate artifact measures 0.67 and 0.56.
LINE_REPETITION_COUNT = 12
LINE_REPETITION_SHARE = 0.45
SENTENCE_REPETITION_COUNT = 12
SENTENCE_REPETITION_SHARE = 0.45
NGRAM_COUNT = 12
NGRAM_COVERAGE = 0.45
# A dominant n-gram is ambiguous on its own: it also appears when a report
# emits many *distinct* lines from one template ("Finding %d: ... resolved").
# Genuine degeneration repeats whole units, so the n-gram detector additionally
# requires that the units themselves be largely duplicates. Measured: the real
# degenerate artifact has a distinct-unit ratio of 0.11, while 300 templated
# findings sharing an 8-gram measure 0.96 and six real reports measure 1.00.
NGRAM_DISTINCT_UNIT_RATIO = 0.5
MARKUP_STRAY_COUNT = 24
MARKUP_STRAY_DENSITY = 5.0  # unbalanced tags per 1000 characters

# Tag names must be matched together with any attributes, otherwise an opening
# tag that carries attributes goes uncounted while its closer is counted and a
# perfectly balanced document reads as entirely stray.
_TAG = re.compile(r"<(/?)([A-Za-z][A-Za-z0-9_.:-]{0,40})(?:\s[^<>]{0,400})?(/?)>")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
_WHITESPACE = re.compile(r"\s+")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sample(value: str) -> str:
    """Bound every quoted fragment so evidence cannot reproduce the failure."""

    collapsed = _WHITESPACE.sub(" ", value).strip()
    if len(collapsed) <= SAMPLE_LIMIT:
        return collapsed
    return collapsed[: SAMPLE_LIMIT - 1] + "\u2026"


def _units(text: str, parts: list[str]) -> list[str]:
    normalized = (_WHITESPACE.sub(" ", part).strip() for part in parts)
    return [part for part in normalized if len(part) >= MIN_UNIT_CHARS]


def _repetition(units: list[str], total_chars: int) -> tuple[str, int, float]:
    if not units:
        return "", 0, 0.0
    unit, count = collections.Counter(units).most_common(1)[0]
    share = min(1.0, (count * len(unit)) / total_chars) if total_chars else 0.0
    return unit, count, share


def _ngram(tokens: list[str]) -> tuple[str, int, float]:
    if len(tokens) < NGRAM_SIZE:
        return "", 0, 0.0
    counts = collections.Counter(
        tuple(tokens[index : index + NGRAM_SIZE])
        for index in range(len(tokens) - NGRAM_SIZE + 1)
    )
    gram, count = counts.most_common(1)[0]
    coverage = min(1.0, (count * NGRAM_SIZE) / len(tokens))
    return " ".join(gram), count, coverage


def _distinct_unit_ratio(units: list[str]) -> float:
    """Share of repeated units that are unique. 1.0 means nothing repeats."""

    if not units:
        return 1.0
    return len(set(units)) / len(units)


def _markup(text: str) -> tuple[int, float, dict[str, int]]:
    opened: collections.Counter[str] = collections.Counter()
    closed: collections.Counter[str] = collections.Counter()
    for closing, raw_name, self_closing in _TAG.findall(text):
        name = raw_name.lower()
        if closing:
            closed[name] += 1
        elif self_closing:
            continue
        else:
            opened[name] += 1
    unbalanced: dict[str, int] = {}
    for name in sorted(set(opened) | set(closed)):
        delta = abs(opened.get(name, 0) - closed.get(name, 0))
        if delta:
            unbalanced[name] = delta
    stray = sum(unbalanced.values())
    density = (stray * 1000.0) / len(text) if text else 0.0
    return stray, density, unbalanced


def _finding(
    kind: str,
    *,
    count: int,
    share: float,
    threshold_count: int,
    threshold_share: float,
    sample: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    finding = {
        "kind": kind,
        "repetition_count": count,
        "content_share": round(share, 4),
        "threshold_count": threshold_count,
        "threshold_share": threshold_share,
        "sample": _sample(sample),
    }
    if detail:
        finding["detail"] = detail
    return finding


def evaluate_terminal_output(text: Any) -> dict[str, Any]:
    """Classify a worker's terminal text as CLEAN, DEGENERATE, or UNEVALUATED.

    UNEVALUATED is returned for a non-string input or for text below the
    statistical floors. It is deliberately distinct from CLEAN: the screen did
    not clear the text, it declined to judge it.
    """

    if not isinstance(text, str):
        return {
            "schema": SCHEMA,
            "status": "UNEVALUATED",
            "unevaluated_reason": "text_not_string",
            "text_sha256": None,
            "char_count": 0,
            "token_count": 0,
            "line_count": 0,
            "triggered_detectors": [],
            "findings": [],
            "measurements": {},
        }

    tokens = text.split()
    lines = text.splitlines()
    measurements: dict[str, Any] = {}
    base = {
        "schema": SCHEMA,
        "text_sha256": _sha256(text),
        "char_count": len(text),
        "token_count": len(tokens),
        "line_count": len(lines),
    }

    if len(text) < MIN_TEXT_CHARS or len(tokens) < MIN_TOKENS:
        return {
            **base,
            "status": "UNEVALUATED",
            "unevaluated_reason": "below_measurement_floor",
            "triggered_detectors": [],
            "findings": [],
            "measurements": {
                "min_text_chars": MIN_TEXT_CHARS,
                "min_tokens": MIN_TOKENS,
            },
        }

    findings: list[dict[str, Any]] = []

    line_units = _units(text, lines)
    line_unit, line_count, line_share = _repetition(line_units, len(text))
    distinct_ratio = _distinct_unit_ratio(line_units)
    measurements["distinct_unit_ratio"] = round(distinct_ratio, 4)
    measurements["max_line_repetition"] = line_count
    measurements["max_line_share"] = round(line_share, 4)
    if line_count >= LINE_REPETITION_COUNT and line_share >= LINE_REPETITION_SHARE:
        findings.append(
            _finding(
                "line_repetition",
                count=line_count,
                share=line_share,
                threshold_count=LINE_REPETITION_COUNT,
                threshold_share=LINE_REPETITION_SHARE,
                sample=line_unit,
            )
        )

    sentence_unit, sentence_count, sentence_share = _repetition(
        _units(text, _SENTENCE_SPLIT.split(text)), len(text)
    )
    measurements["max_sentence_repetition"] = sentence_count
    measurements["max_sentence_share"] = round(sentence_share, 4)
    if (
        sentence_count >= SENTENCE_REPETITION_COUNT
        and sentence_share >= SENTENCE_REPETITION_SHARE
    ):
        findings.append(
            _finding(
                "sentence_repetition",
                count=sentence_count,
                share=sentence_share,
                threshold_count=SENTENCE_REPETITION_COUNT,
                threshold_share=SENTENCE_REPETITION_SHARE,
                sample=sentence_unit,
            )
        )

    gram, gram_count, coverage = _ngram(tokens)
    measurements["max_ngram_repetition"] = gram_count
    measurements["max_ngram_coverage"] = round(coverage, 4)
    measurements["ngram_size"] = NGRAM_SIZE
    if (
        gram_count >= NGRAM_COUNT
        and coverage >= NGRAM_COVERAGE
        and distinct_ratio <= NGRAM_DISTINCT_UNIT_RATIO
    ):
        findings.append(
            _finding(
                "ngram_domination",
                count=gram_count,
                share=coverage,
                threshold_count=NGRAM_COUNT,
                threshold_share=NGRAM_COVERAGE,
                sample=gram,
                detail={
                    "ngram_size": NGRAM_SIZE,
                    "distinct_unit_ratio": round(distinct_ratio, 4),
                    "threshold_distinct_unit_ratio": NGRAM_DISTINCT_UNIT_RATIO,
                },
            )
        )

    stray, density, unbalanced = _markup(text)
    measurements["unbalanced_tags"] = stray
    measurements["unbalanced_tag_density"] = round(density, 4)
    if stray >= MARKUP_STRAY_COUNT and density >= MARKUP_STRAY_DENSITY:
        dominant = sorted(unbalanced.items(), key=lambda row: (-row[1], row[0]))[:5]
        findings.append(
            _finding(
                "markup_imbalance",
                count=stray,
                share=density,
                threshold_count=MARKUP_STRAY_COUNT,
                threshold_share=MARKUP_STRAY_DENSITY,
                sample=dominant[0][0] if dominant else "",
                detail={
                    "unbalanced_by_tag": dict(dominant),
                    "per_1000_chars": round(density, 4),
                },
            )
        )

    return {
        **base,
        "status": "DEGENERATE" if findings else "CLEAN",
        "unevaluated_reason": None,
        "triggered_detectors": sorted(finding["kind"] for finding in findings),
        "findings": findings,
        "measurements": measurements,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", help="file holding the terminal output text")
    args = parser.parse_args(argv)
    with open(args.path, "r", encoding="utf-8", errors="replace") as handle:
        report = evaluate_terminal_output(handle.read())
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report["status"] != "DEGENERATE" else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
