#!/usr/bin/env python3
"""Check a worker's final message against the numbered Returns of its brief, without a model.

A v3 worker brief carries one `## Returns` section of numbered items, `R1.` upward, one line each.
The worker preamble tells the worker to end its final message with a `## Returns` section answering every
number on its own line as `R<n>: done — <the answer, or where it is>` or `R<n>: not done — <why>`, an item
not delivered as asked being not done. This module parses both sides. The brief lint uses the brief parser;
the coordinator runs `check` on each worker's final message. When it reads INCOMPLETE, `followup` prints the
one fixed follow-up the coordinator sends, `check --followup` joins the worker's reply per number, and a
number still missing is an omission in the join. Both parsers ignore fenced code blocks, so an example inside
a fence is never taken for the section. The report carries numbers, states, lengths and digests, never text,
and grants or refuses nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

REPORT_SCHEMA = "orch-dork/handoff-returns/v1"
MAX_ITEMS = 12
MAX_ITEM_CHARS = 300
MAX_BRIEF_BYTES = 65_536  # the brief lint's bound
MAX_HANDOFF_BYTES = 262_144
# CommonMark fences: a run of three or more backticks or tildes opens one; only a line holding nothing but a run of
# the same character at least as long closes it, so a longer fence may quote a shorter one and an inner line such as
# an info-string opener stays content.
FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})")
FENCE_CLOSE = re.compile(r"^[ \t]*(`{3,}|~{3,})[ \t]*$")
BRIEF_HEADING = re.compile(r"^## Returns[ \t]*$")
ANY_HEADING = re.compile(r"^#{1,6}[ \t]")
BRIEF_ITEM = re.compile(r"^R(\d+)\.[ \t]+(\S.*)$")
BRIEF_ITEM_PREFIX = re.compile(r"^R\d+\.")
# The handoff side tolerates a heading of any level, a bold or colon form of the word, bullets, a number or state
# word wrapped in bold, italics, backticks or quotes, case, and the common dash and colon separators, because a
# worker reproduces the form by hand.
HANDOFF_HEADING = re.compile(r"^[ \t]*(?:#{1,6}[ \t]*)?\**Returns\**:?\**[ \t]*$", re.IGNORECASE)
WRAP = "[*_`\"'\u201c\u201d\u2018\u2019]*"
HANDOFF_ANSWER = re.compile(
    r"^[ \t]*(?:[-*+][ \t]+)?" + WRAP + r"R(\d+)" + WRAP + r"[ \t]*[:.)][ \t]*" + WRAP + r"(done|not[ \t]+done)" + WRAP
    + r"[ \t]*(?:[\u2014\u2013:-]+[ \t]*)?(.*)$",
    re.IGNORECASE,
)
HANDOFF_ANSWER_PREFIX = re.compile(r"^[ \t]*(?:[-*+][ \t]+)?" + WRAP + r"R\d+\b", re.IGNORECASE)
# A `#` heading run into its first answer line (`## ReturnsR1: done — …`) reads as the heading and that line;
# prose that merely starts with the word is not a heading.
GLUED_HEADING = re.compile(r"^([ \t]*#{1,6}[ \t]*\**Returns\**:?\**)[ \t]*(" + WRAP + r"R\d+\b.*)$", re.IGNORECASE)
FOLLOWUP_TAIL = (
    "Reply with only a `## Returns` section that answers every numbered item of your brief's `## Returns` "
    "section, in order, one line each: `R<n>: done — <the answer, or where it is>` or `R<n>: not done — <why>`. "
    "An item you could not deliver as asked is not done. Do not redo or repeat other work."
)


class ReturnsError(ValueError):
    """The brief carries no well-formed Returns section, so no handoff can be checked against it."""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _unfenced(text: str) -> list[str]:
    """The message's lines with every fenced code block blanked, so line numbers are kept."""

    lines, fence = [], None
    for line in text.splitlines():
        if fence is None:
            opened = FENCE.match(line)
            if opened:
                fence = opened.group(1)
            lines.append("" if opened else line)
            continue
        closed = FENCE_CLOSE.match(line)
        if closed and closed.group(1)[0] == fence[0] and len(closed.group(1)) >= len(fence):
            fence = None
        lines.append("")
    return lines


def parse_brief_returns(body: str) -> dict[str, Any]:
    """The brief's numbered items and the lint issues of its Returns section: missing, duplicate, empty,
    numbering, unexpected_line, empty_item, too_many, item_too_long."""

    lines = _unfenced(body)
    starts = [i for i, line in enumerate(lines) if BRIEF_HEADING.match(line)]
    issues: list[str] = []
    if not starts:
        return {"items": [], "issues": sorted({"returns:missing"})}
    if len(starts) > 1:
        issues.append("returns:duplicate")
    items: list[dict[str, Any]] = []
    for line in lines[starts[0] + 1:]:
        if ANY_HEADING.match(line):
            break
        if not line.strip():
            continue
        match = BRIEF_ITEM.match(line)
        if match is None:
            issues.append("returns:empty_item" if BRIEF_ITEM_PREFIX.match(line.strip()) else "returns:unexpected_line")
            continue
        text = match.group(2).strip()
        if len(text) > MAX_ITEM_CHARS:
            issues.append("returns:item_too_long")
        items.append({"number": int(match.group(1)), "text": text})
    if not items and "returns:empty_item" not in issues:
        issues.append("returns:empty")
    if [item["number"] for item in items] != list(range(1, len(items) + 1)):
        issues.append("returns:numbering")
    if len(items) > MAX_ITEMS:
        issues.append("returns:too_many")
    return {"items": items, "issues": sorted(set(issues))}


def _handoff_section(text: str) -> list[str] | None:
    """The lines of the last Returns section of the message, up to the next heading or the end."""

    lines: list[str] = []
    for line in _unfenced(text):
        glued = GLUED_HEADING.match(line)
        lines.extend([glued.group(1), glued.group(2)] if glued else [line])
    starts = [i for i, line in enumerate(lines) if HANDOFF_HEADING.match(line)]
    if not starts:
        return None
    section = []
    for line in lines[starts[-1] + 1:]:
        if ANY_HEADING.match(line.lstrip()):
            break
        section.append(line)
    return section


def _requested(brief: str) -> list[int]:
    parsed = parse_brief_returns(brief)
    if parsed["issues"]:
        raise ReturnsError("brief_returns_invalid:" + ",".join(parsed["issues"]))
    return [item["number"] for item in parsed["items"]]


def _read_answers(section: list[str] | None,
                  requested: list[int]) -> tuple[dict[str, dict[str, Any]], int, int, list[int]]:
    """The answers, malformed and repeated line counts and unrequested numbers of one section."""

    answers: dict[str, dict[str, Any]] = {}
    malformed = repeated = 0
    unrequested: list[int] = []
    for line in section or []:
        if not line.strip():
            continue
        match = HANDOFF_ANSWER.match(line)
        explanation = match.group(3).strip() if match else ""
        if match is None or not explanation:
            malformed += 1 if HANDOFF_ANSWER_PREFIX.match(line) else 0
            continue
        number = int(match.group(1))
        if number not in requested:
            unrequested.append(number)
            continue
        if str(number) in answers:
            repeated += 1
            continue
        state = "done" if match.group(2).lower() == "done" else "not_done"
        answers[str(number)] = {"state": state, "chars": len(explanation), "sha256": _sha256(explanation)}
    return answers, malformed, repeated, unrequested


def check_returns(brief: str, handoff: str, followup: str | None = None) -> dict[str, Any]:
    """Per requested number: done or not_done with a non-empty explanation, or missing. COMPLETE when every
    requested number is answered; the first answer to a number counts and a repeat is reported. With the
    worker's reply to the one follow-up, a number the final message does not answer takes the reply's answer;
    an answer the final message gave is never replaced."""

    requested = _requested(brief)
    section = _handoff_section(handoff)
    answers, malformed, repeated, unrequested = _read_answers(section, requested)
    extra: dict[str, Any] = {}
    if followup is not None:
        later = _handoff_section(followup)
        more, more_malformed, more_repeated, more_unrequested = _read_answers(later, requested)
        taken = [n for n in requested if str(n) not in answers and str(n) in more]
        for number in taken:
            answers[str(number)] = more[str(number)]
        malformed, repeated = malformed + more_malformed, repeated + more_repeated
        unrequested = unrequested + more_unrequested
        extra = {"followup_section_found": later is not None, "from_followup": taken,
                 "followup_sha256": _sha256(followup)}
    missing = [n for n in requested if str(n) not in answers]
    report = {
        "schema": REPORT_SCHEMA,
        "status": "COMPLETE" if not missing else "INCOMPLETE",
        "requested": requested,
        "section_found": section is not None,
        "answers": answers,
        "missing": missing,
        "malformed_lines": malformed,
        "unrequested": sorted(set(unrequested)),
        "repeated_answers": repeated,
        "brief_sha256": _sha256(brief),
        "handoff_sha256": _sha256(handoff),
        **extra,
    }
    report["report_sha256"] = _sha256(_canonical(report))
    return report


def followup_message(brief: str, handoff: str) -> str | None:
    """The one fixed follow-up a coordinator sends when the check reads INCOMPLETE, naming the missing section
    or numbers; None when the check reads COMPLETE."""

    report = check_returns(brief, handoff)
    if report["status"] == "COMPLETE":
        return None
    if not report["section_found"]:
        reason = "your final message has no `## Returns` section the check can read"
    else:
        reason = "your `## Returns` section does not answer " + ", ".join("R%d" % n for n in report["missing"])
    return "Your handoff is not complete: " + reason + ". " + FOLLOWUP_TAIL + "\n"


def _read(path_value: str, label: str, limit: int) -> str:
    """One regular file, refused when it is a link, special, over its bound, NUL-bearing or not UTF-8."""

    path = Path(path_value)
    try:
        if path.is_symlink() or not path.is_file():
            raise ReturnsError(label + "_not_a_regular_file")
        if path.stat().st_size > limit:
            raise ReturnsError(label + "_oversized")
        raw = path.read_bytes()
    except OSError as exc:
        raise ReturnsError(label + "_unreadable") from exc
    if len(raw) > limit:
        raise ReturnsError(label + "_oversized")
    if b"\x00" in raw:
        raise ReturnsError(label + "_nul")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReturnsError(label + "_utf8_invalid") from exc


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a worker's final message against its brief's Returns")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check")
    check.add_argument("--brief", required=True)
    check.add_argument("--handoff", required=True)
    check.add_argument("--followup", help="the worker's reply to the one follow-up, joined per number")
    follow = commands.add_parser("followup")
    follow.add_argument("--brief", required=True)
    follow.add_argument("--handoff", required=True)
    args = parser.parse_args(argv)
    try:
        brief = _read(args.brief, "brief", MAX_BRIEF_BYTES)
        handoff = _read(args.handoff, "handoff", MAX_HANDOFF_BYTES)
        if args.command == "followup":
            message = followup_message(brief, handoff)
            if message is not None:
                sys.stdout.write(message)
            return 0 if message is None else 1
        reply = _read(args.followup, "followup", MAX_HANDOFF_BYTES) if args.followup else None
        report = check_returns(brief, handoff, reply)
    except ReturnsError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2
    sys.stdout.write(_canonical(report) + "\n")
    return 0 if report["status"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = [
    "MAX_BRIEF_BYTES",
    "MAX_HANDOFF_BYTES",
    "MAX_ITEMS",
    "MAX_ITEM_CHARS",
    "REPORT_SCHEMA",
    "ReturnsError",
    "check_returns",
    "followup_message",
    "parse_brief_returns",
]
