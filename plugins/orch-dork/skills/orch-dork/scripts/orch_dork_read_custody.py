#!/usr/bin/env python3
"""Issue 96: mechanical read-custody audit over bounded session evidence.

Qualification previously depended on trusting workers not to read sibling
resources, and on a human tailing session logs when trust failed.  This
module makes the read side mechanically checkable, in two deliberately
separate stages:

* `extract_accesses` performs conservative, provider-free extraction of
  candidate resource accesses from one bounded session JSONL file: patch
  envelope targets (`*** Add/Update/Delete File:`) become write accesses,
  and any known repo path mentioned in a tool-call input becomes a read
  access.  Every access carries a hash-bound source pointer (line number
  plus SHA-256 of the raw line), so a finding can be independently
  re-verified against the session file without copying private bodies.
  Only paths are emitted; prompts, messages, and outputs are never copied.
* `audit_read_custody` is a deterministic evaluator: given a frozen custody
  map (lane ownership, shared read allowlist, release events) and extracted
  accesses, it classifies every access and fails closed on any
  out-of-custody read or write that no earlier release authorizes.

Extraction is intentionally over-inclusive (a mentioned path counts as a
read even if the command never opened it); the custody map's shared
allowlist is the pressure valve, and a disputed finding is settled by the
source pointer, not by re-running the model.  Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

AUDIT_SCHEMA = "orch-dork/read-custody-audit/v1"
ACCESS_SCHEMA = "orch-dork/resource-access/v1"
CUSTODY_MAP_SCHEMA = "orch-dork/read-custody-map/v1"
EXCEPTION_SCHEMA = "orch-dork/custody-exception/v1"

_MAP_FIELDS = {"schema", "run_id", "repo_root", "lanes", "shared_read_allowlist", "releases"}
_LANE_FIELDS = {"owned", "forbidden"}
_RELEASE_FIELDS = {"order", "from_lane", "to_lane", "paths"}
_ACCESS_FIELDS = {"schema", "lane_id", "path", "op", "order", "source_pointer"}
_POINTER_FIELDS = {"source", "line", "sha256"}
_EXCEPTION_FIELDS = {"schema", "run_id", "lane_id", "paths", "recorded_at",
                     "disposition", "evidence"}
_EXCEPTION_DISPOSITIONS = ("recorded", "cured", "superseded")
_CURE_EVIDENCE_FIELDS = {"cured_by", "rebuilt_paths", "verification"}
_SUPERSEDED_EVIDENCE_FIELDS = {"superseding_commit", "reverified_by", "verification"}

# Anchored to line starts: a patch envelope's own targets begin a line,
# while a synthetic envelope quoted inside authored content (for example a
# test fixture) sits mid-line behind a diff marker or string quote.
_PATCH_TARGET = re.compile(r"(?m)^\*\*\* (?:Add|Update|Delete) File: (\S+)")
_PATCH_ENVELOPE = re.compile(r"(?m)^\*\*\* Begin Patch")

VERDICT_OWNED = "owned"
VERDICT_SHARED = "shared_allowlist"
VERDICT_RELEASED = "released"
VERDICT_READ_VIOLATION = "out_of_custody_read"
VERDICT_WRITE_VIOLATION = "out_of_custody_write"


def validate_custody_exception(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one custody-exception record; fail closed on any gap.

    Dispositions form the exception lifecycle:

    * `recorded` — the violation is acknowledged; the attempt's trace stays
      non-qualifying.  No further evidence is required.
    * `cured` — every tainted artifact was rebuilt from released state by a
      clean actor; requires `cured_by` (an actor distinct from the violating
      lane), `rebuilt_paths` covering the exception paths, and a
      `verification` pointer.
    * `superseded` — a later commit independently rewrote and re-verified
      every tainted surface; requires `superseding_commit` (40-hex),
      `reverified_by`, and a `verification` pointer.

    A cured or superseded exception no longer disqualifies future traces,
    but the record itself is never deleted: the ledger keeps the history.
    """
    _require_fields(value, _EXCEPTION_FIELDS, "custody_exception")
    if value["schema"] != EXCEPTION_SCHEMA:
        raise ReadCustodyError("custody_exception schema must be %s" % EXCEPTION_SCHEMA)
    for field in ("run_id", "lane_id", "recorded_at"):
        if not isinstance(value[field], str) or not value[field]:
            raise ReadCustodyError("%s must be a non-empty string" % field)
    paths = value["paths"]
    if not isinstance(paths, (list, tuple)) or not paths:
        raise ReadCustodyError("paths must be a non-empty list")
    normalized = sorted(_norm(p) for p in paths)
    disposition = value["disposition"]
    if disposition not in _EXCEPTION_DISPOSITIONS:
        raise ReadCustodyError(
            "disposition must be one of %s" % (_EXCEPTION_DISPOSITIONS,))
    evidence = value["evidence"]
    if disposition == "recorded":
        if evidence not in (None, {}):
            raise ReadCustodyError("recorded exceptions carry no evidence")
    elif disposition == "cured":
        _require_fields(evidence, _CURE_EVIDENCE_FIELDS, "cure evidence")
        if evidence["cured_by"] == value["lane_id"]:
            raise ReadCustodyError("cure requires an actor distinct from the lane")
        rebuilt = sorted(_norm(p) for p in evidence["rebuilt_paths"])
        uncovered = [p for p in normalized
                     if not any(_covers(scope, p) for scope in rebuilt)]
        if uncovered:
            raise ReadCustodyError(
                "cure does not cover tainted paths: %s" % uncovered)
        if not isinstance(evidence["verification"], str) or not evidence["verification"]:
            raise ReadCustodyError("cure requires a verification pointer")
    else:
        _require_fields(evidence, _SUPERSEDED_EVIDENCE_FIELDS,
                        "supersession evidence")
        commit = evidence["superseding_commit"]
        if (not isinstance(commit, str) or len(commit) != 40
                or any(c not in "0123456789abcdef" for c in commit)):
            raise ReadCustodyError("superseding_commit must be 40 lowercase hex")
        if not isinstance(evidence["reverified_by"], str) or not evidence["reverified_by"]:
            raise ReadCustodyError("supersession requires reverified_by")
        if not isinstance(evidence["verification"], str) or not evidence["verification"]:
            raise ReadCustodyError("supersession requires a verification pointer")
    record = {
        "schema": EXCEPTION_SCHEMA,
        "run_id": value["run_id"],
        "lane_id": value["lane_id"],
        "paths": normalized,
        "recorded_at": value["recorded_at"],
        "disposition": disposition,
        "evidence": dict(evidence) if isinstance(evidence, Mapping) else None,
        "qualification_blocking": disposition == "recorded",
    }
    record["exception_sha256"] = _sha256(
        {k: record[k] for k in record if k != "exception_sha256"})
    return record


class ReadCustodyError(ValueError):
    """Malformed custody map or access rows; the audit fails closed."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _require_fields(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    if not isinstance(value, Mapping):
        raise ReadCustodyError("%s must be a mapping" % label)
    unknown = set(value) - allowed
    if unknown:
        raise ReadCustodyError("%s has unknown fields: %s" % (label, sorted(unknown)))
    missing = allowed - set(value)
    if missing:
        raise ReadCustodyError("%s is missing fields: %s" % (label, sorted(missing)))


def _norm(path: str) -> str:
    """Normalize a repo-relative path: no leading ./, no backslash, no NUL."""
    if not isinstance(path, str) or not path or "\x00" in path or path.startswith("/"):
        raise ReadCustodyError("path must be a non-empty relative string: %r" % (path,))
    parts: list[str] = []
    for part in path.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ReadCustodyError("path may not traverse upward: %r" % (path,))
        parts.append(part)
    if not parts:
        raise ReadCustodyError("path resolves to nothing: %r" % (path,))
    return "/".join(parts)


def _covers(scope: str, path: str) -> bool:
    """True when scope (a file or directory prefix) covers path."""
    return path == scope or path.startswith(scope + "/")


# ---------------------------------------------------------------------------
# Stage 1: conservative extraction from one bounded session file.
# ---------------------------------------------------------------------------

def extract_accesses(session_path: str | Path, *, lane_id: str,
                     repo_root: str, known_paths: Iterable[str],
                     start_line: int = 1,
                     end_line: int | None = None) -> list[dict[str, Any]]:
    """Extract candidate resource accesses from a session JSONL file.

    known_paths bounds read detection to actual repository files, keeping
    extraction deterministic and immune to prose mentioning path-like
    strings.  Write detection needs no allowlist: a patch envelope names
    its target explicitly.

    start_line/end_line bound the attempt segment, following the
    attempt-observer discipline: the native session store is append-only
    and a root task is reused across attempts, so the whole lifetime of a
    reused root is never one attempt.  Lines outside the segment are not
    parsed.
    """
    if not isinstance(lane_id, str) or not lane_id:
        raise ReadCustodyError("lane_id must be non-empty")
    if not isinstance(start_line, int) or isinstance(start_line, bool) or start_line < 1:
        raise ReadCustodyError("start_line must be a positive integer")
    if end_line is not None and (
            not isinstance(end_line, int) or isinstance(end_line, bool)
            or end_line < start_line):
        raise ReadCustodyError("end_line must be >= start_line when given")
    root = repo_root.rstrip("/")
    known = sorted({_norm(p) for p in known_paths}, key=len, reverse=True)
    source = str(session_path)
    accesses: list[dict[str, Any]] = []
    order = 0
    with open(session_path, "rb") as handle:
        for line_number, raw in enumerate(handle, start=1):
            if line_number < start_line:
                continue
            if end_line is not None and line_number > end_line:
                break
            try:
                record = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(record, Mapping) or record.get("type") != "response_item":
                continue
            payload = record.get("payload")
            if not isinstance(payload, Mapping):
                continue
            kind = payload.get("type")
            if kind == "custom_tool_call":
                body = payload.get("input")
            elif kind == "function_call":
                body = payload.get("arguments")
            else:
                continue
            if not isinstance(body, str) or not body:
                continue
            if kind == "function_call":
                # arguments is the raw JSON text of the tool's argument
                # object.  Decode one level so the tool input's real
                # newlines become newlines while escapes authored *inside*
                # that input (for example a nested fixture envelope) stay
                # literal; string-level unescaping would flatten both.
                try:
                    decoded = json.loads(body)
                except ValueError:
                    decoded = None
                if isinstance(decoded, Mapping):
                    body = "\n".join(
                        value for value in decoded.values()
                        if isinstance(value, str))
                if not body:
                    continue
            pointer = {
                "source": source,
                "line": line_number,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            text = body
            writes: set[str] = set()
            patch_targets = _PATCH_TARGET.findall(text)
            for target in patch_targets:
                cleaned = target.strip("'\"`")
                if not cleaned:
                    continue
                if cleaned.startswith(root + "/"):
                    cleaned = cleaned[len(root) + 1:]
                try:
                    writes.add(_norm(cleaned))
                except ReadCustodyError:
                    continue
            reads: set[str] = set()
            if not writes and not patch_targets and not _PATCH_ENVELOPE.search(text):
                # Path mentions inside an authored patch body are content
                # being written, not reads performed by the acting agent;
                # a call that authored any patch target is treated as an
                # authoring call even when a code wrapper puts the envelope
                # marker mid-line.
                for candidate in known:
                    if candidate in writes:
                        continue
                    if candidate in text or (root + "/" + candidate) in text:
                        reads.add(candidate)
            for path in sorted(writes):
                order += 1
                accesses.append({
                    "schema": ACCESS_SCHEMA, "lane_id": lane_id, "path": path,
                    "op": "write", "order": order, "source_pointer": dict(pointer),
                })
            for path in sorted(reads):
                order += 1
                accesses.append({
                    "schema": ACCESS_SCHEMA, "lane_id": lane_id, "path": path,
                    "op": "read", "order": order, "source_pointer": dict(pointer),
                })
    return accesses


# ---------------------------------------------------------------------------
# Stage 2: deterministic audit of accesses against a frozen custody map.
# ---------------------------------------------------------------------------

def audit_read_custody(custody_map: Mapping[str, Any],
                       accesses: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Classify every access; FAIL on any unauthorized read or write."""
    _require_fields(custody_map, _MAP_FIELDS, "custody_map")
    if custody_map["schema"] != CUSTODY_MAP_SCHEMA:
        raise ReadCustodyError("custody_map schema must be %s" % CUSTODY_MAP_SCHEMA)
    lanes = custody_map["lanes"]
    if not isinstance(lanes, Mapping) or not lanes:
        raise ReadCustodyError("lanes must be a non-empty mapping")
    owned: dict[str, list[str]] = {}
    for lane_id, record in lanes.items():
        _require_fields(record, _LANE_FIELDS, "lane %s" % lane_id)
        owned[lane_id] = sorted(_norm(p) for p in record["owned"])
    shared = sorted(_norm(p) for p in custody_map["shared_read_allowlist"])
    releases: list[dict[str, Any]] = []
    for row in custody_map["releases"]:
        _require_fields(row, _RELEASE_FIELDS, "release")
        if row["from_lane"] not in owned or row["to_lane"] not in owned:
            raise ReadCustodyError("release names unknown lane: %s" % _canonical(row))
        if not isinstance(row["order"], int) or isinstance(row["order"], bool):
            raise ReadCustodyError("release order must be an integer")
        releases.append({
            "order": row["order"], "from_lane": row["from_lane"],
            "to_lane": row["to_lane"],
            "paths": sorted(_norm(p) for p in row["paths"]),
        })

    rows: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    counts = {VERDICT_OWNED: 0, VERDICT_SHARED: 0, VERDICT_RELEASED: 0,
              VERDICT_READ_VIOLATION: 0, VERDICT_WRITE_VIOLATION: 0}
    access_list = list(accesses)
    for access in access_list:
        _require_fields(access, _ACCESS_FIELDS, "access")
        _require_fields(access["source_pointer"], _POINTER_FIELDS, "source_pointer")
        if access["schema"] != ACCESS_SCHEMA:
            raise ReadCustodyError("access schema must be %s" % ACCESS_SCHEMA)
        lane_id = access["lane_id"]
        if lane_id not in owned:
            raise ReadCustodyError("access names unknown lane: %s" % lane_id)
        op = access["op"]
        if op not in ("read", "write"):
            raise ReadCustodyError("op must be read or write")
        if not isinstance(access["order"], int) or isinstance(access["order"], bool):
            raise ReadCustodyError("access order must be an integer")
        path = _norm(access["path"])

        verdict: str | None = None
        if any(_covers(scope, path) for scope in owned[lane_id]):
            verdict = VERDICT_OWNED
        elif op == "read" and any(_covers(scope, path) for scope in shared):
            verdict = VERDICT_SHARED
        else:
            authorized = any(
                release["to_lane"] == lane_id
                and release["order"] <= access["order"]
                and any(_covers(scope, path) for scope in release["paths"])
                for release in releases
            )
            if authorized:
                verdict = VERDICT_RELEASED
            else:
                verdict = (VERDICT_READ_VIOLATION if op == "read"
                           else VERDICT_WRITE_VIOLATION)
        counts[verdict] += 1
        row = {
            "lane_id": lane_id, "path": path, "op": op,
            "order": access["order"], "verdict": verdict,
            "source_pointer": dict(access["source_pointer"]),
        }
        rows.append(row)
        if verdict in (VERDICT_READ_VIOLATION, VERDICT_WRITE_VIOLATION):
            violations.append(row)

    report = {
        "schema": AUDIT_SCHEMA,
        "run_id": custody_map["run_id"],
        "status": "FAIL" if violations else "PASS",
        "counts": counts,
        "accesses": rows,
        "violations": violations,
        "custody_map_sha256": _sha256(custody_map),
        "accesses_sha256": _sha256(access_list),
    }
    report["report_sha256"] = _sha256(
        {k: report[k] for k in report if k != "report_sha256"})
    return report
