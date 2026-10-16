#!/usr/bin/env python3
"""Freeze Codex-drafted work from opaque text; confirm verified ticket updates.

Codex interprets the input's format. The host validates the draft, selects
ready disjoint tickets, and uses the watcher's existing summary/admission.
Raw input is provenance only. No source parser, provider, or GitHub call runs.
"""
from __future__ import annotations

from contextlib import contextmanager
import difflib
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

INTAKE_SCHEMA = "orch-dork/work-intake/v1"
PREPARE_INPUT_SCHEMA = "orch-dork/work-summary-input/v1"
PREPARE_SCHEMA = "orch-dork/work-summary-report/v1"
PROPOSAL_INPUT_SCHEMA = "orch-dork/ticket-status-proposal-input/v1"
PROPOSAL_SCHEMA = "orch-dork/ticket-status-proposal/v1"
CONFIRM_INPUT_SCHEMA = "orch-dork/ticket-status-confirm-input/v1"
UPDATE_SCHEMA = "orch-dork/ticket-status-update/v1"
MAX_TEXT_BYTES = 262144
_ID = re.compile(r"[^\x00-\x1f\x7f]{1,128}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _watcher():
    import orch_dork_governed_run_watcher
    return orch_dork_governed_run_watcher


def _require(condition: Any, detail: str) -> None:
    if not condition:
        raise ValueError(detail)


def _text(value: Any, limit: int = 16000) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value.encode("utf-8")) <= limit


def _source(task: Any) -> str:
    _require(_text(task, 256), "requesting task identity required")
    return hashlib.sha256(task.encode("utf-8")).hexdigest()


def _relative(value: Any) -> str:
    _require(_text(value, 4096), "relative path required")
    path = Path(value)
    _require(not path.is_absolute() and path.parts and
             all(part.casefold() not in {"..", ".git", ".orch-dork"} for part in path.parts), "unsafe project path")
    _require(path.as_posix() == value, "noncanonical project path")
    return value


@contextmanager
def _file(root: str, relative: str):
    """Pin the parent directory and read one bounded file without hardlinks.

    All components use no-follow opens; a later replace uses the pinned
    parent fd rather than following a path a concurrent edit could redirect.
    """
    parts = Path(_relative(relative)).parts
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open(root, flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_TEXT_BYTES,
                     "ticket file must be one bounded regular file")
            data = stream.read(MAX_TEXT_BYTES + 1)
            _require(len(data) <= MAX_TEXT_BYTES, "ticket file too large")
        data.decode("utf-8", errors="strict")
        yield parent, parts[-1], info, data
    finally:
        os.close(parent)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _path(records: Path, kind: str, digest: Any, task: str) -> Path:
    _require(isinstance(digest, str) and _SHA.fullmatch(digest), "invalid digest")
    return records / "work-intake" / _source(task) / kind / (digest + ".json")


def _read(path: Path, schema: str, field: str) -> dict[str, Any]:
    watcher = _watcher()
    _require(not path.is_symlink() and path.stat().st_size <= 2 * MAX_TEXT_BYTES, "unsafe intake artifact")
    value = watcher.read_json(path)
    _require(value.get("schema") == schema and watcher.seal_valid(value, field), "invalid intake artifact")
    return value


def _report(schema: str, **values: Any) -> dict[str, Any]:
    return _watcher().sealed({"schema": schema, "provider_free": True, **values}, "report_sha256")


def _refused(schema: str, error: Exception) -> dict[str, Any]:
    return _report(schema, status="REFUSED", reason="work_intake:request_invalid", message=str(error),
                   mutation_performed=False)


def _tickets(value: Any, *, worker_limit: int | None = None) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    _require(isinstance(value, list) and 1 <= len(value) <= 128, "tickets must be a bounded array")
    rows = {}
    for row in value:
        _require(isinstance(row, Mapping) and set(row) ==
                 {"id", "status", "depends_on", "writes", "goal", "checks"}, "invalid ticket draft")
        name = row["id"]
        _require(isinstance(name, str) and _ID.fullmatch(name) and name not in rows, "invalid ticket id")
        _require(row["status"] in {"ready", "complete", "blocked"} and _text(row["goal"]), "ticket status/goal")
        deps, writes = row["depends_on"], row["writes"]
        _require(isinstance(deps, list) and all(isinstance(dep, str) for dep in deps) and
                 len(deps) == len(set(deps)) and name not in deps, "ticket dependencies")
        _require(isinstance(writes, list) and len(writes) <= 128, "declare ticket write ownership")
        rows[name] = {**dict(row), "writes": [_relative(path) for path in writes]}
    _require(all(dep in rows for row in rows.values() for dep in row["depends_on"]), "unknown dependency")
    selected, skipped, writes = [], [], []
    for row in rows.values():
        reason = None
        if row["status"] != "ready":
            reason = row["status"]
        elif any(rows[dep]["status"] != "complete" for dep in row["depends_on"]):
            reason = "dependency incomplete"
        elif not row["writes"]:
            reason = "no declared write ownership"
        elif any(a == b or a.startswith(b + "/") or b.startswith(a + "/")
                 for a in row["writes"] for b in writes):
            reason = "write ownership overlaps selected ticket"
        elif len(selected) >= (max(1, worker_limit) if worker_limit is not None else _watcher().admission.MAX_WORKERS):
            reason = "run lane limit"
        if reason:
            skipped.append({"id": row["id"], "reason": reason})
        else:
            selected.append(row)
            writes.extend(row["writes"])
    _require(selected, "no dependency-ready ticket")
    return selected, skipped


def _ticket_lane(row: Mapping[str, Any]) -> dict[str, Any]:
    """Original ticket identifiers remain visible; lane identifiers fit Codex.
    The ticket's write ownership becomes the paths its lane owns, which the
    hook enforces (Issue 247)."""
    name = row["id"]
    identifier = name if _watcher()._LANE_ID.fullmatch(name) else "ticket-" + _sha(name.encode("utf-8"))[:24]
    return {"id": identifier, "goal": "Ticket " + name + ": " + row["goal"], "checks": row["checks"],
            "writes": list(row["writes"])}


def prepare(arguments: Mapping[str, Any], *, requesting_thread_id: str | None,
            records: Path | None = None) -> dict[str, Any]:
    """Validate Codex's interpretation and freeze the work shown before start."""
    watcher = _watcher()
    records = records or watcher.records_root()
    try:
        _source(requesting_thread_id)
        allowed = {"project_root", "input_text", "goal", "model", "effort", "lanes", "tickets",
                   "ticket_file", "worker_model", "worker_effort", "cost_budget_usd"}
        _require(isinstance(arguments, Mapping) and set(arguments) <= allowed, "intake fields")
        raw = arguments.get("input_text")
        _require(_text(raw, MAX_TEXT_BYTES), "input_text must be bounded nonempty text")
        _require(_text(arguments.get("goal")), "Codex-drafted goal required")
        _require(not ("lanes" in arguments and "tickets" in arguments), "draft lanes or tickets, not both")
        start = {key: value for key, value in arguments.items()
                 if key not in {"input_text", "ticket_file", "tickets"}}
        import orch_dork_project_improvements as improvements
        active = improvements.suspend_on_regression(Path(os.path.realpath(str(arguments.get("project_root")))), records=records)
        worker_limit = active["settings"]["worker_count"] if active and active["state"] == "active" else None
        selected, skipped = _tickets(arguments["tickets"], worker_limit=worker_limit) if "tickets" in arguments else ([], [])
        if selected:
            selected = [{**row, "goal": row["goal"] + "\nWrite ownership: " + ", ".join(row["writes"])}
                        for row in selected]
            start["goal"] = str(arguments.get("goal", "")) + "\nTickets: " + ", ".join(row["id"] for row in selected)
            if len(selected) == 1 and not worker_limit:
                start["goal"] += "\n" + selected[0]["goal"]
                start["lanes"] = []
                start.pop("worker_model", None)
                start.pop("worker_effort", None)
            else:
                _require(worker_limit is None or len(selected) == worker_limit,
                         "draft enough independent tickets for the adopted worker count")
                start["lanes"] = [_ticket_lane(row) for row in selected]
        if "ticket_file" in arguments:
            relative = _relative(arguments["ticket_file"])
            _require(selected and not any(path == relative or relative.startswith(path + "/")
                                          for row in selected for path in row["writes"]),
                     "ticket status file is outside lane write ownership")
            start["goal"] += "\nLeave " + relative + " unchanged. Ticket status updates require the host's Verified verdict and separate user confirmation."
        start, preferences_sha256 = improvements.apply_defaults(start, records=records)
        request = watcher.build_request(project_root=str(start.get("project_root")), goal=start.get("goal"),
            model=start.get("model"), effort=start.get("effort"), requesting_thread_id=requesting_thread_id,
            lanes=start.get("lanes", ()), worker_model=start.get("worker_model"),
            worker_effort=start.get("worker_effort") or (start.get("effort") if start.get("lanes") else None))
        project = watcher.read_enrollment(records, Path(request["project_root"]))
        for row in selected:
            for relative in row["writes"]:
                path = Path(os.path.realpath(request["project_root"]))
                for part in Path(relative).parts:
                    path = path / part
                    _require(not path.is_symlink(), "ticket ownership follows a symlink")
                _require(not path.is_file() or path.stat().st_nlink == 1, "ticket ownership aliases a hardlink")
        # Validate every selected ticket's enrolled checks, including a singleton
        # whose work stays in the root and uses all project checks.
        if selected:
            ticket_lanes = watcher._lane_requests([
                _ticket_lane(row) for row in selected])
            seen = set()
            for lane in ticket_lanes:
                watcher._validate_lane(lane, seen)
            watcher.resolve_lanes({**request, "lanes": ticket_lanes}, project)
        summary = watcher.work_summary(request, project, watcher.resolve_lanes(request, project))
        target = None
        if "ticket_file" in arguments:
            _require(selected, "ticket_file needs selected tickets")
            relative = _relative(arguments["ticket_file"])
            with _file(os.path.realpath(request["project_root"]), relative) as (_, _, _, data):
                target = {"path": relative, "sha256": _sha(data)}
        value = watcher.sealed({"schema": INTAKE_SCHEMA, "project_root": os.path.realpath(request["project_root"]),
            "requesting_thread_id": requesting_thread_id, "input_sha256": _sha(raw.encode("utf-8")),
            "summary": summary, "summary_sha256": watcher.policy.sha256(summary),
            "selected_tickets": [row["id"] for row in selected], "target": target,
            "start_arguments": start, "project_preferences_sha256": preferences_sha256}, "intake_sha256")
        path = _path(records, "summaries", value["intake_sha256"], requesting_thread_id)
        if not path.exists():
            watcher.write_json(path, value, create_only=True)
        return _report(PREPARE_SCHEMA, status="PREPARED", summary=summary,
            summary_sha256=value["summary_sha256"], intake_sha256=value["intake_sha256"],
            selected_tickets=value["selected_tickets"], skipped_tickets=skipped,
            start_arguments={**start, "intake_sha256": value["intake_sha256"]},
            instruction="Show this work summary in the requesting task before starting the run.",
            mutation_performed=False)
    except (ValueError, OSError, KeyError, TypeError, watcher.WatcherError) as error:
        return _refused(PREPARE_SCHEMA, error)


def bind(arguments: Mapping[str, Any], request: Mapping[str, Any], project: Mapping[str, Any],
         *, records: Path) -> dict[str, Any] | None:
    """Resolve and match an intake before any admission claim or model dispatch."""
    if "intake_sha256" not in arguments:
        return None
    watcher = _watcher()
    try:
        value = _read(_path(records, "summaries", arguments["intake_sha256"], request["requesting_thread_id"]),
                      INTAKE_SCHEMA, "intake_sha256")
        summary = watcher.work_summary(request, project, watcher.resolve_lanes(request, project))
        _require(value["requesting_thread_id"] == request["requesting_thread_id"] and
                 value["project_root"] == os.path.realpath(request["project_root"]) and
                 value["summary"] == summary and value["summary_sha256"] == watcher.policy.sha256(summary),
                 "prepared summary changed; prepare it again")
        import orch_dork_project_improvements as improvements
        active = improvements.suspend_on_regression(Path(request["project_root"]), records=records)
        _require(value.get("project_preferences_sha256") == (active or {}).get("preferences_sha256"),
                 "project defaults changed; prepare the summary again")
        expected = {key: val for key, val in arguments.items() if key not in {"intake_sha256", "approve_plan_sha256"}}
        _require(value["start_arguments"] == expected, "prepared start arguments changed")
        return value
    except (ValueError, OSError, KeyError, watcher.WatcherError) as error:
        raise watcher.WatcherError("governed_run:request_invalid", str(error)) from error


def read_verified_run(records: Path, run_id: str, task: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read the exact Verified run and its enrolled intake; grant no edit permission."""
    watcher = _watcher()
    _source(task)
    state = watcher.read_status(run_id, records)
    record = state.get("record") or {}
    _require(state.get("state") == "TERMINAL" and record.get("run_id") == run_id and
             record.get("schema") == watcher.RECORD_SCHEMA and
             record.get("requesting_thread_id") == task and
             (record.get("verdict") or {}).get("label") == watcher.VERIFIED and
             watcher.record_verdict(record, None)["label"] == watcher.VERIFIED,
             "run is not Verified for this task")
    value = _read(watcher.run_directory(records, run_id) / "intake.json", INTAKE_SCHEMA, "intake_sha256")
    _require(value["requesting_thread_id"] == task and value["project_root"] == record["project_root"] and
             value["summary_sha256"] == record["summary_sha256"] and
             watcher.policy.sha256(value["summary"]) == record["summary_sha256"] and value["target"],
             "run is not bound to these tickets")
    watcher.read_enrollment(records, Path(record["project_root"]))
    return record, value


def read_status_proposal(records: Path, digest: str, task: str) -> dict[str, Any]:
    """Read one sealed proposal from the requesting task's existing namespace."""
    return _read(_path(records, "proposals", digest, task), PROPOSAL_SCHEMA, "proposal_sha256")


def read_consumed_marker(records: Path, digest: str, task: str) -> dict[str, Any] | None:
    """Read one consumed marker; return None when no confirmation has started.

    The writer in this module writes two shapes with the same update schema
    but different key names; readers must look for both keys because the
    writer switches between them by stage:

    * CLAIMED uses ``marker["state"] == "CLAIMED"`` (the unsealed
      reservation written before ``os.replace``).
    * APPLIED uses ``marker["status"] == "APPLIED"`` (the sealed report
      written after the file replace, with ``report_sha256``).

    Unknown shapes (missing both keys, an empty marker, a non-update
    schema) are returned as-is so the caller's discriminator (the
    orch_dork_mission_tracker `_classify_consumed_marker` helper) can
    treat them as DRIFTED. Read-only callers (for example, tracker
    reconciliation) use this accessor to observe the actual state
    without authorizing another confirmation.
    """
    path = _path(records, "consumed", digest, task)
    if not path.is_file():
        return None
    watcher = _watcher()
    _require(not path.is_symlink() and path.stat().st_size <= 2 * MAX_TEXT_BYTES,
             "unsafe consumed marker")
    value = watcher.read_json(path)
    _require(isinstance(value, dict) and value.get("schema") == UPDATE_SCHEMA,
             "invalid consumed marker")
    return value


def read_target_digest(project_root: str, target_path: str) -> str:
    """Read the bounded target file's exact sha256; refuse any non-follow or oversize."""
    with _file(project_root, target_path) as (_, _, _, data):
        return _sha(data)


def _build_literal_edits(selected_tickets: list[str], original: bytes, edits: Any) -> bytes:
    """Construct bounded exact UTF-8 edits; confer no verification or write authority.

    Callers must validate their own terminal proof and compare the current
    target bytes before using this pure builder. Proposal sealing, enrollment
    and confirmation remain the caller's separate authoritative gates.
    """
    _require(isinstance(selected_tickets, list) and 1 <= len(selected_tickets) <= 128 and
             all(isinstance(name, str) and _ID.fullmatch(name) for name in selected_tickets) and
             len(set(selected_tickets)) == len(selected_tickets), "selected tickets must be bounded unique ids")
    _require(isinstance(original, bytes) and len(original) <= MAX_TEXT_BYTES,
             "ticket text must be bounded bytes")
    before = original.decode("utf-8", errors="strict")
    _require(isinstance(edits, list) and 1 <= len(edits) <= len(selected_tickets), "status edits")
    after, seen = before, set()
    for edit in edits:
        _require(isinstance(edit, Mapping) and set(edit) == {"ticket_id", "before", "after"}, "status edit shape")
        name, old, new = edit["ticket_id"], edit["before"], edit["after"]
        _require(isinstance(name, str) and name in selected_tickets and name not in seen and
                 _text(old, 4096) and _text(new, 4096) and old != new and
                 before.count(old) == 1 and after.count(old) == 1, "status edit must name one selected ticket and unique text")
        seen.add(name)
        after = after.replace(old, new, 1)
    updated = after.encode("utf-8")
    _require(len(updated) <= MAX_TEXT_BYTES, "updated file too large")
    return updated


def propose(arguments: Mapping[str, Any], *, requesting_thread_id: str | None,
            records: Path | None = None) -> dict[str, Any]:
    """Only a Verified run can offer exact literal status edits for confirmation."""
    watcher = _watcher()
    records = records or watcher.records_root()
    try:
        _require(set(arguments) == {"run_id", "edits"}, "proposal fields")
        record, value = read_verified_run(records, arguments["run_id"], requesting_thread_id)
        edits = arguments["edits"]
        with _file(value["project_root"], value["target"]["path"]) as (_, _, _, data):
            _require(_sha(data) == value["target"]["sha256"], "ticket file changed since intake")
        updated = _build_literal_edits(value["selected_tickets"], data, edits)
        before = data.decode("utf-8")
        after = updated.decode("utf-8")
        proposal = watcher.sealed({"schema": PROPOSAL_SCHEMA, "run_id": record["run_id"],
            "requesting_thread_id": requesting_thread_id, "record_sha256": record["record_sha256"],
            "intake_sha256": value["intake_sha256"], "project_root": value["project_root"],
            "target": value["target"], "edits": edits, "updated_text": after,
            "updated_sha256": _sha(updated)}, "proposal_sha256")
        path = _path(records, "proposals", proposal["proposal_sha256"], requesting_thread_id)
        if not path.exists():
            watcher.write_json(path, proposal, create_only=True)
        return _report(PROPOSAL_SCHEMA, status="APPROVAL_REQUIRED", proposal_sha256=proposal["proposal_sha256"],
            file=value["target"]["path"], edits=edits, diff="".join(difflib.unified_diff(
                before.splitlines(keepends=True), after.splitlines(keepends=True),
                fromfile=value["target"]["path"], tofile=value["target"]["path"])),
            question="Apply these exact ticket-status edits? Confirm this proposal's digest only after the user agrees.",
            mutation_performed=False)
    except (ValueError, OSError, KeyError, TypeError, watcher.WatcherError) as error:
        return _refused(PROPOSAL_SCHEMA, error)


def confirm(arguments: Mapping[str, Any], *, requesting_thread_id: str | None,
            records: Path | None = None) -> dict[str, Any]:
    """Consume explicit confirmation of one proposal; compare and replace once."""
    watcher = _watcher()
    records = records or watcher.records_root()
    mutation_performed = False
    try:
        _require(set(arguments) == {"confirm_proposal_sha256"}, "confirmation fields")
        digest = arguments["confirm_proposal_sha256"]
        proposal = read_status_proposal(records, digest, requesting_thread_id)
        record, value = read_verified_run(records, proposal["run_id"], requesting_thread_id)
        _require(record["record_sha256"] == proposal["record_sha256"] and
                 value["intake_sha256"] == proposal["intake_sha256"], "verified result changed")
        # The same lock serializes a new run's admission and this small edit.
        with watcher.machine_lock(records):
            _require(watcher.project_key(Path(value["project_root"])) not in
                     watcher.machine_runs(records)["projects"], "repository has an active governed run")
            with _file(value["project_root"], value["target"]["path"]) as (parent, name, info, data):
                _require(_sha(data) == proposal["target"]["sha256"], "ticket file changed; confirmation is stale")
                marker = _path(records, "consumed", digest, requesting_thread_id)
                watcher.write_json(marker, {"schema": UPDATE_SCHEMA, "state": "CLAIMED", "proposal_sha256": digest},
                                   create_only=True)
                temporary = ".od-status-" + os.urandom(16).hex()
                descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     stat.S_IMODE(info.st_mode), dir_fd=parent)
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(proposal["updated_text"].encode("utf-8"))
                        stream.flush()
                        os.fsync(stream.fileno())
                        os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
                    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    _require((current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) ==
                             (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns), "ticket file changed during confirmation")
                    os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
                    mutation_performed = True
                    os.fsync(parent)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=parent)
                    except FileNotFoundError:
                        pass
                result = _report(UPDATE_SCHEMA, status="APPLIED", proposal_sha256=digest,
                    file=proposal["target"]["path"], updated_sha256=proposal["updated_sha256"], mutation_performed=True)
                watcher.write_json(marker, result)
                return result
    except (ValueError, OSError, KeyError, TypeError, watcher.WatcherError) as error:
        result = _refused(UPDATE_SCHEMA, error)
        if mutation_performed:
            return _report(UPDATE_SCHEMA, status="REFUSED", reason="work_intake:write_unconfirmed",
                message="The confirmed edit was replaced, but recording durability or its receipt failed: "
                        + str(error) + ". This confirmation is consumed; inspect the file before another proposal.",
                mutation_performed=True)
        return result
