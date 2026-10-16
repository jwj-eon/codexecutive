#!/usr/bin/env python3
"""Bounded cleanup of the tasks one governed run owns, after the run ends.

Issue 196.  On Codex 0.160.0 a running turn survives the disconnect of the
client that started it: in `racetrack/codex-facts/daemon-0.160.0.json` the
abandoned turn ran its tool to completion, the thread stayed loaded, and the
work went on with nobody watching.  So a run that ends by stop, interruption
or owner loss cannot assume the disconnect stopped anything; it has to end
what it started and say exactly what it observed.

This helper settles only the tasks the caller owns.  The caller passes the
root task it bound and the worker thread ids that this run's own genuine
spawn items and durable grant outcomes named; a thread id that merely
appeared in a notification is not ownership and is never acted on.  Workers
this owner already closed natively, proven by its own completed
`closeAgent` items or a completed lane cross-check, are passed as
`closed_worker_ids`: Codex may unload a closed worker's thread, so reading
one back can fail for a worker that is provably finished, and the helper
records those as ended and closed without reading, interrupting or
archiving them.  Any other worker it cannot read stays UNKNOWN.

Cleanup reads, interrupts and archives.  It never resumes a thread, starts a
thread or a turn, sends input, or calls any model method, so it can neither
continue the attempt it is cleaning up nor start a new one.  It prefers the
owner connection the caller is already holding; only if that connection has
died, and the caller supplied both a factory and the socket of the daemon
that is already running, does it open exactly one initialized cleanup-only
connection, which it closes itself.  The caller's connection is never
closed, and every notification that arrives while cleanup waits stays queued
on the connection for the caller to read.

Mutations are never retried: one interrupt per in-progress turn and one
archive per worker.  Only reads poll, under one bounded deadline.  A daemon
that has gone, a read that fails, an interrupt or archive that fails, or a
turn still running when the deadline passes is reported as unknown or
uncleared with its exact thread and turn ids; the report never claims
success over state it could not read.

A read is this thread's state only when it comes back with this exact
non-empty thread id and an explicit inventory of turns that each name a turn,
and a turn has ended only when it reports one of the terminal statuses Codex
0.160.0 actually uses.  An answer about another thread, an answer with no
identity or no well-formed turn inventory, and a status this version never
reports are all unknown: they leave the worker unarchived and the report
BLOCKED rather than reading silence as an end.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
from typing import Any, Callable, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import orch_dork_app_server_client as app_server  # noqa: E402


REPORT_SCHEMA = "orch-dork/governed-run-cleanup/v1"
CLIENT_NAME = "orch-dork-governed-run-cleanup"
ALLOWED_METHODS = frozenset({"thread/read", "turn/interrupt", "thread/archive"})
REQUEST_SECONDS = 15.0
POLL_SECONDS = 0.25
MAX_OWNED_WORKERS = 64
MAX_WAIT_SECONDS = 120.0
MAX_ID_BYTES = 256
ACTIVE_TURN_STATUS = "inProgress"
# Codex 0.160.0 reports a turn as inProgress or as one of these three terminal
# statuses (docs/agents/issue170-public-api-census.md and the native thread
# source validation in lifecycle_conformance/host_adapter.py).  Only a
# whitelisted terminal status is an observed end: an unstarted pendingInit
# turn, a missing status and any status this version does not report prove
# nothing and stay unsettled.
ENDED_TURN_STATUSES = frozenset({"completed", "failed", "interrupted"})
REPORT_FIELDS = frozenset({
    "schema", "status", "observed_at", "root", "workers", "connection", "counters",
    "remaining", "issues", "own_workers_confirmed_ended", "own_workers_archived",
    "workers_closed_natively", "root_turn_confirmed_ended", "cleanup_connection_closed",
    "owned_worker_thread_ids", "closed_worker_thread_ids", "wait_seconds", "report_sha256",
})
# ConnectionError and TimeoutError are OSError subclasses, so OSError already
# covers every socket loss and read timeout this transport can raise.
_TRANSPORT_ERRORS = (OSError, ValueError)


class CleanupInputError(ValueError):
    """The caller's own-task identifiers cannot define a cleanup."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sealed(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    core = {key: item for key, item in value.items() if key != field}
    return {**core, field: hashlib.sha256(canonical(core)).hexdigest()}


def seal_valid(value: Any, field: str) -> bool:
    return isinstance(value, Mapping) and value.get(field) == sealed(value, field)[field]


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def report_issues(value: Any) -> list[str]:
    """Why a cleanup report is not a valid sealed report of this schema."""

    if not isinstance(value, Mapping) or set(value) != REPORT_FIELDS:
        return ["shape"]
    issues = []
    if value.get("schema") != REPORT_SCHEMA:
        issues.append("schema")
    if value.get("status") not in {"PASS", "BLOCKED"}:
        issues.append("status")
    if not isinstance(value.get("workers"), list) or not isinstance(value.get("issues"), list):
        issues.append("records")
    for field in ("own_workers_confirmed_ended", "own_workers_archived",
                  "root_turn_confirmed_ended", "cleanup_connection_closed"):
        if value.get(field) is not None and type(value.get(field)) is not bool:
            issues.append(field)
    if value.get("status") == "PASS" and (
        value.get("issues") or value.get("remaining")
        or value.get("own_workers_confirmed_ended") is not True
        or value.get("own_workers_archived") is not True
    ):
        issues.append("unproven_pass")
    if not seal_valid(value, "report_sha256"):
        issues.append("seal")
    return issues


def report_valid(value: Any) -> bool:
    return not report_issues(value)


def _identifier(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > MAX_ID_BYTES:
        raise CleanupInputError("invalid " + label)
    return value


def _owned_ids(value: Any, label: str, *, root_thread_id: str) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise CleanupInputError(label + " must be a sequence of thread ids")
    ordered: list[str] = []
    for item in value:
        thread_id = _identifier(item, label + " entry")
        if thread_id == root_thread_id:
            raise CleanupInputError(label + " names the root task")
        if thread_id not in ordered:
            ordered.append(thread_id)
    if len(ordered) > MAX_OWNED_WORKERS:
        raise CleanupInputError(label + " exceeds " + str(MAX_OWNED_WORKERS) + " threads")
    return ordered


def _turn_ended(status: Any) -> bool:
    # The isinstance guard also keeps an unhashable status out of the lookup.
    return isinstance(status, str) and status in ENDED_TURN_STATUSES


def _turns(read: Any, thread_id: str) -> list[dict[str, Any]] | None:
    """The turns of an exact owned thread read, or None when it proves neither.

    Ownership needs this thread's own non-empty id back and an explicit list of
    turns, each naming the turn it reports.  A read that answers about another
    thread, carries no identity, or carries no well-formed turn inventory says
    nothing about what this thread is still running, so it is never read as
    proof that there is nothing left to end.  An inventory that is explicitly
    empty is well formed: the thread really reports no turns.
    """

    thread = read.get("thread") if isinstance(read, Mapping) else None
    if not isinstance(thread, Mapping):
        return None
    # thread_id is an already validated non-empty identifier, so this equality
    # alone rejects an absent, empty, non-string or foreign thread id.
    if thread.get("id") != thread_id:
        return None
    inventory = thread.get("turns")
    if not isinstance(inventory, list):
        return None
    turns = []
    for turn in inventory:
        if not isinstance(turn, Mapping):
            return None
        turn_id = turn.get("id")
        if not isinstance(turn_id, str) or not turn_id:
            return None
        turns.append({"turn_id": turn_id, "status": turn.get("status")})
    return turns


def _unsettled(turns: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [dict(turn) for turn in turns if not _turn_ended(turn.get("status"))]


def _detail(error: BaseException) -> str:
    return (type(error).__name__ + ":" + str(error))[:200]


class _Transport:
    """The one connection cleanup may use, and at most one replacement.

    A read may fail over to the replacement; a mutation never does, so no
    interrupt or archive is ever sent twice.  Only the connection this class
    opened is ever closed.
    """

    def __init__(self, connection: Any, *, connect: Callable[[Path], Any] | None,
                 socket_path: Path | str | None) -> None:
        usable = connection is not None and not bool(getattr(connection, "closed", False))
        self.caller = connection
        self.caller_usable = usable
        self.caller_lost = False
        self.active = connection if usable else None
        self.source = "caller" if usable else "none"
        self.connect = connect
        self.socket_path = socket_path
        self.created: Any = None
        self.created_initialized = False
        self.created_closed: bool | None = None
        self.replacement_tried = False
        self.requests = 0
        self.failures = 0
        self.issues: list[str] = []
        # The owner connection having died is the condition cleanup exists for,
        # not a cleanup failure, so it is a diagnostic rather than an issue.
        self.notes: list[str] = []

    def _lost(self, error: BaseException) -> None:
        if self.active is not None and self.active is self.caller:
            self.caller_lost = True
            self.notes.append("governed_run_cleanup:owner_connection_lost:" + _detail(error))
        elif self.active is not None:
            self.issues.append("governed_run_cleanup:cleanup_connection_lost:" + _detail(error))
        self.active = None

    def _replace(self) -> bool:
        """Open the single cleanup-only connection to the daemon already running."""

        if self.replacement_tried:
            return False
        self.replacement_tried = True
        if self.connect is None or self.socket_path is None:
            self.issues.append("governed_run_cleanup:no_cleanup_connection")
            return False
        try:
            self.created = self.connect(Path(self.socket_path))
        except Exception as error:  # a factory that cannot reach the daemon
            self.issues.append("governed_run_cleanup:daemon_unavailable:" + _detail(error))
            return False
        try:
            self.created.initialize(CLIENT_NAME)
        except Exception as error:
            self.issues.append("governed_run_cleanup:cleanup_connection_unusable:" + _detail(error))
            self._close_created()
            return False
        self.created_initialized = True
        self.active = self.created
        self.source = "cleanup_only"
        return True

    def _close_created(self) -> None:
        if self.created is None or self.created_closed is not None:
            return
        try:
            self.created.close()
            self.created_closed = True
        except Exception as error:
            self.created_closed = False
            self.issues.append("governed_run_cleanup:cleanup_connection_unclosed:" + _detail(error))
        if self.active is self.created:
            self.active = None

    def request(self, method: str, params: Mapping[str, Any], *,
                mutation: bool) -> tuple[bool, Any]:
        """One bounded request; (True, result) or (False, why it did not land)."""

        if method not in ALLOWED_METHODS:
            raise RuntimeError("governed_run_cleanup:forbidden_method:" + str(method))
        if self.active is None and not self._replace():
            return False, "no_connection"
        self.requests += 1
        try:
            return True, self.active.request(method, params, timeout=REQUEST_SECONDS)
        except app_server.AppServerRequestError as error:
            self.failures += 1
            return False, "refused:" + _detail(error)
        except _TRANSPORT_ERRORS as error:
            self.failures += 1
            detail = "transport:" + _detail(error)
            self._lost(error)
            if mutation or not self._replace():
                return False, detail
        self.requests += 1
        try:
            return True, self.active.request(method, params, timeout=REQUEST_SECONDS)
        except app_server.AppServerRequestError as error:
            self.failures += 1
            return False, "refused:" + _detail(error)
        except _TRANSPORT_ERRORS as error:
            self.failures += 1
            self._lost(error)
            return False, "transport:" + _detail(error)

    def finish(self) -> dict[str, Any]:
        self._close_created()
        return {
            "source": self.source,
            "caller_connection_usable": self.caller_usable,
            "caller_connection_lost": self.caller_lost,
            "caller_connection_closed": False,
            "cleanup_connection_created": self.created is not None,
            "cleanup_connection_initialized": self.created_initialized,
            "cleanup_connection_closed": self.created_closed,
            "cleanup_client_name": CLIENT_NAME,
            "replacement_offered": self.connect is not None and self.socket_path is not None,
            "socket_path": None if self.socket_path is None else str(self.socket_path),
            "requests_sent": self.requests,
            "requests_failed": self.failures,
            "notes": list(self.notes),
        }


def _worker_entry(thread_id: str, *, closed: bool) -> dict[str, Any]:
    return {
        "thread_id": thread_id,
        "closed_natively": closed,
        "read": "closed_natively" if closed else "unread",
        "turns": [],
        "interrupted_turn_ids": [],
        "turns_confirmed_ended": True if closed else None,
        "archived": None,
        "issues": [],
    }


def _read_thread(transport: _Transport, entry: dict[str, Any], *, role: str,
                 reason: str) -> bool:
    """Read one exact owned thread; record why a read cannot be trusted."""

    ok, value = transport.request(
        "thread/read", {"threadId": entry["thread_id"], "includeTurns": True}, mutation=False)
    if not ok:
        entry["read"] = "failed"
        entry["issues"].append("governed_run_cleanup:" + role + "_unreadable" + reason
                               + ":" + str(value))
        return False
    turns = _turns(value, entry["thread_id"])
    if turns is None:
        # One diagnostic for every answer that does not establish this exact
        # thread and its turns: a wrong or absent identity and an absent or
        # malformed turn inventory are the same failure to know what we own.
        entry["read"] = "mismatch"
        entry["issues"].append("governed_run_cleanup:" + role + "_identity_mismatch")
        return False
    entry["read"] = "ok"
    entry["turns"] = turns
    return True


def _interrupt_active(transport: _Transport, entry: dict[str, Any], *, role: str,
                      prefer: str | None = None) -> int:
    """One interrupt for each turn this thread actually reports in progress."""

    active = [turn for turn in entry["turns"] if turn.get("status") == ACTIVE_TURN_STATUS
              and isinstance(turn.get("turn_id"), str)]
    active.sort(key=lambda turn: 0 if turn["turn_id"] == prefer else 1)
    sent = 0
    for turn in active:
        ok, detail = transport.request(
            "turn/interrupt", {"threadId": entry["thread_id"], "turnId": turn["turn_id"]},
            mutation=True)
        if ok:
            entry["interrupted_turn_ids"].append(turn["turn_id"])
            sent += 1
        else:
            entry["issues"].append("governed_run_cleanup:" + role + "_interrupt_failed:"
                                   + turn["turn_id"] + ":" + str(detail))
    return sent


def _confirm_ended(transport: _Transport, entries: Sequence[dict[str, Any]], *, role: str,
                   wait_seconds: float, counters: dict[str, int]) -> None:
    """Poll the exact threads read-only until their turns end or time runs out."""

    pending = [entry for entry in entries
               if entry["read"] == "ok" and _unsettled(entry["turns"])]
    for entry in entries:
        if entry["read"] == "ok" and entry["turns_confirmed_ended"] is None \
                and not _unsettled(entry["turns"]):
            entry["turns_confirmed_ended"] = True
    deadline = time.monotonic() + wait_seconds
    while pending:
        for entry in list(pending):
            counters["confirmation_reads"] += 1
            before = entry["turns"]
            if not _read_thread(transport, entry, role=role, reason="_after_interrupt"):
                entry["turns"] = before
                pending.remove(entry)
                continue
            if not _unsettled(entry["turns"]):
                entry["turns_confirmed_ended"] = True
                pending.remove(entry)
        remaining = deadline - time.monotonic()
        if not pending or remaining <= 0:
            break
        time.sleep(min(POLL_SECONDS, remaining))
    for entry in pending:
        entry["turns_confirmed_ended"] = False
        entry["issues"].append("governed_run_cleanup:" + role + "_turn_not_ended")


def _combine(values: Sequence[Any]) -> bool | None:
    """True only when every observation says so; False beats unknown."""

    if not values:
        return True
    if any(value is False for value in values):
        return False
    if any(value is None for value in values):
        return None
    return True


def _remaining_rows(entries: Sequence[Mapping[str, Any]], *, role: str) -> list[dict[str, Any]]:
    rows = []
    for entry in entries:
        if entry["turns_confirmed_ended"] is True:
            continue
        # The last turns actually read are kept even when a later read failed,
        # so a leftover is named by its exact turn and not only by its thread.
        unsettled = _unsettled(entry["turns"])
        if not unsettled:
            rows.append({"role": role, "thread_id": entry["thread_id"], "turn_id": None,
                         "status": None, "read": entry["read"]})
            continue
        rows.extend({"role": role, "thread_id": entry["thread_id"], "turn_id": turn.get("turn_id"),
                     "status": turn.get("status"), "read": entry["read"]}
                    for turn in unsettled)
    return rows


def settle_owned_tasks(
    connection: Any,
    *,
    root_thread_id: str,
    root_turn_id: str | None,
    worker_thread_ids: Sequence[str],
    closed_worker_ids: Sequence[str] = (),
    interrupt_root: bool = False,
    connect: Callable[[Path], Any] | None = None,
    socket_path: Path | str | None = None,
    wait_seconds: float = 5.0,
) -> dict[str, Any]:
    """End and archive this run's own worker tasks; report what was observed.

    `worker_thread_ids` are the threads this run's own genuine spawn items and
    durable grant outcomes named, and `closed_worker_ids` the subset of those
    the owner already closed natively and proved closed.  A proven-closed
    worker is recorded as ended and closed without being read, interrupted or
    archived, because Codex may have unloaded it; every other worker is read
    with its turns, each turn it actually reports in progress is interrupted
    once, the end is confirmed by bounded read-only polling, and only a worker
    confirmed ended is archived once.

    With `interrupt_root` the root task is read and every turn it reports in
    progress is interrupted, the run's own `root_turn_id` first and any extra
    turn a user started next, since the binding this task ran under has ended.
    The root is never archived, so the user keeps seeing it.  With
    `interrupt_root` false the root is not read or touched at all.

    Returns the sealed report; `status` is PASS only when every owned worker
    was proven closed or confirmed ended and archived, the root turn ended when
    that was asked, nothing remains, and any connection cleanup opened was
    closed.  Raises CleanupInputError before any request when the caller's own
    identifiers cannot define a cleanup.
    """

    root_thread_id = _identifier(root_thread_id, "root_thread_id")
    root_turn_id = _identifier(root_turn_id, "root_turn_id", nullable=True)
    owned = _owned_ids(worker_thread_ids, "worker_thread_ids", root_thread_id=root_thread_id)
    closed = _owned_ids(closed_worker_ids, "closed_worker_ids", root_thread_id=root_thread_id)
    unowned = [thread_id for thread_id in closed if thread_id not in owned]
    if unowned:
        raise CleanupInputError("closed_worker_ids are not owned workers: " + ",".join(unowned))
    if type(interrupt_root) is not bool:
        raise CleanupInputError("invalid interrupt_root")
    if isinstance(wait_seconds, bool) or not isinstance(wait_seconds, (int, float)) \
            or wait_seconds != wait_seconds or not 0.0 <= wait_seconds <= MAX_WAIT_SECONDS:
        raise CleanupInputError("invalid wait_seconds")
    wait_seconds = float(wait_seconds)

    counters = {
        "owned_worker_threads": len(owned),
        "worker_threads_closed_natively": len(closed),
        "worker_threads_read": 0,
        "worker_threads_unreadable": 0,
        "worker_turns_interrupted": 0,
        "worker_threads_observed_ended": 0,
        "worker_threads_archived": 0,
        "root_turns_interrupted": 0,
        "confirmation_reads": 0,
    }
    transport = _Transport(connection, connect=connect, socket_path=socket_path)
    workers = [_worker_entry(thread_id, closed=thread_id in closed) for thread_id in owned]
    root = {
        "thread_id": root_thread_id,
        "known_turn_id": root_turn_id,
        "requested": interrupt_root,
        "closed_natively": False,
        "read": "not_read",
        "turns": [],
        "interrupted_turn_ids": [],
        "turns_confirmed_ended": None,
        "archived": False,
        "issues": [],
    }

    for entry in workers:
        if entry["closed_natively"]:
            continue
        if _read_thread(transport, entry, role="worker", reason=""):
            counters["worker_threads_read"] += 1
            counters["worker_turns_interrupted"] += _interrupt_active(
                transport, entry, role="worker")
        else:
            counters["worker_threads_unreadable"] += 1
    _confirm_ended(transport, workers, role="worker", wait_seconds=wait_seconds,
                   counters=counters)
    for entry in workers:
        if entry["closed_natively"]:
            continue
        if entry["turns_confirmed_ended"] is not True:
            continue
        counters["worker_threads_observed_ended"] += 1
        ok, detail = transport.request(
            "thread/archive", {"threadId": entry["thread_id"]}, mutation=True)
        entry["archived"] = bool(ok)
        if ok:
            counters["worker_threads_archived"] += 1
        else:
            entry["issues"].append("governed_run_cleanup:worker_archive_failed:" + str(detail))

    if interrupt_root:
        if _read_thread(transport, root, role="root", reason=""):
            if root_turn_id is not None and not any(
                turn.get("turn_id") == root_turn_id for turn in root["turns"]
            ):
                root["issues"].append("governed_run_cleanup:root_turn_absent:" + root_turn_id)
            counters["root_turns_interrupted"] += _interrupt_active(
                transport, root, role="root", prefer=root_turn_id)
        _confirm_ended(transport, [root], role="root", wait_seconds=wait_seconds,
                       counters=counters)

    archivable = [entry["archived"] for entry in workers if not entry["closed_natively"]]
    own_workers_confirmed_ended = _combine([entry["turns_confirmed_ended"] for entry in workers])
    own_workers_archived = _combine(archivable)
    remaining = _remaining_rows(workers, role="worker")
    if interrupt_root:
        remaining += _remaining_rows([root], role="root")
    link = transport.finish()
    issues = [issue for entry in [*workers, root] for issue in entry["issues"]] + transport.issues
    cleared = (
        not issues
        and not remaining
        and own_workers_confirmed_ended is True
        and own_workers_archived is True
        and (not interrupt_root or root["turns_confirmed_ended"] is True)
        and (not link["cleanup_connection_created"] or link["cleanup_connection_closed"] is True)
    )
    return sealed({
        "schema": REPORT_SCHEMA,
        "status": "PASS" if cleared else "BLOCKED",
        "observed_at": now(),
        "wait_seconds": wait_seconds,
        "owned_worker_thread_ids": owned,
        "closed_worker_thread_ids": closed,
        "own_workers_confirmed_ended": own_workers_confirmed_ended,
        "own_workers_archived": own_workers_archived,
        # Closed natively by this owner, and so never read or archived here.
        "workers_closed_natively": len(closed),
        "root_turn_confirmed_ended": root["turns_confirmed_ended"] if interrupt_root else None,
        "cleanup_connection_closed": link["cleanup_connection_closed"],
        "root": root,
        "workers": workers,
        "connection": link,
        "counters": counters,
        "remaining": remaining,
        "issues": issues,
    }, "report_sha256")


__all__ = [
    "ALLOWED_METHODS",
    "CLIENT_NAME",
    "CleanupInputError",
    "MAX_OWNED_WORKERS",
    "REPORT_SCHEMA",
    "canonical",
    "report_issues",
    "report_valid",
    "seal_valid",
    "sealed",
    "settle_owned_tasks",
]
